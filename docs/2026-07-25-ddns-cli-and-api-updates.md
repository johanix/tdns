# DDNS update CLI + API RR-update channel — design

> **Superseded by [`2026-08-10-ddns-cli-and-api-updates.md`](2026-08-10-ddns-cli-and-api-updates.md).**
> Kept as discussion history only. The successor retargets persistence from a
> BIND-style journal to SQLite (source of truth), adds atomic REPLACE, and
> leaves the API admission-gate shape open.

> **⚠️ DRAFT — NOT FULLY COOKED.** Committed to main mid-discussion only so the
> work isn't lost. Several forks in §8 are still OPEN — notably **F10**
> (persistence timing: immediate write-back vs. a bind9-style journal) — and all
> of §7 / PR-3 (TSIG authorization) is a *direction sketch*, not a final design.
> The persistence wording in §5.2 and §11 is provisional pending F10. Treat
> nothing here as settled until the §8 forks are closed.

**Date:** 2026-07-25
**Status:** PROPOSED — architecture agreed in discussion (one statement frontend,
two transports; a unified flat `allow-updates` admission gate, §2.1); the
individual design forks in §8 are marked with their state. Not implemented.
**Companion:** `2026-07-13-dynamic-primary-zones.md` (PR #327) — whose product
this feature makes practically usable: an API-provisioned primary is only as
useful as the mechanisms for changing its content.

---

## 1. Motivation

With dynamic zones supported for both secondaries and primaries, the two zone
types differ in exactly one structural way: a secondary's content is updated
upstream (correctly not our problem), while a dynamic primary's content must
be updatable *here* or the zone is an ornament.

The update-mechanism landscape, as assessed and decided 2026-07-24:

| # | Mechanism | State | Decision |
|---|-----------|-------|----------|
| 1 | RFC 2136 UPDATE, SIG(0)-authorized, policy-gated by the template | works today | keep — the designed-in channel |
| 2 | freeze → edit zone file → thaw/reload | works today | rejected as an update channel (operator surgery only) |
| 3 | delete + re-add with prepared zone file | works today | rejected (blunt, availability gap) |
| 4 | RFC 2136 UPDATE, **TSIG**-authorized | gap — TSIG is MAC-verified at transport but ignored for authorization (known since 2026-07-13) | highly relevant; §7 |
| 5 | RR-level updates via the **management API** | does not exist in tdns (tdns-mp has addrr/delrr) | highly relevant; §5 |
| 6 | child-update / delegation channels (allow-child-updates) | v1-refused for dynamic primaries | deferred, maybe never |

The common practical problem with 1 + 4 + 5: **none is usable without CLI
support**. nsupdate exists for (1), but demands the caller find and manage the
right SIG(0) key material, and speaks nothing of (5). This document designs
that CLI support once, for all three.

## 2. Architecture: one frontend, two transports

The core observation: the *batch language* (what to change) and the
*transport/authorization* (how the change is delivered and who may make it)
are orthogonal. `tdns-cli` therefore gets ONE update frontend — a parser from
an nsupdate-like statement language to an ordered action list — and two
interchangeable backends:

```
                        ┌── --via api ──> mgmt API ──> UpdateRequest ──> ZoneUpdater
  input ──> [actions] ──┤                (X-API-Key)     (PreAuthorized)
                        └── --via ddns ──> RFC 2136 msg ──> DNS port ──> updateresponder
                                          (SIG(0), later TSIG)          (Validate/Trust/Approve)
```

- **`--via api`** (mechanism 5): the parsed actions travel over the
  management API; the server synthesizes one `UpdateRequest` and routes it
  through the existing ZoneUpdater/publish path, so snapshot correctness,
  dirty handling and the PR #327 write-back come for free. Authorization is
  the API credential — no key hunting. This is the operator/admin channel.
- **`--via ddns`** (mechanism 1 now, mechanism 4 later): the same actions are
  encoded as a real RFC 2136 message, signed, and sent to the DNS port —
  passing through the full `ValidateUpdate → TrustUpdate → ApproveUpdate`
  pipeline. This is the only variant that *exercises the policy envelope*
  (an API-transported update can never test whether selfsub+TXT gating
  works), which is exactly what tdns-debug's churn/acceptance runs need.

The same statements work against either backend; scripts choose authorization,
not syntax.

### 2.1 Authorization model: `allow-updates` (admission) × `updatepolicy` (scope)

Content modification has two orthogonal authorization axes, kept in separate
config — and keeping them separate is exactly what lets the admission gate stay a
simple flat list:

- **Admission — WHICH mechanisms may modify this zone.** Promote `allow-updates`
  from an `options:` token (its shape today — `options: [ allow-updates ]`) into
  its **own keyed flat list of enabled mechanism tokens**:

  ```yaml
  allow-updates: [ sig0, tsig, api ]   # the "ways in" that are on. Nothing else.
  ```

  `sig0` and `tsig` are the two auth methods of the RFC 2136 DNS UPDATE channel;
  `api` is the management-API channel. A future channel (e.g. `epp`) appends as
  another token — never a restructure. The list carries ONLY which mechanisms are
  on; it holds no per-mechanism config, so it never needs to grow structure.

- **Scope / per-mechanism config — WHAT each mechanism may touch.** Lives in its
  own block, never in the admission list:
  - `sig0` and `tsig` (the DNS channel) share the **`updatepolicy:`** block
    (`self`/`selfsub`, rrtypes), applied by owner name relative to the signer
    (`us.SignerName`) — unchanged from today, and shared by both methods (§7).
    They share the same NAME-scope and cannot be scoped differently by name.
  - `tsig` additionally carries **`tsig-keys: [ ... ]`** — the explicit
    allowlist of which configured TSIG keys may author updates (§7). This is
    tsig's truststore-equivalent: SIG(0) keys opt in via the truststore, so
    TSIG keys need an equally explicit opt-in, or enabling `tsig` would
    silently promote every in-scope-named transfer key into an update
    credential (the scope check is a bare `HasSuffix` on the key name).
    Absent/empty ⇒ no TSIG key may update (fail-closed).
  - `api` is deliberately coarse — operator authority that **bypasses**
    `updatepolicy:` (§5.3); it needs no scope block.
  - a future `epp` brings its OWN block (the registrar model), just as the DNS
    channel's scope lives in `updatepolicy:`. `updatepolicy:` is not universalized.

Keeping config out of the admission list is why the flat list is sufficient
long-term: the "insufficient flexibility" worry only appears if you try to cram
per-mechanism config into the gate, which this model deliberately does not.

**Not admission mechanisms.** Internal, server-sourced updates (CSYNC/KEY
publication, `InternalUpdate`) bypass `allow-updates` entirely — they are not an
externally-selectable mechanism and never appear in the list.

**Backward compatibility (and the migration reality).** `allow-updates` is an
`options:` token today, so this is a cross-field migration, not a scalar remap: a
decode hook maps the token `options: [ allow-updates ]` → the keyed list
`allow-updates: [ sig0 ]` (today's behavior — SIG(0) DNS UPDATE) and strips it from
`options:`; absent → `[]` (no external modification). Enabling TSIG or the API
channel is then a deliberate, visible edit, never inherited silently. Three
interactions ride along and must be handled: (a) template merge needs list-union
for the new key, as `options:` has today; (b) `activateUpdatePolicy` — which today
forces `OptAllowUpdates` off when `updatepolicy` is `none`/unset — must treat the
DNS tokens (`sig0`/`tsig`) as inert in that case (admission without a name-scope is
meaningless); (c) `zone list` and persistence surface the new key.

**Escape hatch (only if ever needed).** Should some future channel genuinely need
config *inline* in the gate, a list element may become either a bare token or a
single-key `{ token: config }` map — a backward-compatible extension of the same
list. Do not build it now; keep config in sibling blocks.

This unifies the admission side: the API channel's `api-may-modify` consent bit
(§5.2) becomes the `api` token, and TSIG enablement becomes the `tsig` token. The
TSIG `tsig-keys:` clause is **retained**, not dissolved — it is tsig's
per-mechanism key allowlist (the truststore-equivalent above), the explicit opt-in
that keeps a transfer key from silently becoming an update credential.

## 3. The command and its statement language

Placement (decided, F4): under the zone tree, mirroring tdns-mp's
`tdns-mpcli agent zone addrr/delrr` shape:

```
tdns-cli auth zone update {addrr,delrr,delrrset} --zone <zone> "<rr>" [...] --via {ddns,api}
tdns-cli auth zone update --zone <zone> --via {ddns,api} --interactive
```

`--via` is REQUIRED — no default (decided, F4): the two channels differ in
authorization model and policy enforcement, so which one a script uses must
be visible in the invocation, not inherited silently.

Statement verbs, one per line in the update reader (tty or piped); RRs and
RR-fragments in ordinary zone-file syntax (parsed with `dns.NewRR`, the same
liberal parser the zone loader uses); blank lines and `#`-comments ignored:

| One-off subcommand | Statement verb | Arguments | Meaning (RFC 2136 §2.5) |
|--------------------|----------------|-----------|-------------------------|
| `addrr` | `ADD` | full RR (`name ttl [class] type rdata`) | add RR to an RRset (§2.5.1) |
| `delrr` | `DEL` | full RR (ttl ignored) | delete a specific RR (§2.5.4) |
| `delrrset` | `DELRRSET` | `name type` | delete an entire RRset (§2.5.2) |
| `delname` | `DELNAME` | `name` | delete all RRsets at a name (§2.5.3; needs applier support, §5.4) |

Session verbs (the update reader (tty or piped) only): `SHOW` (list pending rows,
numbered), `DELROW <n>` (remove row `<n>` as numbered by the last `SHOW`),
`SEND` (transmit the transaction), `ABORT`/`QUIT` (discard and exit).
Nothing is transmitted before `SEND`.

Names may be relative; they are made absolute against `--zone` (always
explicit — no nsupdate-style SOA discovery, F6).

### 3.1 One-off mode

```
tdns-cli auth zone update addrr --zone pizza.example "www 300 IN A 192.0.2.1" "www 300 IN AAAA 2001:db8::1" --via api
tdns-cli auth zone update delrrset --zone pizza.example "www TXT" --via ddns
```

One verb per invocation, one or more statements as arguments, one
transaction. (A mixed ADD+DEL transaction needs interactive mode.)

### 3.2 Interactive mode (which subsumes scripted input)

`tdns-cli auth zone update --zone pizza.example --via api --interactive`
starts a readline REPL (v2/cli already carries the dependency) accepting
the statement + session verbs, accumulating rows until `SEND`. `SHOW`
numbers the pending rows; `DELROW <n>` edits the pending transaction — an
improvement over nsupdate, which has no row editing (mistake = abort and
start over).

There is deliberately NO separate batch/heredoc mode: interactive is a
superset of a heredoc (decided). When stdin is not a tty, the same reader
consumes the same verb stream with the prompt suppressed:

```
tdns-cli auth zone update --zone pizza.example --via api --interactive <<EOF
ADD      www 300 IN A 192.0.2.1
ADD      www 300 IN AAAA 2001:db8::1
DEL      old 300 IN A 192.0.2.99
DELRRSET legacy TXT
SEND
EOF
```

One reader, one parser, one behavior — a heredoc is a replayed interactive
session, and a recorded interactive session replays as a script. No
`--file` flag either: `< file` is the same thing. (An input stream that
ends without `SEND` is discarded with a warning, never auto-sent: an
accidentally truncated script must not half-apply.)

### 3.3 nsupdate compatibility stance (decided: deliberate clean break)

The question was raised whether to stay fully nsupdate-compatible (limit
confusion) or drop its idiosyncrasies. Decision: **clean break, familiar
rhythm** — same line-per-statement feel, same zone-file RR syntax (which is
where the actual muscle memory lives), same `show`/`send` cadence, but NOT
nsupdate's language. Reasons:

1. nsupdate's `update delete` is argument-count-overloaded (name-only vs
   name+type vs full RR) — its single biggest mistake generator. Explicit
   verbs are the point of doing our own.
2. Real nsupdate scripts embed `server`, `zone`, and notably
   `key <algo>:<name> <secret>` statements. Those conflict with tdns-cli's
   flag/config model, and in-script secrets violate the house
   secret-handling posture. Honoring them badly would be worse than not
   honoring them.
3. Partial compatibility is the worst outcome: looks compatible, behaves
   subtly differently — exactly the confusion to avoid. Clearly-different
   is safer than almost-same.
4. Protocol-level compatibility is the real compatibility: tdns speaks
   RFC 2136, so bind9's nsupdate keeps working against it for anyone with
   existing scripts and SIG(0)/TSIG material.

### 3.4 Transaction semantics

One invocation (or one REPL `SEND`) = one zone = one atomic transaction:

- `--via ddns`: all actions in a single RFC 2136 message — atomicity is the
  protocol's (RFC 2136 §3.7: updates are applied atomically per message).
- `--via api`: all actions in a single `UpdateRequest.Actions` list, applied
  by `ApplyZoneUpdateToZoneData` in one pass and published as one snapshot
  update.

Multi-`send` sessions targeting several zones (nsupdate's model) are out of
scope for v1; run the tool once per zone.

## 4. Wire mapping

The frontend normalizes every statement to the RFC 2136 Update-section
encoding before either backend sees it (this is also exactly what
`SprintUpdates` in `v2/zone_updater.go` decodes today). The four operations
are distinguished by CLASS *and* TYPE — CLASS=ANY means "delete", and the
TYPE field then chooses RRset-scope vs whole-name-scope:

| Verb | Class | Type | TTL | Rdata | RFC 2136 |
|------|-------|------|-----|-------|----------|
| `ADD` | `IN` (zone class) | the type | as given | as given | §2.5.1 |
| `DEL` | `NONE` | the type | 0 | as given | §2.5.4 |
| `DELRRSET` | `ANY` | the type | 0 | empty | §2.5.2 |
| `DELNAME` | `ANY` | `ANY` (255) | 0 | empty | §2.5.3 |

Note DELRRSET and DELNAME share CLASS=ANY; only the TYPE differs (a concrete
type vs. `ANY`). This is precisely the fork in the applier's ClassANY branch
(§8, F5): it handles DELRRSET correctly today and no-ops DELNAME.

So the parser's output is simply `[]dns.RR` in update-section encoding —
directly usable as `UpdateRequest.Actions` (api) or as the Update section of
a `dns.Msg` (dns).

## 5. The API backend (mechanism 5)

### 5.1 Client side

The `ddns` command with `--via api` (see fork F4 for the default) resolves
the tdns-auth API client exactly as every other command (GetApiClient), and
sends a new `ZonePost`-style request carrying the zone name and the encoded
action list. The secret-handling conventions from the dynamic-zones work
apply unchanged (nothing here carries secrets — the API key comes from the
CLI config as always).

### 5.2 Server side

A new API operation (`zone update` command in the zone handler, or a
dedicated `/zone/update` endpoint — implementation detail) that:

1. Resolves the zone; refuses unknown zones and zones outside the eligible
   set (F1, decided): **primaries only, and only zones whose `allow-updates`
   list contains the `api` token** (§2.1). Secondaries are always refused (their
   content is upstream's; an API edit would be silently overwritten by the next
   transfer). The `api` token is deliberately coarse — one all-or-nothing
   per-zone operator-consent bit, NOT a full "api-policy" block (§5.3) — set per
   static zone in config, or carried by a template for dynamic primaries (list
   union), persisted in the dynamic entry, visible in `zone list`. Absent by
   default, so the API channel is inert for every existing zone.
2. Validates the action list: every RR parses, every owner name is within
   the zone (out-of-zone names are a hard refusal — RFC 2136 §3.4.2.7
   equivalent), reasonable size cap.
3. Synthesizes ONE `UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName, Actions}`
   with a new **`PreAuthorized bool`** marker, and enqueues it on the
   ZoneUpdater queue.

`PreAuthorized` is a third authorization class, distinct from both existing
ones:

| | admission (`allow-updates` list) + DNS-channel scope (`updatepolicy:`) | sets OptDirty + persists | example |
|---|---|---|---|
| wire update (default) | yes — Validate/Trust/Approve pipeline | yes | RFC 2136 from a client |
| `InternalUpdate` | bypassed | no (deliberately; not operator-visible drift) | CSYNC/KEY publication |
| `PreAuthorized` (new) | bypassed — the API credential IS the authorization | **yes** — this is real content change and must survive restart | `tdns-cli auth zone update ... --via api` |

Concretely, ZoneUpdater's ZONE-UPDATE gate becomes "the zone's `allow-updates`
admits this update's mechanism, OR `ur.InternalUpdate`, OR `ur.PreAuthorized`":
the wire path checks the signer's method (`sig0`/`tsig`) against the list, and the
API path arrives already `PreAuthorized` (the `api` token was checked at the
handler, step 1). The dirty/persist block treats `PreAuthorized` like an external
update, and the PR #327 write-back then persists API-managed primaries
automatically. (Persistence *timing* for static primaries admitted via the `api`
token — immediate vs. journal-backed — is open fork F10.)

### 5.3 What the API channel is NOT

The API credential is all-or-nothing operator authority. This channel
deliberately bypasses the template's update-policy envelope — which is
correct for an operator tool and WRONG for self-service clients. Per-client
self-service stays on the DNS channel (mechanisms 1/4), where the template
constrains what each key may touch. The docs and command help must say this
explicitly, so nobody builds a student-facing frontend on the admin channel.

### 5.4 Applier support for DELNAME (§2.5.3) — a pre-existing gap

DELNAME is the one verb whose wire encoding the *server* does not yet honor,
independent of transport, so it is fixed once in the applier and both
channels inherit it. Today `ApplyZoneUpdateToZoneData` (`v2/zone_updater.go`)
processes each action as `(class, rrtype)`; a DELNAME arrives as
CLASS=ANY/TYPE=ANY and:

1. is denied by the per-action policy gate (`UpdatePolicy.Zone.RRtypes[ANY]`
   is false) on the policy-checked path, and
2. on any path that reaches the body, falls out at the RRset lookup
   (`owner.RRtypes.Get(TypeANY)` misses → `continue`) — a silent no-op.

The fix hoists a DELNAME case above the per-action policy gate:

```go
// DELNAME (RFC 2136 §2.5.3): CLASS=ANY, TYPE=ANY → delete every RRset at
// the name. §3.4.2.4: at the zone apex, SOA and NS RRsets are retained.
if class == dns.ClassANY && rrtype == dns.TypeANY {
    owner := zd.stagedOwner(ownerName)
    if owner == nil {
        continue // name absent; nothing to delete
    }
    isApex := ownerName == zd.ZoneName
    for _, t := range owner.RRtypes.Keys() {
        if isApex && (t == dns.TypeSOA || t == dns.TypeNS) {
            continue // §3.4.2.4 apex retention
        }
        // Policy-gated channel: only remove policy-allowed types, so DELNAME
        // stays inside the envelope. Internal/pre-authorized updates bypass.
        if !ur.InternalUpdate /* && !ur.PreAuthorized (when that lands) */ {
            if _, ok := zd.UpdatePolicy.Zone.RRtypes[t]; !ok {
                continue
            }
        }
        zd.stageDeleteLocked(ownerName, t)
        updated = true
    }
    continue
}
```

Two properties worth stating:

- **Apex retention is RFC-mandated, not a choice** (§3.4.2.4): a DELNAME at
  ZNAME removes everything *except* SOA and NS. Below the apex it removes
  everything at the name.
- **Under a restrictive policy, DELNAME degrades to a bulk DELRRSET over the
  allowed types** (DECIDED, option 1; the alternatives — require TYPE=ANY in the
  policy, or reject policy-gated DELNAME entirely — were rejected). The
  internal/pre-authorized paths remove everything (minus apex SOA/NS). DNSSEC
  chain maintenance is unchanged: like DELRRSET, removals are staged and the
  NSEC/RRSIG state is reconciled at publish time (the existing model does not
  maintain the chain incrementally).

This is a small, self-contained server change with its own tests
(delete-all below apex; apex SOA/NS retained; policy-limited variant;
absent-name no-op) and is independent of PR #327 and of the CLI itself.

## 6. The DNS backend (mechanism 1, then 4)

The sender machinery already exists for delegation sync:
`CreateUpdate(zone, adds, removes)` builds the RFC 2136 message and
`SendUpdate(msg, zonename, addrs)` delivers it (`v2/childsync_utils.go`),
with SIG(0) signing around it (keystate/`Sig0ActiveKeys`). The ddns backend
generalizes this: the update section comes from the parsed batch (including
DELRRSET/DELNAME encodings, which adds/removes don't express today), the
target is `-s/--server addr:port` (default: the zone's own apex NS via
normal resolution), and the signing key is selected by flag:

- `--sig0-keyfile <path>` / `--sig0-key <name>` (keystore-resident key) —
  mechanism 1, works against today's server.
- `--tsig-name/--tsig-secret[-file]` — mechanism 4, once the server
  authorizes TSIG (§7). The flags can ship earlier; the server refuses until
  then, which is an honest error.

Responses are reported with the rcode + any EDE, not swallowed.

## 7. TSIG-authorized updates (mechanism 4) — direction sketch

The known gap: the update responder's authorization pipeline
(`ValidateUpdate → TrustUpdate → ApproveUpdate`) is SIG(0)-only; a TSIG MAC
is verified at the transport layer and then ignored for authorization. The
dynamic-primary feature makes this gap newly expensive: `zone add` already
installs a per-zone inline TSIG key, but that key only gates outbound
transfers — while updating the same zone requires a *different* credential
system (SIG(0) + truststore round-trip).

The key finding: **the authorization logic is reusable, but TSIG needs an
explicit key allowlist that SIG(0) gets for free.** The approval logic
(`updateresponder.go`, the self/selfsub enforcement at :550) keys purely on
`us.SignerName` + the policy's rrtypes — it never asks "was this SIG(0)?", so TSIG
reuses `updatepolicy:` verbatim for NAME-scope. But there is a gap SIG(0) does not
have: a SIG(0) key is opted into update-authorization explicitly, via the
truststore; a TSIG key is merely *configured*, often for transfer. Because the
scope check is a bare `strings.HasSuffix(owner, us.SignerName)`, honoring TSIG
without an allowlist would silently promote every configured TSIG key whose NAME is
a hierarchical ancestor of a zone owner — including a transfer key named
`axfr.net.` — into a full update credential. So TSIG keeps an explicit allowlist.
The work:

- **Admission:** add `tsig` to the zone's `allow-updates` list (§2.1) — the DNS
  channel's second auth method.
- **Key allowlist (`tsig-keys:`), tsig's truststore-equivalent:** an explicit list
  of which configured TSIG keys may author updates for this zone. A key not listed
  can never update, whatever its name (fail-closed; empty/absent ⇒ no TSIG update).
  This is the deliberate opt-in that keeps transfer keys from silently gaining
  update rights. A listed key is THEN further bounded by `updatepolicy:` name-scope
  (a per-name key like `test1.pq.axfr.net.` is confined to its own subtree).
- **Receiver wiring:** the TSIG MAC is ALREADY verified at the transport layer (the
  fork's TsigProvider); today it is dropped for authorization. Honor it: when the
  UPDATE carries a verified TSIG RR whose key name is in `tsig-keys:`, set
  `us.SignerName = <the TSIG key name>`, `us.Validated = true`, and
  `us.ValidatedByTrustedKey = true`, and the existing pipeline authorizes it per
  `updatepolicy:`.
- **Validate and Trust for TSIG = verified MAC + allowlisted.** SIG(0) needs the
  truststore round-trip (`TrustUpdate`) because the key is asserted; a TSIG key is
  pre-shared, so a verified MAC against a key that is IN `tsig-keys:` is the trust —
  the allowlist replaces the truststore lookup, it does not remove the need for an
  explicit trust decision.
- **`zone add --tsig-name ...`** then yields a zone the caller can immediately
  update with the credential they already hold: the inline key already gates
  transfers (implemented) and persists (implemented); adding `tsig` to
  `allow-updates` and the key to `tsig-keys:` makes that same key an update
  credential, scoped to its own name. Per-test keys with one shared template.
- **Scope note:** this authorizes TSIG for ZONE-scope (`self`/`selfsub`) policies.
  Child-scope (delegation) authorization stays SIG(0) — child updates are
  cross-administrative, where asymmetric keys are the right tool.

This lands as its own PR after the CLI exists (phasing, §9): the CLI is what
makes it testable.

## 8. Design forks

- **F1 — API-channel zone eligibility. DECIDED (2026-07-25): primaries
  only, gated by the `api` token in the zone's `allow-updates` list (§2.1, F9).**
  Secondaries are refused outright. Rationale: the API credential is not bounded
  by the DNS update policy (F2), but "operator may modify ANY zone" is too broad
  and a full api-policy block is too much — one per-zone consent token is the
  right compromise. Details in §5.2.
- **F2 — does the API channel respect the update policy? DECIDED
  (2026-07-24): no.** API credential = operator authority within the `api`
  admission token (§2.1); DNS-policy enforcement is the DNS channel's job
  (§5.3 records the consequence).
- **F3 — prerequisites (`yxrrset`/`nxrrset`/...). DECIDED (2026-07-25):
  deferred to phase 2**, both channels. The server does not evaluate
  RFC 2136 prerequisite sections today (nothing in the responder reads the
  Answer section), so this is server work, not just CLI work. The statement
  language reserves `PREREQ ...`; the parser refuses it until implemented.
- **F4 — command placement. DECIDED (2026-07-25):
  `tdns-cli auth zone update {addrr,delrr,delrrset}`** with
  `--via {ddns,api}` and `--interactive`, mirroring tdns-mp's
  `agent zone addrr/delrr` shape (§3). **`--via` has NO default and is
  required** — explicit is the path of least confusion; the channels differ
  in authorization model, and which one a script uses must be visible in
  the invocation.
- **F5 — verb set. DECIDED (2026-07-25): `addrr`/`delrr`/`delrrset`/
  `delname` one-off subcommands, `ADD`/`DEL`/`DELRRSET`/`DELNAME` +
  `SHOW`/`DELROW`/`SEND`/`ABORT` statement verbs** (§3). DELNAME is
  included, and the applier is fixed to support it (§5.4) — a §2.5.3 update
  arriving today from bind9's nsupdate already hits the silent no-op, so
  this closes a pre-existing gap independent of the CLI.
- **F6 — zone targeting. DECIDED: explicit `--zone` always** (house style;
  no SOA-discovery magic). The ddns backend resolves the target server when
  `-s/--server` is not given; the api backend needs no target.
- **F7 — tdns-mp addrr/delrr convergence. NOTE-ONLY (recommendation
  accepted implicitly via F4's naming choice).** Adopting tdns-mp's
  addrr/delrr verb names makes eventual convergence natural — the batch
  format should become the one RR-mutation surface when tdns-mp's pin
  catches up (~470 commits behind). Design nothing that blocks it;
  implement none of it now.
- **F8 — nsupdate compatibility. DECIDED (2026-07-25): deliberate clean
  break, familiar rhythm** — §3.3 records the reasoning.
- **F9 — unified admission gate. DECIDED (2026-07-25): promote
  `allow-updates` from an `options:` token into a FLAT LIST of enabled mechanism
  tokens** (`[ sig0, tsig, api ]`; §2.1), holding admission only. Admission (which
  mechanisms) and scope/config (`updatepolicy:` for the DNS methods; `tsig-keys:`
  for tsig; a per-channel block for anything else) are separate axes, so the list
  stays flat and future channels (e.g. `epp`) append as tokens. This SUPERSEDES
  the standalone `api-may-modify` option (F1 → the `api` token); TSIG enablement
  becomes the `tsig` token, while its `tsig-keys:` allowlist is RETAINED as tsig's
  per-mechanism key opt-in (§7, F11). Backward-compat is a cross-field migration:
  the `options:` token `allow-updates` → the keyed list `allow-updates: [ sig0 ]`
  (§2.1). A `{ token: config }` list element is a reserved escape hatch, not built
  now.
- **F10 — persistence timing for `api`-admitted (and DNS-updated) static
  primaries. OPEN.** A static primary modified in place must have its changes
  written back to its source zonefile, but WHEN is unresolved: immediate
  per-transaction write-back (durable, but rewrites the operator's file and churns
  it at high update rates) vs. a journal-backed model (bind9-style: append per
  update, fold on sync/freeze — durable AND non-clobbering, but tdns has no on-disk
  journal today; the in-memory `IxfrChain` is its natural seed). Lean: ship the CLI
  on immediate write-back (decoupled, paints no corner — the journal is an additive
  swap at the persistence layer); pursue journal-backed persistence as its own
  foundational effort. The provisional "NOT auto-persisted" phrasing in §5.2/§11 is
  pending this.
- **F11 — TSIG update-key allowlist. DECIDED (2026-07-25): retain `tsig-keys:`.**
  TSIG update-authorization keeps an explicit per-zone key allowlist rather than
  relying on key-name scoping alone. Rationale: the scope check is a bare
  `HasSuffix(owner, keyName)`, so without an allowlist, enabling `tsig` would
  silently promote every configured TSIG key whose name is a zone-owner ancestor
  (e.g. a transfer key named for the zone) into a full update credential — SIG(0)
  avoids this via the truststore opt-in; TSIG needs the equivalent. Fail-closed:
  empty/absent `tsig-keys:` ⇒ no TSIG key may update (§7).

## 9. Phasing

- **PR-0 — applier support for DELNAME (§5.4).** A standalone,
  self-contained server bug fix: `ApplyZoneUpdateToZoneData` learns
  CLASS=ANY/TYPE=ANY. Independent of the CLI (closes a latent gap for
  nsupdate today) and of PR #327, so it can land first and on its own.
  Tests per §5.4.
- **PR-1 — statement frontend + API backend.** The one-off subcommands
  (`addrr`/`delrr`/`delrrset`/`delname`) plus the interactive reader (tty
  and non-tty), the new API operation, the generalized `allow-updates` gate
  with its `api` token (F9), `PreAuthorized` plumbing in ZoneUpdater,
  eligibility per F1. Immediately
  useful: eligible primaries become editable with nothing but the tdns-cli
  config. Unit tests: parser round-trip to update-section encoding,
  eligibility matrix (primary+option / primary-without-option / secondary),
  atomicity (one UpdateRequest per transaction), out-of-zone refusal.
- **PR-2 — DNS backend + interactive mode.** SIG(0) signing path reusing
  the childsync sender; REPL. tdns-debug can then drive policy-envelope
  acceptance through the same tool.
- **PR-3 — TSIG authorization (mechanism 4).** Server-side per §7 + the
  already-shipped `--tsig-*` flags light up. Separate design detail round
  before implementation.
- Prerequisites (F3) slot in wherever the need first materializes.

## 10. Relation to existing work

- **PR #327 (dynamic primaries)** — the driving consumer; acceptance
  criterion "UPDATE-per-policy round-trip" becomes runnable without bind9's
  nsupdate.
- **tdns-debug** — churn/ddns runs adopt `--via ddns` for envelope testing;
  the capability matrix gains the api channel as a separate probe.
- **labstuff statusd-style self-service** — must NOT use the api channel
  (§5.3); it is the motivating case for mechanism 4's one-shot provisioning.
- **tdns-mp addrr/delrr** — see F7.
- **API client lib idea** (deferred) — this adds yet another ad-hoc API
  accessor to v2/cli; three consumers now, which strengthens the case for
  the consolidation, but that remains future work.

## 11. Acceptance sketch

- Parser: every verb → correct update-section encoding (class/ttl/rdata
  table in §4), rejection of malformed RRs, out-of-zone names, and reserved
  `PREREQ`.
- API channel: transaction of ADD+DEL+DELRRSET applied atomically to a dynamic
  primary; content persisted (file reflects the change without any freeze);
  restart → content survives; secondary refused; unknown zone refused;
  eligible static primary accepted and marked dirty (write-back timing per F10).
- DNS channel: same batch, SIG(0)-signed, accepted per template policy;
  policy-violating batch refused with the pipeline's rcode; unsigned refused.
- One-off arguments and the interactive reader (tty and piped/heredoc)
  produce byte-identical transactions for the same statements.
