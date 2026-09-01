# DSYNC scheme "API": child-to-parent delegation updates over HTTPS

**Date:** 2026-08-11
**Status:** AS BUILT. All five PRs implemented on `feature/dsync-api-scheme`;
what changed from the design is in §16, what was verified in §17.
**Depends on:** `feature/api-zone-updates-phase2` — this reuses the statement
vocabulary, the applier and the durability ordering built there
(`2026-08-10-ddns-cli-and-api-updates.md`).
**Related:** RFC 9859 (DSYNC), `draft-ietf-dnsop-delegation-mgmt-via-ddns`,
`2026-06-22-DONE-agent-dsync-proxy-for-clueless-primary-plan.md`.

---

## 1. What this is, and what it is not

DSYNC tells a child how to reach its parent to get delegation data changed.
tdns implements two schemes today: NOTIFY (tell the parent to come look) and
UPDATE (send the parent an RFC 2136 UPDATE, signed with SIG(0)). Both are DNS.
Both require the child to hold a SIG(0) key the parent trusts.

The API scheme exists for the children that cannot do that. Not because HTTPS
is better — it is not; the UPDATE scheme is the one to prefer — but because
"our provisioning system can POST JSON and cannot sign a DNS message" is a real
and common constraint, and today it means falling back to a registrar web form.

`SchemeAPI = 4` is already allocated in `v2/core/rr_dsync.go` and is referenced
by nothing. This document fills that hole.

**Not in scope.** The management API stays exactly as it is: a
trusted-operator, single-shared-key, do-anything surface. The DSYNC API is a
different surface with different auth, a different policy and a different
listener, and it must not become a second way to reach the management API's
authority. Nor does anything here change the NOTIFY or UPDATE schemes, or the
phase 1/2 code beyond one refactor named in §6.3.

---

## 2. The shape, end to end

```
child                                                       parent
  │                                                            │
  │ 1. DSYNC discovery (DNSSEC-validated)                       │
  │──── _dsync.example. DSYNC CDS API 443 dsync-api.example. ──>│
  │                                                             │
  │ 2. service description at the target (DNSSEC-validated)     │
  │──── dsync-api.example. URI 1 1 "https://.../dsync/v1" ─────>│
  │──── dsync-api.example. TXT "tdns-child-api-v1.0" ──────────>│
  │                                                             │
  │ 3. POST the desired delegation, HTTP Basic over TLS         │
  │─────────────────────────────────────────────────────────────>│
  │                                          │ authenticate <user,key>
  │                                          │ authorize via updatepolicy.child
  │                                          │ apply → persist → publish
  │<──── 200 (the change is durable and being served) ──────────│
```

---

## 3. Discovery records

Three records, all published by tdns-auth on the parent side.

```
_dsync.example.      7200 IN DSYNC CDS   API 443 dsync-api.example.
_dsync.example.      7200 IN DSYNC CSYNC API 443 dsync-api.example.
dsync-api.example.   7200 IN URI   1 1 "https://dsync-api.example:443/dsync/v1"
dsync-api.example.   7200 IN TXT   "tdns-child-api-v1.0"
```

**The DSYNC target is a service description point, not a server to speak DNS
to.** This is the one structural difference from the other two schemes. For
NOTIFY and UPDATE the target is a host you send a DNS message to, which is why
`PublishDsyncRRs` synthesises A/AAAA records at it. For API the target is
merely a name at which the URI and TXT live; the URI carries the actual
endpoint, and its authority resolves by ordinary means. Address records at the
target are therefore **optional** for this scheme, and `addresses:` must not be
a required config key for it the way it is for the other two.

**The port field.** The wire format demands one, so one is published. The URI
is authoritative for scheme, host, port and path. If the DSYNC port and the
URI's effective port disagree, the URI wins and tdns logs a warning — refusing
would make a cosmetic inconsistency fatal, and the URI is the field that
actually determines where bytes go.

**The rrtype field** keeps its usual meaning: which child-published signal this
endpoint is willing to act on. `ANY` means all of them.

---

## 4. The TXT dialect identifier

An HTTPS endpoint has no self-describing wire format, so the child has to be
told what it is talking to before it talks. That is what the TXT is for.

**Value for the first version: `tdns-child-api-v1.0`.**

Format: whitespace-separated tokens. The first token is the dialect
identifier — an opaque string naming protocol *and* version together, matched
literally. Any following tokens are `key=value` parameters, SVCB-style, all
optional; a child ignores parameters it does not recognise. No parameters are
defined in v1.0.

```
dsync-api.example. TXT "tdns-child-api-v1.0"
dsync-api.example. TXT "tdns-child-api-v1.1 maxrrs=64"     ; hypothetical later
```

Rules:

- Multiple character-strings inside one TXT RR are concatenated with no
  separator, as SPF and DKIM do.
- Multiple TXT RRs at the name are allowed and are how a parent advertises more
  than one dialect at once. The child scans the RRset and picks the first
  record whose dialect it implements, in its own order of preference.
- No TXT, or no recognised dialect: **fail closed**. The child does not guess,
  does not fall back to some default, and does not send credentials. It logs
  and moves to the next DSYNC scheme.

Version is inside the identifier rather than in a `v=` parameter deliberately:
a child matching a literal string cannot accidentally half-understand a future
version, and there is no parsing to get wrong before the trust decision is
made.

---

## 5. Authentication

**HTTP Basic over TLS, with a `<username, key>` tuple.** Not the management
API's single shared `X-API-Key`.

The reason is authorization, not authentication strength: a shared key names
nobody, and a policy that cannot name the principal cannot be granular. The
username is the principal. That is the whole point of the tuple.

### 5.1 Requirements

- **TLS is mandatory.** A URI with an `http://` scheme is refused by the child
  before any request is made. One escape hatch, off by default, named so it
  reads like what it is (`delegationsync.child.api.allow-insecure`), because
  the lab will want it and nothing else should.
- **Full certificate validation**, with the URI's host as the verified name. No
  `InsecureSkipVerify` on this path, ever. The XoT/PKIX tooling from PR #316
  (`tdns-cli cert`) already produces usable certificates for a lab CA.
- **Redirects are not followed.** Go strips `Authorization` on a cross-host
  redirect, which turns a redirect into a silent auth failure rather than a
  leak, but same-host redirects still carry the credential and a redirect on
  this endpoint means something is wrong. Refuse all of them.
- **Keys are machine-generated**, at least 128 bits of entropy, produced by the
  parent. tdns never accepts a user-chosen password here. This is what makes
  §10's cheap hash safe.

### 5.2 Why this and not SIG(0)

Deliberately no SIG(0) key is involved. A child that could sign would use the
UPDATE scheme; requiring a signing key to use the scheme that exists for
children without one would be circular. The credential is the only thing the
child needs, and it is obtained out of band — which is not a gap in the design,
it is the scheme's premise.

---

## 6. Authorization: reuse `updatepolicy`, keyed on the username

This is the core decision and the one that keeps the feature small.

### 6.1 The substitution

The child update policy is evaluated today in `ApproveChildUpdate`
(`v2/updateresponder.go:517`) against two things:

1. `zd.UpdatePolicy.Child.RRtypes[rrtype]` — may this type be touched at all;
2. `us.SignerName` — the SIG(0) key name, compared to the owner name under
   `self` (equal) or `selfsub` (suffix).

The API path changes exactly one of those: **the authenticated principal takes
the place of `us.SignerName`.** Everything else — the RRtype gate, `self` vs
`selfsub`, the rejection reasons — applies verbatim.

```yaml
zones:
  - name: example.
    options: [ delegation-sync-parent, allow-child-updates ]
    updatepolicy:
      child:
        type:    selfsub
        rrtypes: [ A, AAAA, NS, DS, KEY ]
```

Under that policy, principal `child1.example.` may change `A/AAAA/NS/DS/KEY` at
or below `child1.example.` — whether it arrives as a SIG(0)-signed UPDATE from
a key named `child1.example.` or as an authenticated POST from principal
`child1.example.`. One policy, one meaning, two transports. An operator who
already understands the UPDATE scheme has nothing new to learn.

### 6.2 Principal vs username

`self`/`selfsub` compare against a domain name, so the principal must be one.
The username need not be:

- **Default:** the principal is the username. Set the username to the child's
  zone name (`child1.example.`) and there is no additional concept at all.
- **Escape hatch:** the credential record may carry an explicit `principal`
  field, in which case the username is opaque. This exists because trailing
  dots in HTTP Basic usernames are unpleasant to type and because an operator
  may want a human-readable account name.

Nothing else is added. A credential names one principal; scope comes from the
zone's policy, not from the credential. (A credential that is *narrower* than
its principal's policy is a plausible later refinement — §14.)

Usernames are normalised as domain names — case-folded and given a trailing dot
— even when they are not domain names: `acme-registrar` is stored and matched as
`acme-registrar.`. A username only has to be unique, and this provides that at
no cost. The alternative, leaving the dot alone, makes `bob` and `bob.` two
accounts; everywhere else in this system those name the same thing, so a
credential store where they do not is a trap whose failure mode is an
indistinguishable 401.

### 6.3 The one refactor

`ApproveChildUpdate` currently takes `(zone, *UpdateStatus, *dns.Msg)` and
reads the signer name off the status. The policy evaluation needs to be
extracted so both callers share it:

```go
// principal replaces us.SignerName; actions replace r.Ns.
func (zd *ZoneData) approveChildActions(principal string, actions []dns.RR) (bool, uint16, error)
```

`ApproveChildUpdate` keeps its SIG(0)-specific preamble (validation, trusted
key, the unvalidated-KEY-upload special case) and then calls the shared
function. The API path calls it directly. If these two ever drift, one
transport silently enforces a different policy from the other — which is
precisely the class of bug this refactor exists to prevent, so it is worth
doing even though it touches working code.

**`PreAuthorized` must stay false on this path.** Phase 1's `ApiZoneUpdate`
sets it because the management API is a trusted-operator surface where the
policy has already been decided by possession of the key. Here the policy is
the entire point. Setting `PreAuthorized: true` on a DSYNC-API request would
hand every credential-holder the authority of the management API — the single
worst mistake available in this design, and worth a comment at the call site
saying so.

---

## 7. The surface

### 7.1 A separate listener

Its own address, its own router, its own middleware, mandatory TLS. Not a
subrouter under `/api/v1`, and not sharing `apiKeyAuthMiddleware`. Different
auth, different policy, different audience: a registrant's provisioning script
is not a trusted operator, and the strongest guarantee that it cannot reach
operator endpoints is that they are not on the socket it connects to.

### 7.2 Endpoints (dialect `tdns-child-api-v1.0`)

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/dsync/v1/delegation/{child}` | What the parent currently holds |
| `POST` | `/dsync/v1/delegation/{child}` | Declare the desired delegation |

Declarative, not imperative. The child states what its delegation should be and
the parent computes the delta — which mirrors `UpdateModeReplace` in
`SyncZoneDelegationViaUpdate`, is idempotent under retry, and avoids exposing
the phase 1 statement vocabulary on an untrusted surface where every verb is
another thing to police.

```json
{
  "child": "child1.example.",
  "rrsets": {
    "NS":   ["child1.example. 3600 IN NS ns1.child1.example.",
             "child1.example. 3600 IN NS ns2.child1.example."],
    "A":    ["ns1.child1.example. 3600 IN A 192.0.2.1"],
    "DS":   ["child1.example. 3600 IN DS 12345 15 2 ABCD..."]
  }
}
```

An RRset present with an empty array means "remove it". An RRset **absent**
means "leave it alone" — not "remove it". The distinction matters: a client
that only manages DS must not wipe the NS RRset by omission.

Internally this translates to one `replacerrset` statement per (owner, type)
group and goes through `BuildZoneUpdateActions` — the seam phase 1 already
built, and the reason this endpoint is small.

The parent zone is resolved by longest-suffix match of `child` against hosted
zones carrying `delegation-sync-parent`; one service can front many parents.

### 7.3 Response semantics

Same promise as phase 2 gave RFC 2136 (§10 of the phase 1/2 doc): **`200` means
applied, persisted and published.** The handler waits on the `UpdateRequest`
reply channel and answers only after the ZoneUpdater is done. Reusing that
machinery is most of why this endpoint is cheap to build.

| Status | Meaning |
|--------|---------|
| 200 | Applied, durable, being served |
| 400 | Malformed body, unparseable RRs, RRs whose owner is not the named child |
| 401 | Missing or bad credentials |
| 403 | Authenticated but the policy refuses (owner outside `self`/`selfsub`, or an RRtype the policy does not allow) |
| 404 | No hosted parent zone for that child, or the zone does not offer this scheme |
| 409 | Zone frozen |
| 503 | Apply timed out (`UpdateApplyTimeout`), or the update queue is unavailable |

403 bodies carry a machine-readable reason mirroring the EDE the UPDATE path
would have returned, so the two transports diagnose alike. 401 bodies carry
nothing: no hint about whether the username exists.

---

## 8. Security properties worth stating plainly

The API scheme has one exposure the UPDATE scheme does not, and it deserves to
be called out rather than buried in a requirements list.

**A bearer credential goes where discovery says it should go.** Under the
UPDATE scheme, a child fooled into sending its update to the wrong server
leaks nothing: the message is SIG(0)-signed, the wrong server cannot use it,
and the change simply does not happen. Under the API scheme, the same
misdirection hands an attacker a working credential.

Therefore:

1. **The DSYNC, URI and TXT lookups MUST be DNSSEC-validated.** If the parent
   zone is unsigned, or validation is indeterminate, the child MUST NOT use
   this scheme. There is no lab exemption for this one that is not also the
   `allow-insecure` exemption; treat them as the same switch.
2. **TLS validation is not optional** (§5.1) — DNSSEC establishes the intended
   endpoint, TLS establishes that you reached it.
3. **No redirects** (§5.1).
4. **The credential is scoped to one parent.** A child that syncs with several
   parents holds several credentials and never sends one to the other's
   endpoint. Match on the URI's origin, not just the hostname.

Point 1 is a hard prerequisite, not a recommendation, and it is the reason this
scheme is a fallback rather than a default: it inherits a dependency on the
parent being signed that the UPDATE scheme does not have.

---

## 9. Parent-side configuration

Read from the config struct, **not from viper.** The existing
`delegationsync.parent.*` block is read with `viper.GetString` /
`viper.GetStringSlice` throughout `ops_dsync.go` and `childsync_utils.go`; new
code does not extend that pattern, and the parentupdater work in labstuff is a
recent reminder of why (dotted keys silently vanish, and nothing logs it).

```yaml
delegationsync:
   parent:
      schemes: [ notify, update, api ]
      api:
         types:     [ CDS, CSYNC ]
         target:    dsync-api.{ZONENAME}      # {ZONENAME} expanded at run time
         baseurl:   "https://{TARGET}:{PORT}/dsync/v1"
         port:      443
         dialect:   tdns-child-api-v1.0       # what goes in the TXT
         addresses: [ ]                       # optional for this scheme
         listen:    [ "0.0.0.0:443" ]
         cert:      /etc/tdns/dsync-api.crt
         key:       /etc/tdns/dsync-api.key
```

`baseurl` keeps the `{TARGET}`/`{PORT}` template form that `PublishUriRR`
already requires (`v2/ops_uri.go:34`), so publication is a direct call.

Publishing needs one new helper, `PublishTxtRR`, mirroring `PublishUriRR` —
there is no `ops_txt.go` today.

---

## 10. Credentials: storage and provisioning

**Stored in the KeyDB, not in the config file.** A registry adds a registrant
without a config reload, and revocation is immediate. A config-file seed list
is a reasonable convenience for small deployments and can be layered later.

```
ApiCredential(id, parent_zone, username, principal, key_hash, created, expires, disabled)
UNIQUE(parent_zone, username)
```

**Hashing.** SHA-256 with a constant-time compare — *not* argon2id or bcrypt.
That is only safe because §5.1 requires machine-generated keys with ≥128 bits
of entropy: a slow KDF exists to make low-entropy secrets expensive to guess,
and a secret that cannot be guessed does not need one. It buys a cheap
per-request verification with no cache to get wrong. This reasoning is load
bearing — if tdns ever accepts a user-chosen key here, the hash must change in
the same commit.

The plaintext key is displayed once, at creation, and never again.

**Provisioning is out of band** and always will be: the registry's own web UI,
an EPP extension, an email to support. That is not a hole in the design — a
child that could bootstrap a credential in band could sign a DNS message, and
would use the UPDATE scheme.

CLI:

```
tdns-cli auth dsync-api credential add    --zone example. --user child1.example.
tdns-cli auth dsync-api credential list   --zone example.
tdns-cli auth dsync-api credential revoke --zone example. --user child1.example.
```

---

## 11. Child-side configuration and dispatch

```yaml
delegationsync:
   child:
      schemes: [ update, notify, api ]    # preference order, as today
      api:
         credentials:
            - parent:   example.
              username: child1.example.
              key:      "file:/etc/tdns/dsync-api.key"   # SensitiveString
         allow-insecure: false
```

`BestSyncScheme` (`v2/childsync_utils.go:386`) gains an `api` case alongside
`update` and `notify`; `SyncZoneDelegation` (`v2/delegation_sync.go:410`) gains
`case "API": SyncZoneDelegationViaApi(...)`. Preference order is the operator's
and defaults to putting `api` last: it is the fallback, not the choice.

A child with no credential for a parent that advertises only API logs one clear
line saying exactly that, and does not retry in a loop.

---

## 12. What must not change

- The management API: same routes, same `X-API-Key`, same authority.
- The NOTIFY and UPDATE schemes: untouched, including preference order for
  deployments that do not configure `api`.
- Phase 1 and phase 2 behaviour, except the §6.3 extraction.
- A parent that does not configure `delegationsync.parent.api` publishes no API
  DSYNC record, opens no listener, and is bit-for-bit as it is today.

---

## 13. Phasing

Each row is a PR that stands on its own and is testable without the next.

| PR | Scope | Notes |
|----|-------|-------|
| **1** | Parent publishes the records: `api` scheme in `PublishDsyncRRs`, `PublishTxtRR`, config struct | No listener, no auth. Verifiable with `dig`. |
| **2** | §6.3 policy extraction, no behaviour change | Its own PR precisely because it touches the working SIG(0) path. Tests must show identical verdicts before and after. |
| **3** | Credential store + CLI | Independently useful; nothing consumes it yet. |
| **4** | The listener: TLS, Basic auth, `GET`/`POST`, policy, apply-persist-publish | The bulk. Gates on 2 and 3. |
| **5** | Child side: discovery, validation, client, `BestSyncScheme`/`SyncZoneDelegation` dispatch | Gates on 1 and 4 for end-to-end testing. |

PR 2 landing early and alone is the important ordering decision: it is the only
part that can break something that works today.

### PR 2 carries a security fix with a wider blast radius than this feature

Extracting the evaluator exposed a bug in the name matching it was extracted
from, and the fix rides in this branch (commit `5027fd9`). **It is not scoped to
the API scheme.** `evalUpdatePolicyRR` enforces `updatepolicy.child` and
`updatepolicy.zone` for every transport, so every zone with a `self` or
`selfsub` policy was affected — on the RFC 2136 SIG(0) path that works today,
whether or not the zone is a delegation parent and whether or not it ever
enables the API scheme.

`selfsub` compared names with `strings.HasSuffix`, which is not label-aligned:

```
strings.HasSuffix("evilchild1.example.", "child1.example.") == true
```

so a trusted key named `child1.example.` could change `evilchild1.example.` —
a different child's delegation, NS and DS included. Also fixed in the same
commit: an empty principal (every string has the empty suffix, so it approved
everything), the root as a principal, and a case-sensitive comparison that
refused legitimate updates.

Anyone reviewing this branch for the DSYNC API should read PR 2 as a change to
the existing update paths that happens to have been found here.

---

## 14. Deferred

- **Per-credential narrowing** — a credential weaker than its principal's
  policy (one RRtype, or read-only). Wanted eventually; not needed to ship.
- **Multiple principals per credential** — one operator managing unrelated
  children, which `selfsub` cannot express.
- **Rate limiting and lockout.** An internet-facing endpoint with a bearer
  credential wants both. Not v1.0, but not forgettable either.
- **Audit log** of who changed what, when, from where. Arguably belongs with
  the update-origin enum work (`2026-08-11-update-origin-enum.md`) rather than
  here — that project is what makes "who" a first-class field.
- **Config-file credential seeding** for deployments too small to want a DB.

---

## 15. Test plan sketch

Unit:

- TXT parsing: single string, split strings, multiple RRs, unknown dialect,
  unknown parameters, empty.
- Policy equivalence: a table of (principal, owner, rrtype) cases run through
  both `ApproveChildUpdate` and `approveChildActions`, asserting identical
  verdicts — the regression guard for §6.3.
- Declarative-to-statement translation, especially absent vs empty RRset.

Integration (foffe, as with phase 2):

- Publish → `dig` the three records → child discovers → POST → the parent's
  delegation changes and the change survives a restart (phase 2's replay).
- Refusals: wrong password, unknown user, owner outside `selfsub`, RRtype
  outside the policy, frozen zone. Each must produce its documented status.
- The credential-leak guards: unsigned parent zone, `http://` URI, bad
  certificate, redirect. Each must refuse **before** the credential is sent —
  asserted by observing that no request carrying `Authorization` was made, not
  merely that the operation failed.

---

## 16. What changed from the design, and why

All five PRs are built. Recorded here rather than quietly folded into the text
above, so the decisions that did not survive contact with the code are visible.

### 16.1 The request shape: a list, not a map keyed by type

§7.2 sketched `"rrsets": {"NS": [...], "A": [...]}`. That does not survive glue.
NS lives at the child and its addresses live at the nameserver names, so a
map keyed by type alone cannot say *which* A records to remove — and removal is
expressed by an empty list, which has no record to infer an owner from.

Each entry now names owner and type explicitly:

```json
{"child": "child1.example.",
 "rrsets": [
   {"owner": "child1.example.",     "type": "NS", "rrs": ["child1.example. 3600 IN NS ns1.child1.example."]},
   {"owner": "ns1.child1.example.", "type": "A",  "rrs": ["ns1.child1.example. 3600 IN A 192.0.2.1"]},
   {"owner": "child1.example.",     "type": "DS", "rrs": []}
 ]}
```

Absent means "leave alone"; empty means "remove". Unchanged from the design.

### 16.2 The three records go out in one update

The design proposed a `PublishTxtRR` mirroring `PublishUriRR`. Both send an
update of their own, which would have published the DSYNC, the URI and the TXT
as three separate changes. A child that resolved the DSYNC but not yet the URI
can do nothing except fail, so they are built inline and travel in one
`UpdateRequest`: one serial bump, all three visible together or not at all.

### 16.3 CHILD-UPDATE, not ZONE-UPDATE — and a regression it exposed

Delegation data belongs to the configured `DelegationBackend`. Queuing it as
ordinary zone content would mutate in-memory state behind the scanner's back,
which is the disagreement the `delegationbackend` requirement exists to
prevent. So the handler queues `CHILD-UPDATE`.

Which surfaced a live bug in phase 2: only the `ZONE-UPDATE` branch of the
updater answered the reply channel. The RFC 2136 responder queues with
`dur.Status.Type`, which is `CHILD-UPDATE` or `TRUSTSTORE-UPDATE` as often as
it is `ZONE-UPDATE` — so every delegation update from a child (the whole DSYNC
UPDATE scheme) and every SIG(0) key upload stalled for `UpdateApplyTimeout` and
then answered SERVFAIL, for an update that had in fact been applied. Fixed for
all four branches, with a test that reads the switch so a new command cannot be
added without answering.

### 16.4 The policy extraction found an authorization bug

§6.3 predicted a behaviour-neutral refactor. It was — but extracting the
comparison made visible that `selfsub` was `strings.HasSuffix`, which is not
label-aligned:

```
strings.HasSuffix("evilchild1.example.", "child1.example.") == true
```

so a trusted key named `child1.example.` could change a differently-named
sibling's delegation. On the existing SIG(0) path, for every zone with a
`self`/`selfsub` policy, whether or not it ever enables this scheme. Fixed
along with the empty principal (every string has the empty suffix, so it
approved everything), the root as principal, and a case-sensitive comparison
that refused legitimate updates. See §13.

### 16.5 The endpoint decides what it is about; the policy decides who may

`dsyncApiManagedTypes` is `NS, DS, A, AAAA` and is deliberately *not* driven by
`updatepolicy.child.rrtypes`. A parent that allows TXT in its child policy
still does not want this endpoint used to manage arbitrary text records at a
delegation point. Both gates apply: the endpoint refuses an unmanaged type with
400, the policy refuses a disallowed one with 403.

### 16.6 One switch for plaintext and for unvalidated discovery

The design gave `allow-insecure` for `http://` and treated the DNSSEC
requirement separately. They are the same protection seen from two sides —
DNSSEC establishes which endpoint was meant, TLS establishes that this is it —
and an operator who disables one while believing the other still holds has no
protection at all. One switch, `delegationsync.child.api.allow-insecure`,
covers both. Certificate validation has no switch at all.

### 16.7 Address resolution is skipped for this scheme

`BestSyncScheme` resolves the DSYNC target to an address, because NOTIFY and
UPDATE send DNS to it. An API target is a service description point whose
address records are optional, so resolving it would fail on a *correctly*
configured parent. Skipped for `SchemeAPI` only.

---

## 17. As-built status

| PR | Scope | Status |
|----|-------|--------|
| 1 | Parent publishes DSYNC + URI + TXT | built, live-verified on foffe |
| 2 | Policy extraction (+ the §16.4 fix) | built, tested against a verbatim replica |
| 3 | Credential store + CLI | built, live-verified on foffe |
| 4 | The listener | built, live-verified on foffe |
| 5 | Child side | built, live-verified (2026-08-23, see below) |

Verified live on foffe (`/var/tmp/dsyncapi`, parent `dsynctest.example.`):
the three records resolve and decode correctly; `401` with no credentials and
with a wrong key; `200` on GET with correct policy scoping; `404` for a child
with no hosted parent; `200` on POST with the change served in DNS and written
through to the zone file; `403` for a cross-child attempt; `403` for the
label-boundary case the old suffix match allowed; `400` for an unmanaged type
and for an owner outside the child.

**The child half of §11, and what blocked it.** A full child→parent run was
attempted on foffe with a signed parent and a `tdns-cli cert` CA. Two of the
three pieces work:

- **TLS with the internal CA works.** `tdns-cli cert ca` + `cert leaf` for
  `dsync-api.dsynctest.example.`, the listener configured with that pair, and a
  request validated against the CA file: certificate chain verified, SAN
  matched, Basic authenticated, policy approved, change applied and served.
  This is what `delegationsync.child.api.cafile` exists for — trusting a
  private CA without granting it authority over every TLS connection the host
  makes.
- **The parent signs and the trust anchor works.** `inline-signing` plus a
  `default` policy, and the parent's KSK as `imrengine.trust-anchor-file` on
  the child: the child's IMR fetched and validated the parent's DNSKEY RRset
  and recorded it as a trust anchor.

- ~~**The child's IMR cannot resolve the parent through a stub**, which stops
  `AnalyseZoneDelegation` before any DSYNC-API code runs.~~ **Fixed 2026-08-23**
  (#344, PR #380). Root cause: `backfillDS` selected servers with
  `FindClosestKnownZone(name)` — the servers for the zone *itself* — and asked
  them for that zone's DS. A DS is parent-side data, so those servers answer
  REFUSED, correctly; the refusal was booked as a lame delegation, the resulting
  zone-scoped backoff removed the only address a stub zone has, and every
  subsequent query ended with no auth-server attempt. Two fixes: ask the parent's
  servers, and stop reading a refused DS query as evidence of lameness. The
  diagnostics added alongside (#346) are what located it — one run named the
  cause outright.

**The child half now works end to end.** Verified on the training lab
2026-08-23, with a DSYNC-unaware BIND primary and `tdns-agent` beside it as a
`delegation-sync-proxy`:

- the operator edits the child zone in BIND; BIND NOTIFYs the proxy; the proxy
  transfers with TSIG, detects the delegation change, discovers the parent's
  endpoint from the DSYNC + URI + TXT records, and POSTs the delegation — the
  parent applies it and serves it. Repeated across seven separate glue changes.
- **with `allow-insecure: false`**, i.e. the DNSSEC-validated discovery path
  exercised rather than bypassed: the credential is sent only after the URI and
  TXT records validate. `dog <target> uri +sigchase` reports `Result: secure`
  from the lab root through the parent to the target.
- the startup reconcile catches up drift that happened while the agent was down
  (#372, PR #377): proxy work is deferred until the IMR is up rather than
  skipped, then runs.

So `DiscoverDsyncApiEndpoint` reading URI+TXT through an IMR — the one untested
seam when this was written — is now the path the lab runs on.

Two lab notes from the earlier run, neither a code issue: `127.0.0.2` needs an
explicit `ifconfig lo0 alias` on NetBSD (a `127.0.0.1/8` on lo0 does not make
the whole /8 bindable); and the IMR sample config showed `stubs: servers: [
192.0.2.53 ]` as bare IPs, which does not decode — **that one was a code issue
after all, fixed as #347 in PR #380**, along with a test that pins both the
working form and the rejection of the old one.

---

## 18. Consumers that must not depend on DNS resolution

**Requirement (Johan, 2026-08-12), for the statusd migration and any
lab-infrastructure consumer:**

> In a DNS training lab we will not have the responsible servers (like statusd)
> depend on working DNS resolution. The model I aim for is that statusd uses the
> api endpoints announced via dsync api but *without* needing the dns lookups.
> Statusd should have the result of the dsync discovery as static config
> (replacing the existing static config for finding the tdns mgmt API).

This is not a weakening of §8. It is a statement about **who does the
discovery**, and it matters because statusd is part of the machinery that makes
the lab's DNS work: a statusd that cannot publish a delegation until DNS
resolves has a bootstrap cycle in it, and in a teaching lab the DNS is
*expected* to be broken half the time — that is what the students are there to
do.

### The shape

Discovery (§3, §11) produces exactly three things:

| From | Value |
|---|---|
| DSYNC record | the target name |
| URI at the target | the endpoint URL |
| TXT at the target | the dialect |

For a consumer like statusd, those three are **configured**, not resolved. The
endpoint is then used exactly as a discovered one would be: same HTTPS, same
Basic credential, same TLS verification, same policy enforcement at the parent.
Nothing about the *server* side changes, and nothing about the credential
handling changes.

### The seam already exists

`DsyncApiPostDelegationRequest` takes a `*DsyncApiEndpoint` and never resolves
anything itself; `DiscoverDsyncApiEndpoint` is a separate function that
*produces* one. A statically-configured consumer constructs the struct and
skips the discovery call:

```go
ep := &tdns.DsyncApiEndpoint{
    Target:  "dsync-api.dnslab.",                        // for logging only
    Url:     "https://dsync-api.dnslab:8443/dsync/v1",   // from config
    Dialect: tdns.DsyncApiDialectV1,                     // from config
}
```

So no code change is needed to support this — it is a matter of which of the
two entry points the consumer calls.

### What is lost, and why that is the right trade here

DNSSEC-validated discovery is what stops a credential being sent to an
attacker's URL (§8). Static configuration replaces that protection with a
different one: the endpoint came from the operator's own config file, which is
a stronger statement of intent than a DNS lookup, not a weaker one. The
remaining exposure is the same one every statically-configured API client has,
and it is covered by TLS certificate validation — which stays mandatory.

What is genuinely given away is **agility**: a parent that moves its endpoint
has to have every statically-configured consumer updated by hand, where a
discovering child would follow the URI record. For lab infrastructure that is
the correct trade; for a registrant's provisioning system it is not, which is
why discovery remains the default and this is the documented exception.

### The general principle behind it

Johan, 2026-08-12:

> tdns is aiming to be a general purpose s/w, but statusd and the other training
> lab components are not. They are designed for a very specific, single, purpose
> which must always work, regardless of external breakage.

That is a sharper rule than "prefer static config here", and it flips the
default on several trade-offs. General-purpose tdns wants discovery, graceful
degradation and flexibility, because it does not know what it will be asked to
do. Lab infrastructure wants the fewest moving parts that can possibly work,
because it knows exactly what it must do and must do it while everything around
it is on fire — by design, since breaking the DNS is what the students are
there for.

Applied, for any lab component:

- **No discovery.** Configured, not resolved.
- **No fallbacks.** A fallback means the component behaves differently depending
  on what was broken at the time, and in a lab nobody can tell which path ran.
- **No dependency on the service it exists to repair.** This is the one that
  bites: it is easy to write a delegation-repair path that needs working DNS to
  find out which delegation to repair.

The third is worth stating as a REQUIREMENT rather than a preference, so that a
later change cannot helpfully undo it. Adding discovery to statusd would look
like an improvement in a review; it is a regression.

### Consequences for the statusd migration

- statusd replaces its existing static `baseurl`/`apikey` pointing at the tdns
  **management** API with a static endpoint + `<username, key>` pointing at the
  **DSYNC API**. Same shape of config, different surface.
- It thereby stops holding an operator credential that can do anything, and
  starts holding a registrant credential confined by `updatepolicy.child` —
  which is the actual point of the migration, and is worth more than the
  discovery it forgoes.
- The current `parentupdater` work (mechanism `tdns-api`, talking to the
  management API) is the temporary step. This is the destination.
- No IMR, no resolver dependency, and no bootstrap cycle: statusd can publish a
  delegation into a zone that nothing can yet resolve.
