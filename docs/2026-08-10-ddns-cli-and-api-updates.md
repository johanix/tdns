# DDNS update CLI + API RR-updates + zone-content persistence — as built

**Date:** 2026-08-10, revised 2026-08-11 to match the implementation
**Status:** AS BUILT for phases 1 and 2. Supersedes
`2026-07-25-ddns-cli-and-api-updates.md`, and replaces the DESIGN version of
this file — several of its decisions did not survive contact with the code and
are recorded in §15 rather than quietly dropped.
**Companion:** `2026-07-13-dynamic-primary-zones.md` (merged via PR #327) —
API-provisioned primaries are only as useful as content-change channels.
**Branches:** `feature/api-zone-updates` (phase 1),
`feature/api-zone-updates-phase2` (phase 2, branched off phase 1).

**Out of scope:** TSIG authorization of RFC 2136 UPDATEs. SIG(0) DDNS continues
to work as today; TSIG remains transport-verified but not update-authorized.

---

## 1. Motivation

Dynamic primaries exist; content change depended on either RFC 2136 (SIG(0)) or
operator surgery on a zone file. Missing pieces:

1. **Operator RR updates via the management API**, and a usable CLI for both
   the API and DDNS transports.
2. **Durable persistence** of in-flight modifications across restart, without
   inventing BIND-style `.jnl` files.

---

## 2. Phasing (as built)

The original design made durability a prerequisite for the API channel: its
PR-1 was the whole SQLite-as-truth spine and PR-2 the API work behind it. That
ordering was inverted, because durability is a separate problem from the change
mechanism and the change mechanism was what was actually wanted.

| Phase | Scope | Status |
|-------|-------|--------|
| **1** | API channel + five statements + CLI. Zone file is the source of truth. **No persistence** — an API update is exactly as durable as a DDNS update, no more and no less. | **built** |
| **2** | Zone file still the source of truth. Change **deltas** persisted at publish; replayed over the file on load; deleted once they reach the file. Plus the RFC 2136 durability ordering (§10). | **built** |
| **3** | DB as source of truth for zone content (the original design's "model A"). | **deferred** |

---

## 3. Architecture

```
                         ┌── --via api ──> mgmt API ──> UpdateRequest ──┐
  statements ──> actions ┤                 (X-API-Key, PreAuthorized)   │
                         └── --via ddns ──> RFC 2136 ──> updateresponder ┤
                                                                        ▼
                                                              ZoneUpdater
                                                                   │
                                              apply to MapZone working set
                                                                   │
                                            persist delta (phase 2, durable)
                                                                   │
                                                          publish snapshot
                                                                   │
                                                    respond to the client
```

- **One statement frontend**, two transports (`--via` required, no default).
- **Zone file is the source of truth.** The database holds only what has
  happened since the file was last written.
- **Durable before visible before answered** — §10.

---

## 4. Statements and CLI

```
tdns-cli auth zone update {addrr,delrr,delrrset,delname,replacerrset} \
    --zone <zone> --via {ddns,api} ...
```

`--via` is **required**. The channels differ in authorization — the API
bypasses `updatepolicy` because the API key is the credential, DDNS enforces it
— so defaulting to either would hand an operator a different authorization
model than they meant to ask for by omitting a flag.

| Statement | Wire form | Arguments |
|-----------|-----------|-----------|
| `addrr` | CLASS=INET add | one or more `--rr` |
| `delrr` | CLASS=NONE (§2.5.4) | one or more `--rr`; TTL zeroed, it is not part of RR identity |
| `delrrset` | CLASS=ANY + type (§2.5.2) | `--name`, `--type` |
| `delname` | CLASS=ANY + TYPE=ANY (§2.5.3) | `--name` |
| `replacerrset` | CLASS=ANY delete + CLASS=INET adds, one action list | one or more `--rr` |

`replacerrset` **infers** the RRset from the owner and type of the supplied
records, so there is no separate `--name`/`--type`:

```
zone update replacerrset --zone alpha.dnslab. --via api \
    --rr "foo.alpha.dnslab. IN A 1.2.3.4" \
    --rr "foo.alpha.dnslab. IN A 2.3.4.5"
```

Mixed owners or mixed types are refused rather than guessed at. Zero records is
an error, not a silent `delrrset` — with nothing to infer from, the operator
cannot have meant anything specific.

`delrrset` additionally refuses three things:

- type `ANY`, which would be `delname` without `delname`'s apex protections;
- **meta and query types** (OPT, and 128–255: TKEY, TSIG, IXFR, AXFR, MAILB,
  MAILA). `dns.StringToType` resolves these happily, so without the check the
  statement was built, queued, and silently did nothing;
- the **apex SOA and NS RRsets** — see §7.3.

`BuildZoneUpdateActions` is the single translation from statement to update
records, shared by both transports so they cannot drift. Every owner is checked
in-bailiwick there rather than left for the applier to decline.

`--via api` ships the **statement**, not pre-built records, so the server runs
the same builder and validation is authoritative rather than trusted from the
client. The CLI still runs the builder locally first, purely to fail fast.

`--via ddns` appends the pre-classed records to the update section rather than
using `m.Insert`/`m.Remove`/`m.RemoveRRset`. Those helpers re-derive the class
from the operation and **cannot express DELNAME at all**, so re-deriving would
silently drop the one statement with no library helper.

**Not built:** the interactive/heredoc multi-statement session (`SHOW`,
`DELROW`, `SEND`, `ABORT`). Each invocation carries a single statement. Mixed
ADD+DEL batches in one transaction remain future work; the existing
`zone update create` interactive command is untouched beside the new verbs.

---

## 5. API backend and admission

`zone update` on the zone handler:

1. Resolve zone; refuse unknown.
2. Zone must carry **`allow-api-updates`**.
3. Refuse if `OptFrozen` — freeze blocks both channels.
4. Translate the statement; validate.
5. Enqueue `UpdateRequest{Cmd:"ZONE-UPDATE", Actions, PreAuthorized:true}` and
   **wait for the outcome** (§10).

`PreAuthorized` is set in exactly one place — that handler, after the checks
above — and bypasses `updatepolicy` as `InternalUpdate` does. Nothing on the
wire path can set it; a wire request carrying it would be an unauthenticated
update.

`allow-api-updates` is also in `originationOptions`, so a tdns-auth secondary
that may not originate content cannot accept API updates either. Without that,
the API would route around the MUST-NOT-MODIFY invariant `allow-updates` is
already normalized away for.

---

## 6. Persistence (phase 2): a delta journal, not a content store

The zone file is authoritative but lags: it holds the zone as of the last
`write-zone`/`sync`/`freeze`, while the database holds everything since.

**`ZoneDelta`** — one row per RR of one published delta:

| Column | Role |
|--------|------|
| `zone`, `fromserial`, `toserial` | which zone, and which serial step |
| `seq` | order within the delta |
| `action` | `del` or `add` |
| `rr` | presentation form |

**Replay order is `id` — insertion order — not `toserial`.** Serials are
mod-2³² (RFC 1982) and wrap; ordering a replay by them would silently misorder
the tail of a long-lived zone's history. Serials are carried for diagnostics
and for chain validation, never for sequencing.

**Deletes precede adds** within a delta. Replaying a REPLACE the other way
round leaves the RRset empty.

**Empty deltas are not persisted.** Serial-only advances
(`outbound-soa-serial: unixtime`) publish with no content change.

**RRSIGs are not persisted.** `computeZoneDelta` carries signature changes in
`RRset.RRSIGs`; only `RRs` is stored. A stored RRSIG has a fixed validity
window, and replaying it after a long outage republishes a signature that
expired while the server was down. The applier re-signs on the replay path
instead, which is correct however long the gap was. Two consequences:

- Replay depends on the zone being able to sign (online- or inline-signing). A
  zone accepting updates with neither was already producing unsigned RRsets
  when the update was first applied, so replay reproduces that rather than
  causing it; the replay warns when it sees the combination.
- A resign-only change (identical RRs, new RRSIGs) yields no rows at all, so
  routine re-signing never churns the table.

The **apex SOA is likewise absent**, because `diffOwner` strips it for IXFR wire
framing. That is what we want here: the serial is restored explicitly at the end
of a replay, and a replayed SOA record would fight it.

**Life cycle:**

- **Publish** — the delta is written before the snapshot is stored (§10).
- **Load** — parse the file, then replay. One pass for all deltas, so
  secondaries see one serial step rather than a burst of intermediate states
  that never existed as served content. Replay is `InternalUpdate` (these
  changes were authorized when first applied; re-checking a since-tightened
  policy would silently drop live content) and `Replay` (suppressing
  re-persistence, or the history would double on every restart).
- **Write** — `WriteZone` deletes the zone's deltas after a **successful**
  write. That is why `freeze`, `sync` and `write-zone` need no delta handling
  of their own: all three reach the file through it. Dropping before a failed
  write would lose the changes from both file and database.

### 6.1 Chain validation

The first delta's `fromserial` must match the serial of the file just loaded.
If an operator edited the file or restored an older copy, the chain no longer
applies to it, and replaying anyway produces a zone that never existed: some
changes land on content that is gone, and fresh edits are silently overwritten.
Replay refuses and names both serials.

This replaces the original design's `(path, mtime_ns, size, serial)` fingerprint
approach. The serial the deltas already carry answers the same question without
depending on mtimes, which rsync and git checkouts rewrite routinely.

**Known gap:** there is no command to clear the deltas, so the refusal's advice
("write the zone out, or clear the stored deltas") is currently only half
actionable. A `zone deltas drop` is wanted.

### 6.2 Serial after replay

The published serial ends up **strictly greater** than the highest serial the
zone ever published, never equal to it.

Landing on the recorded serial is tempting — the replayed content *is* the
content of that serial — but the replayed zone is not byte-identical: RRSIGs
were regenerated. Reusing the number leaves secondaries holding a different
image of "serial N" and, because their SOA check sees no change, never
transferring the difference; a restart done to refresh signatures near expiry
would refresh only the primary. It also breaks the
same-serial-implies-same-content invariant `updateIxfrChainLocked` treats as an
error, and if anything else differs, that serial names two materially different
zones with nothing to reconcile them.

So replay catches up to the recorded serial and publishes **with** a bump. In
unixtime mode the replay has already passed it and nothing is burnt. The cost —
one serial, one transfer per secondary — is paid only by a zone that actually
had unspooled deltas.

---

## 7. Applier

### 7.1 DELNAME

CLASS=ANY + TYPE=ANY is handled above the per-rrtype policy gate, because
`TypeANY` is never a key in `UpdatePolicy.Zone.RRtypes` and the gate therefore
took its denied branch and continued — which is why DELNAME had always been a
silent no-op. Not specific to our tooling: bind9 `nsupdate`'s
`update delete <name>` hit it too.

Two restrictions, and the first is a **deviation from the original design**,
which said simply to hoist the statement above the gate:

- **Each rrtype is still policy-checked.** Hoisting the whole statement would
  make DELNAME a privilege escalation — a requestor permitted only TXT could
  erase every type at a name in one statement. Denied types are skipped, so
  DELNAME deletes exactly what that requestor could have deleted one statement
  at a time.
- **At the apex, more is retained than the RFC requires:** SOA and NS
  (§3.4.2.3), *plus* DNSKEY, CDS, CDNSKEY and CSYNC.

  Deleting the apex DNSKEY on a zone whose DS is published at the parent does
  not make the zone insecure, it makes it **BOGUS** — resolvers stop answering
  for the whole zone — and dropping CDS/CDNSKEY/CSYNC strands rollover and
  delegation signalling mid-flight. DELNAME is a *wholesale* statement and
  nobody issuing it at the apex is asking for that. The deviation is in the
  conservative direction: it deletes less than the RFC permits, never more, and
  `delrrset --type DNSKEY` remains available for an operator who genuinely
  means it.

### 7.3 Apex SOA/NS, and who owns the TTL

`delrrset` refuses the apex SOA and NS RRsets. A zone missing either cannot be
served, and the apex guard in `publishWorkingSetLocked` would then refuse the
*entire* publish — discarding every other change in the same update. Enforced
in the builder, where the error can explain itself, and again in the applier's
ClassANY branch, because actions can be constructed locally and bypass the
builder.

Only SOA and NS here, deliberately: unlike DELNAME, an explicit
`delrrset --type DNSKEY` is unambiguous intent.

**TTL.** The applier used to overwrite every added record's TTL with
`UpdatePolicy.Zone.TTL` on every channel. That is right for DDNS — a wire
client does not get to choose how long the zone caches what it just added — and
wrong everywhere else. An operator using the API said 3600 deliberately, and an
internal publisher picks TTLs that matter to the signalling it drives: a
rollover wanting a short CDS TTL was silently getting the policy's instead. The
policy TTL is now applied only when the request is neither `InternalUpdate` nor
`PreAuthorized`, consistent with F2.

### 7.2 REPLACE — no applier change was needed

The original design specified a "staged RRset replace" in the applier. It is
unnecessary. A CLASS=ANY delete followed by CLASS=INET adds, carried in one
`Actions` list, is already applied in a single pass under one `zd.mu` with a
single `publishLocked` in the deferred close. A test pins this via the serial
advancing by exactly one, so the empty intermediate RRset is never published
and no secondary can observe it.

REPLACE is therefore purely an encoding concern, handled in
`BuildZoneUpdateActions`.

---

## 8. freeze / thaw / sync

`freeze` and `thaw` are unchanged. **`sync` is an alias for the existing
`write-zone`**, not a second implementation — the zone handler treats them as
one case. Note the delegation subsystem has an unrelated `sync`; they live in
different command namespaces.

The original design's `reconcile export|import|status` trio was not built.
`write-zone`/`sync` already covers export; import is subsumed by the file being
the source of truth, and drift is answered by chain validation (§6.1).

---

## 9. Which paths persist

The hook lives in the shared applier serving ZONE-UPDATE, so **wire updates,
API updates and the internal publishers (CSYNC/KEY/CDS) all persist through one
path** — the original design's F11, as intended.

`ApplyChildUpdateToZoneData` is a separate function with its own publish and
needed its own hook: delegation records written by a CHILD-UPDATE are zone
content like any other, and without it they were served but not recorded.

---

## 10. Durable, then visible, then answered

RFC 2136 §3.4.2.5 makes a NOERROR response a statement that the update **has
been made**. Three orderings had to change:

1. **Persist before publish.** Once a snapshot is stored the content is being
   served and a secondary can pull it via NOTIFY→IXFR. A crash before the row
   was written left that secondary holding content the primary had no record of
   and silently rolled back. A failed write now **refuses the publish**: serial
   restored, working set dropped, zone carries on serving its previous content,
   and the applier returns an error rather than a successful-looking
   `(true, nil)`. Serving a change certain to vanish at the next restart is
   worse than not serving it.

2. **This puts a database write under `zd.mu`,** deliberately. The deadlock
   history in this tree is about paths that *re-enter* zone locking (signing,
   `PublishDnskeyRRs`); `PersistZoneDelta` is a leaf running a few INSERTs in
   one transaction and calling nothing back. The cost is latency, not deadlock,
   and BIND holds its zone lock across the journal write for the same reason.

3. **Respond after publish.** `UpdateResponder` previously wrote the NOERROR
   and *then* queued the request, so the client was told the change was safe
   while it was still a message on a channel. `UpdateRequest` now carries an
   optional reply channel; approved updates are answered only once applied,
   persisted and published. Failure answers SERVFAIL with a new EDE:

   | EDE | Meaning | Retry? |
   |-----|---------|--------|
   | `EDEZoneUpdateNotApplied` | authorized, but could not be applied or made durable | no |
   | `EDEZoneUpdateApplyTimeout` | authorized, but the server stopped waiting (`UpdateApplyTimeout`, 10s) | yes — RFC 2136 updates are idempotent |

   The reply is a non-blocking send on a buffered channel, and every path that
   can drop a ZONE-UPDATE reports on it. Both properties matter: the
   ZoneUpdater is a single goroutine serving every zone, so a caller that timed
   out must never wedge it, and a silent exit path would hang the waiter for
   the full timeout.

**Behavioural change:** a slow or wedged updater now surfaces as SERVFAIL where
it previously produced a silent NOERROR plus a queued request.

---

## 11. Decisions

| # | Decision |
|---|----------|
| F1 | **API admission: a parallel `allow-api-updates` option**, not a promoted `allow-updates: [sig0, api]` list. |
| F2 | API does **not** enforce `updatepolicy`; DDNS does. |
| F3 | `--via` required, no default. |
| F4 | REPLACE is a first-class atomic verb — but needed **no applier work** (§7.2). |
| F5 | **Delta journal with the zone file as source of truth.** DB-as-truth deferred to phase 3. |
| F6 | Drift is caught by **chain validation on the serial** (§6.1), and replay **refuses** on mismatch. |
| F8 | Freeze blocks DDNS **and** API. |
| F9 | TSIG UPDATE authorization deferred. |
| F10 | IXFR history across restart: AXFR fallback accepted. |
| F11 | Internal content changes persist too. |
| F12 | **Commit before publish, and respond after publish** (§10). |

---

## 12. Testing

Unit coverage: DELNAME (deletion, apex retention, policy filtering); REPLACE
atomicity via the serial advancing exactly once; the statement builder
including every refusal path; delta round-trip, wrapped-serial replay ordering,
per-zone deletion; restart round-trip (a second `ZoneData` from the same
unchanged file text — what a restart actually sees); replay idempotency across
three restarts; delta deletion on zone write; refusal to publish an
unpersistable change; strictly-increasing serial after replay; chain-mismatch
refusal; and that the reply channel never blocks.

**Not yet exercised against a running server:** the API endpoint over HTTP, the
`--via ddns` path end to end, replay through a real daemon restart, and the
synchronous response under concurrent load.

---

## 13. Non-goals

BIND `.jnl` compatibility; auto-merge of zonefile edits with concurrent
updates; TSIG as UPDATE authorization; RFC 2136 prerequisites; serving from
SQLite on the query path; multi-zone interactive sessions.

---

## 14. Open items

- `zone deltas drop`, so a refused replay has an escape hatch (§6.1).
- A signed zone that can neither online- nor inline-sign but accepts updates is
  only warned about at replay; a config-validation refusal would catch it
  earlier.
- Collapse `InternalUpdate` / `PreAuthorized` / `Replay` into one `Origin`
  enum — see `2026-08-11-update-origin-enum.md`.
- `UpdateApplyTimeout` (10s) is a guess; worth revisiting against real signing
  latency on the PQ testbed, where a slow algorithm re-signing a large RRset is
  the case that could exceed it.
- API-managed primaries persist a delta and delete it milliseconds later, since
  the updater writes the zonefile after every update. Correct in every crash
  window, merely redundant.
- The RFC 2136 **prerequisite** section is still not evaluated at all, so an
  optional `--require-exists` on `replacerrset` would be inert against tdns and
  meaningful only against bind9 targets. Deferred with the rest of the
  prerequisite work.

---

## 14a. What now depends on this

Two projects gate on the API update channel being durable and acknowledged,
i.e. on phase 2:

- **statusd → tdns-auth over the API.** Replaces the bind9-era
  write-`{zone}.delegations`-then-`rndc reload` mechanism for parent zones with
  direct API calls, behind a per-parent-zone mechanism knob so BIND9 parents
  keep working. The response *is* the commit, which the file+reload path could
  never tell statusd. Uses `replacerrset` per delegation RRset, which keeps the
  declarative property the whole-file rewrite had for free.

- **DSYNC scheme "API".** A third DSYNC scheme beside NOTIFY (RFC 9859) and
  UPDATE (draft-ietf-dnsop-delegation-mgmt-via-ddns), where the DSYNC target
  publishes a URI RR with the API base URL and a TXT carrying an API/dialect
  identifier. Authentication is a `<user, key>` tuple over HTTP Basic + TLS,
  **not** the SIG(0) identity — the scheme exists precisely for children that
  cannot do SIG(0) UPDATE.

  Note this is a **different surface** from the management API described here.
  The management API is trusted-operator and bypasses `updatepolicy` (F2);
  DSYNC-API is child self-service and MUST enforce a policy. Conflating them
  would be a privilege escalation. The two are expected to converge only in the
  sense that statusd should eventually authenticate as a principal on the
  DSYNC-API surface rather than holding a master API key.

---

## 15. What changed from the original design, and why

Recorded so the reasoning is not lost.

- **Model A (SQLite as source of truth) was deferred.** It made the API channel
  wait on a much larger durability project. Phase 2's delta journal gets the
  durability without moving the source of truth.
- **`reconcile export|import|status` was not built.** `write-zone`/`sync`
  covers export; with the file authoritative, import is what loading already
  does; drift is answered by §6.1.
- **The mtime/size fingerprint was replaced by serial chain validation** — the
  serial is already in the delta and does not lie the way mtimes do under rsync
  and git.
- **DELNAME keeps the policy check** rather than being hoisted wholesale above
  the gate, which would have been a privilege escalation (§7.1).
- **REPLACE needed no applier machinery** (§7.2). §9.2 of the original design
  should be considered struck.
- **F1 went to the parallel option**, not the flat list.
- **The interactive session was dropped from phase 1.**
- **§10 is entirely new** — the original design said nothing about when the
  client is answered, and the answer turned out to be "far too early".
