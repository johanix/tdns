# Signing, publishing and NOTIFY — one version, one signing pass, one NOTIFY

**Status:** design.
Reviewed 2026-09-05 — `reviews/2026-09-05-tdns-signing-publish-notify-correctness-review.md`,
*approve with should-fix*. S1–S5 and the Consider items are folded in below; §3.10 lists what
the already-landed C1/C2 commits must change before they un-park.
**Landed, parked pending this revision:** C1 and C2 on `fix/sign-before-publish`, stacked on
the S0 branch. They were implemented ahead of this review — the ordering error is recorded in
§3.10 — and are not to be merged until §3.10 is done.
**Base:** `main` @ `d833c683`. `v2/` tree only.
**Issues:** none filed yet — **still outstanding**, and it was meant to precede C1 landing.
C1 (§3.1) is a correctness defect: an inline-signing secondary serves unsigned authored data
for the length of a signing pass after every changed refresh.
**Companion:** `2026-09-05-refresh-engine-redesign-364-502.md` — the refresh-engine
concurrency work. Separate area, separate review; the global commit order across both is
in §6.

---

## 0. Where the review's findings landed

| finding | addressed |
|---|---|
| S1 first load / nil policy | §3.3 — option A, spelled out, plus the `Ready` gate |
| S2 `notifyIfServable` = `ZoneTransferOut`'s test | §3.4 |
| S3 no NSEC chain generation in the extraction | §3.2 |
| S4 snapshot NOTIFY inputs before dropping the lock | §3.4 — resolved differently: the send is non-blocking and stays under the lock, with the request built there |
| S5 companion §6 describes the old S0 | §6 — corrected when S0 was implemented |
| C1 IXFR full-zone sign | §3.1 — promoted from Consider to the design; this is the one that changes the landed code most |
| C2 first-load vs steady-state failure | §3.3 — split, with different answers |
| C3 file reload of an already-signed zone is a no-op | §7 |
| C4 status line | header |
| C5 file the C1 issue | header — still outstanding |
| C6 `triggerResign` / ticker after C4 | §3.6 |

## 1. The rules this is built on

Settled with Johan, 2026-09-05:

1. **NOTIFY is sent only as the final step of cutting a new snapshot** — including first
   load. Never two NOTIFYs for the same SOA serial.
2. **A given version of a zone is signed exactly once.**
3. **NOTIFY does not belong in the refresh-engine path at all**, other than at the
   snapshot-cutting end of it.
4. **`force` is a tool for special circumstances, not for steady state.** If forced
   re-signing is needed in normal operation, the signing semantics are wrong somewhere.

And the constraint that bounds the work: the snapshot machinery itself — atomic swap,
generation guard, durable-before-visible ordering, the IXFR chain — is believed correct
and is **not** reopened. Everything below changes what the working set *contains* at the
moment of the swap, and who calls publish. It does not change how a swap happens.

---

## 2. What is wrong today

### 2.1 A refresh publishes a version that cannot validate (the defect)

`applyRefreshReplacementLocked` stages the freshly transferred data and publishes it
(`zone_mutation.go:725`). For a zone that signs its own content but receives it unsigned —
in practice an **inline-signing secondary** — that snapshot contains:

| | at that snapshot |
|---|---|
| SOA | **signed** — `resignWorkingSetSOAIfSigned` (`zone_mutation.go:227`), which runs on every publish |
| NSEC chain | **signed** — `restitchNsecLocked` resolves `dak` and signs (`nsec_restitch.go:118`) |
| ZONEMD | **signed** — `updateZonemdLocked` |
| every transferred RRset | **unsigned** |

The zone is already `Ready` in steady state, so that version is served. Two consequences:

- Queries answered from it return unsigned RRsets **alongside a signed NSEC chain** — the
  worst available combination for a validator.
- `ZoneTransferOut`'s fail-closed guard inspects only the apex SOA's RRSIG
  (`dnsutils.go:490`). The SOA *is* signed, so the guard passes and a downstream can AXFR
  this version.

The window lasts until `SetupZoneSigning` → `SignZone` publishes again — i.e. **the
duration of a full signing pass** over the zone, seconds and up, considerably more with PQ
algorithms. It is not a race, it is a state the server sits in after every changed refresh.

Not affected: the DDNS path, which signs each RRset as it stages it
(`zone_updater.go:1156`: `SignRRset(...)`, then `stageRRsetLocked(...)` at `:1161`) and publishes once —
adding a record at serial 100 yields serial 101 carrying both the record and its RRSIG.
Nor a primary reloading an already-signed file. Nor an unsigned zone.

### 2.2 Signing is a second publish

`SignZone` ends with `zd.publishLocked(...)` (`sign.go:969`), and `publishLocked` is
`publishWorkingSetLocked(gen, **true**)` (`zone_mutation.go:346`) — bumpSerial *true*, and
`nextOutboundSerial` returns `CurrentSerial + 1` (`zone_utils.go:1576`). So every signing
pass publishes a new serial and, at `zone_mutation.go:601`, sends a NOTIFY.

One upstream change to an inline-signing secondary today:

| serial | published by | NOTIFY |
|---|---|---|
| S | refresh (`applyRefreshReplacementLocked`, bumpSerial=false) | yes |
| S+1 | `SetupZoneSigning` → `SignZone` → `publishLocked` | yes |
| S+2 | `ResignerEngine` → `resignNow` → `SignZone(force=true)` → `publishLocked` | yes |
| S+2 | the refresh engine's own tail call (`:912` / `:1237`) | yes |

Three serials and four NOTIFYs for one upstream change; a downstream can transfer three
times. Rules 1 and 2, both broken.

First load is the same shape: publish (pre-Ready) → `InstallInitialSnapshot` → policy sync,
which on the not-yet-backfillable path calls `applyZonePolicyTransactional` →
`SignZone(kdb, true)` → publish + NOTIFY (`zone_policy_apply.go:215`) → `replayZoneDeltasOnLoad`
→ `drainAndRunOnFirstLoad` → `SetupZoneSigning` → publish + NOTIFY. Up to three publishes.

### 2.3 NOTIFY is emitted from the refresh engine as well as from publish

`NotifyDownstreams` is the last statement of `publishWorkingSetLocked`
(`zone_mutation.go:601`) — NOTIFY already *is* a step of cutting a snapshot, exactly as
rule 1 wants. The refresh engine then calls it again, three times over:
`refreshengine.go:240` (inside `initialLoadZone`), `:1237` (ticker tail), and `:912` (async
tail, via `NotifyQ`).

Two further problems with the publish-path call itself:

- It runs **under `zd.mu`** — every caller holds it — and `NotifyDownstreams` uses
  `dns.Exchange` (`zone_utils.go:1382`), *not* `ExchangeContext`. So 2 s per unreachable
  downstream is spent holding the zone's own lock, blocking every reader of that zone, and
  no deadline anywhere can interrupt it.
- It fires for the pre-Ready first-load publish, which is the one publish that must not
  notify: a downstream acting on it is refused (`dnsutils.go:457`).

### 2.4 `force` is doing steady-state work, with the wrong tool

`SetupZoneSigning` signs inline (`zone_utils.go:2006`) **and** enqueues to `ResignQ`
(`:2018`); `ResignerEngine`'s channel case then calls `resignNow` → `SignZone(kdb, true)`
(`resigner.go:82`). `force` is not a hint: `shouldSign = force || NeedsResigning(...)`
(`sign.go:196`), so the second pass re-signs every RRset the first pass just signed.

Two distinct defects behind that:

- **The queue has no verb.** `ResignQ` carries a bare `*ZoneData`. "Data changed" and "key
  state changed" arrive on the same channel and the resigner cannot tell them apart, so it
  forces both.
- **`force` is the wrong tool for the case it was written for.** `resignNow`'s comment
  justifies force by the post-rollover case — RRSIGs valid but made by the wrong key. But
  `SignZone` is *additive*: `SignRRset`'s own comment says RRSIGs by no-longer-active keys
  are left in place, and that replacing them "belongs to `ResignZone`". And `ResignZone`
  exists (`sign.go:617`) for precisely that — *"use after toggling key states... when you
  want the served zone's RRSIG set to match the new active set immediately"*, stripping and
  re-signing per RRset so readers never observe an unsigned intermediate. The forced pass
  adds the right signatures and leaves the wrong ones in place: it does not achieve what it
  was written to achieve.

---

## 3. Design

### 3.1 C1 — sign wholesale replacement data before the swap

The rule is already established inside publish, for every *derived* record. From
`restitchNsecLocked`'s justification (`zone_mutation.go:432`):

> *"The chain must describe the snapshot about to be published, so it is repaired HERE —
> before the delta is computed and before the swap, so that secondaries receive the change
> together with the data that caused it. Doing it in a later pass would publish a second
> serial and leave a window in which the served chain contradicts the served zone."*

That is the argument for C1, written by whoever moved the NSEC restitch in. Authored data
arriving from upstream is the one input that never got the same treatment.

**Mechanism.** A staged flag, mirroring `wsIxfrEpochReset` and `wsPersistDelta`:

```go
// wsNeedsFullSign marks a working set as carrying WHOLESALE-REPLACEMENT content
// that has not been signed yet -- a transfer or a file reload of a zone that
// signs its own content. Consumed by publishWorkingSetLocked, which signs the
// staged set before the swap so no unsigned version is ever published.
//
// NOT set by incremental paths: DDNS signs each RRset as it stages it, so a
// full pass there would walk the whole zone on every update for nothing.
wsNeedsFullSign bool
```

Set in `applyRefreshReplacementLocked` — but **not** unconditionally on
`zd.signsItsOwnContent()` (`ixfr_in.go:821`), which is what the first implementation did and
what the review caught.

**An inbound IXFR must not trigger a full-zone sign.** `ixfrTouchedOwners` +
`materializeForIxfr` (`ixfr_in.go:208`, `:254`) deep-copy only the owners a delta reaches and
share every other owner with the published snapshot, precisely so that a three-record delta
does not cost O(zone). That optimisation is already merged on main, and re-signing the whole
zone on top of it throws it away: a 100k-RRset zone whose upstream changed one record produces
a two-record delta (the change plus the SOA), and signing 100k RRsets for it is not a cost
anybody agreed to pay. The publish path has to sign what the delta touched, and nothing else.

So the staged scope is a set, not a boolean:

```go
// wsNeedsFullSign: every authored owner needs signing -- an AXFR, or a file
// reload of a zone that signs its own content. Nothing we hold was signed by us.
wsNeedsFullSign bool

// wsSignOwners: only these owners need signing -- an inbound IXFR, where the
// delta names what changed and materializeForIxfr already deep-copied exactly
// that set. nil with wsNeedsFullSign false means there is nothing to sign.
wsSignOwners map[string]bool
```

`ixfrTouchedOwners` already computes the set, and already includes the apex unconditionally
(the bracket SOAs delimit the sequences rather than appearing inside them, so nothing else
would mark the name `replaceApexSOA` rewrites). Carry it on the transfer scratch zone beside
`ixfrDerived`, and have `applyRefreshReplacementLocked` stage one or the other:

| replacement | staged |
|---|---|
| AXFR, or file reload, of a zone that signs its own content | `wsNeedsFullSign = true` |
| inbound IXFR into such a zone (`new_zd.ixfrDerived`) | `wsSignOwners = <touched>` |
| a zone that does not sign its own content | neither |

`signWorkingSetLocked` takes the owner filter (nil = all). Everything else about it is
unchanged.

**A risk to check when implementing, not a settled fact:** for an IXFR the working set is
built from a map whose untouched owners share their `RRTypeStore` with the snapshot being
served. `stageRRsetLocked` clones an owner before writing, and `cloneOwner`'s own comment says
why that matters ("applyClampToRRset assigns Header().Ttl in place, so a shared RR would have
its TTL changed underneath a snapshot that is being served right now") — but the clone happens
*inside* staging, i.e. after `SignRRset` has already run on the RRset. Scoping the pass to the
touched owners avoids the question entirely, because those are the ones `materializeForIxfr`
deep-copied. Widening the pass would need this walked through first.
Consumed in `publishWorkingSetLocked`, in this slot:

```
  resignWorkingSetSOAIfSigned()          // existing
+ signWorkingSetLocked(...)              // NEW: authored data
  ensureZonemdPresenceLocked()           // existing
  restitchNsecLocked()                   // existing -- signs the NSECs it writes
  updateZonemdLocked()                   // existing -- signs the ZONEMD
  ... persist, chain, swap, notify
```

Authored data first, then the derived records, each still signed by the step that
generates it. Nothing moves; one step is inserted.

**Implemented** on `fix/sign-before-publish` (stacked on the S0 branch). Three things the
implementation settled that the design left open:

- **The extracted signer takes a `signNsec` flag.** SignZone wants each owner's NSEC
  property signed in the same pass; the publish path must *not*, because
  `restitchNsecLocked` runs immediately afterwards and regenerates and signs the chain
  itself. Signing it here would be a second full pass over the zone for a result that is
  about to be replaced.
- **The flag is cleared only on success.** Clearing `wsNeedsFullSign` before the attempt
  leaves a refused-but-still-staged working set marked as already signed, and the next
  publish puts it on the wire unsigned — the exact defect the flag exists to prevent.
- **`GenerateNsecChainWithDak` stays in `SignZone`**, outside the extraction, for the same
  reason as the first point.

### 3.2 C1's hairy corner — the lock and the keys

`SignZone` cannot be called as-is: it takes `zd.mu` itself (`sign.go:871`) and
`publishWorkingSetLocked` already holds it. Worse, its unlocked prologue resolves keys with
`EnsureActiveDnssecKeys(kdb, false)` (`sign.go:836`), and reaching that under the lock
self-deadlocks via `PublishDnskeyRRs`.

The tree already has the pattern and the scar tissue. `resignWorkingSetSOAIfSigned` says it
outright (`zone_mutation.go:264`):

> *"Resolve the active keys here with `zdLocked=true` and pass the non-nil `dak` into
> `SignRRset`, so `SignRRset` does NOT fall into its own `EnsureActiveDnssecKeys` call
> (which would reach `PublishDnskeyRRs` and re-lock `zd.mu` → self-deadlock, the same class
> as the `SignZone`/`UpdateSigValidityFloor` deadlock in `6e090a9`)."*

`restitchNsecLocked` does the same (`nsec_restitch.go:118`). So C1 follows it:

1. Extract `SignZone`'s locked body into `signWorkingSetLocked(dak *DnssecKeys, clamp *ClampParams) (int, error)` — the owner walk, the delegation/glue rules, the ZONEMD skip, the NSEC property. **No lock, no key resolution, no publish.**
2. `SignZone` becomes: resolve `dak` + `clamp` unlocked → `zd.mu.Lock()` → `publishDnskeyRRsLocked(dak)` → `signWorkingSetLocked(...)` → `publishLocked` → unlock. Identical behaviour, one extraction.
3. `publishWorkingSetLocked`, already locked, resolves with `EnsureActiveDnssecKeys(kdb, **true**)` and `ClampParamsForZone`, then calls `signWorkingSetLocked` directly. It must also call `publishDnskeyRRsLocked(dak)` first: a zone transferred from an upstream that does not sign carries no DNSKEY RRset.

Every call inside `signWorkingSetLocked` must take a non-nil `dak`. That is the whole
discipline; it is not optional and it is the reason this is its own commit.

### 3.3 C1 — failure semantics, and first load

Two different cases, and the review is explicit that they must not share a sentence.

**Steady state — a zone that is already signed, whose re-sign fails.** Do not swap; keep
serving the previous snapshot; set **`DnssecError`**.

`DnssecError` is service-impacting (`enums.go:445`), so the zone renders as an ERROR and the
query/NOTIFY/UPDATE handlers refuse. That is intended, and it is Johan's call: a signed zone
whose signing is broken is broken, and should say so loudly rather than quietly serving an
ageing snapshot while the operator believes all is well. The last good version stays the
published one — refusing the swap is what guarantees that — but the zone does not pretend to
be healthy.

(The first implementation used `DnssecPolicyWarning`, reasoning from
`refuseUnrepairableChainLocked`, which uses the warning for a structurally similar refusal.
Overruled: an unrepairable NSEC chain and an unsignable zone are not the same severity, and
the decision here is that the second one is service-impacting. §3.10.)

**First load — a zone whose DNSSEC policy is not bound yet.** Do **not** refuse, do **not**
set an error, publish unsigned, and stay **not Ready**.

This is the case the review blocks on, and the reason is a genuine ordering constraint rather
than an oversight: the policy binds post-Ready (`syncZoneDnssecPolicyFromConfig`, the PR-2
deferral), the first refresh publish happens before that, and `EnsureActiveDnssecKeys` refuses
to mint keys with a nil policy (`sign.go:504`). Applying the steady-state rule here would
refuse the first snapshot of every inline-signing zone, and the zone would never load at all.

So `signWorkingSetBeforePublishLocked` returns cleanly when `zd.DnssecPolicy == nil`, ahead of
any key resolution. The policy apply then signs and publishes, and that publish is the one
that becomes visible.

**The Ready gate that makes the unsigned first snapshot safe.** Publishing it is only
acceptable because nothing can see it, and that is *not* true as the code stands: `Ready` is
flipped unconditionally in `InstallInitialSnapshot` (both branches) and again in
`applyRefreshReplacementLocked`. A signing zone must not become Ready on a snapshot whose apex
SOA carries no RRSIG — otherwise option A serves the very defect C1 removes, from the moment
Ready flips until the policy apply finishes. `GetOwner` gates queries on `Ready`
(`zone_utils.go:1236`) and `ZoneTransferOut` gates transfers on it, so the flag is the whole
protection.

Same predicate as §3.4, in all three places that set it.

Alternative B — bind or mint keys before the first refresh publish, so C1 can sign it — is
rejected here rather than left open: it reopens the PR-2 "no bind before Ready" decision, which
exists so a restart cannot hide applied≠intent, and that is not a decision to take as a side
effect of this change.

`publishWorkingSetLocked` already refuses in three cases (apex-less working set,
unrepairable NSEC chain, delta-persist failure) and each keeps the previous snapshot, so
this is the established shape rather than a new one. It does mean a persistent signing
failure freezes the zone at its last good version rather than serving new data unsigned —
which is the intended trade and consistent with `ZoneTransferOut` refusing to hand out an
unsigned copy.

### 3.4 C2 — NOTIFY only when the published version is externally usable

Replace the unconditional `NotifyDownstreams()` at `zone_mutation.go:601` with a gated,
non-blocking hand-off:

```go
// notifyIfServable emits at most one NOTIFY for the version just published, and
// only if a downstream could actually take it. The predicate is deliberately
// ZoneTransferOut's own admission test: notifying about a version we would then
// refuse to transfer is how a downstream burns its retry budget.
func (zd *ZoneData) notifyIfServable() // ZoneTransferOut's admission test, verbatim
```

The predicate is `ZoneTransferOut`'s, expressed the same way it is there rather than
paraphrased: **Ready, and if `signsItsOwnContent()` then the pinned apex SOA carries an
RRSIG.** "Unsigned zone" was the earlier wording and is ambiguous — it can be read as "has no
RRSIGs" or as "is not configured to sign" — and the two differ exactly where it matters, on a
signing zone holding an unsigned snapshot, which must not notify. Use `signsItsOwnContent()`
(`ixfr_in.go:821`), not an inlined option test, so the two predicates cannot drift apart.

The same predicate gates the `Ready` flip (§3.3).

Two changes bundled with it:

- **The request is built entirely under the lock.** Zone name, serial and the target list
  are read while `zd.mu` is held, and `peerAddrs` copies the targets into a fresh slice, so
  nothing is re-read from the live `ZoneData` afterwards. A hand-off that captured a
  `*ZoneData` and let the sender read `zd.Notify` later could notify the wrong set, or nil.
- **Off the lock, and off the goroutine.** The emission hands a `NotifyRequest` to
  `NotifyQ` with a **non-blocking** send (drop + count on a full queue), instead of running
  `dns.Exchange` per target under `zd.mu`. NOTIFY is best-effort by design — a downstream
  that misses one refreshes on its SOA timer — and blocking a publish on a serial consumer
  is how the stall gets rebuilt somewhere new. `NotifyQ` depth goes from 10 to 100
  (`main_initfuncs.go:216`), matching `DnsNotifyQ`.
- **The Ready transition.** With C1, first load publishes a *signed* snapshot before the
  zone is Ready, so the gate suppresses its NOTIFY — correctly. If the policy sync then
  backfills (no re-sign, no publish), nothing else would ever notify. So
  `InstallInitialSnapshot` emits one when it flips a servable zone to Ready. "Became
  servable" is a snapshot-cutting event; this keeps rule 1 exact rather than approximately
  true.

`NotifyDownstreams` itself — the blocking `dns.Exchange` loop — survives C2 and is deleted
in **C3**, which removes its last three callers. This section said C2 deletes it, which was
wrong about the ordering: after C2 the publish path no longer calls it, but
`refreshengine.go:240` and `:1237` still do.

**Implemented** on `fix/sign-before-publish`, with two mechanics the design left open:

- **The send happens under `zd.mu`, deliberately.** `publishWorkingSetLocked` cannot drop
  the lock — its callers own it — so "off the lock" is not available inside it. What makes
  that safe is that a non-blocking channel send cannot block: there is no I/O and no
  waiting, which is the entire property the old inline `dns.Exchange` loop lacked.
- **The queue is read from the package-global `Conf`.** `publishWorkingSetLocked` has no
  `*Config` in scope, and threading one onto `ZoneData` (as `DelegationSyncQ` is) would mean
  setting it at every site that builds a `ZoneData` — miss one and that zone silently never
  notifies. The signing path already reads `Conf` from inside this same call chain
  (`sign.go`), and the apps initialise the global (`conf := &tdns.Conf`), so this is the
  established shape rather than a new one. A nil queue is a no-op.

### 3.5 C3 — delete the refresh engine's NOTIFYs

`refreshengine.go:240`, `:912`, `:1237` go. One behaviour goes with them, deliberately: the
async tail notifies on `updated || force`, commented *"Force typically means config
reload-zones, so we want to notify even if unchanged"*. Under rule 1 that is a NOTIFY for
an unchanged serial, and it is removed rather than preserved.

### 3.6 C4 — give `ResignQ` a verb, and use the right tool

```go
type ResignRequest struct {
	Zd     *ZoneData
	Reason ResignReason // ResignKeyStateChanged | ResignPeriodic | ResignPolicyApplied
}
```

| reason | what the resigner does |
|---|---|
| key state changed (rollover, key removal) | `ResignZone` — replacement, which is what the case needs |
| periodic validity maintenance | `SignZone(force=false)` on the ticker, unchanged |
| data changed | **nothing** — never enqueued; C1 signed it at publish |

Producers to convert: `triggerResign` (rollovers, `key_state_worker`, the API) plus
`SetupZoneSigning`'s enqueue. `triggerResign` already drops on a full `ResignQ` and keeps that
behaviour; after C4 it sends `ResignRequest{Reason: ResignKeyStateChanged}`. The periodic
ticker keeps calling `SignZone(force=false)` and is **not** routed through `ResignZone`:
replacement is for a key-state change, ageing signatures are not one.

`force` disappears from the steady-state path entirely. It survives where it belongs: a
policy binding change, via `applyZonePolicyTransactional` → `SignZone(kdb, true)`
(`zone_policy_apply.go:215`), which is a special circumstance by any reading.

### 3.7 C5 — what `SetupZoneSigning` becomes

With C1, the two post-refresh call sites (`refreshengine.go:870`, `:1232`) have nothing to
do and are deleted. The three `OnFirstLoad` registrations (`parseconfig.go:1477`,
`dynamic_primary.go:430`, `refreshengine.go:1034`) still need the zone signed once after
the policy binds — but the *signing* there is the policy path's job
(`applyZonePolicyTransactional`) or a single `SignZone(force=false)`, and the enqueue
becomes a watchlist registration:

```go
func (zd *ZoneData) registerForPeriodicResign(resignq chan<- ResignRequest) error
```

No inline sign, no forced re-sign, no second publish.

### 3.8 First load, before and after

The FIRST load of a zone whose keys and policy do not exist yet. A later load — a restart of
a zone that has both — signs at the refresh publish like any steady-state refresh, and only
the last two rows differ.

| step | today | after |
|---|---|---|
| refresh publishes | unsigned data, signed SOA/NSEC/ZONEMD, **NOTIFY** | **unsigned** (§3.3: no policy to sign under), **not Ready**, **no NOTIFY** |
| `InstallInitialSnapshot` | flips Ready unconditionally | flips Ready **only if servable**; **NOTIFY** when it does |
| policy sync — backfill | no publish | no publish; Ready + **NOTIFY** happened above (the snapshot was already signed, which is what made backfill eligible) |
| policy sync — apply | forced sign + publish + **NOTIFY** | forced sign + publish → this is the publish that makes the zone servable, so Ready flips and **one NOTIFY** goes out |
| replay | may publish + **NOTIFY** | may publish + NOTIFY (a real content change) |
| `OnFirstLoad` → `SetupZoneSigning` | sign + publish + **NOTIFY**, then the resigner force-signs + publish + **NOTIFY** | registration only |

Up to five NOTIFYs across three-plus serials, down to one per version that actually changed —
and, importantly, none at all until there is a version a downstream could take.

**§3.8 as written before this review claimed the refresh publish is signed at first load.**
That is true only under the rejected option B (bind keys before the first publish). Under
option A it is unsigned and invisible, and the policy apply is what produces the first
servable version.

### 3.9 What the landed C1/C2 commits must change

C1 and C2 were implemented before this review — the branch is parked, unmerged, at
`fix/sign-before-publish`. Measured against the review, most of it stands: the nil-policy skip
is option A (§3.3) already, the extraction leaves `GenerateNsecChainWithDak` in `SignZone`
(§3.2), and the NOTIFY request is built under the lock (§3.4). Four things must change before
it un-parks:

| # | change | why |
|---|---|---|
| 1 | `wsNeedsFullSign = zd.signsItsOwnContent()` becomes the two-way staging in §3.1 | as written it re-signs a 100k-RRset zone for a two-record IXFR delta, discarding an optimisation already merged on main |
| 2 | the refusal sets `DnssecError`, not `DnssecPolicyWarning` | §3.3; the first implementation reasoned from the NSEC-chain refusal and was overruled |
| 3 | `Ready` must not flip on a signing zone whose snapshot has no apex SOA RRSIG — `InstallInitialSnapshot` (both branches) and `applyRefreshReplacementLocked` | §3.3; without it the unsigned first-load snapshot is served to queries, which is C1's own defect relocated |
| 4 | `snapshotIsServableLocked` calls `signsItsOwnContent()` instead of inlining the option test | §3.4; same predicate today, two places to drift tomorrow |

And one process item that was missed: the C1 issue named in the header block was to be
filed *before* C1 landed.

### 3.10 Not in scope, but noticed

`NameExists` reads `publishedSnapshot()` with no Ready check (`zone_utils.go:1230`), and the
query path reads *other* zones' snapshots directly for signal and parent data
(`queryresponder.go:560`, `:698`). Both bypass `GetOwner`'s `ErrZoneNotReady` gate
(`zone_utils.go:1236`). Harmless once C1 and the §3.3 Ready gate land (there is no unsigned published version left
to leak), but the Ready invariant is being relied on in more places than it is enforced.
Worth a sweep, separately.

---

## 4. Risk assessment

| # | risk | likelihood | impact | mitigation | detection |
|---|---|---|---|---|---|
| R1 | Self-deadlock re-locking `zd.mu` during the in-publish signing pass | **high** if §3.2 is not followed exactly — the tree has done this before (`6e090a9`) | severe: the zone's publisher wedges, the zone stops updating | pre-resolved `dak` with `zdLocked=true`, non-nil into every `SignRRset`; `signWorkingSetLocked` takes no lock and resolves nothing | it hangs immediately and obviously; a publish test with a signed zone catches it in CI |
| R2 | Signing under `zd.mu` lengthens the lock hold on every changed refresh | certain | moderate: readers of that zone stall for the signing pass | signing already happened under `zd.mu` (`sign.go:871`) — the hold moves, it does not grow. What DOES shrink it: C2 takes `dns.Exchange` off the same lock | publish latency per zone |
| R3 | `wsNeedsFullSign` set on an incremental path by mistake | low | low–moderate: a full zone walk per DDNS update | one setter, in `applyRefreshReplacementLocked`; test asserts a DDNS publish does not trigger a full pass | signing counters per publish |
| R9 | A full-zone sign fires on an inbound IXFR, discarding the touched-owner optimisation already on main | **certain** if §3.1 stages a bare boolean — the first implementation did | severe at scale: 100k RRsets re-signed for a two-record delta, per delta | stage `wsSignOwners` from `ixfrTouchedOwners` for an `ixfrDerived` replacement | signing counters per publish; an IXFR test that asserts only the touched owners were signed |
| R10 | `Ready` flips on a signing zone holding an unsigned first-load snapshot | **certain** without the §3.3 gate — the flag is set unconditionally in three places today | severe: queries answered unsigned from a Ready zone, which is C1's own defect moved to first load | gate all three sites on the §3.4 predicate | a first-load test that asserts the zone is not Ready until the policy apply publishes |
| R4 | A zone freezes at its last good version on a persistent signing failure (§3.3) | low | moderate, and intended (§3.3) | `DnssecError` set and surfaced; the alternative is a zone that quietly serves an ageing snapshot while its signing is broken | the zone renders as an ERROR row on `zone list` — `DnssecError` is service-impacting (`enums.go:445`), unlike `RefreshError` |
| R5 | Dropping the "notify on force with no change" behaviour surprises an operator relying on `reload-zones` to poke downstreams | medium | low: a downstream refreshes on its own timer | documented as a deliberate removal; `zone reload --force` still bumps and publishes when content changed | operator report |
| R6 | The Ready-transition NOTIFY (§3.4) double-fires with a policy-apply publish landing in the same instant | low | low: one redundant NOTIFY, the thing rule 1 forbids | emit on the Ready flip only when that flip did not itself publish | serial in the NOTIFY vs the served serial |
| R7 | `ResignRequest` migration misses a producer, so a rollover stops re-signing | medium | severe: zone goes bogus after a rollover | the channel type changes, so every producer is a compile error — no silent misses | compile |
| R8 | `ResignZone` behaves differently from `SignZone(force=true)` in some case the rollover path depended on | medium | moderate | `ResignZone` is the documented tool for exactly this and is strictly more correct (it removes stale RRSIGs, which force does not); rollover tests must run against it before C4 lands | rollover integration test |

**Rollback.** C1 is one flag and one call; reverting it restores the old two-publish
behaviour. C2–C5 are independent of it and of each other.

---

## 5. LOC estimate

| commit | file | added | removed | net |
|---|---|---|---|---|
| C1 | `sign.go` — extract `signWorkingSetLocked` from `SignZone` | 40 | 25 | +15 |
| C1 | `zone_mutation.go` — flag, key resolution, sign step, failure path | 75 | 5 | +70 |
| C1 | `structs.go` — `wsNeedsFullSign` | 8 | 0 | +8 |
| C2 | `zone_mutation.go` — `notifyIfServable`, `InstallInitialSnapshot` emission | 55 | 2 | +53 |
| C2 | `zone_utils.go` — delete `NotifyDownstreams` | 0 | 25 | −25 |
| C2 | `main_initfuncs.go` — queue depth ×2 | 2 | 2 | 0 |
| C3 | `refreshengine.go` — delete three notify sites | 0 | 30 | −30 |
| C4 | `resigner.go` — `ResignRequest`, reason switch, `ResignZone` for key state | 60 | 25 | +35 |
| C4 | producers (`ksk_rollover_*`, `delegation_sync*`, `delsync_proxy*`) | 25 | 20 | +5 |
| C5 | `zone_utils.go` — `SetupZoneSigning` → `registerForPeriodicResign` | 20 | 35 | −15 |
| C5 | `refreshengine.go`, `parseconfig.go`, `dynamic_primary.go` — call sites | 12 | 20 | −8 |
| | **total** | **297** | **189** | **+108** |

Tests:

| file | LOC |
|---|---|
| `publish_signing_test.go` — a transferred inline-signed zone publishes exactly one signed version; no unsigned snapshot is ever stored | 130 |
| `notify_once_test.go` — one NOTIFY per changed serial; none for the pre-Ready publish; one at the Ready transition | 110 |
| `resign_intent_test.go` — data change never enqueues; key-state change uses `ResignZone` and removes stale RRSIGs | 90 |
| `publish_signing_failure_test.go` — signing failure keeps the previous snapshot and sets `DnssecError` | 60 |
| **total** | **390** |

**Overall: ~490 lines touched, ~500 net new including tests.** Smaller than the engine work,
and C1 is the only commit whose *shape* is delicate.

---

## 6. Commit order

Across both documents, on one branch:

| # | commit | doc |
|---|---|---|
| 1 | **#502 deadline stopgap** — bound the SOA probe, name the unreachable upstream ✅ **implemented** (`fix/refresh-probe-deadline-502`) | engine doc, S0 |
| 2 | **C1** — sign wholesale replacement before the swap — landed, **parked** pending §3.9 | here, §3.1–3.3 |
| 3 | **C2** — NOTIFY only when the version is servable, off the lock — landed, **parked** pending §3.9 | here, §3.4 |
| 4 | **C3** — delete the refresh engine's NOTIFYs | here, §3.5 |
| 5 | **C4** — `ResignQ` intent; `ResignZone` for key-state changes | here, §3.6 |
| 6 | **C5** — `SetupZoneSigning` becomes a registration | here, §3.7 |
| 7.. | the refresh-engine work | engine doc, S1–S5 |

The stopgap jumps the queue because the lab is exposed to #502 today and it is forty lines.
C1 comes before the NOTIFY work because once the refresh publishes signed data, C2's gate
has only one kind of publish to reason about.

---

## 7. Testing

- **The defect, as a test:** an inline-signing secondary transfers a zone; assert that
  *every* snapshot ever stored has RRSIGs on its authored RRsets — i.e. no intermediate is
  observable. Fails today.
- **One serial per change:** a transfer producing one content change yields exactly one new
  published serial.
- **One NOTIFY per version:** count `NotifyQ` sends across a full first load and a
  subsequent changed refresh.
- **No NOTIFY for the pre-Ready publish**, and exactly one at the Ready transition when the
  policy sync backfills.
- **Signing failure:** with signing forced to fail, the previous snapshot is still served
  and `DnssecError` is set.
- **DDNS is untouched:** an update publishes once, signed, and does not trigger a full-zone
  signing pass.
- **An inbound IXFR signs only what it touched.** A delta of two records into a large signed
  zone signs those owners and the apex, and no others. This is the test that would have caught
  the first implementation, and it is the one to write first.
- **A primary file reload of an already-signed zone is a no-op pass.** `wsNeedsFullSign` is
  set, the pass runs, and `SignRRset` with `force=false` writes no new RRSIGs because the
  existing ones are valid and by an active key. Pin it, so "sign wholesale replacement" never
  becomes "re-sign the world on every SIGHUP".
- **First load stays invisible until it is servable.** A zone with no keys and no policy loads,
  publishes unsigned, is **not Ready**, answers no queries and emits no NOTIFY; the policy apply
  then signs, publishes, flips Ready and emits exactly one.
- **Rollover:** a key-state change re-signs via `ResignZone` and leaves no RRSIG by a
  no-longer-active key — the thing `SignZone(force=true)` never did.
- Run all three test modules: `go test ./...` from `v2/` skips `v2/cli` and `v2/cache`.
