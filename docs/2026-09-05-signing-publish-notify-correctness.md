# Signing, publishing and NOTIFY — one version, one signing pass, one NOTIFY

**Status:** design, reviewed in conversation 2026-09-05. C1 implemented; C2–C5 pending.
**Base:** `main` @ `d833c683`. `v2/` tree only.
**Issues:** none filed yet. C1 (§3.1) is a correctness defect and deserves one.
**Companion:** `2026-09-05-refresh-engine-redesign-364-502.md` — the refresh-engine
concurrency work. Separate area, separate review; the global commit order across both is
in §6.

---

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

Set in `applyRefreshReplacementLocked` when `zd.signsItsOwnContent()` (`ixfr_in.go:821`).
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

### 3.3 C1 — failure semantics

Signing fails → **do not swap**; keep serving the previous snapshot; set
`DnssecPolicyWarning`.

*Not* `DnssecError`, which is what this section said before it was implemented. `DnssecError`
is service-impacting (`enums.go:445`), so recording it would make the query and transfer
handlers refuse — taking a zone that is still serving a perfectly good signed snapshot off
the air because a *newer* version could not be signed. That is the opposite of "keep serving
the previous snapshot". The NSEC-chain refusal three lines below in the same function reaches
the same conclusion and uses the same warning.

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
func (zd *ZoneData) notifyIfServable() // Ready && (unsigned zone || apex SOA has an RRSIG)
```

Two changes bundled with it:

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

`NotifyDownstreams` itself — the blocking `dns.Exchange` loop — has no remaining callers
and is deleted.

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

| step | today | after |
|---|---|---|
| refresh publishes | unsigned data, signed SOA/NSEC/ZONEMD, **NOTIFY** | signed (C1), pre-Ready, **no NOTIFY** |
| `InstallInitialSnapshot` | flips Ready | flips Ready, **NOTIFY** if servable |
| policy sync — backfill | no publish | no publish, no NOTIFY |
| policy sync — apply | forced sign + publish + **NOTIFY** | forced sign + publish + **NOTIFY** (special circumstance, kept) |
| replay | may publish + **NOTIFY** | may publish + NOTIFY (real content change) |
| `OnFirstLoad` → `SetupZoneSigning` | sign + publish + **NOTIFY**, then resigner force-signs + publish + **NOTIFY** | registration only |

Up to five NOTIFYs across three-plus serials, down to one per version that actually changed.

### 3.9 Not in scope, but noticed

`NameExists` reads `publishedSnapshot()` with no Ready check (`zone_utils.go:1230`), and the
query path reads *other* zones' snapshots directly for signal and parent data
(`queryresponder.go:560`, `:698`). Both bypass `GetOwner`'s `ErrZoneNotReady` gate
(`zone_utils.go:1236`). Harmless once C1 lands (there is no unsigned published version left
to leak), but the Ready invariant is being relied on in more places than it is enforced.
Worth a sweep, separately.

---

## 4. Risk assessment

| # | risk | likelihood | impact | mitigation | detection |
|---|---|---|---|---|---|
| R1 | Self-deadlock re-locking `zd.mu` during the in-publish signing pass | **high** if §3.2 is not followed exactly — the tree has done this before (`6e090a9`) | severe: the zone's publisher wedges, the zone stops updating | pre-resolved `dak` with `zdLocked=true`, non-nil into every `SignRRset`; `signWorkingSetLocked` takes no lock and resolves nothing | it hangs immediately and obviously; a publish test with a signed zone catches it in CI |
| R2 | Signing under `zd.mu` lengthens the lock hold on every changed refresh | certain | moderate: readers of that zone stall for the signing pass | signing already happened under `zd.mu` (`sign.go:871`) — the hold moves, it does not grow. What DOES shrink it: C2 takes `dns.Exchange` off the same lock | publish latency per zone |
| R3 | `wsNeedsFullSign` set on an incremental path by mistake | low | low–moderate: a full zone walk per DDNS update | one setter, in `applyRefreshReplacementLocked`; test asserts a DDNS publish does not trigger a full pass | signing counters per publish |
| R4 | A zone freezes at its last good version on a persistent signing failure (§3.3) | low | moderate, and intended | `DnssecError` set and surfaced; the alternative is serving unvalidatable data | the zone renders as an ERROR row on `zone list` — `DnssecError` is service-impacting (`enums.go:445`), unlike `RefreshError` |
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
| 2 | **C1** — sign wholesale replacement before the swap ✅ **implemented** (`fix/sign-before-publish`) | here, §3.1–3.3 |
| 3 | **C2** — NOTIFY only when the version is servable, off the lock | here, §3.4 |
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
- **Rollover:** a key-state change re-signs via `ResignZone` and leaves no RRSIG by a
  no-longer-active key — the thing `SignZone(force=true)` never did.
- Run all three test modules: `go test ./...` from `v2/` skips `v2/cli` and `v2/cache`.
