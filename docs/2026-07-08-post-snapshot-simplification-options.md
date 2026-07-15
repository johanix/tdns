# Post-snapshot simplification options

**Date:** 2026-07-08
**Scope:** Active tree only (`v2/`, `cmdv2/`). Legacy trees (`cmd/`, `tdns/`,
`music/`, `obe/`) explicitly excluded.
**Nature:** Read-only evaluation. No code was changed. This document records
simplification *options*, not decisions.
**Context:** Evaluation performed on branch `feature/zone-snapshot-correctness`
(tip `a093592`), i.e. after the immutable-snapshot publication model landed.

---

## Summary

| # | Question | Verdict | Confidence |
|---|----------|---------|------------|
| a | Is anything using `ValidatorEngine`? | Dead code. Removable. | High |
| b | Is `RRTypeStore`'s concurrency still needed? | Not for served data — strong case for a plain map. | High (design), Medium (full write-audit) |
| c | Are all `ZoneData` fields needed? | A few write-only/vestigial fields; one documented redundant cluster. | High for the named fields |
| d | Locks removable in query / transfer hot path? | Partial — the win is the per-RRset shard locks, same change as (b). | High |

The through-line: **(b) and (d) are the same fix**, and it is the
highest-value simplification available. (a) is the easiest clean win. (c) is
minor.

---

## (a) ValidatorEngine — dead code

`ValidatorEngine` (`v2/validatorengine.go:23`) is a goroutine that blocks
reading `conf.Internal.ValidatorCh`, started three times in
`v2/main_initfuncs.go:250,259,267`. The channel is **created**
(`v2/main_initfuncs.go:190`) and **read** (`v2/validatorengine.go:24`) — but
there is **not a single send site** anywhere in `v2/` or `cmdv2/`. Every
reference to `ValidatorCh`, `ValidatorRequest`, and `ValidatorResponse` was
grepped: they appear only in the engine, the struct definitions, the config
field, and the channel init. No caller ever submits a `ValidatorRequest`.

So the goroutine parks forever on an empty channel. It is also gated behind
`viper.GetBool("validator.active")` (`v2/validatorengine.go:28`), but even when
"active" nothing feeds it. Real validation happens elsewhere via direct calls
to `ValidateChildDnskeys` / `ValidateRRset` — exactly what the engine would
have called.

**Removable:**

- `v2/validatorengine.go` (171 lines)
- `ValidatorRequest` / `ValidatorResponse` (`v2/structs.go:644-651`)
- `ValidatorCh` field (`v2/config.go:454`)
- its `make()` (`v2/main_initfuncs.go:190`)
- the 3 `StartEngineNoError` calls (`v2/main_initfuncs.go:250,259,267`)

~200 lines net, zero behavior change. The only risk is an out-of-tree consumer
importing the exported structs — worth a quick check before deleting them.

---

## (b) RRTypeStore vs. plain maps — strong case to simplify

`RRTypeStore` (`v2/rrtypestore.go:7`) wraps a
`core.ConcurrentMap[uint16, core.RRset]` — a 16-shard `RWMutex` map. Under the
snapshot model its concurrency is **redundant for served data**, for two
verified reasons:

1. **Writes are single-writer.** Every `RRtypes.Set`/`Delete` is either
   construction of a *fresh, not-yet-published* `OwnerData` during zone load
   (`v2/dnsutils.go:575-593`) or staging into `workingSet` under `zd.mu`
   (`v2/zone_mutation.go:36,45,50,205,223,228`). No writer mutates a
   *published* store — the documented copy-strategy-A invariant
   (`v2/zone_snapshot.go:170-179`), CI-grep-enforced.

2. **Reads are post-freeze.** Served reads come off the immutable snapshot,
   whose owner map `snap.Data` is *already* a plain `map[string]*OwnerData`
   (`v2/zone_snapshot.go:17-24`). The snapshot de-concurrent-ified the owner
   map but left each owner's `RRtypes` as a `ConcurrentMap` — an asymmetry
   with no justification once the freeze invariant is accepted.

**The case:** back `RRTypeStore` with a plain `map[uint16]core.RRset` (keeping
the same `Get/Set/Keys/Count` API so no call sites change), relying on `zd.mu`
for staging writes and snapshot immutability for reads. Not used in any
genuinely-concurrent context — the IMR/resolver path (`v2/dnslookup.go`) builds
per-operation `OwnerData` locally, not shared.

**What would break** only if the invariant is violated (a future direct writer
to a published store) — the same failure mode the design already warns about.

---

## (c) ZoneData fields — a few removable, one redundant cluster

Verified write-only / vestigial fields (evidence = exact reference list):

- **`LatestRefresh`** — written once (`v2/refreshengine.go:120`), **never
  read**. Dead.
- **`LatestError`** — written in 8 places (all `= time.Now()`), **never read**.
  Dead bookkeeping.
- **`ApexLen`** — incremented on load (`v2/dnsutils.go:571`) and copied on flip
  (`v2/zone_mutation.go:312`), but **no logic ever reads it**. Write-only
  leftover from older name-handling.
- **`IxfrChain`** (on `ZoneData`) — copied into the snapshot
  (`v2/zone_mutation.go:341`) but **never populated anywhere**, so it is always
  empty. Vestigial, tied to the not-yet-implemented IXFR project — either wire
  it up there (see `docs/2026-07-02-ixfr-support.md`) or drop it now.

**Documented redundant-by-design cluster:** `Error`, `ErrorType`, `ErrorMsg`,
`LatestError` are all derived from `Errors map[ErrorType]ZoneError` and kept in
sync by `SetError`/`ClearError` (`v2/structs.go:155-165`). Deliberately
duplicated for legacy call sites — a consolidation opportunity (migrate readers
to `ErrorList()`), not dead code. `LatestError` is the one member of the
cluster that is pure dead weight.

**Suspicious but load-bearing — leave them:**

- `XfrType` — surfaced to API (`v2/zone_utils.go:200,279`).
- `RefreshCount` — gates responses when a zone never refreshed
  (`v2/defaultqueryhandlers.go:103,164`, `v2/updateresponder.go:135`).
- `PrimariesConf`/`Upstreams` and `ParentNS`/`ParentServers` — as-written vs.
  resolved variants, both read.

---

## (d) Hot-path locks — partial, and the same change as (b)

The snapshot refactor already did the big structural win: **neither the query
responder nor the transfer path takes `zd.mu` while building a response.**
`zd.snapshot` is an `atomic.Pointer` (`v2/structs.go:178`), both paths pin one
snapshot at entry (`v2/queryresponder.go:623`, `v2/dnsutils.go:264`), and
`snap.Data` is a lock-free plain map.

The **remaining** hot-path locks are the shard `RWMutex` RLocks *inside*
`RRtypes.Get/GetOnlyRRSet/Keys/Count`, hit on immutable snapshot data:

- **Highest value — AXFR out loop** (`v2/dnsutils.go:362-363`): calls
  `RRtypes.Keys()` (16-shard RLock + goroutine fan-out) plus `GetOnlyRRSet`
  **for every owner in the zone** while streaming a transfer. All against
  frozen data.
- **Query path**: repeated `RRtypes.Get/Count/Keys` RLocks per query
  (`v2/queryresponder.go:94-95,417,462,515,697,792`, `v2/auth_utils.go:35-164`).
  `Count()` RLocks all 16 shards; `Keys()` also spawns goroutines — heavy for
  reading a handful of RR types.

**These vanish for free if (b) is done** — a plain-map-backed snapshot RRset
store makes every one of these a lock-free map read. It is a data-type change,
not a mechanical "delete `Lock()`"; no lock statement is safe to just remove on
its own.

**Keep (genuinely mutable):**

- the global `Zones` registry lookup (`v2/zone_utils.go:612,623`)
- `zd.Status` via `GetStatus()` (`v2/enums.go:436`)
- per-connection TSIG state (`v2/dnsutils.go:246`)
- the KeyDB signing path
- the publisher-side `zd.mu` that serializes working-set build + atomic swap

---

## Ranked recommendation

1. **Lock-free snapshot RRset store** (b + d together) — retire
   `RRTypeStore`'s concurrent map for the *served* path; biggest
   correctness-neutral perf/simplicity win, removes all hot-path RLocks.
   Requires holding the freeze invariant, which the design already asserts.
2. **Delete `ValidatorEngine`** (a) — ~200 lines, trivially safe, no behavior
   change.
3. **Drop `LatestRefresh`, `LatestError`, `ApexLen`** (c) — verified write-only.
4. **Decide `IxfrChain`'s fate** with the IXFR project — vestigial until then.
5. **Housekeeping:** 8 stray `.go~` editor-backup files are in the tree (e.g.
   `v2/imrengine.go~`, `v2/delegation_utils.go~`, `cmdv2/cli/root.go~`). Not
   compiled, but clutter that shows up in greps.

---

## Deeper thread not fully resolved

There are now *three* owner-map representations — `zd.Data` (`ConcurrentMap`),
`workingSet` (plain map), and `snap.Data` (plain map). It is plausible
`zd.Data`'s concurrent type is now redundant too, but confirming whether
`zd.Data` can be retired needs a dedicated trace of every remaining live-store
reader. Worth its own read-only pass before touching it.

---

## Method note

Evaluation ran four parallel read-only investigations (one per question) plus
direct grep/read verification of the `ValidatorCh` send sites, the
`RRtypes.Set/Delete` writer discipline, and per-field reference counts on
`ZoneData`. All `file:line` citations above were checked against the working
tree at branch tip `a093592`.
