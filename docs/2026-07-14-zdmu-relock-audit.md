# Audit: re-entrant `zd.mu` deadlock class — search for instance #3

Date: 2026-07-14
Branch: `feature/zone-snapshot-correctness`
Scope: `v2/` (the maintained tree)

## The class

A path that **already holds `zd.mu`** — either a `*Locked` method, or a caller
that did `zd.mu.Lock()` and has not yet unlocked — transitively calls a method
that itself does `zd.mu.Lock()`/`RLock()`. Go's `sync.RWMutex` is **not
reentrant**, so this is a permanent self-deadlock: the goroutine holding
`zd.mu` blocks forever waiting for itself, and every other user of that zone
(queries, zone list, `ParseZones` behind `confMu`) piles up behind it, wedging
the daemon.

Prior fixed instances:

- **#1 — 6e090a9** `SignZone` (holds `zd.mu`) → `UpdateSigValidityFloor` →
  `SetError`/`ClearError` re-locked `zd.mu`. Fixed with
  `setErrorLocked`/`clearErrorLocked` + a `zdLocked` flag on
  `UpdateSigValidityFloor`.
- **#2 — 23710d1** `resignWorkingSetSOAIfSigned` (under a held `zd.mu` via
  `publishWorkingSetLocked`) → `SignRRset` → `EnsureActiveDnssecKeys` →
  `PublishDnskeyRRs` re-locked `zd.mu`. Fixed by adding a `zdLocked` flag to
  `EnsureActiveDnssecKeys` that routes the DNSKEY publish through the existing
  `publishDnskeyRRsLocked`, and by having `resignWorkingSetSOAIfSigned` resolve
  the `dak` up front and pass it non-nil into `SignRRset`.

## Method

1. Enumerated every `zd.mu` acquisition — the **re-lockers**:
   `grep -rn 'zd\.mu\.\(R\)\?Lock' --include='*.go' | grep -v _test.go`
   (52 sites; no `RLock` — every acquisition is a full `Lock()`).
2. Enumerated every `*Locked` method (`grep -rn 'func .*Locked('`) and every
   explicit `zd.mu.Lock()` … `Unlock()` region — the **held-lock contexts**.
3. For each held-lock context, followed the call graph (directly and
   transitively) to see whether it can reach any re-locker from step 1,
   focusing on the DNSSEC sign/publish/resign, transport-signal, and
   zone-update apply paths, and on the specific re-lockers `PublishDnskeyRRs`,
   `SetError`/`ClearError`, `ErrorList`, `SetStatus`, `UpdateSigValidityFloor`,
   `Zones.Set`, and the publish/resign helpers.
4. Classified each candidate REAL vs safe.

## `zd.mu` re-lockers (methods that acquire `zd.mu`)

Error/status setters and readers (all in `enums.go`): `SetError`, `ClearError`,
`SetStatus`, `GetStatus`, `HasError`, `HasErrorOtherThan`,
`HasServiceImpactingError`, `HasAutoRolloverImpactingError`, `ErrorList`
(`SetStatus` also re-enters `Zones.Set`).

DNSSEC/publish: `PublishDnskeyRRs` (`ops_dnskey.go`), `ResignZone`,
`StripZoneRRSIGs`, `SignZone`, `GenerateNsecChain` (`sign.go`),
`CreateTransportSignalRRs` (`tsignal.go`).

Publish/mutation: `pendingChanges`, `requestPublish`, `publishSync`,
`publishNow`, `InstallInitialSnapshot`, `runPublisher` (`zone_mutation.go`),
`Lock()` (`structs.go`).

Zone data / refresh: `FetchFromFile`, `FetchFromUpstream`, `WriteZone`,
`SetOption`, `RepopulateDynamicRRs` (`zone_utils.go`),
`ApplyChildUpdateToZoneData`, `ApplyZoneUpdateToZoneData`, `ZoneUpdaterEngine`
(`zone_updater.go`), `ProxyDelegationPreRefresh`, `ProxyDelegationPostRefresh`
(`delsync_proxy.go`), `GetDelegationData`, `ListChildren`
(`delegation_backend_direct.go`), catalog handlers (`apihandler_catalog.go`),
`setZonePolicy`, `changeZonePolicy`, `APIzone` (`apihandler_zone.go`),
`RefreshEngine` / `initialLoadZone` regions (`refreshengine.go`).

## Held-lock contexts checked

The central held-lock context is the **publish path**:
`publishWorkingSetLocked` (and its wrappers `publishLocked` / `publishSync` /
`publishNow` / `runPublisher` / `applyRefreshReplacementLocked` /
`commitTransportSignalLocked`, and the two `initialLoadZone` / refresh
`serialChanged` blocks in `refreshengine.go`). Everything that re-signs the SOA
under the lock funnels through:

```
… (held zd.mu) → publishWorkingSetLocked → resignWorkingSetSOAIfSigned
    → EnsureActiveDnssecKeys(zdLocked=true)   ← the chokepoint
    → SignRRset(dak != nil)                    ← no re-enter (dak resolved)
```

### Direct callees of `publishWorkingSetLocked` — all safe

`zoneStillLive`, `apexFromSnapshotData`, `nextOutboundSerial`,
`setWorkingSetSOASerial`, `buildSnapshotLocked` (`soaFromApex`,
`cloneSignalSynth`, `copyIxfrChain`), `snapshot.Store`, `KeyDB.SaveOutgoingSerial`,
`NotifyDownstreams` (only `dns.Exchange`, no `zd.mu`) — none acquire `zd.mu`.

### `EnsureActiveDnssecKeys(zdLocked=true)` transitive callees

- `kdb.GetDnssecKeys` / `GetDnssecKeysByState` / `PromoteDnssecKey` /
  `GenerateKeypair` / `RegisterBootstrapActiveKSK` / `UpdateDnssecKeyState` /
  `LoadRolloverZoneRow` — DB/keystore ops, no `zd` receiver, no `zd.mu`. Safe.
- `reconcileActiveKeyAlgorithms`, `refreshActiveDnssecKeys` — no `zd.mu`. Safe.
- `PublishDnskeyRRs` — routed to `publishDnskeyRRsLocked` when `zdLocked` (the
  #2 fix). Safe.
- **`WarnLargeAlgKskReusedAsZsk` / `WarnLargeAlgZoneSigningRole` — RE-LOCK.**
  See #3 below.

### Other signing held-lock contexts — safe

- `SignZone`, `ResignZone`, `GenerateNsecChain`: resolve `dak` via
  `EnsureActiveDnssecKeys(kdb, false)` **before** `zd.mu.Lock()`, then under the
  lock call `SignRRset(dak != nil)` (skips the key-ensure path),
  `publishDnskeyRRsLocked`, `GenerateNsecChainWithDak` (staging only), and
  `publishLocked` (the chokepoint above). `SignZone` also calls
  `UpdateSigValidityFloor(zdLocked=true)` (the #1 fix). Safe.
- `ApplyChildUpdateToZoneData` / `ApplyZoneUpdateToZoneData`: resolve `dak`
  before the lock, pass non-nil `dak` into `SignRRset` under the lock, and
  `publishLocked` on the deferred exit (the chokepoint). Safe.
- `CreateTransportSignalRRs`: resolves `dak` before the lock (its own comment
  documents the #2 idiom); `createTransportSignal{SVCB,TSYNC}` sign with the
  non-nil `dak` and then `commitTransportSignalLocked → publishWorkingSetLocked`
  (the chokepoint). Safe.
- `SyncZoneDelegationViaNotify` calls `SignRRset(…, nil, …)` (nil dak) — but
  `delegation_sync.go` holds **no** `zd.mu` anywhere and `GetOwner` reads the
  published snapshot without holding the lock, so this runs UNLOCKED. Safe.
- Query path (`queryresponder.go`) online-signs with a nil dak, but holds no
  `zd.mu` (reads the immutable snapshot). Safe.

### Non-signing held-lock contexts — safe

`refreshengine.go` field-assignment locks (OnFirstLoad swap; the pre-registered
stub and reload config-merge blocks; `applyReloadedPolicyLocked`) touch only
fields; their `SetError` / `UpdateSigValidityFloor(zdLocked=false)` /
`triggerResign` / `GetSOA` calls are all **after** the `Unlock()`. Catalog
handlers, `delsync_proxy` `ProxyDelegation*`, `zone_utils` `FetchFrom*` /
`WriteZone` / `SetOption` / `RepopulateDynamicRRs`, `apihandler_zone`
`setZonePolicy` / `changeZonePolicy` (their `SignZone` /
`UpdateSigValidityFloor` run after unlock, per #1), `ZoneUpdaterEngine`, and
`delegation_backend_direct` `GetDelegationData` / `ListChildren` call no
re-locker inside their lock scope. `InstallInitialSnapshot` builds the snapshot
via `buildSnapshotLocked` directly (no `resignWorkingSetSOAIfSigned`). Safe.

## Verdict: **instance #3 EXISTS** (fixed here)

`EnsureActiveDnssecKeys` calls two large-algorithm warning helpers that each
read the zone's error list and set a `DnssecPolicyWarning`:

- `WarnLargeAlgKskReusedAsZsk` (`sign.go`, active-KSK-reused-as-CSK / no real
  ZSK branch), and
- `WarnLargeAlgZoneSigningRole` (`sign.go`, right after a fresh ZSK is
  generated),

and both call `zd.ErrorList()` (`enums.go`, `zd.mu.Lock()`) followed by
`zd.SetError()` (`enums.go`, `zd.mu.Lock()`).

Real deadlock chain (fresh-key ZSK branch, the common one):

```
applyRefreshReplacementLocked / publishLocked / commitTransportSignalLocked   (hold zd.mu)
  → publishWorkingSetLocked
  → resignWorkingSetSOAIfSigned
  → EnsureActiveDnssecKeys(zdLocked=true)
  → (generate ZSK) WarnLargeAlgZoneSigningRole
  → zd.ErrorList()  → zd.mu.Lock()   ← SELF-DEADLOCK
```

Reachability: guarded only by `isLarge(alg)`, i.e. the algorithm being listed in
`dnssec.large_algorithms`. That is exactly the live **PQ-DNSSEC** configuration
(MLDSA/FALCON/…). The re-lock fires **before** the DNSKEY publish that #2 fixed,
so 23710d1 did not cover it — and 23710d1's regression test uses ED25519 (not a
large algorithm), so `WarnLargeAlgZoneSigningRole` returned early and never hit
the re-lock. On a large-algorithm signed zone, a refresh / initial-load / update
that re-signs the SOA during publish while the ZSK is first generated
deterministically wedges the daemon.

### Fix (mirrors #1 / #2)

- `enums.go`: add `errorListLocked()` (unlocked body of `ErrorList`);
  `setErrorLocked` already exists from #1.
- `large_ksk.go`: add a `zdLocked bool` parameter to
  `WarnLargeAlgZoneSigningRole` and `WarnLargeAlgKskReusedAsZsk`. When
  `zdLocked` they route the read/write through `errorListLocked` /
  `setErrorLocked` instead of `ErrorList` / `SetError`.
- `sign.go`: both callsites (the only two callers, both inside
  `EnsureActiveDnssecKeys`) pass the function's `zdLocked` down. Every other
  path into `EnsureActiveDnssecKeys` passes `zdLocked=false`, so unlocked
  callers are unchanged.

### Regression test

`v2/zdmu_relock_largealg_test.go` — `TestResignSOAUnderLockLargeAlgNoSelfDeadlock`
drives `resignWorkingSetSOAIfSigned` under a held `zd.mu` with an empty keystore
and ED25519 marked large (`Conf.Internal.LargeAlgorithms`), so the fresh-key ZSK
generation reaches `WarnLargeAlgZoneSigningRole`. Timeout-guarded: a
re-introduced re-lock blocks the goroutine forever and the 10s timeout fails the
test. Verified — flipping the `sign.go:537` flag back to `false` trips the
timeout exactly after "generated ZSK"; the test also asserts the SOA is signed
and the `DnssecPolicyWarning` was actually recorded, proving the re-lock site was
exercised (not skipped).

## Result

`go build ./...` and `go test -race ./...` in `v2/` both pass. One new instance
(#3) found and fixed; no further reachable re-lock deadlock found in the audited
paths. With #1/#2/#3 fixed, the audited class is considered closed for the
DNSSEC sign/publish/resign, transport-signal, and zone-update apply paths.
