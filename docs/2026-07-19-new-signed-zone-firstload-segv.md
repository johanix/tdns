# BUG: SIGSEGV on first-load of a new online-signed zone (PR-2)

- **Severity:** HIGH — crashes the whole `tdns-auth` daemon. Merge-blocker for
  PR-2 (#292).
- **Found:** 2026-07-19, live testing of #292 on foffe (137-zone PQ testbed)
  while provisioning fixtures for the policy-reload matrix.
- **Branch:** fix on `fix/new-signed-zone-firstload-segv` (off #292 `6da9344`).

## Symptom

Adding a **brand-new online-signed zone** (one with no DNSSEC keys yet in the
keystore) to a #292 server and loading it crashes the daemon with a nil-pointer
SIGSEGV during startup / first bind. The existing zones on the same server are
unaffected until the new zone is reached, at which point the process dies — so a
single new signed zone takes the entire server down.

Observed: after adding `b.preload.axfr.net` (a fresh `online-signing` primary) to
the config and restarting, the daemon loaded ~137 existing zones fine, reached
`b.preload`, logged `no active DNSSEC keys available, will generate new keys`, and
segfaulted.

## Stack trace

```
signal SIGSEGV: segmentation violation code=0x1 addr=0x21 pc=0xaf5b10

github.com/johanix/tdns/v2.(*ZoneData).EnsureActiveDnssecKeys   sign.go:505
github.com/johanix/tdns/v2.(*ZoneData).resignWorkingSetSOAIfSigned  zone_mutation.go:206
github.com/johanix/tdns/v2.(*ZoneData).publishWorkingSetLocked   zone_mutation.go:305
github.com/johanix/tdns/v2.(*ZoneData).applyRefreshReplacementLocked  zone_mutation.go:359
github.com/johanix/tdns/v2.(*ZoneData).FetchFromFile             zone_utils.go:236
github.com/johanix/tdns/v2.(*ZoneData).Refresh                   zone_utils.go:49
github.com/johanix/tdns/v2.initialLoadZone                       refreshengine.go:55
github.com/johanix/tdns/v2.RefreshEngine                         refreshengine.go:291
```

## Root cause

`addr=0x21` is the byte offset of the `KSKAlgorithm` field within `DnssecPolicy`
(`Name string`[0:16], `Error string`[16:32], `Algorithm uint8`@0x20,
`KSKAlgorithm uint8`@0x21). The faulting line is:

```go
// sign.go:505 (EnsureActiveDnssecKeys, key-generation path)
pkc, msg, err := kdb.GenerateKeypair(zd.ZoneName, "ensure-active-keys",
    DnskeyStateActive, dns.TypeDNSKEY, zd.DnssecPolicy.KSKAlgorithm, "KSK", nil)
```

**`zd.DnssecPolicy` is nil.** It is nil because of a deliberate PR-2 change:

- PR-2 stopped binding the policy struct *before* load. At the first-bind sites
  (`refreshengine.go:279–283`, dynamic-add `:602`) it records only the config
  policy **name** and comments *"Do NOT bind intent here — on restart that
  pre-bind hides applied≠intent (blocking ①)."* The struct `zd.DnssecPolicy` is
  bound later, **post-Ready**, by `syncZoneDnssecPolicyFromConfig`
  (`completeFirstZonePolicyAndLoad`).
- But `initialLoadZone` runs `zd.Refresh` **before** that. `Refresh →
  FetchFromFile → applyRefreshReplacementLocked → publishWorkingSetLocked →
  resignWorkingSetSOAIfSigned` re-signs the apex SOA as part of publishing the
  working set. `resignWorkingSetSOAIfSigned` gates only on the
  `online-signing`/`inline-signing` **option** (`zone_mutation.go:187`), then
  calls `EnsureActiveDnssecKeys`, which for a **keyless** zone falls through the
  early "already have keys" return (`sign.go:436`) and the "promote published"
  path (nothing to promote) into the **generate** path — dereferencing the
  still-nil `zd.DnssecPolicy`.

**Why existing zones don't crash:** they already have active keys, so
`EnsureActiveDnssecKeys` returns at `sign.go:436` (`len(KSKs)>0 && len(ZSKs)>0`)
and never reaches the generate path. Only a zone with **no keys** reaches
`sign.go:505`.

**Why the test suite + the A2 live test missed it:** unit tests construct
`ZoneData` with a policy already set; the A2 herd test ran against the 137
existing, already-keyed PQ zones. The bug needs a *keyless* zone first-loaded
under #292's new deferred-binding ordering — exactly the "add a new signed zone"
case (config zone or the dynamic-add path, matrix Group F).

## Design tension

This is the intersection of two correct-in-isolation designs:
- PR-2 must NOT pre-bind the policy (blocking ①: on restart the fresh binding
  would equal intent and hide a pending `applied≠intent` change).
- The snapshot/publish path re-signs the SOA on load, which needs a bound policy
  to (generate keys and) sign.

The resolution is not to re-introduce pre-binding, but to make the load-time
resign **tolerant of a not-yet-bound policy**: a new zone simply isn't signable
until `syncZoneDnssecPolicyFromConfig` binds its policy and `SetupZoneSigning`
(via OnFirstLoad, post-Ready) signs it. The load-time SOA re-sign should be a
no-op until then.

## Fix

Two guards (existing keyed zones — the common path — are unaffected because their
`zd.DnssecPolicy` is non-nil):

1. **`resignWorkingSetSOAIfSigned` (`zone_mutation.go`):** return early when
   `zd.DnssecPolicy == nil` — the zone's policy hasn't been bound yet, so there is
   nothing to re-sign under. This is the semantic fix and also avoids a spurious
   error log on every new-zone load.
2. **`EnsureActiveDnssecKeys` (`sign.go`):** before the key-generation path, if
   keys are still missing **and** `zd.DnssecPolicy == nil`, return a clear error
   instead of dereferencing nil. Defense-in-depth so no caller can segfault here.

After the fix, a new online-signed zone loads without crashing (load-time resign
skipped), then is bound + signed post-Ready by
`syncZoneDnssecPolicyFromConfig`→`applyZonePolicyTransactional`
(which binds `zd.DnssecPolicy` before `SignZone`) and `SetupZoneSigning`.

## Reproduction

1. On a #292 server, add a fresh `online-signing` primary zone (no keys in the
   keystore) to the config with a valid `dnssecpolicy`.
2. Restart (or otherwise first-bind the zone).
3. Daemon SIGSEGVs at `sign.go:505` when it reaches the new zone.

## Regression guard

Add a unit test that first-loads a keyless online-signed `ZoneData` with
`DnssecPolicy == nil` through the publish/resign path (or calls
`EnsureActiveDnssecKeys` with a nil policy and no keys) and asserts a returned
error rather than a panic.
