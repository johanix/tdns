# Project B Review — Zone-Mutation Snapshot Correctness

**Date:** 2026-07-08
**Source:** evaluation summary from an external review agent, of the snapshot-correctness (Project B) implementation.

**Verdict: Do not merge.** Two critical defects + one confirmed regression must be
fixed first. The writer side (B1/B2 staging, publish, dual-write, locking) is
genuinely solid and well-tested. The reader cutover (B3) is incomplete in exactly
the way that matters: the serial-tearing bug this project was chartered to
eliminate is **moved, not fixed**.

## Objective gates

- ✅ Builds clean, `go vet` clean, 7 GPG-signed commits, correctly milestoned
  B1→B2→B3, tdns-mp untouched (scope respected).
- ❌ **`-race` acceptance gate FAILS** — 2 tests regress (`TestRepublishPubkey…`,
  `TestRepublishPubcds…`), confirmed passing on `origin/main`. (Not a data race —
  assertion failures.)

## CRITICAL (block merge)

### C1 — Intra-response snapshot tearing: the core bug is not actually fixed.

QueryResponder and ZoneTransferOut make many independent `snapshot.Load()` calls
per response (verified: `queryresponder.go` lines 274, 340, 370, 624, 631, 654,
670, 680, 688, 737, 777…; no single threaded snap). If a `publish()` lands
mid-query, the Answer RRset and the authority SOA come from different snapshot
generations → different content under a mismatched serial. This is precisely plan
§0's "two secondaries serve different content for the same serial." The
immutable-snapshot machinery is correct; it's just not being used atomically per
response.

**Fix:** load the snapshot once at the top of QueryResponder (and ZoneTransferOut)
and thread that one `*zoneSnapshot` through all readers. This is the central
deliverable of B3 and is currently unmet. `TestConcurrentServeAndUpdate` misses it
because it loads once per iteration and never drives the real multi-load query
path.

### C2 — Catalog membership parsing left on live `zd.Data`, now broken.

`v2/catalog.go` (untouched by B) still reads `zd.Data.IsEmpty()`/`IterBuffered()`
(lines 56, 81). B3 removed the dual-write, so live `zd.Data` is now empty/stale →
`ParseCatalogZone` returns "catalog zone data is empty" on every load, silently
breaking catalog auto-configuration.

**Fix:** read `zd.publishedSnapshot().Data`.

## MAJOR

### M1 — ZoneTransferOut can emit a torn AXFR

Same root cause as C1, distinct path: `dnsutils.go` 261/345/354. Load once, iterate
that snapshot.

### M2 — Reachable nil-snapshot panic in `soaForResponse` (`zone_snapshot.go:251`)

The fallback dereferences apex with no nil-check, and
`applyRefreshReplacementLocked` sets `Ready=true` even when the publish was dropped
via the `!zoneStillLive` early-return, leaving `Ready && snapshot==nil`. Query
dispatch doesn't gate on `Ready`.

**Fix:** nil-guard the fallback and/or SERVFAIL when `publishedSnapshot()==nil`.

## Regression

### R1 — the 2 failing tests are a TEST-HARNESS gap, not a production bug

(Verified by the trace agent, and it's sound.) `newMapZone` populates `zd.Data` but
never installs a snapshot, so post-cutover `GetOwner` returns nil. Real zones always
publish before `OnZonePostRefresh` runs, so republish works in production.

**Fix:** `newMapZone` must call `InstallInitialSnapshot()`. But note: this is also a
warning sign — several tests now pass **vacuously** (they expect empty and get empty
for the wrong reason), which is why C1/C2 slipped through.

## MINOR / hardening

- **m1** — dead reader `XXfindServerTSYNCRRset` (`queryresponder.go:942`) still
  iterates live `zd.Data`; delete it.
- **m2** (reviewer's own finding) — `snapshotMapFromData` shares the `*RRTypeStore`
  pointer with live `zd.Data` (`zone_snapshot.go:176`, `odCopy := od` copies the
  pointer, not the store). Latent, not currently exploitable — B removed the
  in-place writers, so nothing mutates the shared store post-publish. But it's a
  fragile invariant the grep gate doesn't fully protect; a future direct `zd.Data`
  writer silently reintroduces the immutability bug. Consider deep-copying in
  `snapshotMapFromData`, or documenting the invariant loudly.
- **m3** — the CI grep gate only catches mutation regressions (`RRtypes.Set`/
  `Data.Set`), not reader regressions — which is exactly what C1/C2 are.
  Scope-correct per the plan, but it gives zero protection against the two worst
  findings.

## What's genuinely good (credit where due)

The writer side is well-executed: staging via `cloneOwner`/`cloneRRset` correctly
fresh-allocates, publish is properly locked under `zd.mu`, the coalescing publisher
+ generation guard are sound, the `pendingChanges`/debug zone-txlog observability is
clean, and the immutability discipline on the write path holds. The B1→B2→B3
strangler structure was followed faithfully.

## Recommendation

Send back with **C1, C2, M1, M2, R1** as required fixes (C1 is the headline — the
project doesn't achieve its own goal without it). **m1–m3** as follow-ups. After
C1's "load once per response" fix, the acceptance test should be strengthened to
drive QueryResponder under concurrent publishes (not just the raw snapshot), or
C1-class tearing will regress silently.

## Addendum (2026-07-08) — pre-existing harness failures + a real StripZoneRRSIGs bug

When the eight fixes above were applied, `go test -race .` in `v2/` had **14
further failures** beyond the two R1 named — all the *same* root cause R1
identified (a test builds/loads a zone but never installs a published snapshot,
so after the B3 reader cutover every read returns empty). The original eval
undercounted this. None were introduced by the eight fixes.

Failing tests, by file:
- `delsync_proxy_p2_test.go` — TestProxyPreRefresh{NoChange,CDSChange,CSYNCChange,NSChange}, TestProxySelfDebounceOnRepeatedTransfer
- `delsync_proxy_update_test.go` — TestProxyApexKEYs, TestProxyCurrentDelegationRRs, TestProxyCurrentDelegationRRsUnsigned
- `zone_transfer_out_test.go` — TestZoneTransferOut_{RoundTrip,LargeZoneSpansEnvelopes,LargeApexSpansEnvelopes,TSIGLargeApexEnvelopeSizes,TSIGRoundTrip}
- `sign_reconcile_test.go` — TestStripZoneRRSIGs

**Harness fix:** the shared helpers `testZone` and `loadTestTransferZone` now call
`InstallInitialSnapshot()` after loading (mirroring `testSnapshotZone`/`newMapZone`),
and `testZone`-based tests register the zone so `publishLocked`'s `zoneStillLive`
(registry + generation) guard does not silently drop the publish. Two tests that
mutated zone data *after* the snapshot was built — `TestStripZoneRRSIGs` and
`TestZoneTransferOut_OversizeRRsetAborts` (which had been passing **vacuously**
because the empty transfer "failed" for the wrong reason) — were made
B3-compatible (mutate the live store, then re-publish).

**Real bug found — not just harness — `StripZoneRRSIGs` mis-keyed every stripped
RRset.** Once `TestStripZoneRRSIGs` could actually run, it showed
`StripZoneRRSIGs` (`sign.go`) staging each stripped RRset under `rrset.RRtype` —
but `GetOnlyRRSet` returns RRsets whose `RRtype` field is unset (0); the store
keys by type separately. So every strip landed under type **0**, leaving the real
RRSIGs untouched (the function returned the correct removal *count* but published
unstripped data). Fixed by keying the stage on the authoritative loop type
(`rrset.RRtype = rrt` before staging). This was a **B3 regression** — B3 rewrote
`StripZoneRRSIGs` onto the working-set/stage path — that the harness gap had been
hiding; exactly the "tests now pass vacuously" risk flagged in R1.

Result: `go test -race .` in `v2/` is fully green.
