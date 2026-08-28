# Review: publish and verify ZONEMD (#391)

**Superseded for merge readiness** by
[`2026-08-25-pr391-zonemd-publication-rereview.md`](2026-08-25-pr391-zonemd-publication-rereview.md)
(against `c7fb7abe`). This file is the review of `1ee61d7a`.

**Date:** 2026-08-25
**PR:** [#391](https://github.com/johanix/tdns/pull/391)
**Branch:** `feature/zonemd-publication` @ `1ee61d7a`
**Base:** `main`
**Size:** 36 files, +4885 / −71 (of which ~2300 lines are tests and ~940 docs)
**Lens:** safety, correctness, and possible improvements. Same bar as
[#390](https://github.com/johanix/tdns/pull/390): what a nameserver can
serve that is wrong, not style.

Design: [`2026-08-25-zonemd-publication-design.md`](2026-08-25-zonemd-publication-design.md).

---

## Verdict

**Request changes.** The architecture is right: presence before the NSEC
restitch, digest after, verify on the scratch zone before the hard flip,
remove-on-failure rather than serve a stale digest, and the RFC 4034
§6.3 sort fix is independently confirmed. One failure path still
publishes an apex NSEC that claims ZONEMD after the RRset has been
dropped. The primary restitch path already refuses a publish for that
class of inconsistency; this one should too.

| # | Finding | Severity | Nature |
|---|---------|----------|--------|
| 1 | `abandonZonemdLocked` continues the publish if the repair restitch fails | **Must fix** | Apex NSEC can list ZONEMD with no RRset |
| 2 | Digest duplicate suppression still compares the whole wire (TTL) | Should fix | RFC 8976 §3.3.1 duplicates are RDATA, not TTL |
| 3 | Shrinking `wire-cache-max-bytes` does not evict hits | Improvement | Memory can stay above the new budget |
| 4 | No `FetchFromUpstream` gate test | Improvement | The secondary path is why verify exists |

Off by default. A zone without `publish-zonemd` / `verify-zonemd` is
unchanged. No cross-repo callers.

---

## FINDING 1 — Repair restitch failure still publishes (must fix)

`ensureZonemdPresenceLocked` stages the apex ZONEMD, `restitchNsecLocked`
writes a bitmap that lists it, then `updateZonemdLocked` computes the
digest. If that compute or sign fails, `abandonZonemdLocked` removes the
RRset and restitches again so the bitmap matches.

```331:344:v2/zonemd_publish.go
func (zd *ZoneData) abandonZonemdLocked(err error) {
	zd.removeZonemdLocked()
	zd.noteZonemdStateLocked(err.Error())
	if rerr := zd.restitchNsecLocked(); rerr != nil {
		lgSigner.Error("the NSEC chain could not be repaired after dropping the ZONEMD;"+
			" the apex NSEC may claim a type the zone does not carry",
			"zone", zd.ZoneName, "error", rerr)
	}
}
```

On `rerr != nil` the function returns and `publishWorkingSetLocked`
continues to the snapshot swap. The first restitch already succeeded
(otherwise the publish would have been refused at
`zone_mutation.go:424–426`). The served snapshot can then have: no apex
ZONEMD, apex NSEC still listing `TypeZONEMD`. NXRRSET for ZONEMD fails;
a validator sees a chain that does not describe the zone.

That is the failure `refuseUnrepairableChainLocked` exists to prevent,
and the comment at `zonemd_publish.go:327–330` draws the distinction:
missing ZONEMD is fine, an unrepairable NSEC is not. The repair-failure
branch logs the NSEC hole and then does the thing the comment says not
to do.

**Fix:** if the repair restitch fails, call `refuseUnrepairableChainLocked`
(with the serial from before this publish’s bump) and return without
swapping. The previous snapshot stays self-consistent. Add a test that
forces the second restitch to fail and asserts the previous snapshot is
still served.

The path is rare (first restitch just succeeded under the same lock),
but it is the one the code itself calls out, and it is untested:
nothing in `zonemd_publish_test.go` drives `abandonZonemdLocked`.

---

## FINDING 2 — Duplicate suppression still includes TTL (should fix)

The sort comparator is RDATA-only (`zonemd.go:294–310`), which is the
dnspython-discovered bug and is pinned by
`TestZoneDigestSortsRRSIGsByRdataNotByTTL`. Duplicate suppression right
after it still uses the whole canonical wire:

```314:318:v2/zonemd.go
	for _, e := range entries {
		if prev != nil && bytes.Equal(prev, e.wire) {
			continue
		}
```

RFC 8976 §3.3.1 defines duplicates by owner/class/type/RDATA, not TTL.
Two RRs that differ only in TTL are both hashed. Appendix A never
triggers it (uniform TTLs). A signed zone with the NSEC-vs-other RRSIG
TTL split does **not** hit this (different RDATA: TypeCovered). The
case that would is a genuine duplicate RRset with mismatched TTLs,
which `core.IsDuplicate` already treats as one RR.

**Fix:** compare `e.typ` + `e.rdata` (or `e.rdata` alone inside a
per-type run), not `e.wire`. Add a unit test: same owner/type/RDATA,
two TTLs, counted once.

---

## FINDING 3 — Budget shrink does not evict hits (improvement)

`zonemd_cache.go:171–174`: a cache hit always keeps the block, even
when `CachedBytes` already exceeds a newly lowered
`wire-cache-max-bytes`. Admission is only for misses. Reloading a
smaller budget therefore does not shrink memory until owners miss
(content change) or the cache is disabled (`< 0`, which clears the
map).

Not a digest-correctness bug. Either evict on the next pass until
under budget, or say in the config docs that a shrink takes effect on
the next miss / disable.

---

## FINDING 4 — Verify’s load-bearing path is untested at the gate (improvement)

`gateIncomingZonemd` is called from `FetchFromFile` and
`FetchFromUpstream`, on the scratch zone, before pre-refresh callbacks
and `applyRefreshReplacementLocked`. Placement is correct. File-reload
refuse/accept/warn are tested (`zonemd_verify_test.go`). The secondary
AXFR path — the case the option exists for (`enums.go`) — is not.

A test that AXFRs a zone whose apex ZONEMD does not match, with
`verify-zonemd` on and `on-verify-failure: refuse`, and asserts the
previous snapshot is still served, would pin the live path the way
`TestDrainReleasesReaderOnCancellation` pinned #390.

---

## What looks right

**Publish split.** Presence before `restitchNsecLocked`, digest after,
RRSIG(ZONEMD) excluded from the input. Placeholder digests never reach
`snapshot.Store`. Option-off removes the RRset and the bitmap is
restitched (tested).

**Failure philosophy (happy path).** A digest/sign failure drops the
record rather than keeping the previous value. Stale is what a verifier
reports as tampering; absent is a state RFC 8976 defines.

**Secondaries.** `OptPublishZonemd` is in `originationOptions` and
stripped for a mirroring secondary; `OptVerifyZonemd` is not.
`zoneManagesZonemd` also checks `zoneMayOriginateContent`. Unsigned
ZONEMD in a signed zone is refused by `zonemdSignableLocked` until a
policy is bound.

**Updates.** Apex ZONEMD is refused to DDNS and the API when the server
manages it; DELNAME retains it; the journal drops it only for a
managed zone so replay cannot resurrect a digest for the wrong serial.
IXFR still carries it.

**Verify.** One function (`VerifyZonemd`) for the gate, CLI, API, and
`dog AXFR +zonemd`. Unsupported scheme/hash is not invalid. Default
`on-verify-failure` is refuse. `IgnoreSerial` is diagnostic only and
never used at the gate. `dog` refuses `IXFR +zonemd`. Verify rebuilds
from records; `TestVerificationDoesNotUseTheWireCache` poisons every
cached block and still gets `valid`.

**Sort.** Tiebreak is canonical RDATA, not whole-wire and not
wire-minus-TTL. Independently checked against dnspython 2.8.0.
`digest_variant` makes old `ZoneFileState` rows `Unknown` rather than
`Changed`, so the first restart after upgrade does not treat every
signed zone as an edited file.

**Cache.** Publish-only, under `zd.mu`, validity is `*OwnerData`
pointer identity, which matches the copy-on-write invariant.
`canonicalOwnerOrder` still agrees with `canonicalOwnerLess` (tested);
NSEC chain order is not a casualty of dropping the map.

**File-identity digest** is independent of publishing a ZONEMD
(tested). SHA-384 publish can reuse the value `ZoneFileState` wants.

---

## Scope already declined (agree)

- No incremental SIMPLE digest (RFC 8976 has none).
- No hand-rolled DNS label escaping in `canonicalSortKey`.
- `on-verify-failure: warn` and “unsupported is not invalid” are
  rollout / registry choices, not holes.
- Verify does not mean “refuse a zone that publishes no ZONEMD”.

Post-gate mutations (dynamic RRs, journal reconcile on a primary file
reload, future mutating `OnZonePreRefresh`) can make served content
diverge from what was verified. For a mirroring secondary the gate is
the whole story. For a primary with `publish-zonemd` the next publish
recomputes. Not blocking; worth a sentence in the config docs so
`verify-zonemd` on a primary is not mistaken for a continuous
attestation of the live zone including the journal.

---

## Suggested merge order relative to this finding

Land after finding 1: repair-restitch failure refuses the publish.
Finding 2 can ride along; 3 and 4 do not have to.
