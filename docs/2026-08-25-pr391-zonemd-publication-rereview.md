# Re-review: #391 ZONEMD publication

**Date:** 2026-08-25 (second pass)
**Prior review:** [`2026-08-25-pr391-zonemd-publication-review.md`](2026-08-25-pr391-zonemd-publication-review.md) (against `1ee61d7a`)
**PR:** [#391](https://github.com/johanix/tdns/pull/391)
**Branch:** `feature/zonemd-publication` @ `c7fb7abe`
**Lens:** did the four findings close, and did the fix commit introduce
anything new.

New commits since `1ee61d7a`:

- `15250776` — operator-facing docs (RFCs list, update refusals, templates, guide index).
- `c7fb7abe` — address the review.

---

## Verdict

**Approve.** All four findings are closed in the code, not only in the
commit message. Each has a test. The two that change a digest have
independent expected values (dnspython). No new correctness hole.

| # | First-pass finding | Now |
|---|--------------------|-----|
| 1 | Repair restitch failure still publishes | **Closed.** `abandonZonemdLocked` returns false and calls `refuseUnrepairableChainLocked`. `publishWorkingSetLocked` stops. |
| 2 | Duplicate suppression compared whole wire (TTL) | **Closed.** Dedup is `(type, RDATA)`; lowest TTL kept, deterministic, dnspython-pinned. |
| 3 | Budget shrink did not evict hits | **Closed.** Hits over the new budget are deleted. Same canonical prefix kept. |
| 4 | No `FetchFromUpstream` gate test | **Closed.** Four AXFR tests: refuse, accept, warn, option off. |

The config-guide note that `verify-zonemd` on a primary is not a
continuous attestation of the live zone (journal / DDNS) is in
`guide/config-tdns-auth.md`.

---

## Finding 1 — closed

```344:369:v2/zonemd_publish.go
func (zd *ZoneData) abandonZonemdLocked(prevSerial uint32, err error) bool {
	zd.removeZonemdLocked()
	// ...
	rerr := zd.restitchNsecLocked()
	if rerr == nil {
		return true
	}
	zd.refuseUnrepairableChainLocked(prevSerial, ...)
	return false
}
```

`updateZonemdLocked` now returns that bool. `publishWorkingSetLocked`
returns without swapping when it is false (`zone_mutation.go:438–440`).
A missing digest still publishes; only a broken chain refuses.

Tests:

- `TestAbandoningTheZonemdRefusesThePublishWhenTheChainCannotBeRepaired`
  — keystore closed so the repair restitch cannot sign; serial rolled
  back, previous snapshot still served, `DnssecPolicyWarning` set.
- `TestAbandoningTheZonemdContinuesWhenTheChainRepairsCleanly` — ZONEMD
  dropped, apex NSEC bitmap no longer lists the type, publish may
  continue.

The refuse test drives `abandonZonemdLocked` directly (they say so).
The publish-path half is the one `if !updateZonemdLocked { return }`
line, which is there.

---

## Finding 2 — closed

Sort still tiebreaks on RDATA; equal RDATA then whole-wire so the
lowest TTL sorts first. The scan keeps the first of a `(type, RDATA)`
run, not a full-wire equal.

`TestZoneDigestCountsATTLOnlyDuplicateOnce` parses both TTL copies
(five RRs), expects dnspython 2.8.0 digests for SHA-384 and SHA-512,
and reverses the pair to prove the survivor does not depend on input
order.

---

## Finding 3 — closed

```171:182:v2/zonemd_cache.go
		case hit && stats.CachedBytes+len(block) > budget:
			delete(zd.zonemdCache, name)
			stats.Hits++
```

The block is still hashed (digest correctness unchanged). It is not
kept. Walk order is canonical, so the same prefix fits on every pass.

`TestWireCacheEvictsWhenTheBudgetShrinks` fills the cache, sets the
budget to a quarter, publishes with no content change, and asserts
bytes are under budget, some owners remain, not all were dropped.

---

## Finding 4 — closed

Real AXFR from a fake primary:

| Test | Option / mode | Outcome |
|------|----------------|---------|
| `TestVerifyZonemdGateRefusesACorruptTransfer` | verify on, refuse | error, previous snapshot still served, `fresh.` not adopted |
| `TestVerifyZonemdGateAcceptsAGoodTransfer` | verify on | adopted |
| `TestVerifyZonemdGateWarnModeAdoptsATransfer` | warn | adopted |
| `TestVerifyZonemdGateOffAdoptsACorruptTransfer` | option off | adopted, check not run |

These go through `FetchFromUpstream`, which is the gate’s live caller.

---

## Nothing new that should block

Docs commit is operator-facing only. No godoc-orphaning of the
`updateZonemdLocked` / `abandonZonemdLocked` split. `prevSerial` is the
value saved before the bump, which is what
`refuseUnrepairableChainLocked` needs.
