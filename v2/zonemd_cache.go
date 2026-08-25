/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"encoding/hex"
	"fmt"
	"hash"
	"time"

	"github.com/miekg/dns"
)

// Caching the canonical wire form, so a publish re-encodes what changed rather
// than the zone.
//
// The digest is a hash over every record in the zone, rendered into an exact
// canonical form. Rendering is the expensive half -- a copy and a pack per
// record, both allocating -- and it dominates: ~7 of the ~9 seconds a
// 1.1M-record zone takes to parse and digest (see zoneFileLooksUntouched). A
// publish typically changes three or four names and re-renders 1.1 million.
//
// The hash itself cannot be made incremental: SHA-384 over a sorted
// concatenation has no way to patch the middle. So this attacks the constant,
// not the complexity, and the thing worth keeping is the rendering.
//
// WHAT IS CACHED, AND WHY IT NEEDS NO INVALIDATION
//
// One block per OWNER name. RFC 8976 orders by (owner, type, RDATA), so every
// record at one owner sorts into a contiguous run and an owner's contribution
// to the hash is a self-contained block of bytes (see digestBlock).
//
// Validity is decided by POINTER IDENTITY of the *OwnerData, not by a flag
// anyone has to remember to clear. Every mutation path in zone_mutation.go
// either goes through cloneOwner -- which builds a fresh OwnerData -- or
// installs a caller's fresh one, or deletes the entry outright; nothing is
// mutated in place, which is the copy-on-write invariant the snapshot design
// already enforces with a CI grep gate. So a touched owner arrives as a new
// pointer and misses; an untouched owner is the same pointer and hits. There
// is no invalidation code, and therefore none to get wrong.
//
// PUBLISH ONLY
//
// The cache is read and written by the publish path alone, under zd.mu.
// Verification -- `zone zonemd verify`, the verify-zonemd gate -- builds from
// the records every time. Not a concession: a verification that reads cached
// bytes verifies the cache rather than the zone, and one stale entry would
// make a wrong digest pass. Confining it to the locked path also means no
// OwnerData shared with a published snapshot is ever written off-lock.

// DefaultZonemdWireCacheBytes is the per-zone budget when none is configured.
//
// Sized so an ordinary zone fits entirely and gets the whole benefit, while a
// zone large enough for the cache to matter to the host is bounded rather than
// unbounded. It is a per-ZONE figure: a server with many large zones multiplies
// it, which is the limitation named in the config documentation.
const DefaultZonemdWireCacheBytes = 64 << 20 // 64 MiB

// zonemdCacheEntry is one owner's rendered block, tagged with the OwnerData it
// was rendered from. The tag IS the validity check.
type zonemdCacheEntry struct {
	owner *OwnerData
	block []byte
}

// ZonemdCacheStats is what the last digest pass cost and what it is holding,
// reported by `zone zonemd status` so the memory/CPU trade is tuned from
// measurements rather than from guesses.
type ZonemdCacheStats struct {
	// MaxBytes is the effective budget; 0 means caching is disabled.
	MaxBytes int `json:"max_bytes"`
	// CachedBytes is what the cache holds, WireBytes what a full digest reads.
	// The ratio is how much of the zone the budget is covering.
	CachedBytes int `json:"cached_bytes"`
	WireBytes   int `json:"wire_bytes"`
	// CachedOwners of Owners: the same ratio counted in names.
	CachedOwners int `json:"cached_owners"`
	Owners       int `json:"owners"`
	// Hits is how many owners the last pass reused rather than re-rendered.
	Hits int `json:"hits"`
	// LastDigest is how long the last digest took, which is the number an
	// operator is actually trading memory for.
	LastDigest time.Duration `json:"last_digest"`
}

// zonemdCacheBudget returns the effective budget for the zone:
// 0/unset => default; negative => caching disabled.
//
// Deliberately the same shape as ixfrBudget, down to the sentinel, because it
// answers the same kind of question and an operator should not have to learn a
// second convention. Caller must hold zd.mu.
func (zd *ZoneData) zonemdCacheBudget() int {
	if zd.zonemdWireCacheMaxBytes == 0 {
		return DefaultZonemdWireCacheBytes
	}
	return zd.zonemdWireCacheMaxBytes
}

// zonemdDigestsLocked computes the digest of the working set once per
// algorithm, rendering each owner at most once.
//
// The blocks do not depend on the hash, so a zone publishing SHA-384 and
// SHA-512 renders once and hashes twice -- which is why the algorithms are
// taken together rather than one call per digest.
//
// Runs with zd.mu held.
func (zd *ZoneData) zonemdDigestsLocked(scheme uint8, algs []uint8) (map[uint8]string, error) {
	if zd.workingSet == nil {
		return nil, fmt.Errorf("zone %s: no working set to digest", zd.ZoneName)
	}
	if len(algs) == 0 {
		return nil, fmt.Errorf("zone %s: no ZONEMD algorithms to compute", zd.ZoneName)
	}

	hashers := make([]hash.Hash, len(algs))
	for i, alg := range algs {
		h, err := zonemdHasherForScheme(scheme, alg)
		if err != nil {
			return nil, err
		}
		hashers[i] = h
	}

	apex := dns.CanonicalName(zd.ZoneName)
	data := zd.workingSet

	names := make([]string, 0, len(data))
	for name := range data {
		names = append(names, name)
	}
	canonicalOwnerOrder(names)

	budget := zd.zonemdCacheBudget()
	if budget < 0 {
		// Disabled. Release whatever a previous configuration accumulated
		// rather than holding it for a cache nobody is going to read.
		zd.zonemdCache = nil
	} else if zd.zonemdCache == nil {
		zd.zonemdCache = make(map[string]zonemdCacheEntry, len(data))
	}

	stats := ZonemdCacheStats{MaxBytes: max(budget, 0), Owners: len(names)}
	started := time.Now()

	for _, name := range names {
		od := data[name]
		if od == nil {
			continue
		}

		var block []byte
		hit := false
		if e, ok := zd.zonemdCache[name]; ok && e.owner == od {
			block, hit = e.block, true
		} else {
			var err error
			block, err = digestBlock(apex, ownerRRsForDigest(od))
			if err != nil {
				return nil, err
			}
		}

		for _, h := range hashers {
			h.Write(block)
		}
		stats.WireBytes += len(block)

		switch {
		case hit:
			stats.Hits++
			stats.CachedBytes += len(block)
			stats.CachedOwners++

		case budget > 0 && stats.CachedBytes+len(block) <= budget:
			// Admitted. Note the budget is measured against what is already
			// held, so filling is first-come in canonical order and the
			// remainder is rendered and dropped -- the win degrades in
			// proportion to the shortfall rather than disappearing at a cliff.
			zd.zonemdCache[name] = zonemdCacheEntry{owner: od, block: block}
			stats.CachedBytes += len(block)
			stats.CachedOwners++

		default:
			// Rendered and dropped. Any entry still filed under this name
			// belongs to an OwnerData that no longer exists here, so it is
			// holding memory for a block nothing will match again.
			delete(zd.zonemdCache, name)
		}
	}

	// Entries for owners that have LEFT the zone are never visited above, so
	// they are never counted and never dropped. len(cache) > the number of
	// entries this pass accounted for is exactly the condition that says some
	// exist.
	if len(zd.zonemdCache) > stats.CachedOwners {
		for name := range zd.zonemdCache {
			if _, live := data[name]; !live {
				delete(zd.zonemdCache, name)
			}
		}
	}

	stats.LastDigest = time.Since(started)
	zd.zonemdCacheStats = stats

	out := make(map[uint8]string, len(algs))
	for i, alg := range algs {
		out[alg] = hex.EncodeToString(hashers[i].Sum(nil))
	}
	return out, nil
}

// dropZonemdCache releases the cache, for a zone that stops publishing a
// digest or is being torn down.
func (zd *ZoneData) dropZonemdCacheLocked() {
	zd.zonemdCache = nil
	zd.zonemdCacheStats = ZonemdCacheStats{}
}
