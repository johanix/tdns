package tdns

import (
	"fmt"
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// buildZoneText returns an unsigned zone with n names under the apex.
func buildZoneText(apex string, n int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\t3600\tIN\tSOA\tns.%s hostmaster.%s 1 7200 1800 604800 7200\n",
		apex, apex, apex)
	fmt.Fprintf(&b, "%s\t3600\tIN\tNS\tns.%s\n", apex, apex)
	fmt.Fprintf(&b, "ns.%s\t3600\tIN\tA\t127.0.0.1\n", apex)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "n%04d.%s\t3600\tIN\tA\t10.%d.%d.%d\n",
			i, apex, i/65536%256, i/256%256, i%256)
		fmt.Fprintf(&b, "n%04d.%s\t3600\tIN\tTXT\t\"filler %d\"\n", i, apex, i)
	}
	return b.String()
}

// cacheTestZone is an unsigned primary publishing a ZONEMD, with a settable
// wire-cache budget.
func cacheTestZone(t *testing.T, names int, budget int) *ZoneData {
	t.Helper()
	zd := testZone(t, "cache.example.", buildZoneText("cache.example.", names))
	registerZones(t, zd)
	zd.Options = map[ZoneOption]bool{OptPublishZonemd: true, OptAllowApiUpdates: true}
	zd.UpdatePolicy = policyAllowing(dns.TypeA, dns.TypeTXT)
	zd.mu.Lock()
	zd.zonemdWireCacheMaxBytes = budget
	zd.mu.Unlock()
	if _, err := zd.publishSync(); err != nil {
		t.Fatalf("initial publish: %v", err)
	}
	return zd
}

func cacheStats(zd *ZoneData) ZonemdCacheStats {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return zd.zonemdCacheStats
}

// The whole point: a publish that changes one name must re-render one name.
func TestWireCacheReusesUntouchedOwners(t *testing.T) {
	zd := cacheTestZone(t, 200, 0)

	first := cacheStats(zd)
	if first.Hits != 0 {
		t.Errorf("the first digest reported %d cache hits; there was nothing to hit", first.Hits)
	}
	if first.CachedOwners != first.Owners {
		t.Fatalf("the default budget did not hold a %d-owner zone: %d of %d owners, %d bytes",
			first.Owners, first.CachedOwners, first.Owners, first.CachedBytes)
	}

	// Touch exactly one name.
	zd.mu.Lock()
	zd.ensureWorkingSet()
	rr := mustRR(t, "n0007.cache.example. 3600 IN A 10.0.0.99")
	zd.stageRRsetLocked("n0007.cache.example.",
		mkRRset("n0007.cache.example.", dns.TypeA, rr))
	zd.publishLocked(zd.generation.Load())
	zd.mu.Unlock()

	second := cacheStats(zd)
	// Every owner except the apex (whose SOA serial always moves) and the one
	// touched should have been reused.
	wantHits := second.Owners - 2
	if second.Hits != wantHits {
		t.Errorf("a publish that changed one name reused %d of %d owners, expected %d",
			second.Hits, second.Owners, wantHits)
	}
	assertZonemdMatchesSnapshot(t, zd, "after a one-name change")
}

// A budget of zero means the default; a negative budget means off. Same
// sentinel convention as ixfr-chain-max-bytes.
func TestWireCacheBudgetSentinels(t *testing.T) {
	t.Run("unset means the default", func(t *testing.T) {
		zd := cacheTestZone(t, 20, 0)
		if got := cacheStats(zd).MaxBytes; got != DefaultZonemdWireCacheBytes {
			t.Errorf("budget reported as %d, want the default %d",
				got, DefaultZonemdWireCacheBytes)
		}
	})

	t.Run("negative disables", func(t *testing.T) {
		zd := cacheTestZone(t, 20, -1)
		st := cacheStats(zd)
		if st.MaxBytes != 0 {
			t.Errorf("a negative budget reported MaxBytes %d, want 0 (disabled)", st.MaxBytes)
		}
		if st.CachedBytes != 0 || st.CachedOwners != 0 {
			t.Errorf("caching happened with the cache disabled: %d bytes, %d owners",
				st.CachedBytes, st.CachedOwners)
		}
		zd.mu.Lock()
		nonEmpty := len(zd.zonemdCache)
		zd.mu.Unlock()
		if nonEmpty != 0 {
			t.Errorf("the cache map holds %d entries with caching disabled", nonEmpty)
		}
		// ...and the digest is still correct, which is the thing that must not
		// depend on the cache at all.
		assertZonemdMatchesSnapshot(t, zd, "with caching disabled")
	})
}

// A budget smaller than the zone caches what fits and re-renders the rest --
// the win degrades in proportion rather than vanishing.
func TestWireCacheDegradesProportionally(t *testing.T) {
	// Size the budget from the zone's actual wire size, so the test does not
	// depend on how many bytes an A record happens to occupy.
	full := cacheTestZone(t, 200, 0)
	wire := cacheStats(full).WireBytes
	if wire == 0 {
		t.Fatal("the zone reported zero wire bytes")
	}

	zd := cacheTestZone(t, 200, wire/2)
	st := cacheStats(zd)

	if st.CachedBytes > wire/2 {
		t.Errorf("the cache holds %d bytes, over its %d budget", st.CachedBytes, wire/2)
	}
	if st.CachedOwners == 0 {
		t.Error("a budget of half the zone cached nothing")
	}
	if st.CachedOwners >= st.Owners {
		t.Errorf("a budget of half the zone cached all %d owners", st.Owners)
	}
	if st.WireBytes != wire {
		t.Errorf("wire bytes reported as %d, want %d -- the whole zone is still digested",
			st.WireBytes, wire)
	}
	assertZonemdMatchesSnapshot(t, zd, "with a half-size budget")
}

// The cache must not outlive the owners it describes. A name deleted from the
// zone leaves an entry nothing will ever match again.
func TestWireCacheDropsDepartedOwners(t *testing.T) {
	zd := cacheTestZone(t, 50, 0)
	zd.mu.Lock()
	before := len(zd.zonemdCache)
	zd.mu.Unlock()

	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.stageOwnerDeleteLocked("n0007.cache.example.")
	zd.stageOwnerDeleteLocked("n0008.cache.example.")
	zd.publishLocked(zd.generation.Load())
	after := len(zd.zonemdCache)
	zd.mu.Unlock()

	if after != before-2 {
		t.Errorf("the cache holds %d entries after two owners left, was %d", after, before)
	}
	assertZonemdMatchesSnapshot(t, zd, "after deleting two owners")
}

// The digest must not depend on whether anything was cached. This is the
// invariant that makes the whole optimisation admissible.
func TestWireCacheDoesNotChangeTheDigest(t *testing.T) {
	text := buildZoneText("cache.example.", 120)
	reference, err := ZoneDigestHex("cache.example.",
		parseZoneRRs(t, "cache.example.", text), ZonemdSchemeSimple, ZonemdAlgSHA384)
	if err != nil {
		t.Fatal(err)
	}

	for _, budget := range []int{0, -1, 1 << 30, 4096, 1} {
		t.Run(fmt.Sprintf("budget=%d", budget), func(t *testing.T) {
			zd := cacheTestZone(t, 120, budget)
			// The published zone has a ZONEMD the reference zone does not --
			// but ZoneDigest excludes the apex ZONEMD, so the two are digests
			// of the same content. The serial has moved, though, so compare
			// against a recomputation rather than the reference constant.
			assertZonemdMatchesSnapshot(t, zd, "cached digest")

			// And with the serial put back, against the uncached reference.
			zd.mu.Lock()
			zd.ensureWorkingSet()
			zd.setWorkingSetSOASerial(1)
			got, derr := zd.zonemdDigestsLocked(ZonemdSchemeSimple, []uint8{ZonemdAlgSHA384})
			zd.workingSet = nil
			zd.mu.Unlock()
			if derr != nil {
				t.Fatal(derr)
			}
			if got[ZonemdAlgSHA384] != reference {
				t.Errorf("budget %d produced a different digest\n  got:  %s\n  want: %s",
					budget, got[ZonemdAlgSHA384], reference)
			}
		})
	}
}

// Two algorithms share one rendering pass, so the second costs a hash and not
// a re-encode.
func TestWireCacheRendersOncePerPublishForTwoAlgorithms(t *testing.T) {
	zd := cacheTestZone(t, 100, 0)
	zd.mu.Lock()
	zd.zonemdAlgs = []uint8{ZonemdAlgSHA384, ZonemdAlgSHA512}
	zd.mu.Unlock()
	if _, err := zd.publishSync(); err != nil {
		t.Fatal(err)
	}
	assertZonemdMatchesSnapshot(t, zd, "two algorithms")

	st := cacheStats(zd)
	// WireBytes counts each owner's block ONCE even though it was hashed
	// twice; a per-algorithm pass would have counted it twice.
	if st.WireBytes > st.CachedBytes+4096 {
		t.Errorf("wire bytes (%d) far exceed cached bytes (%d); the blocks look"+
			" like they were built once per algorithm", st.WireBytes, st.CachedBytes)
	}
}

// Verification must NOT read the cache: a check that trusts cached bytes
// verifies the cache rather than the zone.
func TestVerificationDoesNotUseTheWireCache(t *testing.T) {
	zd := cacheTestZone(t, 60, 0)
	if cacheStats(zd).CachedOwners == 0 {
		t.Fatal("test setup: nothing was cached")
	}

	// Corrupt every cached block. A verification that read them would now
	// disagree with the published digest; one that rebuilds will not notice.
	zd.mu.Lock()
	for name, e := range zd.zonemdCache {
		poisoned := append([]byte(nil), e.block...)
		for i := range poisoned {
			poisoned[i] ^= 0xff
		}
		zd.zonemdCache[name] = zonemdCacheEntry{owner: e.owner, block: poisoned}
	}
	zd.mu.Unlock()

	r, err := zd.VerifyZonemdOfPublished(VerifyZonemdOpts{})
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}
	if r.Verdict != "valid" {
		t.Errorf("verification read the wire cache: it reported %q against a"+
			" poisoned cache, so it is verifying the cache and not the zone", r.Verdict)
	}
}

// mkRRset is a small helper for staging a replacement RRset in tests.
func mkRRset(name string, rrtype uint16, rrs ...dns.RR) core.RRset {
	return core.RRset{Name: name, Class: dns.ClassINET, RRtype: rrtype, RRs: rrs}
}

func BenchmarkZonemdDigestCached(b *testing.B)   { benchmarkZonemdDigest(b, 0) }
func BenchmarkZonemdDigestUncached(b *testing.B) { benchmarkZonemdDigest(b, -1) }

// benchmarkZonemdDigest measures the per-publish digest of a zone in which one
// name changed -- the shape of an ordinary update, and the case the cache
// exists for.
func benchmarkZonemdDigest(b *testing.B, budget int) {
	t := &testing.T{}
	zd := cacheTestZone(t, 5000, budget)
	if t.Failed() {
		b.Fatal("zone setup failed")
	}
	b.Cleanup(zd.stopPublisher)

	rr, err := dns.NewRR("n0007.cache.example. 3600 IN A 10.0.0.99")
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		zd.mu.Lock()
		zd.ensureWorkingSet()
		zd.stageRRsetLocked("n0007.cache.example.",
			mkRRset("n0007.cache.example.", dns.TypeA, rr))
		if _, err := zd.zonemdDigestsLocked(ZonemdSchemeSimple, []uint8{ZonemdAlgSHA384}); err != nil {
			zd.mu.Unlock()
			b.Fatal(err)
		}
		zd.workingSet = nil
		zd.mu.Unlock()
	}
}
