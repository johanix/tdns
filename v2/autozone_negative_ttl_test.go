/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// An identity zone is an auto zone: important, rarely asked, and looked up by
// peers while it is being published. A denial from it says "not yet" far more
// often than "never", so a resolver must not hold one for long. With an SOA
// minimum of an hour, a peer that asked a moment before a record arrived went
// on being told the record did not exist for the hour (#653), while the record
// itself, once there, was cached for two minutes.
//
// The time a resolver holds a denial is the smaller of the SOA's TTL and its
// minimum (RFC 2308 section 5), which is also the TTL of the NSEC records that
// prove it (RFC 9077).
func TestAnAutoZoneKeepsItsDenialsShort(t *testing.T) {
	const zone = "identity.autozone.example."
	kdb := newTestKeyDB(t)
	zd, err := kdb.CreateAutoZone(zone, nil, []string{"ns.autozone.example."})
	if err != nil {
		t.Fatalf("CreateAutoZone: %v", err)
	}
	t.Cleanup(func() {
		zd.stopPublisher()
		Zones.Remove(zone)
	})

	soa, err := zd.GetSOA()
	if err != nil {
		t.Fatalf("GetSOA: %v", err)
	}
	negative := min(soa.Hdr.Ttl, soa.Minttl)
	if negative != autoZoneNegativeTTL {
		t.Errorf("a denial from the auto zone is held for %d s (SOA TTL %d, minimum %d), want %d",
			negative, soa.Hdr.Ttl, soa.Minttl, autoZoneNegativeTTL)
	}
	if autoZoneNegativeTTL > 60 {
		t.Errorf("autoZoneNegativeTTL is %d s; an identity zone's denials are held for a minute at most", autoZoneNegativeTTL)
	}

	// The records themselves keep the zone's TTL: only denials are short.
	if soa.Hdr.Ttl != 3600 {
		t.Errorf("SOA TTL is %d, want the zone's 3600", soa.Hdr.Ttl)
	}
	ns, err := zd.GetRRset(zone, dns.TypeNS)
	if err != nil || ns == nil || len(ns.RRs) == 0 {
		t.Fatalf("GetRRset NS: %v, %v", ns, err)
	}
	if got := ns.RRs[0].Header().Ttl; got != 3600 {
		t.Errorf("NS TTL is %d, want the zone's 3600", got)
	}

	// The NSEC chain takes its TTL from the same place.
	zd.mu.Lock()
	zd.ensureWorkingSet()
	nsecTTL := zd.nsecTTLLocked()
	zd.dropBareWorkingSetLocked()
	zd.mu.Unlock()
	if nsecTTL != autoZoneNegativeTTL {
		t.Errorf("NSEC TTL is %d, want %d", nsecTTL, autoZoneNegativeTTL)
	}
}
