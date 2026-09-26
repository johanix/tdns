/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * An add that lands in an existing RRset must leave the RRset with one TTL
 * (RFC 2181 §5.2). The applier used to give the new RR the update-policy TTL
 * and append it next to members that kept the TTL they were loaded with, so a
 * child's delta UPDATE left the delegation NS RRset with mixed TTLs (#767).
 */
package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// rrsetTTLs returns the TTLs of the published RRset at (owner, rrtype).
func rrsetTTLs(t *testing.T, zd *ZoneData, owner string, rrtype uint16) []uint32 {
	t.Helper()
	od := getOwnerFrom(zd.publishedSnapshot(), owner)
	if od == nil {
		t.Fatalf("owner %s is not in the published snapshot", owner)
	}
	rrset, ok := od.RRtypes.Get(rrtype)
	if !ok || len(rrset.RRs) == 0 {
		t.Fatalf("no %s RRset at %s", dns.TypeToString[rrtype], owner)
	}
	var ttls []uint32
	for _, rr := range rrset.RRs {
		ttls = append(ttls, rr.Header().Ttl)
	}
	return ttls
}

func assertRRsetTTL(t *testing.T, zd *ZoneData, owner string, rrtype uint16, want uint32, wantCount int) {
	t.Helper()
	ttls := rrsetTTLs(t, zd, owner, rrtype)
	if len(ttls) != wantCount {
		t.Errorf("%s %s: %d RRs, want %d", owner, dns.TypeToString[rrtype], len(ttls), wantCount)
	}
	for _, ttl := range ttls {
		if ttl != want {
			t.Errorf("%s %s: TTLs %v, want all %d", owner, dns.TypeToString[rrtype], ttls, want)
			return
		}
	}
}

// ddnsTTLZone: the occlusion fixture (delegation NS and DS at 3600) with an
// update-policy TTL that differs from the loaded one, as in the report.
func ddnsTTLZone(t *testing.T) (*ZoneData, *KeyDB) {
	t.Helper()
	kdb := newTestKeyDB(t)
	zd := updatableOcclusionZone(t, kdb)
	zd.UpdatePolicy.Zone.TTL = 120
	return zd, kdb
}

// A DDNS add to the delegation NS RRset re-TTLs the existing members to the
// policy TTL: the parent decides how long child data is cached.
func TestDDNSAddToDelegationNSUnifiesTTL(t *testing.T) {
	zd, kdb := ddnsTTLZone(t)
	applyRR(t, zd, kdb, VerbAddRR, "child.occl.example. 3600 IN NS ns2.child.occl.example.")
	assertRRsetTTL(t, zd, "child.occl.example.", dns.TypeNS, 120, 2)
}

// The DS RRset gets the same treatment, and is still signed afterwards.
func TestDDNSAddToDSUnifiesTTL(t *testing.T) {
	zd, kdb := ddnsTTLZone(t)
	applyRR(t, zd, kdb, VerbAddRR,
		"child.occl.example. 3600 IN DS 54321 15 2 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")
	assertRRsetTTL(t, zd, "child.occl.example.", dns.TypeDS, 120, 2)
	if n := sigCount(t, zd, "child.occl.example.", dns.TypeDS); n == 0 {
		t.Error("the re-TTLed DS RRset is unsigned")
	}
}

// dns.IsDuplicate ignores the TTL, so re-adding an RR that is already there is
// not a no-op when the TTL differs: it brings the RRset to the policy TTL.
func TestDDNSDuplicateAddNormalisesTTL(t *testing.T) {
	zd, kdb := ddnsTTLZone(t)
	applyRR(t, zd, kdb, VerbAddRR, "child.occl.example. 3600 IN NS ns1.child.occl.example.")
	assertRRsetTTL(t, zd, "child.occl.example.", dns.TypeNS, 120, 1)
}

// On the API channel the policy TTL does not apply; the caller's TTL is kept
// and the rest of the RRset follows it.
func TestPreAuthorizedAddUnifiesToCallerTTL(t *testing.T) {
	zd, kdb := ddnsTTLZone(t)
	actions, err := BuildZoneUpdateActions(zd.ZoneName, ZoneUpdateSpec{
		Verb: VerbAddRR, RRs: []string{"child.occl.example. 600 IN NS ns2.child.occl.example."},
	})
	if err != nil {
		t.Fatalf("building add: %v", err)
	}
	if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: zd.ZoneName, Actions: actions, PreAuthorized: true,
	}, kdb); err != nil {
		t.Fatalf("applying add: %v", err)
	}
	assertRRsetTTL(t, zd, "child.occl.example.", dns.TypeNS, 600, 2)
}

// The path the report actually hit: a child's delta UPDATE goes through the
// child applier, which gives added RRs the child-policy TTL.
func applyChildRR(t *testing.T, zd *ZoneData, kdb *KeyDB, rr string) {
	t.Helper()
	r, err := dns.NewRR(rr)
	if err != nil {
		t.Fatalf("NewRR %q: %v", rr, err)
	}
	if _, err := zd.ApplyChildUpdateToZoneData(UpdateRequest{
		Cmd: "CHILD-UPDATE", ZoneName: zd.ZoneName, Actions: []dns.RR{r},
	}, kdb); err != nil {
		t.Fatalf("ApplyChildUpdateToZoneData %q: %v", rr, err)
	}
}

func childTTLZone(t *testing.T) (*ZoneData, *KeyDB) {
	t.Helper()
	zd, kdb := ddnsTTLZone(t)
	zd.UpdatePolicy.Child = UpdatePolicyDetail{
		Type:    "selfsub",
		RRtypes: map[uint16]bool{dns.TypeNS: true, dns.TypeA: true, dns.TypeDS: true},
		TTL:     120,
	}
	return zd, kdb
}

func TestChildUpdateAddToDelegationNSUnifiesTTL(t *testing.T) {
	zd, kdb := childTTLZone(t)
	// Hold on to the RRs the pre-update snapshot serves.
	old, ok := getOwnerFrom(zd.publishedSnapshot(), "child.occl.example.").RRtypes.Get(dns.TypeNS)
	if !ok {
		t.Fatal("no delegation NS RRset before the update")
	}

	applyChildRR(t, zd, kdb, "child.occl.example. 3600 IN NS ns2.child.occl.example.")
	assertRRsetTTL(t, zd, "child.occl.example.", dns.TypeNS, 120, 2)

	// The re-TTL wrote into cloned RRs, not into the snapshot concurrent
	// readers may still hold.
	for _, rr := range old.RRs {
		if rr.Header().Ttl != 3600 {
			t.Errorf("the pre-update snapshot was mutated: %s", rr.String())
		}
	}
}

func TestChildUpdateAddToDSUnifiesTTL(t *testing.T) {
	zd, kdb := childTTLZone(t)
	applyChildRR(t, zd, kdb,
		"child.occl.example. 3600 IN DS 54321 15 2 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")
	assertRRsetTTL(t, zd, "child.occl.example.", dns.TypeDS, 120, 2)
	if n := sigCount(t, zd, "child.occl.example.", dns.TypeDS); n == 0 {
		t.Error("the re-TTLed DS RRset is unsigned")
	}
}
