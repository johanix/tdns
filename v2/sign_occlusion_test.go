/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Occluded names: what is below a delegation is the child zone's data, and
 * RFC 4035 §2.2 leaves it out of this zone's authoritative data. The signer
 * used to recognise that only for the glue address types, so every other type
 * below a cut was signed (#546).
 */
package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// One delegation with everything that can sit under it: real glue, a non-glue
// name (the one that was signed), a name deeper still, and -- outside the cut
// -- a sibling whose spelling a string-suffix test would swallow.
const occlusionZone = `occl.example.	3600	IN	SOA	ns.occl.example. hostmaster.occl.example. 1 7200 1800 604800 7200
occl.example.	3600	IN	NS	ns.occl.example.
ns.occl.example.	3600	IN	A	127.0.0.1
alpha.occl.example.	3600	IN	A	10.0.0.1
child.occl.example.	3600	IN	NS	ns1.child.occl.example.
child.occl.example.	3600	IN	DS	12345 15 2 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
ns1.child.occl.example.	3600	IN	A	10.0.0.2
occluded.child.occl.example.	3600	IN	TXT	"the child's data; not ours to sign"
deep.occluded.child.occl.example.	3600	IN	MX	10 mx.example.
notchild.occl.example.	3600	IN	TXT	"authoritative, despite the spelling"
`

func occlusionTestZone(t *testing.T, kdb *KeyDB) *ZoneData {
	t.Helper()
	zd := testZone(t, "occl.example.", occlusionZone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptInlineSigning: true, OptAllowUpdates: true}
	zd.DnssecPolicy = &DnssecPolicy{
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		// Real lifetimes: these zones sign twice, and the sig-validity floor
		// check sets a DnssecError on the first pass that the second refuses on.
		SigValidity: PolicySigValidity{
			Default: 30 * 86400, DNSKEY: 30 * 86400, DS: 30 * 86400,
		},
	}
	zd.InstallInitialSnapshot()
	return zd
}

// rrsigsAt returns, per RRtype, how many RRSIGs the PUBLISHED zone carries at
// one owner, plus the count on its NSEC property.
func rrsigsAt(t *testing.T, zd *ZoneData, name string) (perType map[uint16]int, nsecSigs int, present bool) {
	t.Helper()
	snap := zd.publishedSnapshot()
	if snap == nil {
		t.Fatal("nothing published")
	}
	od := getOwnerFrom(snap, name)
	if od == nil {
		return nil, 0, false
	}
	perType = map[uint16]int{}
	for _, rrt := range od.RRtypes.Keys() {
		perType[rrt] = len(od.RRtypes.GetOnlyRRSet(rrt).RRSIGs)
	}
	return perType, len(od.NSEC.RRSIGs), true
}

// assertOccluded: the name is in the zone data (a transfer carries it) but the
// signer left no signature anywhere on it, and it is not on the NSEC chain.
func assertOccluded(t *testing.T, zd *ZoneData, pass, name string) {
	t.Helper()
	perType, nsecSigs, present := rrsigsAt(t, zd, name)
	if !present {
		t.Fatalf("%s: %q is missing from the published zone; occluded data is still"+
			" transferred, it is only not signed", pass, name)
	}
	for rrt, n := range perType {
		if n != 0 {
			t.Errorf("%s: %q has %d RRSIG(s) over its %s RRset; it is below a delegation"+
				" and is not this zone's authoritative data (RFC 4035 §2.2)",
				pass, name, n, dns.TypeToString[rrt])
		}
	}
	if nsecSigs != 0 {
		t.Errorf("%s: %q has a signed NSEC; an occluded name is not on the chain", pass, name)
	}
}

// assertSigned: an authoritative name, signed as usual.
func assertSigned(t *testing.T, zd *ZoneData, pass, name string, rrtype uint16) {
	t.Helper()
	perType, _, present := rrsigsAt(t, zd, name)
	if !present {
		t.Fatalf("%s: %q is missing from the published zone", pass, name)
	}
	if perType[rrtype] == 0 {
		t.Errorf("%s: %q %s is unsigned; it is authoritative data of this zone",
			pass, name, dns.TypeToString[rrtype])
	}
}

func assertOcclusionInvariants(t *testing.T, zd *ZoneData, pass string) {
	t.Helper()

	// Below the cut: glue, the non-glue name that #546 is about, and one deeper.
	assertOccluded(t, zd, pass, "ns1.child.occl.example.")
	assertOccluded(t, zd, pass, "occluded.child.occl.example.")
	assertOccluded(t, zd, pass, "deep.occluded.child.occl.example.")

	// The delegation point itself is NOT occluded: its DS and its NSEC are this
	// zone's, and only the NS RRset is not.
	perType, nsecSigs, present := rrsigsAt(t, zd, "child.occl.example.")
	if !present {
		t.Fatalf("%s: the delegation point is missing from the published zone", pass)
	}
	if perType[dns.TypeNS] != 0 {
		t.Errorf("%s: the delegation NS RRset is signed", pass)
	}
	if perType[dns.TypeDS] == 0 {
		t.Errorf("%s: the DS at the delegation point is unsigned; it is the parent's"+
			" own record and the whole chain of trust rests on it", pass)
	}
	if nsecSigs == 0 {
		t.Errorf("%s: the delegation point has no signed NSEC; a validator needs it"+
			" to prove the delegation is unsigned or to authenticate the DS", pass)
	}

	// Outside the cut, including the name a string-suffix test would swallow.
	assertSigned(t, zd, pass, "occl.example.", dns.TypeSOA)
	assertSigned(t, zd, pass, "alpha.occl.example.", dns.TypeA)
	assertSigned(t, zd, pass, "ns.occl.example.", dns.TypeA)
	assertSigned(t, zd, pass, "notchild.occl.example.", dns.TypeTXT)
}

// SignZone is the shared pass: an online-signing primary and an inline-signing
// secondary both reach it, which is why #546 showed up on both.
func TestSignZoneLeavesOccludedNamesUnsigned(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := occlusionTestZone(t, kdb)

	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	assertOcclusionInvariants(t, zd, "SignZone")
}

// ResignZone carries the same rule: it re-signs from scratch after a key-state
// change, and had the same glue-only test.
func TestResignZoneLeavesOccludedNamesUnsigned(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := occlusionTestZone(t, kdb)

	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	if _, err := zd.ResignZone(kdb); err != nil {
		t.Fatalf("ResignZone: %v", err)
	}
	assertOcclusionInvariants(t, zd, "ResignZone")
}

// occludedNames is what the signer and the NSEC chain now share, so a name is
// either the child's for both or ours for both.
func TestOccludedNames(t *testing.T) {
	names := []string{
		"occl.example.",
		"child.occl.example.",
		"ns1.child.occl.example.",
		"deep.occluded.child.occl.example.",
		"notchild.occl.example.",
		"CHILD.occl.example.",
		"NS2.CHILD.occl.example.",
	}
	delegations := []string{"child.occl.example."}
	occluded := occludedNames(names, delegations)

	for _, want := range []string{
		"ns1.child.occl.example.",
		"deep.occluded.child.occl.example.",
		"NS2.CHILD.occl.example.",
	} {
		if !occluded[want] {
			t.Errorf("%q is not occluded by the child.occl.example. delegation", want)
		}
	}
	for _, want := range []string{
		"occl.example.",
		"child.occl.example.",
		"notchild.occl.example.",
		"CHILD.occl.example.",
	} {
		if occluded[want] {
			t.Errorf("%q is occluded; the delegation point itself and its siblings are not", want)
		}
	}

	if occludedNames(names, nil) != nil {
		t.Error("a zone with no delegation should allocate no map")
	}
}

// seedOccludedRRSIG attaches an RRSIG to an occluded name's RRset, the way an
// older build that signed below the cut would have left it, and republishes.
func seedOccludedRRSIG(t *testing.T, zd *ZoneData, name string, rrtype uint16) {
	t.Helper()
	od, ok := zd.Data.Get(name)
	if !ok {
		t.Fatalf("%q missing from zd.Data", name)
	}
	rrset := od.RRtypes.GetOnlyRRSet(rrtype)
	if len(rrset.RRs) == 0 {
		t.Fatalf("%q has no %s RRset to seed", name, dns.TypeToString[rrtype])
	}
	rrset.RRtype = rrtype
	rrset.RRSIGs = []dns.RR{&dns.RRSIG{
		Hdr:         dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: rrtype,
		KeyTag:      4242,
		SignerName:  zd.ZoneName,
	}}
	od.RRtypes.Set(rrtype, rrset)
	zd.InstallInitialSnapshot()
}

// A signing pass must HEAL a zone an older build signed below the cut, not just
// stop adding to it. Merely skipping the owner leaves those signatures on the
// wire until the zone is next loaded from source -- and AXFR is where #546 was
// visible in the first place. ResignZone in particular used to nil-and-resign
// these RRsets, so a bare skip would swap refreshed signatures for frozen ones.
func TestSigningStripsRRSIGsAlreadyOnOccludedNames(t *testing.T) {
	for _, tc := range []struct {
		pass string
		run  func(zd *ZoneData, kdb *KeyDB) error
	}{
		{"SignZone", func(zd *ZoneData, kdb *KeyDB) error { _, err := zd.SignZone(kdb, true); return err }},
		{"ResignZone", func(zd *ZoneData, kdb *KeyDB) error { _, err := zd.ResignZone(kdb); return err }},
	} {
		t.Run(tc.pass, func(t *testing.T) {
			kdb := newTestKeyDB(t)
			zd := occlusionTestZone(t, kdb)
			seedOccludedRRSIG(t, zd, "occluded.child.occl.example.", dns.TypeTXT)
			seedOccludedRRSIG(t, zd, "ns1.child.occl.example.", dns.TypeA)

			// Both cases need one pass to have happened: ResignZone re-signs an
			// already-signed zone, and its own guard refuses an unsigned one.
			if _, err := zd.SignZone(kdb, true); err != nil {
				t.Fatalf("SignZone: %v", err)
			}
			if err := tc.run(zd, kdb); err != nil {
				t.Fatalf("%s: %v", tc.pass, err)
			}

			assertOcclusionInvariants(t, zd, tc.pass+" over pre-signed occluded data")
		})
	}
}
