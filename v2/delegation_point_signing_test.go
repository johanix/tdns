/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * A delegation point carries exactly one signature of the parent's: the DS.
 * The NS RRset there is the child's own and the addresses are glue, both
 * signed in the child by the child's keys. And a child's KEY is not zone
 * content at all -- signed or unsigned.
 */
package tdns

import (
	"context"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// glueAtTheCutZone: in-bailiwick glue AT the delegation point, which is what
// `child. NS child.` requires and what makes the address there glue rather than
// ordinary data.
const glueAtTheCutZone = `cut.example.	3600	IN	SOA	ns.cut.example. hostmaster.cut.example. 1 7200 1800 604800 7200
cut.example.	3600	IN	NS	ns.cut.example.
ns.cut.example.	3600	IN	A	127.0.0.1
alpha.cut.example.	3600	IN	A	10.0.0.1
child.cut.example.	3600	IN	NS	child.cut.example.
child.cut.example.	3600	IN	A	10.0.0.2
child.cut.example.	3600	IN	AAAA	2001:db8::2
child.cut.example.	3600	IN	TXT	"the child's apex, not ours"
child.cut.example.	3600	IN	DS	12345 15 2 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
`

func cutTestZone(t *testing.T, kdb *KeyDB) *ZoneData {
	t.Helper()
	zd := testZone(t, "cut.example.", glueAtTheCutZone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptInlineSigning: true, OptAllowUpdates: true, OptAllowApiUpdates: true}
	zd.DnssecPolicy = &DnssecPolicy{
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		SigValidity: PolicySigValidity{
			Default: 30 * 86400, DNSKEY: 30 * 86400, DS: 30 * 86400,
		},
	}
	zd.UpdatePolicy = policyAllowing(dns.TypeA, dns.TypeAAAA, dns.TypeTXT, dns.TypeNS, dns.TypeDS, dns.TypeKEY)
	zd.InstallInitialSnapshot()
	return zd
}

func assertCutInvariants(t *testing.T, zd *ZoneData, pass string) {
	t.Helper()
	perType, nsecSigs, present := rrsigsAt(t, zd, "child.cut.example.")
	if !present {
		t.Fatalf("%s: the delegation point is missing from the published zone", pass)
	}
	// C1: "only the DS" is stricter than naming NS and glue, and it is meant to
	// be. The name at a cut is the child's apex, so a TXT there is the child's
	// too -- unsigned, like the rest of it.
	for _, rrt := range []uint16{dns.TypeNS, dns.TypeA, dns.TypeAAAA, dns.TypeTXT} {
		if perType[rrt] != 0 {
			t.Errorf("%s: the %s at the delegation point has %d RRSIG(s); it is the child's,"+
				" signed in the child (RFC 4035 §2.2)", pass, dns.TypeToString[rrt], perType[rrt])
		}
	}
	if perType[dns.TypeDS] == 0 {
		t.Errorf("%s: the DS at the delegation point is unsigned; it exists only in the"+
			" parent and only the parent can sign it", pass)
	}
	if nsecSigs == 0 {
		t.Errorf("%s: the delegation point has no signed NSEC", pass)
	}
	// The zone's own data is untouched by the rule.
	if n := sigCount(t, zd, "alpha.cut.example.", dns.TypeA); n == 0 {
		t.Errorf("%s: an ordinary name is unsigned", pass)
	}
	if n := sigCount(t, zd, "cut.example.", dns.TypeNS); n == 0 {
		t.Errorf("%s: the apex NS RRset is unsigned", pass)
	}
}

func TestSignZoneSignsOnlyTheDSAtADelegationPoint(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := cutTestZone(t, kdb)
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	assertCutInvariants(t, zd, "SignZone")
}

func TestResignZoneSignsOnlyTheDSAtADelegationPoint(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := cutTestZone(t, kdb)
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	if _, err := zd.ResignZone(kdb); err != nil {
		t.Fatalf("ResignZone: %v", err)
	}
	assertCutInvariants(t, zd, "ResignZone")
}

// A zone an older build signed heals on its next pass rather than carrying
// those signatures until it is loaded from source again.
func TestSigningStripsGlueRRSIGsLeftAtADelegationPoint(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := cutTestZone(t, kdb)
	seedOccludedRRSIG(t, zd, "child.cut.example.", dns.TypeA)
	seedOccludedRRSIG(t, zd, "child.cut.example.", dns.TypeNS)

	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	assertCutInvariants(t, zd, "SignZone over pre-signed glue")
}

// The update path applies the same rule, including for the record that creates
// the cut: at the moment the NS is added the owner is not a delegation point
// yet, so the answer cannot depend on asking whether it is one.
func TestUpdateSignsOnlyTheDSAtADelegationPoint(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := cutTestZone(t, kdb)
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}

	// Glue first, THEN the NS that makes the name a cut: the awkward order.
	applyRR(t, zd, kdb, VerbAddRR, "new.cut.example. 3600 IN A 10.0.0.7")
	applyRR(t, zd, kdb, VerbAddRR, "new.cut.example. 3600 IN NS new.cut.example.")

	perType, _, present := rrsigsAt(t, zd, "new.cut.example.")
	if !present {
		t.Fatal("the new delegation point is missing from the published zone")
	}
	if perType[dns.TypeNS] != 0 {
		t.Errorf("the NS that created the cut was signed: %d RRSIG(s)", perType[dns.TypeNS])
	}
	if perType[dns.TypeA] != 0 {
		t.Errorf("an address written before the cut existed kept %d RRSIG(s) after it did",
			perType[dns.TypeA])
	}

	// And a DS added afterwards still gets one.
	applyRR(t, zd, kdb, VerbAddRR,
		"new.cut.example. 3600 IN DS 54321 15 2 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")
	if n := sigCount(t, zd, "new.cut.example.", dns.TypeDS); n == 0 {
		t.Error("the DS at the new delegation point is unsigned")
	}
}

// Removing the delegation makes the former glue ordinary address data again,
// and it must be signed.
func TestRemovingADelegationSignsItsFormerGlue(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := cutTestZone(t, kdb)
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}

	applyDelRRset(t, zd, kdb, "child.cut.example.", "NS")

	for _, rrt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		if n := sigCount(t, zd, "child.cut.example.", rrt); n == 0 {
			t.Errorf("the former glue %s is unsigned; with the cut gone it is this zone's"+
				" own data and a validator will SERVFAIL on it", dns.TypeToString[rrt])
		}
	}
}

// A child's KEY is truststore material and never becomes a record of the parent
// zone -- signed or unsigned. ZoneUpdater's CHILD-UPDATE case is the choke point
// every delegation backend passes through, and it already refuses key material.
// The ZONE-UPDATE path has no such guard, and two of ApplyZoneUpdateToZoneData's
// three callers never reach ZoneUpdater at all -- notably the delta replay,
// which re-applies persisted actions with the update-policy check deliberately
// skipped. So the applier itself has to refuse, and this pins that it does.
func TestZoneUpdateApplierRefusesAChildKeyAtADelegationPoint(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := cutTestZone(t, kdb)
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}

	keyRR := mustRR(t, "child.cut.example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE=")
	if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: zd.ZoneName, Actions: []dns.RR{dns.Copy(keyRR)},
	}, kdb); err != nil {
		t.Fatalf("ApplyZoneUpdateToZoneData: %v", err)
	}
	assertNoKeyInZone(t, zd, "child.cut.example.", "zone update")

	// The same applier, reached the way a restart reaches it: replaying a
	// persisted delta, which skips the update-policy re-check by design.
	if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: zd.ZoneName, Actions: []dns.RR{dns.Copy(keyRR)},
		InternalUpdate: true, Replay: true, Description: "replay of persisted deltas",
	}, kdb); err != nil {
		t.Fatalf("ApplyZoneUpdateToZoneData (replay): %v", err)
	}
	assertNoKeyInZone(t, zd, "child.cut.example.", "delta replay")

	// And the zone's own KEY, at a name that is not a cut, is ordinary content.
	applyRR(t, zd, kdb, VerbAddRR, "alpha.cut.example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE=")
	perType, _, present := rrsigsAt(t, zd, "alpha.cut.example.")
	if !present {
		t.Fatal("alpha is missing from the published zone")
	}
	if _, hasKey := perType[dns.TypeKEY]; !hasKey {
		t.Error("a KEY at an ordinary name was refused; only key material at a" +
			" delegation point is the child's")
	}
}

func assertNoKeyInZone(t *testing.T, zd *ZoneData, name, pass string) {
	t.Helper()
	perType, _, present := rrsigsAt(t, zd, name)
	if !present {
		return // the owner does not exist at all, which is fine
	}
	if _, hasKey := perType[dns.TypeKEY]; hasKey {
		t.Errorf("%s: a child's KEY became content of the parent zone at %s;"+
			" it belongs in the truststore, and being unsigned is not good enough", pass, name)
	}
}

// A1. The refusal in the applier can only see a cut that already exists, so an
// update writing the KEY BEFORE the NS that makes one walks past it. Removal is
// what closes that, and removal is also what cleans up a KEY that leaked in
// before any of this existed. "Published but unsigned" is not a resting state
// for a child's key material.
func TestAChildKeyAtACutIsRemovedHoweverItArrived(t *testing.T) {
	const keyStr = "KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE="

	t.Run("KEY added before the NS that makes the cut", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		zd := cutTestZone(t, kdb)
		if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
			t.Fatalf("SignZone: %v", err)
		}
		applyRR(t, zd, kdb, VerbAddRR, "fresh.cut.example. 3600 IN "+keyStr)
		applyRR(t, zd, kdb, VerbAddRR, "fresh.cut.example. 3600 IN NS ns1.fresh.cut.example.")
		assertNoKeyInZone(t, zd, "fresh.cut.example.", "KEY before NS")
	})

	t.Run("a signing pass removes one already in the zone", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		zd := cutTestZone(t, kdb)
		seedKeyAt(t, zd, "child.cut.example.", keyStr)

		if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
			t.Fatalf("SignZone: %v", err)
		}
		assertNoKeyInZone(t, zd, "child.cut.example.", "SignZone")
	})

	t.Run("a delete can take one back out", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		zd := cutTestZone(t, kdb)
		if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
			t.Fatalf("SignZone: %v", err)
		}
		// Seeded, so there is something for the delete to remove: refusing the
		// delete alongside the add is how a leak becomes permanent. No signing
		// pass afterwards -- that would remove it too, and mask the answer.
		seedKeyAt(t, zd, "child.cut.example.", keyStr)
		applyDelRRset(t, zd, kdb, "child.cut.example.", "KEY")
		assertNoKeyInZone(t, zd, "child.cut.example.", "delrrset")
	})
}

// seedKeyAt puts a KEY straight into the zone data, the way an older build --
// or a leak past the classifier -- would have left it.
func seedKeyAt(t *testing.T, zd *ZoneData, name, keyStr string) {
	t.Helper()
	od, ok := zd.Data.Get(name)
	if !ok {
		t.Fatalf("%q is missing from zd.Data", name)
	}
	od.RRtypes.Set(dns.TypeKEY, core.RRset{
		Name: name, RRtype: dns.TypeKEY, Class: dns.ClassINET,
		RRs: []dns.RR{mustRR(t, name+" 3600 IN "+keyStr)},
	})
	zd.InstallInitialSnapshot()
}
