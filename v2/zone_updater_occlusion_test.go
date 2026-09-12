/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The update path and the zone cut. #549 taught the bulk signing passes that
 * data below a delegation is not this zone's to sign; ApplyZoneUpdateToZoneData
 * had no such test at all, and could put the defect back one record at a time
 * (#550).
 */
package tdns

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// updatableOcclusionZone: the #549 fixture, signed, with updates enabled.
func updatableOcclusionZone(t *testing.T, kdb *KeyDB) *ZoneData {
	t.Helper()
	zd := occlusionTestZone(t, kdb)
	zd.Options[OptAllowApiUpdates] = true
	zd.UpdatePolicy = policyAllowing(dns.TypeA, dns.TypeTXT, dns.TypeNS, dns.TypeDS, dns.TypeMX)
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatalf("initial SignZone: %v", err)
	}
	return zd
}

func applyDelRRset(t *testing.T, zd *ZoneData, kdb *KeyDB, name, rrtype string) {
	t.Helper()
	actions, err := BuildZoneUpdateActions(zd.ZoneName, ZoneUpdateSpec{
		Verb: VerbDelRRset, Name: name, Rrtype: rrtype,
	})
	if err != nil {
		t.Fatalf("building delrrset %s %s: %v", name, rrtype, err)
	}
	if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: zd.ZoneName, Actions: actions,
	}, kdb); err != nil {
		t.Fatalf("applying delrrset %s %s: %v", name, rrtype, err)
	}
}

// sigCount is the number of RRSIGs the published zone carries at (name, type).
func sigCount(t *testing.T, zd *ZoneData, name string, rrtype uint16) int {
	t.Helper()
	perType, _, present := rrsigsAt(t, zd, name)
	if !present {
		t.Fatalf("%q is missing from the published zone", name)
	}
	return perType[rrtype]
}

// An update that writes below an existing cut must not sign what it wrote.
func TestUpdateDoesNotSignBelowADelegation(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := updatableOcclusionZone(t, kdb)

	applyRR(t, zd, kdb, VerbAddRR, `new.child.occl.example. 3600 IN TXT "written by an update"`)

	if n := sigCount(t, zd, "new.child.occl.example.", dns.TypeTXT); n != 0 {
		t.Errorf("an update signed a name below a delegation: %d RRSIG(s)", n)
	}
	// And the authoritative side of the same update path still signs.
	applyRR(t, zd, kdb, VerbAddRR, `fresh.occl.example. 3600 IN TXT "ordinary data"`)
	if n := sigCount(t, zd, "fresh.occl.example.", dns.TypeTXT); n == 0 {
		t.Error("an update left an ordinary authoritative name unsigned")
	}
}

// The NS RRset at a delegation point is the child's copy. A later signing pass
// will not remove a signature written here: SignZone skips a non-apex NS by
// type, so it neither writes that RRSIG nor takes it away -- which is why this
// one had to be stopped at the source.
func TestUpdateDoesNotSignADelegationNS(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := updatableOcclusionZone(t, kdb)

	applyRR(t, zd, kdb, VerbAddRR, "sub.occl.example. 3600 IN NS ns1.sub.occl.example.")
	if n := sigCount(t, zd, "sub.occl.example.", dns.TypeNS); n != 0 {
		t.Errorf("an update signed a delegation NS RRset: %d RRSIG(s)", n)
	}

	// A full pass does not clean up after it, which is the point.
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	if n := sigCount(t, zd, "sub.occl.example.", dns.TypeNS); n != 0 {
		t.Errorf("after a full signing pass the delegation NS still has %d RRSIG(s)", n)
	}

	// The apex NS is authoritative and stays signed.
	if n := sigCount(t, zd, "occl.example.", dns.TypeNS); n == 0 {
		t.Error("the apex NS RRset is unsigned")
	}
}

// A DS at a delegation point is the parent's own record, and the chain of trust
// rests on it. It is the reason the rule is per type and not per name.
func TestUpdateStillSignsADSAtADelegationPoint(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := updatableOcclusionZone(t, kdb)

	applyRR(t, zd, kdb, VerbAddRR,
		"child.occl.example. 3600 IN DS 54321 15 2 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")
	if n := sigCount(t, zd, "child.occl.example.", dns.TypeDS); n == 0 {
		t.Error("an update left the DS at a delegation point unsigned")
	}
}

// Creating a delegation occludes what is already underneath it. Those names are
// not in the update, so nothing else on this path looks at them.
func TestUpdateCreatingADelegationStripsWhatItOccludes(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := updatableOcclusionZone(t, kdb)

	// deep.sub is ordinary authoritative data to begin with.
	applyRR(t, zd, kdb, VerbAddRR, `deep.sub.occl.example. 3600 IN TXT "ours, for now"`)
	if n := sigCount(t, zd, "deep.sub.occl.example.", dns.TypeTXT); n == 0 {
		t.Fatal("the name was not signed before the delegation existed")
	}

	// Now delegate sub.occl.example., which puts deep.sub below the cut.
	applyRR(t, zd, kdb, VerbAddRR, "sub.occl.example. 3600 IN NS ns1.sub.occl.example.")

	if n := sigCount(t, zd, "deep.sub.occl.example.", dns.TypeTXT); n != 0 {
		t.Errorf("a name a new delegation occluded kept %d RRSIG(s)", n)
	}
}

// And the mirror, which is the direction that hurts: removing a delegation
// makes what it hid this zone's data again. Left unsigned inside a signed zone
// it is a SERVFAIL for every validator, not merely a protocol violation.
func TestUpdateRemovingADelegationSignsWhatItUncovers(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := updatableOcclusionZone(t, kdb)

	if n := sigCount(t, zd, "occluded.child.occl.example.", dns.TypeTXT); n != 0 {
		t.Fatal("the fixture starts with a signed occluded name")
	}

	applyDelRRset(t, zd, kdb, "child.occl.example.", "NS")

	if n := sigCount(t, zd, "occluded.child.occl.example.", dns.TypeTXT); n == 0 {
		t.Error("a name the removed delegation uncovered is unsigned; it is this" +
			" zone's authoritative data now and a validator will SERVFAIL on it")
	}
	if n := sigCount(t, zd, "ns1.child.occl.example.", dns.TypeA); n == 0 {
		t.Error("the former glue is unsigned; it is ordinary address data now")
	}
}

// Nested delegations: removing the outer cut does not surface what the inner
// one still covers.
func TestUpdateRemovingAnOuterDelegationLeavesTheInnerOneOccluding(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := updatableOcclusionZone(t, kdb)

	// An inner delegation, and a name below it.
	applyRR(t, zd, kdb, VerbAddRR, "inner.child.occl.example. 3600 IN NS ns1.inner.child.occl.example.")
	applyRR(t, zd, kdb, VerbAddRR, `deep.inner.child.occl.example. 3600 IN TXT "the inner child's"`)

	applyDelRRset(t, zd, kdb, "child.occl.example.", "NS")

	if n := sigCount(t, zd, "deep.inner.child.occl.example.", dns.TypeTXT); n != 0 {
		t.Errorf("removing the outer delegation signed %d RRset(s) still below the inner one", n)
	}
	// While a sibling the outer cut alone was hiding IS uncovered.
	if n := sigCount(t, zd, "occluded.child.occl.example.", dns.TypeTXT); n == 0 {
		t.Error("a name only the outer delegation hid was left unsigned")
	}
}
