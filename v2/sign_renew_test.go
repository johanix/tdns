package tdns

import (
	"testing"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// renewalTestZone is a signed zone with a REAL signature validity. The other
// signing fixtures leave DnssecPolicy.SigValidity zero, which sigLifetime turns
// into a five-minute lifetime -- and a zone whose every signature expires in
// five minutes is due for renewal the moment it is signed, which is precisely
// what these tests must be able to tell apart from a healthy one.
//
// It carries a delegation and glue beneath it so the skip rules have something
// to skip.
func renewalTestZone(t *testing.T, kdb *KeyDB) *ZoneData {
	t.Helper()
	const zone = `renew.example.	3600	IN	SOA	ns.renew.example. hostmaster.renew.example. 1 7200 1800 604800 7200
renew.example.	3600	IN	NS	ns.renew.example.
ns.renew.example.	3600	IN	A	127.0.0.1
alpha.renew.example.	3600	IN	A	10.0.0.1
bravo.renew.example.	3600	IN	A	10.0.0.2
child.renew.example.	3600	IN	NS	ns1.child.renew.example.
ns1.child.renew.example.	3600	IN	A	10.0.0.53
`
	zd := testZone(t, "renew.example.", zone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptInlineSigning: true, OptAllowUpdates: true, OptAllowApiUpdates: true}
	zd.DnssecPolicy = &DnssecPolicy{
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		SigValidity:  PolicySigValidity{Default: 14 * 24 * 3600, DNSKEY: 14 * 24 * 3600, DS: 14 * 24 * 3600},
	}
	zd.InstallInitialSnapshot()
	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("initial SignZone: %v", err)
	}
	return zd
}

// ageSignatures pushes every signature on one RRset to the brink of expiry, in
// the published snapshot, so the next renewal pass finds it due.
func ageSignatures(t *testing.T, zd *ZoneData, name string, rrtype uint16) {
	t.Helper()
	od := getOwnerFrom(zd.publishedSnapshot(), name)
	if od == nil {
		t.Fatalf("aging %s %s: no such owner", name, dns.TypeToString[rrtype])
	}
	var sigs []dns.RR
	if rrtype == dns.TypeNSEC {
		sigs = od.NSEC.RRSIGs
	} else {
		sigs = od.RRtypes.GetOnlyRRSet(rrtype).RRSIGs
	}
	if len(sigs) == 0 {
		t.Fatalf("aging %s %s: it carries no signature", name, dns.TypeToString[rrtype])
	}
	for _, sig := range sigs {
		sig.(*dns.RRSIG).Expiration = uint32(time.Now().Add(30 * time.Second).Unix())
	}
}

// sigStrings returns an RRset's signatures as text, for byte-for-byte
// comparison across a renewal.
func sigStrings(od *OwnerData, rrtype uint16) []string {
	if od == nil {
		return nil
	}
	var sigs []dns.RR
	if rrtype == dns.TypeNSEC {
		sigs = od.NSEC.RRSIGs
	} else {
		sigs = od.RRtypes.GetOnlyRRSet(rrtype).RRSIGs
	}
	out := make([]string, 0, len(sigs))
	for _, s := range sigs {
		out = append(out, s.String())
	}
	return out
}

func sigsOf(zd *ZoneData, name string, rrtype uint16) []string {
	return sigStrings(getOwnerFrom(zd.publishedSnapshot(), name), rrtype)
}

// chainShape records what the NSEC chain asserts: which name each NSEC points
// at, and which types it claims exist there. A signature renewal may rewrite
// NSEC records -- it does -- but it must never change what they say.
func chainShape(t *testing.T, zd *ZoneData) map[string]string {
	t.Helper()
	out := map[string]string{}
	snap := zd.publishedSnapshot()
	for name := range snap.Data {
		od := getOwnerFrom(snap, name)
		if od == nil || len(od.NSEC.RRs) == 0 {
			continue
		}
		nsec, ok := od.NSEC.RRs[0].(*dns.NSEC)
		if !ok {
			t.Fatalf("%s: NSEC property holds a %T", name, od.NSEC.RRs[0])
		}
		types := ""
		for _, tp := range nsec.TypeBitMap {
			types += dns.TypeToString[tp] + " "
		}
		out[name] = nsec.NextDomain + " [" + types + "]"
	}
	return out
}

// The reported symptom, as a test: once a minute, on a zone nobody had touched,
// the periodic pass bumped the serial, re-signed, swapped the snapshot and
// notified every downstream. A pass that renews nothing must leave no trace at
// all -- and since a NOTIFY is emitted by the publish, proving that no publish
// happened proves that no NOTIFY did.
func TestRenewingAnUnchangedZonePublishesNothing(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := renewalTestZone(t, kdb)

	before := zd.publishedSnapshot()
	serial := zd.CurrentSerial

	for pass := 1; pass <= 3; pass++ {
		renewed, err := zd.RenewZoneSignatures(kdb)
		if err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		if renewed != 0 {
			t.Errorf("pass %d: renewed %d RRsets on a zone whose signatures are 14 days old", pass, renewed)
		}
	}

	if after := zd.publishedSnapshot(); after != before {
		t.Errorf("the snapshot was swapped: a renewal that signed nothing published anyway,"+
			" which is what notifies every downstream (serial %d -> %d)", serial, zd.CurrentSerial)
	}
	if zd.CurrentSerial != serial {
		t.Errorf("serial moved from %d to %d with no change to the zone", serial, zd.CurrentSerial)
	}
	zd.mu.Lock()
	staged := zd.workingSet != nil
	zd.mu.Unlock()
	if staged {
		t.Error("a working set was left behind; the next publish would carry it, and a" +
			" leftover working set is what turns a no-op into a serial bump")
	}
}

// The pass exists to renew ageing signatures, so it must actually do that --
// for the RRset that is due and for no other.
func TestRenewingSignsOnlyTheAgeingRRset(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := renewalTestZone(t, kdb)

	alphaBefore := sigsOf(zd, "alpha.renew.example.", dns.TypeA)
	bravoBefore := sigsOf(zd, "bravo.renew.example.", dns.TypeA)
	nsBefore := sigsOf(zd, "ns.renew.example.", dns.TypeA)
	serial := zd.CurrentSerial

	ageSignatures(t, zd, "alpha.renew.example.", dns.TypeA)

	renewed, err := zd.RenewZoneSignatures(kdb)
	if err != nil {
		t.Fatal(err)
	}
	if renewed != 1 {
		t.Fatalf("renewed %d RRsets, want exactly the one that was ageing", renewed)
	}

	if got := sigsOf(zd, "alpha.renew.example.", dns.TypeA); len(got) == 0 || got[0] == alphaBefore[0] {
		t.Errorf("the ageing RRset was not re-signed: %v", got)
	}
	for _, tc := range []struct {
		name string
		was  []string
	}{
		{"bravo.renew.example.", bravoBefore},
		{"ns.renew.example.", nsBefore},
	} {
		got := sigsOf(zd, tc.name, dns.TypeA)
		if len(got) != len(tc.was) || (len(got) > 0 && got[0] != tc.was[0]) {
			t.Errorf("%s was re-signed although its signature was not ageing:\n was %v\n now %v",
				tc.name, tc.was, got)
		}
	}
	if zd.CurrentSerial != serial+1 {
		t.Errorf("serial %d -> %d, want a single bump", serial, zd.CurrentSerial)
	}
}

// R6, the landmine the design is built around. ensureWorkingSet is a shallow
// copy and SignRRset rewrites the RRset it is given in place, so a pass that
// signs an RRset taken straight from the snapshot writes new signatures into
// the version that is being served -- under a serial that was published, and
// transferred, with the old ones.
func TestRenewingDoesNotWriteThroughToThePublishedSnapshot(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := renewalTestZone(t, kdb)

	published := zd.publishedSnapshot()
	publishedSerial := published.Serial

	ageSignatures(t, zd, "alpha.renew.example.", dns.TypeA)

	// Captured AFTER aging, which rewrites the expiration in place: these are
	// the exact bytes a downstream holding this serial would have.
	publishedAlpha := sigStrings(getOwnerFrom(published, "alpha.renew.example."), dns.TypeA)

	if _, err := zd.RenewZoneSignatures(kdb); err != nil {
		t.Fatal(err)
	}

	got := sigStrings(getOwnerFrom(published, "alpha.renew.example."), dns.TypeA)
	if len(got) != len(publishedAlpha) || (len(got) > 0 && got[0] != publishedAlpha[0]) {
		t.Errorf("serial %d changed under a reader after it was published:\n was %v\n now %v\n"+
			"the RRset must be cloned before SignRRset -- cloneOwner is not enough,"+
			" its RRtypes entries still share slices with the snapshot",
			publishedSerial, publishedAlpha, got)
	}
}

// Renewal renews; it does not repair. An RRset with no signature means a build
// path failed, and healing it here would hide that.
func TestRenewingDoesNotRepairAMissingSignature(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := renewalTestZone(t, kdb)

	before := zd.publishedSnapshot()
	od := getOwnerFrom(before, "alpha.renew.example.")
	rs := od.RRtypes.GetOnlyRRSet(dns.TypeA)
	rs.RRSIGs = nil
	od.RRtypes.Set(dns.TypeA, rs)

	renewed, err := zd.RenewZoneSignatures(kdb)
	if err != nil {
		t.Fatal(err)
	}
	if renewed != 0 {
		t.Errorf("renewed %d RRsets; an unsigned RRset is SignZone's to repair, not this pass's", renewed)
	}
	if zd.publishedSnapshot() != before {
		t.Error("the zone was republished to repair a missing signature")
	}
	if sigs := sigsOf(zd, "alpha.renew.example.", dns.TypeA); len(sigs) != 0 {
		t.Errorf("the missing signature was silently restored: %v", sigs)
	}
}

// A delegation's NS and the glue beneath it are not ours to sign. Nothing signs
// them today, so they carry no signature and the walk skips them for that reason
// alone -- these fixtures give them one, so the skip is tested where it is
// actually written rather than by accident.
func TestRenewingSkipsDelegationsAndGlue(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := renewalTestZone(t, kdb)

	before := zd.publishedSnapshot()
	donor := getOwnerFrom(before, "alpha.renew.example.").RRtypes.GetOnlyRRSet(dns.TypeA)
	if len(donor.RRSIGs) == 0 {
		t.Fatal("fixture: alpha is unsigned")
	}

	for _, tc := range []struct {
		name   string
		rrtype uint16
	}{
		{"child.renew.example.", dns.TypeNS},
		{"ns1.child.renew.example.", dns.TypeA},
	} {
		od := getOwnerFrom(before, tc.name)
		if od == nil {
			t.Fatalf("fixture: %s is missing", tc.name)
		}
		rs := od.RRtypes.GetOnlyRRSet(tc.rrtype)
		sig := dns.Copy(donor.RRSIGs[0]).(*dns.RRSIG)
		sig.Hdr.Name = tc.name
		sig.TypeCovered = tc.rrtype
		sig.Expiration = uint32(time.Now().Add(30 * time.Second).Unix())
		rs.RRSIGs = []dns.RR{sig}
		od.RRtypes.Set(tc.rrtype, rs)
	}

	renewed, err := zd.RenewZoneSignatures(kdb)
	if err != nil {
		t.Fatal(err)
	}
	if renewed != 0 {
		t.Errorf("renewed %d RRsets; a delegation's NS and its glue are the child's,"+
			" and signing them would put records on the wire that no validator asked for", renewed)
	}
	if zd.publishedSnapshot() != before {
		t.Error("the zone was republished over a delegation")
	}
}

// The NSEC property is not an RRtypes entry, so a walk of RRtypes alone misses
// it and its signatures age out unrenewed -- while the chain is what denial is
// proven from.
func TestRenewingRenewsAnAgeingNsecSignature(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := renewalTestZone(t, kdb)

	before := sigsOf(zd, "bravo.renew.example.", dns.TypeNSEC)
	if len(before) == 0 {
		t.Fatal("fixture: bravo has no signed NSEC")
	}
	shape := chainShape(t, zd)

	ageSignatures(t, zd, "bravo.renew.example.", dns.TypeNSEC)

	renewed, err := zd.RenewZoneSignatures(kdb)
	if err != nil {
		t.Fatal(err)
	}
	if renewed != 1 {
		t.Fatalf("renewed %d RRsets, want the one ageing NSEC", renewed)
	}
	if got := sigsOf(zd, "bravo.renew.example.", dns.TypeNSEC); len(got) == 0 || got[0] == before[0] {
		t.Errorf("the ageing NSEC signature was not renewed: %v", got)
	}
	assertChainInvariant(t, zd, "after renewing an NSEC signature")
	if got := chainShape(t, zd); len(got) != len(shape) {
		t.Errorf("the chain gained or lost names: %d -> %d", len(shape), len(got))
	} else {
		for name, was := range shape {
			if got[name] != was {
				t.Errorf("%s: the chain changed what it asserts\n was %s\n now %s", name, was, got[name])
			}
		}
	}
}

// A renewal publish still runs restitchNsecLocked, and it is NOT a no-op:
// changedChainNames compares RRSIG bytes, so a fresh signature marks its owner
// changed and the chain is rewritten and re-signed for that name and its
// predecessor. What must not change is what the chain says.
func TestRenewingDoesNotChangeTheShapeOfTheChain(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := renewalTestZone(t, kdb)

	shape := chainShape(t, zd)
	ageSignatures(t, zd, "alpha.renew.example.", dns.TypeA)

	if _, err := zd.RenewZoneSignatures(kdb); err != nil {
		t.Fatal(err)
	}

	assertChainInvariant(t, zd, "after a signature renewal")
	got := chainShape(t, zd)
	if len(got) != len(shape) {
		t.Fatalf("the chain covers %d names, was %d", len(got), len(shape))
	}
	for name, was := range shape {
		if got[name] != was {
			t.Errorf("%s: the chain changed what it asserts\n was %s\n now %s", name, was, got[name])
		}
	}
}

// Staged-but-unpublished changes belong to another writer. Renewing from the
// snapshot and staging the result on top of them would silently revert what they
// staged.
func TestRenewingDefersWhileAPublishIsPending(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := renewalTestZone(t, kdb)

	ageSignatures(t, zd, "alpha.renew.example.", dns.TypeA)

	rr, err := dns.NewRR("bravo.renew.example. 3600 IN A 10.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.stageRRsetLocked("bravo.renew.example.",
		core.RRset{Name: "bravo.renew.example.", RRtype: dns.TypeA, RRs: []dns.RR{rr}})
	zd.mu.Unlock()

	renewed, err := zd.RenewZoneSignatures(kdb)
	if err != nil {
		t.Fatal(err)
	}
	if renewed != 0 {
		t.Errorf("renewed %d RRsets while a publish was pending", renewed)
	}

	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.workingSet == nil {
		t.Fatal("the pending working set was discarded")
	}
	staged := zd.stagedOwner("bravo.renew.example.")
	if staged == nil {
		t.Fatal("the staged owner is gone")
	}
	if got := staged.RRtypes.GetOnlyRRSet(dns.TypeA); len(got.RRs) != 1 || got.RRs[0].String() != rr.String() {
		t.Errorf("the pending change was overwritten by a renewal of the published version: %v", got.RRs)
	}
}
