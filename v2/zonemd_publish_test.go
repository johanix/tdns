package tdns

import (
	"fmt"
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const zonemdZone = `md.example.	3600	IN	SOA	ns.md.example. hostmaster.md.example. 1 7200 1800 604800 7200
md.example.	3600	IN	NS	ns.md.example.
ns.md.example.	3600	IN	A	127.0.0.1
alpha.md.example.	3600	IN	A	10.0.0.1
charlie.md.example.	3600	IN	A	10.0.0.3
`

// snapshotZonemd returns the apex ZONEMD RRset of the published snapshot.
func snapshotZonemd(t *testing.T, zd *ZoneData) core.RRset {
	t.Helper()
	snap := zd.publishedSnapshot()
	if snap == nil {
		t.Fatal("nothing published")
	}
	apex := getOwnerFrom(snap, zd.ZoneName)
	if apex == nil {
		t.Fatal("no apex in the published snapshot")
	}
	return apex.RRtypes.GetOnlyRRSet(dns.TypeZONEMD)
}

// assertZonemdMatchesSnapshot is the invariant the whole feature reduces to:
// for the serial being served, recomputing the digest over the published
// snapshot reproduces the apex ZONEMD RDATA, and ZONEMD.Serial is the SOA's.
//
// It recomputes from the snapshot rather than trusting the cached value, so a
// digest taken at the wrong moment in the publish -- before the NSEC restitch,
// before the SOA re-sign, before the serial bump -- fails here rather than at
// some validator downstream.
func assertZonemdMatchesSnapshot(t *testing.T, zd *ZoneData, context string) {
	t.Helper()

	snap := zd.publishedSnapshot()
	if snap == nil {
		t.Fatalf("%s: nothing published", context)
	}
	rs := snapshotZonemd(t, zd)
	if len(rs.RRs) == 0 {
		t.Fatalf("%s: the zone publishes no apex ZONEMD", context)
	}

	rrs := zoneRRsFromSnapshot(snap)
	for _, rr := range rs.RRs {
		z, ok := rr.(*dns.ZONEMD)
		if !ok {
			t.Fatalf("%s: the apex ZONEMD RRset holds a %T", context, rr)
		}
		if z.Serial != snap.Serial {
			t.Errorf("%s: ZONEMD serial %d does not match the published SOA serial %d",
				context, z.Serial, snap.Serial)
		}
		want, err := ZoneDigestHex(zd.ZoneName, rrs, z.Scheme, z.Hash)
		if err != nil {
			t.Fatalf("%s: recomputing the %s digest: %v", context, zonemdAlgName(z.Hash), err)
		}
		if !strings.EqualFold(want, z.Digest) {
			t.Errorf("%s: the published %s digest does not describe the published zone\n"+
				"  published: %s\n  recomputed: %s",
				context, zonemdAlgName(z.Hash), z.Digest, want)
		}
	}

	if zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning] {
		if len(rs.RRSIGs) == 0 {
			t.Errorf("%s: the apex ZONEMD is unsigned in a signed zone, which is BOGUS"+
				" to every validator that asks for it", context)
		}
	}
}

// zonemdTestZone builds an unsigned primary that publishes a ZONEMD.
func zonemdTestZone(t *testing.T, algs ...uint8) *ZoneData {
	t.Helper()
	zd := testZone(t, "md.example.", zonemdZone)
	registerZones(t, zd)
	zd.Options = map[ZoneOption]bool{OptPublishZonemd: true, OptAllowApiUpdates: true}
	zd.UpdatePolicy = policyAllowing(dns.TypeA, dns.TypeTXT, dns.TypeZONEMD)
	zd.mu.Lock()
	zd.zonemdAlgs = algs
	zd.mu.Unlock()
	// testZone installs a snapshot straight from zd.Data, which never passes
	// through the publish path. One publish is what a config change or a load
	// would have queued.
	if _, err := zd.publishSync(); err != nil {
		t.Fatalf("initial publish: %v", err)
	}
	return zd
}

// zonemdSigningTestZone builds an inline-signing primary that publishes a
// ZONEMD, signed and with an NSEC chain.
func zonemdSigningTestZone(t *testing.T, kdb *KeyDB) *ZoneData {
	t.Helper()
	zd := testZone(t, "md.example.", zonemdZone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{
		OptInlineSigning: true, OptPublishZonemd: true,
		OptAllowUpdates: true, OptAllowApiUpdates: true,
	}
	zd.DnssecPolicy = &DnssecPolicy{
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		// Real signature lifetimes, unlike the NSEC-chain fixtures. Those sign
		// once; these sign repeatedly, and the sig-validity floor check sets a
		// DnssecError on the first pass that the SECOND pass then refuses on.
		SigValidity: PolicySigValidity{
			Default: 30 * 86400, DNSKEY: 30 * 86400, DS: 30 * 86400,
		},
	}
	zd.UpdatePolicy = policyAllowing(dns.TypeA, dns.TypeTXT, dns.TypeZONEMD)
	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("initial SignZone: %v", err)
	}
	return zd
}

// The base case: an unsigned zone with the option on publishes a digest that
// describes it.
func TestZonemdPublishedOnAnUnsignedZone(t *testing.T) {
	zd := zonemdTestZone(t)
	assertZonemdMatchesSnapshot(t, zd, "initial publish")

	rs := snapshotZonemd(t, zd)
	if len(rs.RRs) != 1 {
		t.Fatalf("expected one ZONEMD RR by default, got %d", len(rs.RRs))
	}
	z := rs.RRs[0].(*dns.ZONEMD)
	if z.Scheme != ZonemdSchemeSimple || z.Hash != ZonemdAlgSHA384 {
		t.Errorf("default parameters are not SIMPLE/SHA-384: scheme %d alg %d", z.Scheme, z.Hash)
	}
	if len(rs.RRSIGs) != 0 {
		t.Error("an unsigned zone produced an RRSIG over its ZONEMD")
	}
}

// A zone that did not ask for one is left exactly as the operator wrote it.
func TestZonemdIsNotPublishedWithoutTheOption(t *testing.T) {
	zd := testZone(t, "md.example.", zonemdZone)
	registerZones(t, zd)
	zd.Options = map[ZoneOption]bool{}
	if _, err := zd.publishSync(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if rs := snapshotZonemd(t, zd); len(rs.RRs) != 0 {
		t.Fatalf("a zone without publish-zonemd grew a ZONEMD: %+v", rs.RRs)
	}
}

// An apex ZONEMD the operator wrote into the zone file of a zone that does NOT
// publish one is their record, not ours, and survives untouched.
func TestOperatorAuthoredZonemdIsLeftAlone(t *testing.T) {
	authored := zonemdZone +
		"md.example.	3600	IN	ZONEMD	1 1 1 " + strings.Repeat("ab", 48) + "\n"
	zd := testZone(t, "md.example.", authored)
	registerZones(t, zd)
	zd.Options = map[ZoneOption]bool{}
	if _, err := zd.publishSync(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	rs := snapshotZonemd(t, zd)
	if len(rs.RRs) != 1 {
		t.Fatalf("the operator's ZONEMD was removed: %+v", rs.RRs)
	}
	if got := rs.RRs[0].(*dns.ZONEMD).Digest; !strings.EqualFold(got, strings.Repeat("ab", 48)) {
		t.Errorf("the operator's ZONEMD digest was rewritten: %s", got)
	}
}

// Every publish invalidates the digest, so it has to be recomputed by every
// publish -- not by the first one and then left behind.
func TestZonemdSurvivesUpdates(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := zonemdSigningTestZone(t, kdb)
	assertZonemdMatchesSnapshot(t, zd, "initial")

	steps := []struct {
		verb string
		rr   string
		why  string
	}{
		{VerbAddRR, "bravo.md.example. 3600 IN A 10.0.0.2", "a name enters the zone and the chain"},
		{VerbAddRR, "alpha.md.example. 3600 IN TXT \"x\"", "an existing name's bitmap changes"},
		{VerbDelRR, "bravo.md.example. 3600 IN A 10.0.0.2", "a name leaves the zone and the chain"},
		{VerbAddRR, "zulu.md.example. 3600 IN A 10.0.0.9", "a name enters at the end, moving the wrap"},
	}
	for i, s := range steps {
		applyRR(t, zd, kdb, s.verb, s.rr)
		assertZonemdMatchesSnapshot(t, zd, fmt.Sprintf("step %d (%s)", i+1, s.why))
	}
}

// A bare publish moves the serial and re-signs the SOA. Both are digest input,
// so a ZONEMD left alone by a "nothing changed" publish is already wrong.
func TestZonemdIsRecomputedByAPublishThatChangesNothingElse(t *testing.T) {
	zd := zonemdTestZone(t)
	before := snapshotZonemd(t, zd).RRs[0].(*dns.ZONEMD).Digest

	if _, err := zd.publishSync(); err != nil {
		t.Fatalf("second publish: %v", err)
	}
	assertZonemdMatchesSnapshot(t, zd, "after a bare publish")

	after := snapshotZonemd(t, zd).RRs[0].(*dns.ZONEMD).Digest
	if strings.EqualFold(before, after) {
		t.Error("the digest did not change across a serial bump, so it cannot have" +
			" covered the SOA -- which RFC 8976 requires it to")
	}
}

// SignZone and ResignZone rewrite every RRSIG in the zone, and RRSIGs are
// digest input. Both end in a publish, which is what has to put the digest
// back in step.
func TestZonemdSurvivesSigningPasses(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := zonemdSigningTestZone(t, kdb)

	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	assertZonemdMatchesSnapshot(t, zd, "after SignZone")

	if _, err := zd.ResignZone(kdb); err != nil {
		t.Fatalf("ResignZone: %v", err)
	}
	assertZonemdMatchesSnapshot(t, zd, "after ResignZone")
}

// The end-to-end proof: write the zone out, read it back, and verify the
// ZONEMD in the file against a digest computed over the file's own contents.
// This is what an external verifier does, and it is the test that catches any
// divergence between the write path and the read path.
func TestZonemdInAWrittenZoneFileVerifies(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := zonemdSigningTestZone(t, kdb)

	text, err := writeZoneToTemp(t, zd)
	if err != nil {
		t.Fatalf("writing the zone: %v", err)
	}
	if !strings.Contains(text, "ZONEMD") {
		t.Fatalf("the written zone file carries no ZONEMD:\n%s", text)
	}

	reread := testZone(t, "md.example.", text)
	apex, ok := reread.Data.Get("md.example.")
	if !ok {
		t.Fatal("no apex after re-reading the written file")
	}
	rs := apex.RRtypes.GetOnlyRRSet(dns.TypeZONEMD)
	if len(rs.RRs) == 0 {
		t.Fatal("the re-read zone has no apex ZONEMD")
	}

	var rrs []dns.RR
	for tuple := range reread.Data.Iter() {
		od := tuple.Val
		rrs = append(rrs, ownerRRsForDigest(&od)...)
	}
	soa := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs[0].(*dns.SOA)

	for _, rr := range rs.RRs {
		z := rr.(*dns.ZONEMD)
		if z.Serial != soa.Serial {
			t.Errorf("the file's ZONEMD serial %d does not match its SOA serial %d",
				z.Serial, soa.Serial)
		}
		want, err := ZoneDigestHex("md.example.", rrs, z.Scheme, z.Hash)
		if err != nil {
			t.Fatalf("digesting the re-read zone: %v", err)
		}
		if !strings.EqualFold(want, z.Digest) {
			t.Errorf("the ZONEMD written to the zone file does not verify against the"+
				" file's own contents\n  in file:    %s\n  recomputed: %s", z.Digest, want)
		}
	}
}

// The apex NSEC has to list ZONEMD, or the NXRRSET proof for it contradicts
// the zone. This is the whole reason presence is decided before the restitch.
func TestApexNsecBitmapListsZonemd(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := zonemdSigningTestZone(t, kdb)

	snap := zd.publishedSnapshot()
	apex := getOwnerFrom(snap, zd.ZoneName)
	if apex == nil || len(apex.NSEC.RRs) == 0 {
		t.Fatal("the apex has no NSEC")
	}
	nsec := apex.NSEC.RRs[0].(*dns.NSEC)
	for _, t2 := range nsec.TypeBitMap {
		if t2 == dns.TypeZONEMD {
			return
		}
	}
	t.Errorf("the apex NSEC bitmap does not list ZONEMD, so a validator asking for a"+
		" type the zone owns is told it does not exist: %v", nsec.TypeBitMap)
}

// Turning the option off takes OUR record out, and the NSEC bitmap with it.
func TestZonemdRemovedWhenTheOptionIsTurnedOff(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := zonemdSigningTestZone(t, kdb)
	if len(snapshotZonemd(t, zd).RRs) == 0 {
		t.Fatal("test setup: no ZONEMD to remove")
	}

	zd.mu.Lock()
	zd.Options[OptPublishZonemd] = false
	zd.mu.Unlock()
	if _, err := zd.publishSync(); err != nil {
		t.Fatalf("publish after turning the option off: %v", err)
	}

	if rs := snapshotZonemd(t, zd); len(rs.RRs) != 0 {
		t.Fatalf("the ZONEMD survived the option being turned off: %+v", rs.RRs)
	}
	apex := getOwnerFrom(zd.publishedSnapshot(), zd.ZoneName)
	if apex == nil || len(apex.NSEC.RRs) == 0 {
		t.Fatal("the apex lost its NSEC")
	}
	for _, tt := range apex.NSEC.RRs[0].(*dns.NSEC).TypeBitMap {
		if tt == dns.TypeZONEMD {
			t.Error("the apex NSEC still claims a ZONEMD the zone no longer carries")
		}
	}
}

// ...and turning it on adds one to a zone that has been running without.
func TestZonemdAppearsWhenTheOptionIsTurnedOn(t *testing.T) {
	zd := testZone(t, "md.example.", zonemdZone)
	registerZones(t, zd)
	zd.Options = map[ZoneOption]bool{}
	if _, err := zd.publishSync(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(snapshotZonemd(t, zd).RRs) != 0 {
		t.Fatal("test setup: the zone already publishes a ZONEMD")
	}

	zd.mu.Lock()
	zd.Options[OptPublishZonemd] = true
	zd.mu.Unlock()
	if _, err := zd.publishSync(); err != nil {
		t.Fatalf("publish after turning the option on: %v", err)
	}
	assertZonemdMatchesSnapshot(t, zd, "after turning the option on")
}

// More than one (scheme, algorithm) pair is one RRset with one RR each, and
// every one of them has to describe the same zone.
func TestZonemdWithMultipleAlgorithms(t *testing.T) {
	zd := zonemdTestZone(t, ZonemdAlgSHA384, ZonemdAlgSHA512)
	assertZonemdMatchesSnapshot(t, zd, "two algorithms")

	rs := snapshotZonemd(t, zd)
	if len(rs.RRs) != 2 {
		t.Fatalf("expected two ZONEMD RRs, got %d", len(rs.RRs))
	}
	seen := map[uint8]bool{}
	for _, rr := range rs.RRs {
		z := rr.(*dns.ZONEMD)
		if seen[z.Hash] {
			t.Fatalf("algorithm %d is published twice", z.Hash)
		}
		seen[z.Hash] = true
	}
	if !seen[ZonemdAlgSHA384] || !seen[ZonemdAlgSHA512] {
		t.Errorf("expected SHA-384 and SHA-512, got %v", seen)
	}
	// The two digests are over the same records with different hashes, so they
	// differ in length as well as in value.
	a := rs.RRs[0].(*dns.ZONEMD)
	b := rs.RRs[1].(*dns.ZONEMD)
	if len(a.Digest) == len(b.Digest) {
		t.Errorf("SHA-384 and SHA-512 digests are the same length (%d)", len(a.Digest))
	}
}

// A signed zone whose policy is not yet bound -- every new zone, for the
// window before the post-Ready sync -- must publish NO ZONEMD rather than an
// unsigned one. An unsigned apex RRset in a signed zone is BOGUS, not merely
// undigested.
func TestZonemdNotPublishedWhileSigningIsNotReady(t *testing.T) {
	zd := testZone(t, "md.example.", zonemdZone)
	registerZones(t, zd)
	zd.Options = map[ZoneOption]bool{OptInlineSigning: true, OptPublishZonemd: true}
	zd.DnssecPolicy = nil // not yet bound

	if _, err := zd.publishSync(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if rs := snapshotZonemd(t, zd); len(rs.RRs) != 0 {
		t.Fatalf("a signed zone with no policy published an unsigned ZONEMD: %+v", rs.RRs)
	}
}

// The journal records what someone CHANGED. A managed ZONEMD is recomputed on
// every publish, so journalling it would replay a digest from one serial onto
// a zone file at another as though an operator had written it.
func TestJournalDeltaExcludesManagedZonemd(t *testing.T) {
	mk := func(name string, rrtype uint16) core.RRset {
		return core.RRset{Name: name, RRtype: rrtype, Class: dns.ClassINET}
	}
	in := []core.RRset{
		mk("md.example.", dns.TypeZONEMD),
		mk("md.example.", dns.TypeA),
		mk("sub.md.example.", dns.TypeZONEMD), // not the apex: ordinary zone data
	}

	managed := &ZoneData{ZoneName: "md.example.",
		Options: map[ZoneOption]bool{OptPublishZonemd: true}}
	out := managed.withoutDerivedRecords(in)
	if len(out) != 2 {
		t.Fatalf("expected the apex ZONEMD to be dropped and nothing else, got %d: %+v",
			len(out), out)
	}
	for _, rs := range out {
		if rs.RRtype == dns.TypeZONEMD && rs.Name == "md.example." {
			t.Error("the managed apex ZONEMD survived into the journal delta")
		}
	}

	// Off, the apex ZONEMD is operator data and belongs in the journal.
	unmanaged := &ZoneData{ZoneName: "md.example.", Options: map[ZoneOption]bool{}}
	if got := len(unmanaged.withoutDerivedRecords(in)); got != 3 {
		t.Errorf("an unmanaged apex ZONEMD was dropped from the journal delta: kept %d of 3", got)
	}
}

// Accepting an update to a derived record and then overwriting it would report
// success for a change that never happened.
func TestUpdateRefusesToWriteAManagedApexZonemd(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := zonemdSigningTestZone(t, kdb)

	rr := mustRR(t, "md.example. 3600 IN ZONEMD 1 1 1 "+strings.Repeat("cd", 48))
	_, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: zd.ZoneName, Actions: []dns.RR{rr},
	}, kdb)
	if err == nil {
		t.Fatal("an update to the managed apex ZONEMD was accepted")
	}
	if !strings.Contains(err.Error(), "publish-zonemd") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	assertZonemdMatchesSnapshot(t, zd, "after the refused update")
}

// A replay is filtered rather than refused: the journal may hold a ZONEMD from
// before the option was set, and losing every other change in it would be the
// larger failure.
func TestReplayDropsAManagedApexZonemdInsteadOfFailing(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := zonemdSigningTestZone(t, kdb)

	zonemd := mustRR(t, "md.example. 3600 IN ZONEMD 1 1 1 "+strings.Repeat("cd", 48))
	other := mustRR(t, "replayed.md.example. 3600 IN A 10.9.9.9")
	if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: zd.ZoneName, Replay: true,
		Actions: []dns.RR{zonemd, other},
	}, kdb); err != nil {
		t.Fatalf("a replay carrying a ZONEMD failed instead of dropping it: %v", err)
	}

	snap := zd.publishedSnapshot()
	if od := getOwnerFrom(snap, "replayed.md.example."); od == nil {
		t.Error("the replay's other change was lost")
	}
	assertZonemdMatchesSnapshot(t, zd, "after the replay")
}

// DELNAME at the apex retains the server's ZONEMD for the same reason it
// retains SOA and NS: the next publish would recreate it, so reporting it as
// deleted would be reporting a change that does not survive the breath after.
func TestDelnameRetainsAManagedApexZonemd(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := zonemdSigningTestZone(t, kdb)

	delname := &dns.ANY{Hdr: dns.RR_Header{
		Name: zd.ZoneName, Rrtype: dns.TypeANY, Class: dns.ClassANY}}
	if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: zd.ZoneName, PreAuthorized: true,
		Actions: []dns.RR{delname},
	}, kdb); err != nil {
		t.Fatalf("DELNAME at the apex: %v", err)
	}
	if rs := snapshotZonemd(t, zd); len(rs.RRs) == 0 {
		t.Error("DELNAME at the apex deleted the server-managed ZONEMD")
	}
}

// ZoneDigest excludes the apex ZONEMD and the RRSIG covering it, so publishing
// one cannot perturb the zone-file identity the reconciliation depends on.
// Without this there is a feedback loop: writing the file changes the digest
// that identifies it.
func TestFileIdentityDigestIsUnaffectedByPublishingZonemd(t *testing.T) {
	plain := testZone(t, "md.example.", zonemdZone)
	withMD := testZone(t, "md.example.", zonemdZone+
		"md.example.	3600	IN	ZONEMD	1 1 1 "+strings.Repeat("ab", 48)+"\n")

	a, err := plain.zoneDigestOfWorkingData()
	if err != nil {
		t.Fatalf("digesting the plain zone: %v", err)
	}
	b, err := withMD.zoneDigestOfWorkingData()
	if err != nil {
		t.Fatalf("digesting the zone with a ZONEMD: %v", err)
	}
	if a != b {
		t.Errorf("adding an apex ZONEMD changed the file-identity digest;"+
			" writing the file would then change the digest that identifies it\n"+
			"  without: %s\n  with:    %s", a, b)
	}
}

// The cached digest is what the zone-file write records as the file's
// identity, so it has to be the same value an independent recomputation
// produces.
func TestCachedDigestEqualsTheRecomputedOne(t *testing.T) {
	zd := zonemdTestZone(t)

	cached, ok := zd.cachedZonemdDigest(zd.publishedSnapshot().Serial,
		ZonemdSchemeSimple, ZonemdAlgSHA384)
	if !ok {
		t.Fatal("no cached digest after a publish")
	}
	recomputed, err := ZoneDigestHex(zd.ZoneName, zoneRRsFromSnapshot(zd.publishedSnapshot()),
		ZonemdSchemeSimple, ZonemdAlgSHA384)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(cached, recomputed) {
		t.Errorf("the cached digest differs from a recomputation\n  cached: %s\n  fresh:  %s",
			cached, recomputed)
	}
	// ...and it is only offered for the serial it describes.
	if _, ok := zd.cachedZonemdDigest(zd.publishedSnapshot().Serial+1,
		ZonemdSchemeSimple, ZonemdAlgSHA384); ok {
		t.Error("the cache answered for a serial it does not describe")
	}
}

func TestResolveZonemdConf(t *testing.T) {
	tests := []struct {
		name       string
		in         ZonemdConf
		wantScheme uint8
		wantAlgs   []uint8
		wantErr    string
	}{
		{"empty defaults to SIMPLE/SHA-384", ZonemdConf{}, 1, []uint8{1}, ""},
		{"explicit SHA-512", ZonemdConf{Algorithms: []uint8{2}}, 1, []uint8{2}, ""},
		{"both, order preserved", ZonemdConf{Algorithms: []uint8{2, 1}}, 1, []uint8{2, 1}, ""},
		{"explicit SIMPLE", ZonemdConf{Scheme: 1}, 1, []uint8{1}, ""},
		{"unknown scheme", ZonemdConf{Scheme: 2}, 0, nil, "not implemented"},
		{"reserved algorithm 0", ZonemdConf{Algorithms: []uint8{0}}, 0, nil, "not implemented"},
		{"unknown algorithm", ZonemdConf{Algorithms: []uint8{7}}, 0, nil, "not implemented"},
		{"duplicate algorithm", ZonemdConf{Algorithms: []uint8{1, 1}}, 0, nil, "listed twice"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			set, err := resolveZonemdConf(tc.in)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got none", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected an error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if set.Scheme != tc.wantScheme {
				t.Errorf("scheme: got %d want %d", set.Scheme, tc.wantScheme)
			}
			if fmt.Sprint(set.Algorithms) != fmt.Sprint(tc.wantAlgs) {
				t.Errorf("algorithms: got %v want %v", set.Algorithms, tc.wantAlgs)
			}
		})
	}
}

// publish-zonemd writes a locally computed record into the zone, so a
// tdns-auth secondary that may not originate content must not carry it.
func TestPublishZonemdIsStrippedOnAMirroringSecondary(t *testing.T) {
	opts := map[ZoneOption]bool{OptPublishZonemd: true}
	eff, _, suppressed, msg := normalizeOptionsForRole(AppTypeAuth, Secondary, opts, "")
	if !suppressed[OptPublishZonemd] {
		t.Fatal("publish-zonemd was not stripped on a mirroring secondary")
	}
	if eff[OptPublishZonemd] {
		t.Error("publish-zonemd survived into the effective options")
	}
	if !strings.Contains(msg, "publish-zonemd") {
		t.Errorf("the operator is not told what was ignored: %q", msg)
	}

	// An inline-signing secondary re-signs what it receives, so any upstream
	// digest is already invalid for what it serves: it must publish its own.
	inline := map[ZoneOption]bool{OptPublishZonemd: true, OptInlineSigning: true}
	eff, _, _, _ = normalizeOptionsForRole(AppTypeAuth, Secondary, inline, "")
	if !eff[OptPublishZonemd] {
		t.Error("publish-zonemd was stripped from an inline-signing secondary," +
			" which originates by definition")
	}
}

func TestZonemdSettingsDiffer(t *testing.T) {
	tests := []struct {
		name    string
		onA     bool
		schemeA uint8
		algsA   []uint8
		onB     bool
		schemeB uint8
		algsB   []uint8
		want    bool
	}{
		{"both off", false, 1, []uint8{1}, false, 1, []uint8{2}, false},
		{"turned on", false, 1, nil, true, 1, []uint8{1}, true},
		{"turned off", true, 1, []uint8{1}, false, 1, nil, true},
		{"unchanged", true, 1, []uint8{1}, true, 1, []uint8{1}, false},
		{"algorithm added", true, 1, []uint8{1}, true, 1, []uint8{1, 2}, true},
		{"algorithm order", true, 1, []uint8{1, 2}, true, 1, []uint8{2, 1}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := zonemdSettingsDiffer(tc.onA, tc.schemeA, tc.algsA, tc.onB, tc.schemeB, tc.algsB)
			if got != tc.want {
				t.Errorf("got %v want %v", got, tc.want)
			}
		})
	}
}

// A publish that drops the ZONEMD leaves the apex NSEC claiming a type the
// zone no longer carries, and repairs it. If that repair CANNOT be made, the
// publish must be refused rather than completed: an NSEC asserting a ZONEMD
// the apex does not own is a signed proof that contradicts the zone, which is
// the defect refuseUnrepairableChainLocked exists to keep off the wire. A
// missing digest is fine; a broken chain is not.
//
// Drives abandonZonemdLocked directly. The publish path's half of this is one
// line -- `if !zd.updateZonemdLocked(...) { return }` -- and what needs pinning
// is the decision, which is here: the serial is rolled back, the previous
// snapshot is still served, and the caller is told to stop.
func TestAbandoningTheZonemdRefusesThePublishWhenTheChainCannotBeRepaired(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := zonemdSigningTestZone(t, kdb)
	assertZonemdMatchesSnapshot(t, zd, "before")

	beforeSerial := zd.publishedSnapshot().Serial
	beforeSnap := zd.publishedSnapshot()

	// Break the signing restitchNsecLocked does on the NSECs it rewrites. This
	// used to close the keystore, which worked while the restitch resolved its
	// own keys; the publish now resolves ONCE and passes the material in, so
	// closing the store fails the resolution instead -- earlier, and in a
	// different function. A material carrying no usable keys injects the failure
	// where the test wants it: SignRRset refuses that directly.
	unusable := &signingMaterial{dak: &DnssecKeys{}}

	zd.mu.Lock()
	zd.ensureWorkingSet()
	// Something must have changed, or restitchNsecLocked returns at its
	// "nothing changed" guard and never reaches the signing that now fails.
	zd.stageRRsetLocked("newname.md.example.", core.RRset{
		Name: "newname.md.example.", Class: dns.ClassINET, RRtype: dns.TypeA,
		RRs: []dns.RR{mustRR(t, "newname.md.example. 3600 IN A 10.5.5.5")},
	})
	cont := zd.abandonZonemdLocked(beforeSerial, unusable, fmt.Errorf("forced failure"))
	gotSerial := zd.CurrentSerial
	zd.mu.Unlock()

	if cont {
		t.Fatal("the publish was allowed to continue with an apex NSEC that claims" +
			" a ZONEMD the zone no longer carries")
	}
	if gotSerial != beforeSerial {
		t.Errorf("the serial was not rolled back: %d, want %d", gotSerial, beforeSerial)
	}
	if zd.publishedSnapshot() != beforeSnap {
		t.Error("a new snapshot was installed by a publish that should have been refused")
	}
	if !zd.HasError(DnssecPolicyWarning) {
		t.Error("the refusal is not visible to the operator as a zone error")
	}
}

// The ordinary failure is unchanged: a zone that cannot produce a digest is
// published WITHOUT one, and the publish continues.
func TestAbandoningTheZonemdContinuesWhenTheChainRepairsCleanly(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := zonemdSigningTestZone(t, kdb)
	beforeSerial := zd.publishedSnapshot().Serial

	zd.mu.Lock()
	zd.ensureWorkingSet()
	cont := zd.abandonZonemdLocked(beforeSerial, mustSigningMaterial(t, zd), fmt.Errorf("forced failure"))
	staged := zd.stagedOwner(zd.ZoneName)
	zd.mu.Unlock()

	if !cont {
		t.Fatal("a repairable chain refused the publish; a missing digest is not" +
			" a reason to take the zone off the air")
	}
	if len(staged.RRtypes.GetOnlyRRSet(dns.TypeZONEMD).RRs) != 0 {
		t.Error("the ZONEMD was not dropped")
	}
	for _, tt := range staged.NSEC.RRs[0].(*dns.NSEC).TypeBitMap {
		if tt == dns.TypeZONEMD {
			t.Error("the apex NSEC still claims a ZONEMD the zone no longer carries")
		}
	}
}

// mustSigningMaterial resolves a publish's signing context the way
// publishWorkingSetLocked does, for tests that call a publish-path helper
// directly.
func mustSigningMaterial(t *testing.T, zd *ZoneData) *signingMaterial {
	t.Helper()
	sm, err := zd.resolveSigningMaterialLocked()
	if err != nil {
		t.Fatalf("resolveSigningMaterialLocked: %v", err)
	}
	return sm
}
