/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"sort"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// denialZone is signed by the tdns signer and then served by a secondary that
// holds no key, the case in #770. ent.example. is an empty non-terminal,
// insecure.example. an unsigned delegation, and *.wild.example. a wildcard
// with a sibling (a.wild.example.) that sorts between it and names it
// answers for, so that a wildcard NODATA needs two different NSECs.
const denialZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 300
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.2
host.ent.example.	3600	IN	A	10.0.0.3
*.wild.example.	3600	IN	TXT	"wild"
a.wild.example.	3600	IN	A	10.0.0.5
insecure.example.	3600	IN	NS	ns.insecure.example.
ns.insecure.example.	3600	IN	A	10.0.0.4
`

// signedTestZone hosts zoneText signed here by the tdns signer, inline-signing
// with an ED25519 KSK and ZSK. With blackLies the zone has no NSEC chain and
// every denial is a compact denial, synthesized and signed per response.
func signedTestZone(t *testing.T, name, zoneText string, blackLies bool) (*ZoneData, *KeyDB) {
	t.Helper()
	kdb := newTestKeyDB(t)
	zd := testZone(t, name, zoneText)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptInlineSigning: true, OptBlackLies: blackLies}
	zd.DnssecPolicy = &DnssecPolicy{
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		SigValidity: PolicySigValidity{
			Default: 30 * 86400, DNSKEY: 30 * 86400, DS: 30 * 86400,
		},
	}
	zd.InstallInitialSnapshot()
	if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	return zd, kdb
}

// compactDenialZone hosts zoneText signed here with black-lies, the one kind of
// zone whose denials are compact (RFC 9824).
func compactDenialZone(t *testing.T, name, zoneText string) (*ZoneData, *KeyDB) {
	t.Helper()
	return signedTestZone(t, name, zoneText, true)
}

// snapshotZoneText renders every record in snap, signatures and NSECs
// included, as zone-file text: what a secondary receives over AXFR.
func snapshotZoneText(snap *zoneSnapshot) string {
	var names []string
	for name := range snap.Data {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return canonicalCompare(names[i], names[j]) < 0 })
	var b strings.Builder
	for _, name := range names {
		od := snap.Data[name]
		if od == nil || od.RRtypes == nil {
			continue
		}
		types := sortedRRtypes(od)
		// The SOA first, so the text starts the way a zone file does.
		sort.SliceStable(types, func(i, j int) bool { return types[i] == dns.TypeSOA && types[j] != dns.TypeSOA })
		for _, typ := range types {
			rs := od.RRtypes.GetOnlyRRSet(typ)
			for _, rr := range append(append([]dns.RR{}, rs.RRs...), rs.RRSIGs...) {
				b.WriteString(rr.String() + "\n")
			}
		}
		for _, rr := range append(append([]dns.RR{}, od.NSEC.RRs...), od.NSEC.RRSIGs...) {
			b.WriteString(rr.String() + "\n")
		}
	}
	return b.String()
}

// presignedSecondary signs denialZone here, then hands its records to a second
// zone that holds no key and signs nothing: a plain secondary of a zone signed
// elsewhere. edit, if given, changes the records on the way. It returns the
// secondary and the zone's DNSKEYs.
func presignedSecondary(t *testing.T, edit func(string) string) (*ZoneData, []*dns.DNSKEY) {
	t.Helper()
	signer, _ := signedTestZone(t, "example.", denialZone, false)
	snap := signer.publishedSnapshot()
	var keys []*dns.DNSKEY
	if rs := getRRsetFrom(snap, "example.", dns.TypeDNSKEY); rs != nil {
		for _, rr := range rs.RRs {
			keys = append(keys, rr.(*dns.DNSKEY))
		}
	}
	if len(keys) == 0 {
		t.Fatal("the signed zone has no DNSKEY RRset")
	}
	text := snapshotZoneText(snap)
	if edit != nil {
		text = edit(text)
	}
	// The secondary takes the zone's name over from the signer.
	Zones.Remove("example.")
	return testSnapshotZone(t, "example.", text), keys
}

// dropRecords removes the records at owner ("" for any owner) of type typ,
// and the RRSIGs over them. dropSigs removes only those RRSIGs.
func dropRecords(owner, typ string) func(string) string { return dropMatching(owner, typ, true) }
func dropSigs(owner, typ string) func(string) string    { return dropMatching(owner, typ, false) }

func dropMatching(owner, typ string, records bool) func(string) string {
	return func(text string) string {
		var out []string
		for _, line := range strings.Split(text, "\n") {
			// name, TTL, class, type, RDATA: the fields of rr.String().
			f := strings.SplitN(line, "\t", 5)
			if len(f) == 5 && (owner == "" || strings.EqualFold(f[0], owner)) {
				if (records && f[3] == typ) || (f[3] == "RRSIG" && strings.HasPrefix(f[4], typ+" ")) {
					continue
				}
			}
			out = append(out, line)
		}
		return strings.Join(out, "\n")
	}
}

// denialAsk queries zd with DO set, and CO as given, the way the handler does.
func denialAsk(t *testing.T, zd *ZoneData, kdb *KeyDB, qname string, qtype uint16, co bool) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(qname, qtype)
	req.SetEdns0(4096, true)
	if co {
		edns0.SetCO(req)
	}
	msgo, err := edns0.ExtractFlagsAndEDNS0Options(req)
	if err != nil {
		t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
	}
	rw := &fakeRW{}
	if err := zd.QueryResponder(context.Background(), rw, req, qname, qtype, msgo, kdb, nil); err != nil {
		t.Fatalf("QueryResponder(%s %s): %v", qname, dns.TypeToString[qtype], err)
	}
	if rw.written == nil {
		t.Fatalf("no response written for %s %s", qname, dns.TypeToString[qtype])
	}
	return rw.written
}

// nsecsIn returns the NSECs in a section.
func nsecsIn(rrs []dns.RR) []*dns.NSEC {
	var out []*dns.NSEC
	for _, rr := range rrs {
		if n, ok := rr.(*dns.NSEC); ok {
			out = append(out, n)
		}
	}
	return out
}

// verifySection checks every RRSIG in rrs against keys, and that every NSEC and
// SOA in rrs has a valid one: what a validator requires of a proof.
func verifySection(t *testing.T, rrs []dns.RR, keys []*dns.DNSKEY) {
	t.Helper()
	type rrsetKey struct {
		name string
		typ  uint16
	}
	sets := map[rrsetKey][]dns.RR{}
	var sigs []*dns.RRSIG
	for _, rr := range rrs {
		if sig, ok := rr.(*dns.RRSIG); ok {
			sigs = append(sigs, sig)
			continue
		}
		k := rrsetKey{strings.ToLower(rr.Header().Name), rr.Header().Rrtype}
		sets[k] = append(sets[k], rr)
	}
	verified := map[rrsetKey]bool{}
	for _, sig := range sigs {
		k := rrsetKey{strings.ToLower(sig.Hdr.Name), sig.TypeCovered}
		set := sets[k]
		if len(set) == 0 {
			t.Errorf("an RRSIG over %s %s with no RRset beside it", sig.Hdr.Name, dns.TypeToString[sig.TypeCovered])
			continue
		}
		var ok bool
		for _, key := range keys {
			if key.KeyTag() == sig.KeyTag && sig.Verify(key, set) == nil {
				ok = true
			}
		}
		if !ok {
			t.Errorf("the RRSIG over %s %s does not verify", sig.Hdr.Name, dns.TypeToString[sig.TypeCovered])
			continue
		}
		verified[k] = true
	}
	for k := range sets {
		if (k.typ == dns.TypeNSEC || k.typ == dns.TypeSOA) && !verified[k] {
			t.Errorf("%s %s has no valid RRSIG", k.name, dns.TypeToString[k.typ])
		}
	}
}

// nsecCovers reports whether nsec proves that name does not exist: name lies
// strictly between its owner and its next name in canonical order, or after
// the owner of the last NSEC, whose next name is the apex.
func nsecCovers(t *testing.T, nsec *dns.NSEC, name string) bool {
	t.Helper()
	owner, next := nsec.Hdr.Name, nsec.NextDomain
	if testWireCompare(t, owner, name) >= 0 {
		return false
	}
	if testWireCompare(t, owner, next) >= 0 { // the last NSEC
		return true
	}
	return testWireCompare(t, name, next) < 0
}

func nsecHas(nsec *dns.NSEC, typ uint16) bool {
	for _, t := range nsec.TypeBitMap {
		if t == typ {
			return true
		}
	}
	return false
}

func findNSEC(nsecs []*dns.NSEC, owner string) *dns.NSEC {
	for _, n := range nsecs {
		if strings.EqualFold(n.Hdr.Name, owner) {
			return n
		}
	}
	return nil
}

// countDenialWarnings counts the calls to logDenialGap for the rest of the test.
func countDenialWarnings(t *testing.T) *int {
	t.Helper()
	n := 0
	orig := logDenialGap
	logDenialGap = func(zone string, serial uint32, reason, qname string) { n++ }
	t.Cleanup(func() { logDenialGap = orig })
	return &n
}

// checkChainDenials asks zd for every kind of negative answer, with and
// without CO, and checks each the way a validator does: the rcode, the RRSIGs
// in AUTHORITY against the zone's keys, and the NSECs against the claim --
// covering what does not exist, owned by what does, never NXNAME.
func checkChainDenials(t *testing.T, zd *ZoneData, kdb *KeyDB, keys []*dns.DNSKEY) {
	t.Helper()
	for _, co := range []bool{false, true} {
		mode := "DO"
		if co {
			mode = "DO+CO"
		}
		t.Run(mode, func(t *testing.T) {
			check := func(t *testing.T, m *dns.Msg, wantRcode int) []*dns.NSEC {
				t.Helper()
				if m.Rcode != wantRcode {
					t.Fatalf("rcode = %s, want %s; authority %v", dns.RcodeToString[m.Rcode], dns.RcodeToString[wantRcode], m.Ns)
				}
				if co != edns0.HasCO(m) {
					t.Errorf("CO on the response = %v, want %v (echoed)", edns0.HasCO(m), co)
				}
				verifySection(t, m.Ns, keys)
				nsecs := nsecsIn(m.Ns)
				for _, n := range nsecs {
					if nsecHas(n, dns.TypeNXNAME) {
						t.Errorf("NXNAME in a chain answer: %s", n)
					}
				}
				return nsecs
			}

			t.Run("name does not exist", func(t *testing.T) {
				nsecs := check(t, denialAsk(t, zd, kdb, "nx.example.", dns.TypeA, co), dns.RcodeNameError)
				var name, wild bool
				for _, n := range nsecs {
					name = name || nsecCovers(t, n, "nx.example.")
					wild = wild || nsecCovers(t, n, "*.example.")
				}
				if !name || !wild || len(nsecs) != 2 {
					t.Errorf("want two NSECs covering nx.example. and *.example.; got %v", nsecs)
				}
			})

			t.Run("name does not exist, one NSEC covers both", func(t *testing.T) {
				// zz.www.example. and *.www.example. both sort after the last
				// owner, www.example., whose NSEC wraps to the apex.
				nsecs := check(t, denialAsk(t, zd, kdb, "zz.www.example.", dns.TypeA, co), dns.RcodeNameError)
				if len(nsecs) != 1 || !nsecCovers(t, nsecs[0], "zz.www.example.") || !nsecCovers(t, nsecs[0], "*.www.example.") {
					t.Errorf("want the one NSEC covering both, once; got %v", nsecs)
				}
			})

			t.Run("type does not exist", func(t *testing.T) {
				nsecs := check(t, denialAsk(t, zd, kdb, "www.example.", dns.TypeTXT, co), dns.RcodeSuccess)
				if len(nsecs) != 1 || !strings.EqualFold(nsecs[0].Hdr.Name, "www.example.") ||
					nsecHas(nsecs[0], dns.TypeTXT) || nsecHas(nsecs[0], dns.TypeCNAME) {
					t.Errorf("want www.example.'s own NSEC, without TXT; got %v", nsecs)
				}
			})

			t.Run("empty non-terminal", func(t *testing.T) {
				nsecs := check(t, denialAsk(t, zd, kdb, "ent.example.", dns.TypeA, co), dns.RcodeSuccess)
				if len(nsecs) != 1 || !nsecCovers(t, nsecs[0], "ent.example.") ||
					!dns.IsSubDomain("ent.example.", nsecs[0].NextDomain) {
					t.Errorf("want the NSEC covering ent.example. with its next name below it; got %v", nsecs)
				}
			})

			t.Run("wildcard, type does not exist", func(t *testing.T) {
				nsecs := check(t, denialAsk(t, zd, kdb, "foo.wild.example.", dns.TypeA, co), dns.RcodeSuccess)
				wild := findNSEC(nsecs, "*.wild.example.")
				var cover bool
				for _, n := range nsecs {
					cover = cover || nsecCovers(t, n, "foo.wild.example.")
				}
				if wild == nil || nsecHas(wild, dns.TypeA) || !cover || len(nsecs) != 2 {
					t.Errorf("want the NSEC covering foo.wild.example. and the wildcard's own; got %v", nsecs)
				}
			})

			t.Run("DS at an insecure delegation", func(t *testing.T) {
				nsecs := check(t, denialAsk(t, zd, kdb, "insecure.example.", dns.TypeDS, co), dns.RcodeSuccess)
				if n := findNSEC(nsecs, "insecure.example."); n == nil || len(nsecs) != 1 ||
					!nsecHas(n, dns.TypeNS) || nsecHas(n, dns.TypeDS) {
					t.Errorf("want the NSEC at the cut, NS without DS; got %v", nsecs)
				}
			})

			t.Run("DS at an in-zone name", func(t *testing.T) {
				nsecs := check(t, denialAsk(t, zd, kdb, "www.example.", dns.TypeDS, co), dns.RcodeSuccess)
				if n := findNSEC(nsecs, "www.example."); n == nil || len(nsecs) != 1 || nsecHas(n, dns.TypeDS) {
					t.Errorf("want www.example.'s own NSEC, without DS; got %v", nsecs)
				}
			})

			t.Run("DS at the apex, parent not hosted", func(t *testing.T) {
				nsecs := check(t, denialAsk(t, zd, kdb, "example.", dns.TypeDS, co), dns.RcodeSuccess)
				if n := findNSEC(nsecs, "example."); n == nil || len(nsecs) != 1 || nsecHas(n, dns.TypeDS) {
					t.Errorf("want the apex's own NSEC, without DS; got %v", nsecs)
				}
			})

			t.Run("referral to an insecure delegation", func(t *testing.T) {
				m := denialAsk(t, zd, kdb, "www.insecure.example.", dns.TypeA, co)
				if m.Rcode != dns.RcodeSuccess || m.Authoritative {
					t.Fatalf("want a referral; got rcode %s aa %v", dns.RcodeToString[m.Rcode], m.Authoritative)
				}
				verifySection(t, m.Ns, keys)
				nsecs := nsecsIn(m.Ns)
				if n := findNSEC(nsecs, "insecure.example."); n == nil || len(nsecs) != 1 ||
					!nsecHas(n, dns.TypeNS) || nsecHas(n, dns.TypeDS) {
					t.Errorf("want the NSEC at the cut, NS without DS; got %v", nsecs)
				}
			})

			t.Run("wildcard answer", func(t *testing.T) {
				m := denialAsk(t, zd, kdb, "foo.wild.example.", dns.TypeTXT, co)
				if m.Rcode != dns.RcodeSuccess || len(m.Answer) == 0 {
					t.Fatalf("want the wildcard's TXT; got rcode %s answer %v", dns.RcodeToString[m.Rcode], m.Answer)
				}
				nsecs := nsecsIn(m.Ns)
				if len(nsecs) != 1 || !nsecCovers(t, nsecs[0], "foo.wild.example.") {
					t.Errorf("want the NSEC covering foo.wild.example.; got %v", nsecs)
				}
				verifySection(t, m.Ns, keys)
			})
		})
	}
}

// A secondary of a zone signed elsewhere answers every kind of negative from
// the chain it received, with the signatures the chain carries, and a
// validator accepts each answer (#770). Before, it answered with an NSEC it
// made up at the query name and could not sign.
func TestChainDenial(t *testing.T) {
	sec, keys := presignedSecondary(t, nil)
	warnings := countDenialWarnings(t)
	// The secondary's own KeyDB, with no keys for the zone.
	checkChainDenials(t, sec, newTestKeyDB(t), keys)
	if *warnings != 0 {
		t.Errorf("a complete chain logged %d warnings", *warnings)
	}
}

// The chain index a denial is proved from is built before the snapshot is
// published, so the first negative answer of a serial does not build it
// inside the query (the design's Q7). A zone without a chain gets none.
func TestDenialIndexBuiltAtPublish(t *testing.T) {
	sec, _ := presignedSecondary(t, nil)
	if snap := sec.publishedSnapshot(); snap == nil || len(snap.nsecIndex) == 0 {
		t.Error("the published snapshot of a zone with a chain has no chain index")
	}

	plain := testSnapshotZone(t, "plain.example.", `plain.example. 3600 IN SOA ns.plain.example. h.plain.example. 1 7200 1800 604800 300
plain.example. 3600 IN NS ns.plain.example.
ns.plain.example. 3600 IN A 10.0.0.1
`)
	if snap := plain.publishedSnapshot(); snap == nil || snap.nsecIndex != nil {
		t.Error("a zone with no chain got a chain index at publish")
	}
}

// A stored cover with no RRSIG is served as the zone holds it, and nothing is
// synthesized in its place: a secondary has no key to sign one with (S1).
func TestChainWildcardCoverWithoutRRSIG(t *testing.T) {
	sec, _ := presignedSecondary(t, dropSigs("a.wild.example.", "NSEC"))
	warnings := countDenialWarnings(t)

	m := denialAsk(t, sec, newTestKeyDB(t), "foo.wild.example.", dns.TypeTXT, false)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) == 0 {
		t.Fatalf("want the wildcard's TXT; got rcode %s answer %v", dns.RcodeToString[m.Rcode], m.Answer)
	}
	nsecs := nsecsIn(m.Ns)
	if len(nsecs) != 1 || !strings.EqualFold(nsecs[0].Hdr.Name, "a.wild.example.") {
		t.Errorf("want the stored NSEC at a.wild.example. and nothing synthesized; got %v", nsecs)
	}
	for _, rr := range m.Ns {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeNSEC {
			t.Errorf("an RRSIG over an NSEC the zone holds unsigned: %s", sig)
		}
	}
	if *warnings != 1 {
		t.Errorf("warnings = %d, want 1", *warnings)
	}
}

// A stored NSEC that contradicts the answer -- here one listing the very type
// asked for -- is not attached, and the gap is reported (C1).
func TestChainDenialContradictionIsAGap(t *testing.T) {
	sec, _ := presignedSecondary(t, func(text string) string {
		var out []string
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "www.example.\t") && strings.Contains(line, "\tNSEC\t") {
				line += " TXT"
			}
			out = append(out, line)
		}
		return strings.Join(out, "\n")
	})
	warnings := countDenialWarnings(t)

	m := denialAsk(t, sec, newTestKeyDB(t), "www.example.", dns.TypeTXT, false)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 {
		t.Fatalf("want NODATA; got rcode %s answer %v", dns.RcodeToString[m.Rcode], m.Answer)
	}
	if nsecs := nsecsIn(m.Ns); len(nsecs) != 0 {
		t.Errorf("an NSEC listing TXT was attached to a TXT NODATA: %v", nsecs)
	}
	if *warnings != 1 {
		t.Errorf("warnings = %d, want 1", *warnings)
	}
}

// A secondary whose chain has a gap serves what it holds, with the right
// rcode, and warns once per serial -- at the first gap, not at the serial's
// first negative answer (S2).
func TestChainDenialGapWarnsOncePerSerial(t *testing.T) {
	sec, keys := presignedSecondary(t, dropRecords("www.example.", "NSEC"))
	kdb := newTestKeyDB(t)
	warnings := countDenialWarnings(t)

	// A denial the chain still proves: no warning.
	m := denialAsk(t, sec, kdb, "nx.example.", dns.TypeA, false)
	if m.Rcode != dns.RcodeNameError || len(nsecsIn(m.Ns)) != 2 {
		t.Fatalf("nx.example.: rcode %s, authority %v", dns.RcodeToString[m.Rcode], m.Ns)
	}
	verifySection(t, m.Ns, keys)
	if *warnings != 0 {
		t.Fatalf("a proved denial logged %d warnings", *warnings)
	}

	// The gap: www.example. has lost its NSEC. NODATA, the signed SOA, no NSEC.
	m = denialAsk(t, sec, kdb, "www.example.", dns.TypeTXT, false)
	if m.Rcode != dns.RcodeSuccess || len(nsecsIn(m.Ns)) != 0 {
		t.Errorf("www.example. TXT: rcode %s, authority %v", dns.RcodeToString[m.Rcode], m.Ns)
	}
	verifySection(t, m.Ns, keys)
	if *warnings != 1 {
		t.Errorf("warnings after the first gap = %d, want 1", *warnings)
	}

	// Another gap in the same serial: still one.
	denialAsk(t, sec, kdb, "www.example.", dns.TypeMX, false)
	if *warnings != 1 {
		t.Errorf("warnings after a second gap = %d, want 1", *warnings)
	}
}

// A zone that is signed but holds no NSEC chain -- a secondary of a
// compact-denial primary -- has no proof to give. It answers with the right
// rcode and the signed SOA, and warns once per serial.
func TestSignedZoneWithoutChain(t *testing.T) {
	sec, keys := presignedSecondary(t, dropRecords("", "NSEC"))
	warnings := countDenialWarnings(t)
	kdb := newTestKeyDB(t)

	m := denialAsk(t, sec, kdb, "nx.example.", dns.TypeA, false)
	if m.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN", dns.RcodeToString[m.Rcode])
	}
	if nsecs := nsecsIn(m.Ns); len(nsecs) != 0 {
		t.Errorf("a zone with no chain served NSECs: %v", nsecs)
	}
	var soaSig bool
	for _, rr := range m.Ns {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeSOA {
			soaSig = true
		}
	}
	if !soaSig {
		t.Errorf("no RRSIG over the SOA: %v", m.Ns)
	}
	verifySection(t, m.Ns, keys)

	denialAsk(t, sec, kdb, "www.example.", dns.TypeTXT, false)
	if *warnings != 1 {
		t.Errorf("warnings = %d, want 1", *warnings)
	}
}

// An unsigned zone answers a DO query as it answers one without DO: the SOA and
// the rcode, never an NSEC (#771). Before, a missing name got NOERROR and an
// unsigned NSEC, and resolvers cached NODATA for it.
func TestUnsignedZoneDenials(t *testing.T) {
	zd := testSnapshotZone(t, "neg.example.", negProofZone)
	for _, withKDB := range []bool{false, true} {
		var kdb *KeyDB
		name := "without a KeyDB"
		if withKDB {
			kdb = newTestKeyDB(t)
			name = "with a KeyDB"
		}
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				qname string
				qtype uint16
				rcode int
			}{
				{"nope.neg.example.", dns.TypeA, dns.RcodeNameError},
				{"ns.neg.example.", dns.TypeTXT, dns.RcodeSuccess},
				{"b.neg.example.", dns.TypeA, dns.RcodeSuccess}, // an empty non-terminal
				{"insecure.neg.example.", dns.TypeDS, dns.RcodeSuccess},
				{"www.insecure.neg.example.", dns.TypeA, dns.RcodeSuccess}, // a referral
			} {
				for _, co := range []bool{false, true} {
					m := denialAsk(t, zd, kdb, tc.qname, tc.qtype, co)
					if m.Rcode != tc.rcode {
						t.Errorf("%s %s (CO %v): rcode %s, want %s", tc.qname, dns.TypeToString[tc.qtype], co,
							dns.RcodeToString[m.Rcode], dns.RcodeToString[tc.rcode])
					}
					if nsecs := nsecsIn(m.Ns); len(nsecs) != 0 {
						t.Errorf("%s %s (CO %v): an unsigned zone served NSECs: %v", tc.qname, dns.TypeToString[tc.qtype], co, nsecs)
					}
				}
			}
		})
	}
}

// A zone signed here serves a signed SOA on every negative path, or it is
// broken: even with the keys to sign a synthesized NSEC, a denial beside an
// unsigned SOA is a SERVFAIL, as a positive answer from that zone already is.
func TestSignedHereDenialNeedsASignedSOA(t *testing.T) {
	zd := testSnapshotZone(t, "neg.example.", negProofZone)
	zd.Options = map[ZoneOption]bool{OptOnlineSigning: true, OptBlackLies: true}
	kdb := newTestKeyDB(t)
	for _, role := range []string{"KSK", "ZSK"} {
		if _, _, err := kdb.GenerateKeypair("neg.example.", "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, role, nil); err != nil {
			t.Fatalf("generate %s: %v", role, err)
		}
	}
	for _, tc := range []struct {
		qname string
		qtype uint16
	}{
		{"nope.neg.example.", dns.TypeA},
		{"ns.neg.example.", dns.TypeTXT},
		{"b.neg.example.", dns.TypeA},
		{"insecure.neg.example.", dns.TypeDS},
	} {
		if m := denialAsk(t, zd, kdb, tc.qname, tc.qtype, false); m.Rcode != dns.RcodeServerFailure {
			t.Errorf("%s %s: rcode %s, want SERVFAIL", tc.qname, dns.TypeToString[tc.qtype], dns.RcodeToString[m.Rcode])
		}
	}
}

// An owner node holding no records and with nothing beneath it is a name that
// does not exist. It reaches QueryResponder past the existence check, and now
// goes to the same NXDOMAIN as every other such name, with the chain's proof
// on a secondary.
func TestEmptyOwnerNodeIsNXDOMAINFromTheChain(t *testing.T) {
	sec, keys := presignedSecondary(t, nil)
	base := sec.publishedSnapshot()
	data := map[string]*OwnerData{}
	for k, v := range base.Data {
		data[k] = v
	}
	data["vestigial.example."] = NewOwnerData("vestigial.example.")
	sec.snapshot.Store(sec.buildSnapshotLocked(base.Serial, data, nil))

	m := denialAsk(t, sec, newTestKeyDB(t), "vestigial.example.", dns.TypeA, false)
	if m.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[m.Rcode])
	}
	verifySection(t, m.Ns, keys)
	var cover bool
	for _, n := range nsecsIn(m.Ns) {
		cover = cover || nsecCovers(t, n, "vestigial.example.")
	}
	if !cover {
		t.Errorf("no NSEC covering vestigial.example.: %v", m.Ns)
	}
}

// A zone signed here without black-lies answers every negative from the NSEC
// chain the signer keeps for it, as black-lies is documented to mean (stage
// 2). It is asked with no KeyDB at all: every proof is stored, and nothing is
// signed at query time.
func TestSignedHereChainDenial(t *testing.T) {
	zd, _ := signedTestZone(t, "example.", denialZone, false)
	var keys []*dns.DNSKEY
	for _, rr := range getRRsetFrom(zd.publishedSnapshot(), "example.", dns.TypeDNSKEY).RRs {
		keys = append(keys, rr.(*dns.DNSKEY))
	}
	warnings := countDenialWarnings(t)
	checkChainDenials(t, zd, nil, keys)
	if *warnings != 0 {
		t.Errorf("a complete chain logged %d warnings", *warnings)
	}
}

// With black-lies, a zone signed here keeps compact denial: an NSEC owned by
// the name asked, bearing NXNAME, signed per response, and NOERROR unless the
// client set CO (RFC 9824).
func TestSignedHereBlackLiesKeepsCompactDenial(t *testing.T) {
	zd, kdb := compactDenialZone(t, "example.", denialZone)
	var keys []*dns.DNSKEY
	for _, rr := range getRRsetFrom(zd.publishedSnapshot(), "example.", dns.TypeDNSKEY).RRs {
		keys = append(keys, rr.(*dns.DNSKEY))
	}
	for _, tc := range []struct {
		co    bool
		rcode int
	}{{false, dns.RcodeSuccess}, {true, dns.RcodeNameError}} {
		m := denialAsk(t, zd, kdb, "nx.example.", dns.TypeA, tc.co)
		if m.Rcode != tc.rcode {
			t.Errorf("CO %v: rcode %s, want %s", tc.co, dns.RcodeToString[m.Rcode], dns.RcodeToString[tc.rcode])
		}
		nsecs := nsecsIn(m.Ns)
		if len(nsecs) != 1 || !strings.EqualFold(nsecs[0].Hdr.Name, "nx.example.") || !nsecHas(nsecs[0], dns.TypeNXNAME) {
			t.Errorf("CO %v: want one compact NSEC at nx.example. with NXNAME; got %v", tc.co, nsecs)
		}
		verifySection(t, m.Ns, keys)
	}
}

// A gap in the chain of a zone signed here is the zone's own defect: every
// answer that needs the missing record is a SERVFAIL, and no NSEC is
// synthesized to cover the gap (the design's Q3). Answers the chain still
// proves are unaffected, and nothing is logged as a secondary's warning.
func TestSignedHereChainGapIsServfail(t *testing.T) {
	zd, _ := signedTestZone(t, "example.", denialZone, false)
	base := zd.publishedSnapshot()
	data := map[string]*OwnerData{}
	for k, v := range base.Data {
		data[k] = v
	}
	strip := func(name string, sigsOnly bool) {
		od := *data[name]
		if sigsOnly {
			od.NSEC.RRSIGs = nil
		} else {
			od.NSEC = core.RRset{}
		}
		data[name] = &od
	}
	strip("www.example.", false)      // a NODATA at www.example. has no proof
	strip("a.wild.example.", true)    // the cover of foo.wild.example. is unsigned
	strip("insecure.example.", false) // the cut has no NSEC
	zd.snapshot.Store(zd.buildSnapshotLocked(base.Serial, data, nil))
	warnings := countDenialWarnings(t)

	for _, tc := range []struct {
		qname string
		qtype uint16
		rcode int
	}{
		{"www.example.", dns.TypeTXT, dns.RcodeServerFailure},
		{"foo.wild.example.", dns.TypeTXT, dns.RcodeServerFailure}, // a wildcard answer
		{"foo.wild.example.", dns.TypeA, dns.RcodeServerFailure},   // a wildcard NODATA
		{"insecure.example.", dns.TypeDS, dns.RcodeServerFailure},
		{"www.insecure.example.", dns.TypeA, dns.RcodeServerFailure}, // a referral
		{"nx.example.", dns.TypeA, dns.RcodeNameError},               // still proved
	} {
		m := denialAsk(t, zd, nil, tc.qname, tc.qtype, false)
		if m.Rcode != tc.rcode {
			t.Errorf("%s %s: rcode %s, want %s; authority %v", tc.qname, dns.TypeToString[tc.qtype],
				dns.RcodeToString[m.Rcode], dns.RcodeToString[tc.rcode], m.Ns)
		}
		if tc.rcode == dns.RcodeServerFailure && len(m.Ns) != 0 {
			t.Errorf("%s %s: a SERVFAIL carried authority records: %v", tc.qname, dns.TypeToString[tc.qtype], m.Ns)
		}
	}
	if *warnings != 0 {
		t.Errorf("a zone signed here logged %d secondary warnings; its gaps are errors", *warnings)
	}
}
