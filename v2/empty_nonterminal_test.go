/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"testing"

	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// entZone has three empty non-terminals -- a.example, mail.example and
// _tcp.mail.example -- each owning nothing while a descendant owns something.
const entZone = `example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200
example. 3600 IN NS ns.example.
ns.example. 3600 IN A 10.0.0.1
www.a.example. 3600 IN A 10.0.0.2
_25._tcp.mail.example. 3600 IN TXT "tlsa-ish"
`

func entAsk(t *testing.T, zd *ZoneData, kdb *KeyDB, qname string, qtype uint16, do, co bool) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(qname, qtype)
	req.SetEdns0(4096, do)
	if co {
		edns0.SetCO(req)
	}
	msgo, err := edns0.ExtractFlagsAndEDNS0Options(req)
	if err != nil {
		t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
	}
	rw := &fakeRW{}
	if err := zd.QueryResponder(context.Background(), rw, req, qname, qtype, msgo, kdb, nil); err != nil {
		t.Fatalf("QueryResponder(%s): %v", qname, err)
	}
	if rw.written == nil {
		t.Fatalf("no response written for %s", qname)
	}
	return rw.written
}

func entNSEC(t *testing.T, m *dns.Msg) *dns.NSEC {
	t.Helper()
	for _, rr := range m.Ns {
		if nsec, ok := rr.(*dns.NSEC); ok {
			return nsec
		}
	}
	t.Fatalf("no NSEC in AUTHORITY: %v", m.Ns)
	return nil
}

func entHasType(nsec *dns.NSEC, t uint16) bool {
	for _, typ := range nsec.TypeBitMap {
		if typ == t {
			return true
		}
	}
	return false
}

// An empty non-terminal exists. RFC 1034 section 4.3.2 resolves against the
// label tree and RFC 4592 section 2.2.2 names the case, so the answer is
// NODATA. It was NXDOMAIN, and under DO the zone signed an NSEC bearing NXNAME
// -- proof from the zone's own key that a name does not exist, beside an answer
// it will sign for that name's descendant.
func TestEmptyNonTerminalIsNodata(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := testSnapshotZone(t, "example.", entZone)

	for _, qname := range []string{"a.example.", "mail.example.", "_tcp.mail.example."} {
		t.Run(qname, func(t *testing.T) {
			m := entAsk(t, zd, kdb, qname, dns.TypeA, false, false)
			if m.Rcode != dns.RcodeSuccess {
				t.Errorf("rcode = %s, want NOERROR: the name has descendants that exist",
					dns.RcodeToString[m.Rcode])
			}
			if len(m.Answer) != 0 {
				t.Errorf("ANSWER has %d records; a NODATA has none", len(m.Answer))
			}
			if len(m.Ns) == 0 {
				t.Error("no SOA in AUTHORITY")
			}
		})
	}

	// The descendants that make them non-terminal still answer.
	if m := entAsk(t, zd, kdb, "www.a.example.", dns.TypeA, false, false); m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Errorf("www.a.example. A = %s with %d answers, want NOERROR with 1",
			dns.RcodeToString[m.Rcode], len(m.Answer))
	}

	// And a name with nothing at or below it is still NXDOMAIN.
	if m := entAsk(t, zd, kdb, "nosuch.example.", dns.TypeA, false, false); m.Rcode != dns.RcodeNameError {
		t.Errorf("nosuch.example. A = %s, want NXDOMAIN", dns.RcodeToString[m.Rcode])
	}
}

// RFC 9824 section 3.2: "For a query for an ENT, the NSEC Type Bit Maps field
// will only contain RRSIG and NSEC." NXNAME in that bitmap is the signed half
// of the bug: a validator holds cryptographic proof of non-existence for a name
// whose descendant validates.
func TestEmptyNonTerminalProofCarriesNoNXNAME(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := testSnapshotZone(t, "example.", entZone)

	for _, co := range []bool{false, true} {
		name := "DO"
		if co {
			name = "DO and CO"
		}
		t.Run(name, func(t *testing.T) {
			m := entAsk(t, zd, kdb, "a.example.", dns.TypeA, true, co)
			if m.Rcode != dns.RcodeSuccess {
				t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
			}
			nsec := entNSEC(t, m)
			if nsec.Hdr.Name != "a.example." {
				t.Errorf("NSEC owner = %s, want a.example.", nsec.Hdr.Name)
			}
			if entHasType(nsec, dns.TypeNXNAME) {
				t.Errorf("NXNAME in an ENT bitmap; the zone is signing that a name with descendants does not exist: %s", nsec)
			}
			if !entHasType(nsec, dns.TypeNSEC) || !entHasType(nsec, dns.TypeRRSIG) {
				t.Errorf("bitmap should be exactly RRSIG and NSEC: %s", nsec)
			}
			if len(nsec.TypeBitMap) != 2 {
				t.Errorf("bitmap has %d types, want 2 (RRSIG, NSEC): %s", len(nsec.TypeBitMap), nsec)
			}
		})
	}

	// The contrast: a name that really does not exist still gets NXNAME.
	m := entAsk(t, zd, kdb, "nosuch.example.", dns.TypeA, true, true)
	if !entHasType(entNSEC(t, m), dns.TypeNXNAME) {
		t.Errorf("NXNAME missing for a name that genuinely does not exist: %v", m.Ns)
	}
}

// RFC 4592 section 4.1: a wildcard is used only for a name that does not
// exist. An ENT exists, so it must not be answered from the wildcard -- which
// is why the check stands ahead of the wildcard lookup rather than beside the
// NXDOMAIN it replaces.
func TestEmptyNonTerminalBlocksWildcardSynthesis(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := testSnapshotZone(t, "example.", `example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200
example. 3600 IN NS ns.example.
ns.example. 3600 IN A 10.0.0.1
*.example. 3600 IN A 10.0.0.9
www.a.example. 3600 IN A 10.0.0.2
`)

	m := entAsk(t, zd, kdb, "a.example.", dns.TypeA, false, false)
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 0 {
		t.Errorf("the wildcard answered for an ENT: %v", m.Answer)
	}

	// A name that does not exist still gets the wildcard.
	if m := entAsk(t, zd, kdb, "nosuch.example.", dns.TypeA, false, false); len(m.Answer) != 1 {
		t.Errorf("wildcard did not answer for a nonexistent name: %v", m.Answer)
	}
}

// DS is trapped ahead of the ordinary path, so it needs its own answer.
func TestEmptyNonTerminalDSQuery(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := testSnapshotZone(t, "example.", entZone)

	m := entAsk(t, zd, kdb, "a.example.", dns.TypeDS, false, false)
	if m.Rcode != dns.RcodeSuccess {
		t.Errorf("a.example. DS = %s, want NOERROR", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 0 {
		t.Errorf("ANSWER has %d records; a NODATA has none", len(m.Answer))
	}
}

// The walk itself: every ancestor between an owner and the apex that owns
// nothing, and nothing else.
func TestEntNamesFrom(t *testing.T) {
	data := map[string]*OwnerData{
		"example.":               {},
		"ns.example.":            {},
		"www.a.example.":         {},
		"_25._tcp.mail.example.": {},
	}
	ents := entNamesFrom("example.", data)

	for _, want := range []string{"a.example.", "mail.example.", "_tcp.mail.example."} {
		if _, ok := ents[want]; !ok {
			t.Errorf("%s missing from the ENT set: %v", want, ents)
		}
	}
	for _, unwanted := range []string{"example.", "ns.example.", "www.a.example.", "_25._tcp.mail.example."} {
		if _, ok := ents[unwanted]; ok {
			t.Errorf("%s is an owner and must not be an ENT: %v", unwanted, ents)
		}
	}
	if len(ents) != 3 {
		t.Errorf("want 3 ENTs, got %d: %v", len(ents), ents)
	}

	// A flat zone has none, and the result is nil rather than an empty map.
	if got := entNamesFrom("example.", map[string]*OwnerData{"example.": {}, "www.example.": {}}); got != nil {
		t.Errorf("flat zone produced %v, want nil", got)
	}
}

// An owner can exist in Data holding no records — an UPDATE that deleted its
// last RRset without deleting the node. With descendants beneath it that is an
// empty non-terminal like any other, and it must not become a signed denial
// while its children still answer.
//
// It reaches QueryResponder by a different route: the name IS in Data, so
// nameExistsFrom sends it past the ENT check to the Count() == 0 branch, which
// used to answer NXDOMAIN with NXNAME. A snapshot is built directly here
// because a zone file cannot express an owner with no records.
func TestEmptyOwnerNodeWithDescendantsIsNodata(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := testSnapshotZone(t, "example.", entZone)

	base := zd.publishedSnapshot()
	if base == nil {
		t.Fatal("no published snapshot")
	}
	data := map[string]*OwnerData{}
	for k, v := range base.Data {
		data[k] = v
	}
	// a.example. gains a node holding nothing; www.a.example. stays beneath it.
	// vestigial.example. gains one with nothing beneath it at all.
	data["a.example."] = NewOwnerData("a.example.")
	data["vestigial.example."] = NewOwnerData("vestigial.example.")
	zd.snapshot.Store(zd.buildSnapshotLocked(base.Serial, data, nil))

	t.Run("with descendants: NODATA", func(t *testing.T) {
		m := entAsk(t, zd, kdb, "a.example.", dns.TypeA, true, true)
		if m.Rcode != dns.RcodeSuccess {
			t.Errorf("rcode = %s, want NOERROR: www.a.example. still answers beneath it",
				dns.RcodeToString[m.Rcode])
		}
		if nsec := entNSEC(t, m); entHasType(nsec, dns.TypeNXNAME) {
			t.Errorf("NXNAME for a name with descendants: %s", nsec)
		}
	})

	t.Run("nothing beneath it: still NXDOMAIN", func(t *testing.T) {
		m := entAsk(t, zd, kdb, "vestigial.example.", dns.TypeA, true, true)
		if m.Rcode != dns.RcodeNameError {
			t.Errorf("rcode = %s, want NXDOMAIN: the node holds nothing and nothing is beneath it",
				dns.RcodeToString[m.Rcode])
		}
	})
}

// #594 landed the CO echo and this PR landed the ENT answer; they meet on the
// same response. A CO client asking about an ENT gets the flag (RFC 9824
// §5.1 puts it on every response to a CO query) and a bitmap with no NXNAME
// (§3.2). Neither change can quietly undo the other.
func TestEmptyNonTerminalAnswersACOClient(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := testSnapshotZone(t, "example.", entZone)

	m := entAsk(t, zd, kdb, "a.example.", dns.TypeA, true, true)
	if m.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
	}
	if !edns0.HasCO(m) {
		t.Error("no CO on a response to a CO query")
	}
	if nsec := entNSEC(t, m); entHasType(nsec, dns.TypeNXNAME) {
		t.Errorf("NXNAME in an ENT bitmap: %s", nsec)
	}

	// And the contrast still holds with CO in play.
	nx := entAsk(t, zd, kdb, "nosuch.example.", dns.TypeA, true, true)
	if nx.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN for a name that does not exist", dns.RcodeToString[nx.Rcode])
	}
	if !entHasType(entNSEC(t, nx), dns.TypeNXNAME) {
		t.Error("NXNAME missing for a name that genuinely does not exist")
	}
}
