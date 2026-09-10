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

// entSetCO sets the Compact Answers OK flag (RFC 9824 section 5.1), bit 14 of
// the OPT TTL field. By hand because edns0.SetCO arrives with the
// compact-denial work on another branch; the two are independent.
func entSetCO(m *dns.Msg) {
	if opt := m.IsEdns0(); opt != nil {
		opt.Hdr.Ttl |= 1 << 14
	}
}

func entAsk(t *testing.T, zd *ZoneData, kdb *KeyDB, qname string, qtype uint16, do, co bool) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(qname, qtype)
	req.SetEdns0(4096, do)
	if co {
		entSetCO(req)
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
