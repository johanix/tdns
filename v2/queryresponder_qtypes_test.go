/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// Which query types the responder answers: docs/2026-09-14-query-types-served.md.

const qtypesZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.2
www.example.	3600	IN	CAA	0 issue "ca.example"
www.example.	3600	IN	HINFO	"cpu" "os"
www.example.	3600	IN	HTTPS	1 . alpn=h2
host.example.	3600	IN	PTR	target.example.
dn.example.	3600	IN	DNAME	other.example.
unknown.example.	3600	IN	TYPE20000	\# 4 0a000001
private.example.	3600	IN	TYPE65400	\# 2 abcd
alias.example.	3600	IN	CNAME	www.example.
*.wild.example.	3600	IN	TXT	"w"
*.wild.example.	3600	IN	CAA	0 issue "ca.example"
sub.example.	3600	IN	NS	ns.sub.example.
ns.sub.example.	3600	IN	A	10.0.0.5
`

const qtypesSignedZoneText = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.2
www.example.	3600	IN	CAA	0 issue "ca.example"
www.example.	3600	IN	HTTPS	1 . alpn=h2
alias.example.	3600	IN	CNAME	www.example.
*.wild.example.	3600	IN	TXT	"w"
`

// qtypesSignedZone hosts qtypesSignedZoneText inline-signed, with its NSEC
// chain, and returns the KeyDB to query it with.
func qtypesSignedZone(t *testing.T) *KeyDB {
	t.Helper()
	kdb := newTestKeyDB(t)
	zd := testZone(t, "example.", qtypesSignedZoneText)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptInlineSigning: true}
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
	return kdb
}

// qtRender renders a section as "owner TYPE" lines in wire order, an RRSIG as
// "owner RRSIG COVERED", leaving out OPT.
func qtRender(rrs []dns.RR) []string {
	out := []string{}
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype == dns.TypeOPT {
			continue
		}
		s := core.CanonicalizeName(h.Name) + " " + dns.Type(h.Rrtype).String()
		if sig, ok := rr.(*dns.RRSIG); ok {
			s += " " + dns.Type(sig.TypeCovered).String()
		}
		out = append(out, s)
	}
	return out
}

// qtCovered returns the types the signatures of an RRSIG answer cover, by
// type number and without repeats, failing the test for any record that is
// not an RRSIG owned by qname.
func qtCovered(t *testing.T, rrs []dns.RR, qname string) []string {
	t.Helper()
	seen := map[uint16]bool{}
	for _, rr := range rrs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok || !core.EqualNames(sig.Hdr.Name, qname) {
			t.Errorf("unexpected record in an RRSIG answer for %s: %s", qname, rr)
			continue
		}
		seen[sig.TypeCovered] = true
	}
	types := make([]uint16, 0, len(seen))
	for rrtype := range seen {
		types = append(types, rrtype)
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	out := []string{}
	for _, rrtype := range types {
		out = append(out, dns.Type(rrtype).String())
	}
	return out
}

// qtNSEC returns the first NSEC in a section, or nil.
func qtNSEC(rrs []dns.RR) *dns.NSEC {
	for _, rr := range rrs {
		if nsec, ok := rr.(*dns.NSEC); ok {
			return nsec
		}
	}
	return nil
}

// Every data type a zone holds is answered from it: the RRset where the owner
// holds it, NODATA where it does not. Before, only the types on two lists
// were, and PTR, CAA, HTTPS and unknown types were REFUSED at the very names
// holding them.
func TestQueryResponderServesStoredTypes(t *testing.T) {
	kdb := newTestKeyDB(t)
	testSnapshotZone(t, "example.", qtypesZone)

	for _, tc := range []struct {
		what   string
		qname  string
		qtype  uint16
		rcode  int
		answer []string
	}{
		{"PTR", "host.example.", dns.TypePTR, dns.RcodeSuccess, []string{"host.example. PTR"}},
		{"CAA", "www.example.", dns.TypeCAA, dns.RcodeSuccess, []string{"www.example. CAA"}},
		{"HINFO", "www.example.", dns.TypeHINFO, dns.RcodeSuccess, []string{"www.example. HINFO"}},
		{"HTTPS", "www.example.", dns.TypeHTTPS, dns.RcodeSuccess, []string{"www.example. HTTPS"}},
		{"DNAME at its owner", "dn.example.", dns.TypeDNAME, dns.RcodeSuccess, []string{"dn.example. DNAME"}},
		{"an unassigned data type", "unknown.example.", 20000, dns.RcodeSuccess, []string{"unknown.example. TYPE20000"}},
		{"an unregistered private-use type", "private.example.", 65400, dns.RcodeSuccess, []string{"private.example. TYPE65400"}},
		{"CAA through a wildcard", "x.wild.example.", dns.TypeCAA, dns.RcodeSuccess, []string{"x.wild.example. CAA"}},
		{"a type the owner does not hold", "host.example.", dns.TypeCAA, dns.RcodeSuccess, []string{}},
		{"CNAME at an owner without one", "www.example.", dns.TypeCNAME, dns.RcodeSuccess, []string{}},
		{"RRSIG in an unsigned zone", "www.example.", dns.TypeRRSIG, dns.RcodeSuccess, []string{}},
		{"DELEG at a zone cut, not a referral", "sub.example.", core.TypeDELEG, dns.RcodeSuccess, []string{}},
		{"a name that does not exist", "nope.example.", dns.TypeCAA, dns.RcodeNameError, []string{}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			m := occAsk(t, kdb, tc.qname, tc.qtype, false)
			if m.Rcode != tc.rcode {
				t.Fatalf("rcode = %s, want %s", dns.RcodeToString[m.Rcode], dns.RcodeToString[tc.rcode])
			}
			if !m.Authoritative {
				t.Error("AA not set")
			}
			if got := qtRender(m.Answer); !reflect.DeepEqual(got, tc.answer) {
				t.Errorf("ANSWER = %q, want %q", got, tc.answer)
			}
			if len(tc.answer) == 0 {
				// NODATA and NXDOMAIN carry the SOA, and no referral's NS.
				if got := qtRender(m.Ns); !reflect.DeepEqual(got, []string{"example. SOA"}) {
					t.Errorf("AUTHORITY = %q, want the SOA alone", got)
				}
			}
		})
	}
}

// Meta-TYPEs and reserved types name nothing a zone can hold and are refused
// before the name lookup, alike at a name that exists, one that does not, one
// below a zone cut and a CNAME: REFUSED, AA clear, no NS RRset, EDE 30. Before,
// those four got a REFUSED with AA and the NS RRset, NXDOMAIN, a referral and
// the CNAME.
func TestQueryResponderRefusesMetaAndReservedTypes(t *testing.T) {
	kdb := newTestKeyDB(t)
	testSnapshotZone(t, "example.", qtypesZone)

	for _, qtype := range []uint16{0, dns.TypeOPT, dns.TypeTSIG, dns.TypeTKEY, dns.TypeMAILA, 61440, 65535} {
		for _, qname := range []string{"www.example.", "nope.example.", "host.sub.example.", "alias.example."} {
			t.Run(fmt.Sprintf("TYPE%d at %s", qtype, qname), func(t *testing.T) {
				m := occAsk(t, kdb, qname, qtype, false)
				if m.Rcode != dns.RcodeRefused {
					t.Fatalf("rcode = %s, want REFUSED", dns.RcodeToString[m.Rcode])
				}
				if m.Authoritative {
					t.Error("AA set on the refusal")
				}
				if len(m.Answer) != 0 || len(m.Ns) != 0 {
					t.Errorf("the refusal carries records: ANSWER %q, AUTHORITY %q", qtRender(m.Answer), qtRender(m.Ns))
				}
				if !hasEDE(m, dns.ExtendedErrorCodeInvalidQueryType) {
					t.Error("no EDE 30 (Invalid Query Type)")
				}
			})
		}
	}

	t.Run("a query without EDNS gets no OPT", func(t *testing.T) {
		zd := FindZone("www.example.")
		req := new(dns.Msg)
		req.SetQuestion("www.example.", dns.TypeTSIG)
		msgo, err := edns0.ExtractFlagsAndEDNS0Options(req)
		if err != nil {
			t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
		}
		rw := &fakeRW{}
		if err := zd.QueryResponder(context.Background(), rw, req, "www.example.", dns.TypeTSIG, msgo, kdb, nil); err != nil {
			t.Fatalf("QueryResponder: %v", err)
		}
		if m := rw.written; m == nil || m.Rcode != dns.RcodeRefused || m.IsEdns0() != nil {
			t.Errorf("response = %v, want REFUSED without an OPT", m)
		}
	})

	// The meta types with paths of their own keep them.
	for _, tc := range []struct {
		what  string
		qtype uint16
		rcode int
	}{
		{"NXNAME keeps its FORMERR", dns.TypeNXNAME, dns.RcodeFormatError},
		{"AXFR below the apex reaches the transfer code", dns.TypeAXFR, dns.RcodeNotAuth},
	} {
		t.Run(tc.what, func(t *testing.T) {
			if m := occAsk(t, kdb, "www.example.", tc.qtype, false); m.Rcode != tc.rcode {
				t.Errorf("rcode = %s, want %s", dns.RcodeToString[m.Rcode], dns.RcodeToString[tc.rcode])
			}
		})
	}
}

// An RRSIG query is answered with the signatures stored at the owner, with or
// without DO. At a CNAME-only owner RRSIG and NSEC are data the node holds
// (RFC 4035 section 2.5): they are answered there, and the CNAME is not
// followed. Before, every RRSIG query got NODATA, and both followed the CNAME.
func TestSignedRRSIGAndNSECAnswers(t *testing.T) {
	kdb := qtypesSignedZone(t)

	for _, tc := range []struct {
		what    string
		qname   string
		qtype   uint16
		covered []string // an RRSIG answer: the types its signatures cover
		answer  []string // otherwise the answer without DO; DO adds the RRSIG
		proof   bool     // under DO, an NSEC in AUTHORITY
	}{
		{"RRSIG at an owner holding three RRsets", "www.example.", dns.TypeRRSIG, []string{"A", "NSEC", "HTTPS", "CAA"}, nil, false},
		{"RRSIG at a CNAME-only owner", "alias.example.", dns.TypeRRSIG, []string{"CNAME", "NSEC"}, nil, false},
		{"RRSIG through a wildcard", "x.wild.example.", dns.TypeRRSIG, []string{"TXT"}, nil, true},
		{"NSEC at a CNAME-only owner", "alias.example.", dns.TypeNSEC, nil, []string{"alias.example. NSEC"}, false},
	} {
		for _, do := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, DO=%v", tc.what, do), func(t *testing.T) {
				m := occAsk(t, kdb, tc.qname, tc.qtype, do)
				if m.Rcode != dns.RcodeSuccess {
					t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
				}
				if tc.covered != nil {
					if got := qtCovered(t, m.Answer, tc.qname); !reflect.DeepEqual(got, tc.covered) {
						t.Errorf("the signatures cover %q, want %q", got, tc.covered)
					}
				} else {
					want := tc.answer
					if do {
						want = append(slices.Clone(tc.answer), tc.qname+" RRSIG NSEC")
					}
					if got := qtRender(m.Answer); !reflect.DeepEqual(got, want) {
						t.Errorf("ANSWER = %q, want %q", got, want)
					}
				}
				if tc.proof && do && qtNSEC(m.Ns) == nil {
					t.Errorf("no NSEC proving %s does not exist", tc.qname)
				}
			})
		}
	}
}

// ANY gets one RRset, the lowest type, unless allow-any-queries is set, and
// then every RRset at the owner and its NSEC. The option is read per query,
// so a change on the KeyDB -- which is what a reload makes -- changes the next
// answer. At a CNAME-only owner both modes answer the CNAME without following
// it.
func TestAnyQueries(t *testing.T) {
	kdb := qtypesSignedZone(t)

	for _, tc := range []struct {
		what   string
		allow  bool
		qname  string
		do     bool
		answer []string
	}{
		{"minimal", false, "www.example.", false, []string{"www.example. A"}},
		{"minimal, DO", false, "www.example.", true, []string{"www.example. A", "www.example. RRSIG A"}},
		{"minimal at the apex", false, "example.", false, []string{"example. NS"}},
		{"full", true, "www.example.", false, []string{
			"www.example. A", "www.example. HTTPS", "www.example. CAA", "www.example. NSEC",
		}},
		{"full, DO", true, "www.example.", true, []string{
			"www.example. A", "www.example. RRSIG A",
			"www.example. HTTPS", "www.example. RRSIG HTTPS",
			"www.example. CAA", "www.example. RRSIG CAA",
			"www.example. NSEC", "www.example. RRSIG NSEC",
		}},
		{"full at a CNAME-only owner", true, "alias.example.", false, []string{"alias.example. CNAME"}},
		{"minimal at a CNAME-only owner", false, "alias.example.", false, []string{"alias.example. CNAME"}},
		{"minimal again once the option is cleared", false, "www.example.", false, []string{"www.example. A"}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			opts := map[AuthOption]string{}
			if tc.allow {
				opts[AuthOptAllowAnyQueries] = "true"
			}
			kdb.SetOptions(opts)
			m := occAsk(t, kdb, tc.qname, dns.TypeANY, tc.do)
			if m.Rcode != dns.RcodeSuccess {
				t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
			}
			if got := qtRender(m.Answer); !reflect.DeepEqual(got, tc.answer) {
				t.Errorf("ANSWER = %q, want %q", got, tc.answer)
			}
		})
	}
}

// The answer and NODATA paths that ANY and RRSIG share with the exact match,
// in a signed zone under DO.
func TestSignedAnswersUnderDO(t *testing.T) {
	kdb := qtypesSignedZone(t)

	t.Run("CAA with its signature", func(t *testing.T) {
		m := occAsk(t, kdb, "www.example.", dns.TypeCAA, true)
		want := []string{"www.example. CAA", "www.example. RRSIG CAA"}
		if got := qtRender(m.Answer); m.Rcode != dns.RcodeSuccess || !reflect.DeepEqual(got, want) {
			t.Errorf("rcode %s, ANSWER %q; want NOERROR, %q", dns.RcodeToString[m.Rcode], got, want)
		}
	})

	t.Run("a wildcard answer with its signature and proof", func(t *testing.T) {
		m := occAsk(t, kdb, "x.wild.example.", dns.TypeTXT, true)
		want := []string{"x.wild.example. TXT", "x.wild.example. RRSIG TXT"}
		if got := qtRender(m.Answer); m.Rcode != dns.RcodeSuccess || !reflect.DeepEqual(got, want) {
			t.Errorf("rcode %s, ANSWER %q; want NOERROR, %q", dns.RcodeToString[m.Rcode], got, want)
		}
		if qtNSEC(m.Ns) == nil {
			t.Error("no NSEC proving x.wild.example. does not exist")
		}
	})

	t.Run("NODATA lists the owner's types", func(t *testing.T) {
		m := occAsk(t, kdb, "www.example.", dns.TypeMX, true)
		if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 {
			t.Fatalf("rcode %s, ANSWER %q; want NODATA", dns.RcodeToString[m.Rcode], qtRender(m.Answer))
		}
		nsec := qtNSEC(m.Ns)
		if nsec == nil {
			t.Fatal("no NSEC in the NODATA response")
		}
		for _, rrtype := range []uint16{dns.TypeA, dns.TypeCAA, dns.TypeHTTPS} {
			if !slices.Contains(nsec.TypeBitMap, rrtype) {
				t.Errorf("bitmap %v lacks %s", nsec.TypeBitMap, dns.Type(rrtype))
			}
		}
		if slices.Contains(nsec.TypeBitMap, dns.TypeMX) {
			t.Errorf("bitmap %v lists MX", nsec.TypeBitMap)
		}
	})
}

// allow-any-queries reads as a bool like minimal-responses, except that an
// invalid value reads as off.
func TestParseAuthOptionsAllowAnyQueries(t *testing.T) {
	for _, tc := range []struct {
		opts []string
		want string
		set  bool
	}{
		{nil, "", false},
		{[]string{"minimal-responses"}, "", false},
		{[]string{"allow-any-queries"}, "true", true},
		{[]string{"allow-any-queries:true"}, "true", true},
		{[]string{"allow-any-queries:false"}, "false", true},
		{[]string{"allow-any-queries:yes"}, "false", true},
	} {
		conf := &Config{}
		conf.AuthEngine.OptionsStrs = tc.opts
		conf.ParseAuthOptions()
		got, ok := conf.AuthEngine.Options[AuthOptAllowAnyQueries]
		if ok != tc.set || got != tc.want {
			t.Errorf("%q: allow-any-queries = %q (set %v), want %q (set %v)", tc.opts, got, ok, tc.want, tc.set)
		}
	}
}
