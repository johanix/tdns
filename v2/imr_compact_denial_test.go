/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * An RFC 9824 compact denial of existence reaches the resolver as NOERROR
 * plus an NSEC owned by the denied name with NXNAME in its bitmap. The
 * resolver understands that shape, so it owes each of its own clients the
 * answer that client can cope with: NXDOMAIN to one that will never see the
 * NSEC, NOERROR to a validator that would read the NSEC as existence, and
 * NXDOMAIN again to one that said it reads NXNAME. And a client that did not
 * set DO gets no DNSSEC records at all, the NSEC included.
 */
package tdns

import (
	"context"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

func testSOA(t *testing.T, apex string) dns.RR {
	t.Helper()
	soa, err := dns.NewRR(apex + " 900 IN SOA ns1." + apex + " hostmaster." + apex + " 1 7200 1800 604800 900")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	return soa
}

func testNSEC(owner string, bitmap []uint16) *dns.NSEC {
	return &dns.NSEC{
		Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 900},
		NextDomain: "\000." + owner,
		TypeBitMap: bitmap,
	}
}

// testRRSIG is a signature-shaped record: the tests here ask whether a
// signature is served, never whether it verifies.
func testRRSIG(owner string, covered uint16, signer string) *dns.RRSIG {
	now := time.Now()
	return &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 900},
		TypeCovered: covered,
		Algorithm:   dns.ED25519,
		Labels:      uint8(dns.CountLabel(owner)),
		OrigTtl:     900,
		Expiration:  uint32(now.Add(24 * time.Hour).Unix()),
		Inception:   uint32(now.Add(-time.Hour).Unix()),
		KeyTag:      12345,
		SignerName:  signer,
		Signature:   "AAAA",
	}
}

// signedProof is the AUTHORITY section of a signed negative answer as the
// resolver caches it: the apex SOA and the NSEC at the qname, each with its
// signature in the RRset beside it.
func signedProof(t *testing.T, qname, apex string, bitmap []uint16) (soa, nsec *core.RRset) {
	t.Helper()
	soa = &core.RRset{
		Name: apex, Class: dns.ClassINET, RRtype: dns.TypeSOA,
		RRs:    []dns.RR{testSOA(t, apex)},
		RRSIGs: []dns.RR{testRRSIG(apex, dns.TypeSOA, apex)},
	}
	nsec = &core.RRset{
		Name: qname, Class: dns.ClassINET, RRtype: dns.TypeNSEC,
		RRs:    []dns.RR{testNSEC(qname, bitmap)},
		RRSIGs: []dns.RR{testRRSIG(qname, dns.TypeNSEC, apex)},
	}
	return soa, nsec
}

// seedCompactDenial caches what handleNegative makes of a compact denial for
// a name that does not exist: NXDOMAIN, marked compact, with the proof.
func seedCompactDenial(t *testing.T, imr *Imr, qname string, qtype uint16, apex string) {
	t.Helper()
	soa, nsec := signedProof(t, qname, apex, []uint16{dns.TypeNSEC, dns.TypeRRSIG, dns.TypeNXNAME})
	imr.Cache.Set(qname, qtype, &cache.CachedRRset{
		Name:          qname,
		RRtype:        qtype,
		Rcode:         uint8(dns.RcodeNameError),
		RRset:         soa,
		NegAuthority:  []*core.RRset{soa, nsec},
		CompactDenial: true,
		Context:       cache.ContextNXDOMAIN,
		State:         cache.ValidationStateSecure,
		Expiration:    time.Now().Add(15 * time.Minute),
		Transport:     core.TransportDo53,
	})
}

// flaggedQuery is an EDNS query with DO and CO as asked, the way dog sends
// one with +dnssec and +co.
func flaggedQuery(qname string, qtype uint16, do, co bool) *dns.Msg {
	r := new(dns.Msg)
	r.SetQuestion(qname, qtype)
	r.SetEdns0(4096, do)
	if co {
		edns0.SetCO(r)
	}
	return r
}

func answerFromCache(t *testing.T, imr *Imr, r *dns.Msg) *dns.Msg {
	t.Helper()
	msgo, err := edns0.ExtractFlagsAndEDNS0Options(r)
	if err != nil {
		t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
	}
	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, r.Question[0].Name, r.Question[0].Qtype, msgo)
	if cw.got == nil {
		t.Fatal("no response written")
	}
	return cw.got
}

func authorityHas(m *dns.Msg, rrtype uint16) bool {
	for _, rr := range m.Ns {
		if rr.Header().Rrtype == rrtype {
			return true
		}
	}
	return false
}

// THE MATRIX. Same cached denial, four clients, and the answer follows the
// client: what the NSEC would mean to it decides the rcode, DO decides
// whether it sees the NSEC at all, and CO on the response marks the one row
// that is the compact form the client asked for.
func TestCompactDenialAnswerFollowsTheClient(t *testing.T) {
	const qname = "nosuch.example."
	imr := newTestImr(t)
	seedCompactDenial(t, imr, qname, dns.TypeMX, "example.")

	cases := []struct {
		name      string
		do, co    bool
		rcode     int
		nsec, sig bool
		coBack    bool
	}{
		// Never sees the NSEC, so nothing contradicts the truth.
		{"no DO, no CO", false, false, dns.RcodeNameError, false, false, false},
		// A validator that reads the NSEC as "this name exists": NOERROR is
		// the only answer consistent with the proof it is given.
		{"DO, no CO", true, false, dns.RcodeSuccess, true, true, false},
		// CO without DO is a client that reads NXNAME but asked for no
		// DNSSEC records: a plain NXDOMAIN, and CO back because the flag
		// answers "this resolver speaks CO", not "this answer is compact".
		{"CO, no DO", false, true, dns.RcodeNameError, false, false, true},
		// The client said it reads NXNAME: the compact form, marked as such.
		{"DO and CO", true, true, dns.RcodeNameError, true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := answerFromCache(t, imr, flaggedQuery(qname, dns.TypeMX, tc.do, tc.co))
			if resp.Rcode != tc.rcode {
				t.Errorf("rcode = %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[tc.rcode])
			}
			if !authorityHas(resp, dns.TypeSOA) {
				t.Errorf("no SOA in AUTHORITY; a negative answer carries one for every client")
			}
			if got := authorityHas(resp, dns.TypeNSEC); got != tc.nsec {
				t.Errorf("NSEC in AUTHORITY = %v, want %v", got, tc.nsec)
			}
			if got := authorityHas(resp, dns.TypeRRSIG); got != tc.sig {
				t.Errorf("RRSIG in AUTHORITY = %v, want %v", got, tc.sig)
			}
			if got := edns0.HasCO(resp); got != tc.coBack {
				t.Errorf("CO on response = %v, want %v", got, tc.coBack)
			}
			if len(resp.Answer) != 0 {
				t.Errorf("ANSWER has %d records; a denial has none", len(resp.Answer))
			}
		})
	}
}

// THE DO LEAK, on an ordinary NODATA too. The cached proof of a NODATA holds
// the NSEC beside the SOA, and a client that did not set DO was served both.
func TestCachedNodataServesNoNSECWithoutDO(t *testing.T) {
	const qname, apex = "www.example.", "example."
	imr := newTestImr(t)
	soa, nsec := signedProof(t, qname, apex, []uint16{dns.TypeA, dns.TypeNSEC, dns.TypeRRSIG})
	imr.Cache.Set(qname, dns.TypeMX, &cache.CachedRRset{
		Name:         qname,
		RRtype:       dns.TypeMX,
		Rcode:        uint8(dns.RcodeSuccess),
		RRset:        soa,
		NegAuthority: []*core.RRset{soa, nsec},
		Context:      cache.ContextNoErrNoAns,
		State:        cache.ValidationStateSecure,
		Expiration:   time.Now().Add(15 * time.Minute),
		Transport:    core.TransportDo53,
	})

	resp := answerFromCache(t, imr, flaggedQuery(qname, dns.TypeMX, false, false))
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if !authorityHas(resp, dns.TypeSOA) {
		t.Error("no SOA in AUTHORITY")
	}
	if authorityHas(resp, dns.TypeNSEC) || authorityHas(resp, dns.TypeRRSIG) {
		t.Errorf("DNSSEC records served to a client without DO: %v", resp.Ns)
	}

	resp = answerFromCache(t, imr, flaggedQuery(qname, dns.TypeMX, true, false))
	if !authorityHas(resp, dns.TypeNSEC) || !authorityHas(resp, dns.TypeRRSIG) {
		t.Errorf("proof withheld from a DO client: %v", resp.Ns)
	}
}

// What the authoritative server sends is NOERROR. What it proves is that the
// name does not exist, and that is what goes in the cache: NXDOMAIN, marked
// compact, whether or not the proof could be validated. The proof here is
// unsigned, so there is no validation and nothing to fetch, and the
// classification still has to come out right.
func TestHandleNegativeCachesCompactDenialAsNXDOMAIN(t *testing.T) {
	const qname, apex = "nosuch.example.", "example."
	imr := newTestImr(t)

	upstream := func(bitmap []uint16) *dns.Msg {
		r := new(dns.Msg)
		r.SetQuestion(qname, dns.TypeMX)
		r.Response = true
		r.Rcode = dns.RcodeSuccess
		r.Ns = []dns.RR{testSOA(t, apex), testNSEC(qname, bitmap)}
		return r
	}

	ctxt, rcode, ok := imr.handleNegative(qname, dns.TypeMX, upstream([]uint16{dns.TypeNSEC, dns.TypeRRSIG, dns.TypeNXNAME}), core.TransportDo53)
	if !ok {
		t.Fatal("handleNegative did not handle a compact denial")
	}
	if ctxt != cache.ContextNXDOMAIN || rcode != dns.RcodeNameError {
		t.Fatalf("classified as %s/%s, want NXDOMAIN/NXDOMAIN",
			cache.CacheContextToString[ctxt], dns.RcodeToString[rcode])
	}
	c := imr.Cache.Get(qname, dns.TypeMX)
	if c == nil {
		t.Fatal("nothing cached")
	}
	if !c.CompactDenial || c.Context != cache.ContextNXDOMAIN || c.Rcode != uint8(dns.RcodeNameError) {
		t.Fatalf("cached compact=%v context=%s rcode=%s, want compact NXDOMAIN",
			c.CompactDenial, cache.CacheContextToString[c.Context], dns.RcodeToString[int(c.Rcode)])
	}

	// Control: the NODATA form of the same NSEC is a NODATA and stays one.
	const existing = "www.example."
	r := upstream([]uint16{dns.TypeA, dns.TypeNSEC, dns.TypeRRSIG})
	r.Question[0].Name = existing
	r.Ns[1].Header().Name = existing
	ctxt, rcode, ok = imr.handleNegative(existing, dns.TypeMX, r, core.TransportDo53)
	if !ok || ctxt != cache.ContextNoErrNoAns || rcode != dns.RcodeSuccess {
		t.Fatalf("NODATA classified as %s/%s (ok=%v), want NoErrNoAns/NOERROR",
			cache.CacheContextToString[ctxt], dns.RcodeToString[rcode], ok)
	}
	if c := imr.Cache.Get(existing, dns.TypeMX); c == nil || c.CompactDenial {
		t.Fatalf("NODATA cached as a compact denial: %+v", c)
	}
}

// CD used to take the proof away and leave the rcode behind. serveNegativeResponse
// answered a +cd client with the SOA alone, whatever it had asked for, while the
// cached-answer path in ImrResponder never looked at CD and sent the NSEC. On a
// compact denial the two disagreed in the worst direction: negativeRcode
// downgrades to NOERROR *because* the client is about to read the owner=qname
// NSEC as existence, so dropping that NSEC left a +cd +dnssec client holding
// NOERROR and nothing else for a name that does not exist.
func TestCompactDenialWithCheckingDisabled(t *testing.T) {
	const qname = "nosuch.example."

	for _, tc := range []struct {
		name   string
		do, co bool
		rcode  int
		nsec   bool
	}{
		// The regression: DO asked for the proof, CD must not withhold it.
		{"CD, DO, no CO", true, false, dns.RcodeSuccess, true},
		{"CD, DO and CO", true, true, dns.RcodeNameError, true},
		// CD without DO is unchanged: the SOA and nothing else, and NXDOMAIN
		// is safe because no NSEC goes with it.
		{"CD, no DO", false, false, dns.RcodeNameError, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			imr := newTestImr(t)
			seedCompactDenial(t, imr, qname, dns.TypeMX, "example.")

			r := flaggedQuery(qname, dns.TypeMX, tc.do, tc.co)
			r.CheckingDisabled = true
			msgo, err := edns0.ExtractFlagsAndEDNS0Options(r)
			if err != nil {
				t.Fatalf("ExtractFlagsAndEDNS0Options: %v", err)
			}
			if !msgo.CD {
				t.Fatal("setup: the query did not carry CD")
			}

			w := &fakeResponseWriter{}
			m := new(dns.Msg)
			edns0.EnsureResponseOPT(m, r, dns.DefaultMsgSize)
			if _, err := imr.ProcessAuthDNSResponse(context.Background(), qname, dns.TypeMX,
				nil, dns.RcodeNameError, cache.ContextNXDOMAIN, msgo, m, w, r, core.TransportDo53); err != nil {
				t.Fatalf("ProcessAuthDNSResponse: %v", err)
			}
			if w.msg == nil {
				t.Fatal("nothing was written")
			}
			if w.msg.Rcode != tc.rcode {
				t.Errorf("rcode = %s, want %s", dns.RcodeToString[w.msg.Rcode], dns.RcodeToString[tc.rcode])
			}
			if got := authorityHas(w.msg, dns.TypeNSEC); got != tc.nsec {
				t.Errorf("NSEC in AUTHORITY = %v, want %v (a NOERROR without the NSEC is a NODATA for a name that does not exist)", got, tc.nsec)
			}
			if !authorityHas(w.msg, dns.TypeSOA) {
				t.Error("no SOA in AUTHORITY")
			}
		})
	}
}
