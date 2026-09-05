/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * A cached NODATA is a denial, not an answer. The SOA it carries proves the
 * denial and belongs in AUTHORITY; it must never be served as the answer to
 * the question that was denied.
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

// seedNodata caches the NODATA that an authoritative server returns for a name
// that exists without the queried type: rcode NOERROR, the zone apex SOA as
// the proof, ContextNoErrNoAns.
func seedNodata(t *testing.T, imr *Imr, qname string, qtype uint16, apex string) {
	t.Helper()
	soa, err := dns.NewRR(apex + " 900 IN SOA ns1." + apex + " hostmaster." + apex + " 1 7200 1800 604800 900")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	proof := &core.RRset{
		Name:   apex,
		Class:  dns.ClassINET,
		RRtype: dns.TypeSOA,
		RRs:    []dns.RR{soa},
	}
	imr.Cache.Set(qname, qtype, &cache.CachedRRset{
		Name:       qname,
		RRtype:     qtype,
		Rcode:      uint8(dns.RcodeSuccess),
		RRset:      proof,
		Context:    cache.ContextNoErrNoAns,
		State:      cache.ValidationStateSecure,
		Expiration: time.Now().Add(15 * time.Minute),
		Transport:  core.TransportDo53,
	})
}

// THE REGRESSION. IterativeDNSQuery's cache consult returned the stored RRset
// for every context it was willing to serve, negative ones included. For a
// NODATA entry that RRset is the SOA proving the denial -- so the caller, which
// tests `rrset != nil` before it ever looks at the context, put the zone apex
// SOA into the ANSWER section under a qname that SOA does not own, and never
// reached serveNegativeResponse.
//
// The cold resolution was correct; every cache hit afterwards was wrong.
func TestCachedNodataIsNotReturnedAsAnAnswer(t *testing.T) {
	imr := newTestImr(t)
	seedNodata(t, imr, "ns1.example.", dns.TypeSOA, "example.")

	rrset, rcode, ctxt, _, err := imr.IterativeDNSQuery(context.Background(),
		"ns1.example.", dns.TypeSOA, nil, false, 0)
	if err != nil {
		t.Fatalf("IterativeDNSQuery: %v", err)
	}
	if rrset != nil {
		t.Fatalf("a cached NODATA returned an answer RRset (%s %s, %d RRs); "+
			"callers place a non-nil RRset in the ANSWER section, so the proof SOA is served as the answer",
			rrset.Name, dns.TypeToString[rrset.RRtype], len(rrset.RRs))
	}
	if ctxt != cache.ContextNoErrNoAns {
		t.Errorf("context = %s, want NoErrNoAns -- it is what tells the caller to build a negative response",
			cache.CacheContextToString[ctxt])
	}
	if rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[rcode])
	}
}

// NXDOMAIN took the same branch and was reported unaffected only because the
// responder answers it from its own cache short-circuit first. The branch was
// wrong for both, so both are pinned.
func TestCachedNxdomainIsNotReturnedAsAnAnswer(t *testing.T) {
	imr := newTestImr(t)
	soa, err := dns.NewRR("example. 900 IN SOA ns1.example. hostmaster.example. 1 7200 1800 604800 900")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	imr.Cache.Set("nx.example.", dns.TypeA, &cache.CachedRRset{
		Name:   "nx.example.",
		RRtype: dns.TypeA,
		Rcode:  uint8(dns.RcodeNameError),
		RRset: &core.RRset{
			Name: "example.", Class: dns.ClassINET, RRtype: dns.TypeSOA, RRs: []dns.RR{soa},
		},
		Context:    cache.ContextNXDOMAIN,
		State:      cache.ValidationStateSecure,
		Expiration: time.Now().Add(15 * time.Minute),
		Transport:  core.TransportDo53,
	})

	rrset, rcode, ctxt, _, err := imr.IterativeDNSQuery(context.Background(),
		"nx.example.", dns.TypeA, nil, false, 0)
	if err != nil {
		t.Fatalf("IterativeDNSQuery: %v", err)
	}
	if rrset != nil {
		t.Fatal("a cached NXDOMAIN returned an answer RRset; the SOA proves the denial, it does not answer the query")
	}
	if ctxt != cache.ContextNXDOMAIN {
		t.Errorf("context = %s, want NXDOMAIN", cache.CacheContextToString[ctxt])
	}
	if rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN", dns.RcodeToString[rcode])
	}
}

// A positive answer must still come back as one, or the fix would have traded
// a wrong answer for no answer at all.
func TestCachedAnswerIsStillReturned(t *testing.T) {
	imr := newTestImr(t)
	a, err := dns.NewRR("host.example. 300 IN A 192.0.2.1")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	imr.Cache.Set("host.example.", dns.TypeA, &cache.CachedRRset{
		Name:   "host.example.",
		RRtype: dns.TypeA,
		Rcode:  uint8(dns.RcodeSuccess),
		RRset: &core.RRset{
			Name: "host.example.", Class: dns.ClassINET, RRtype: dns.TypeA, RRs: []dns.RR{a},
		},
		Context:    cache.ContextAnswer,
		State:      cache.ValidationStateSecure,
		Expiration: time.Now().Add(5 * time.Minute),
		Transport:  core.TransportDo53,
	})

	rrset, _, ctxt, _, err := imr.IterativeDNSQuery(context.Background(),
		"host.example.", dns.TypeA, nil, false, 0)
	if err != nil {
		t.Fatalf("IterativeDNSQuery: %v", err)
	}
	if rrset == nil || len(rrset.RRs) != 1 {
		t.Fatal("a cached positive answer was not returned")
	}
	if ctxt != cache.ContextAnswer {
		t.Errorf("context = %s, want Answer", cache.CacheContextToString[ctxt])
	}
}

// The wire shape of the defect, end to end through the responder rather than
// through the consult: ANSWER empty, the proof in AUTHORITY, AD restored.
//
// AD is the half that the consult-level tests above cannot see. The issue
// reported it cleared on every cache hit, and it comes back only because the
// negative path -- reached now that the SOA exclusion is gone -- sets it from
// the entry's validation state. A fix that put the proof in AUTHORITY but left
// AD off would still fail a validating client, and would pass every other test
// in this file.
func TestCachedNodataOnTheWireKeepsADAndAnEmptyAnswer(t *testing.T) {
	imr := newTestImr(t)
	seedNodata(t, imr, "ns1.example.", dns.TypeSOA, "example.")

	r := new(dns.Msg)
	r.SetQuestion("ns1.example.", dns.TypeSOA)
	r.SetEdns0(4096, true)

	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, "ns1.example.", dns.TypeSOA,
		&edns0.MsgOptions{RD: true, DO: true})

	if cw.got == nil {
		t.Fatal("responder wrote no response")
	}
	if cw.got.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR for NODATA", dns.RcodeToString[cw.got.Rcode])
	}
	if n := len(cw.got.Answer); n != 0 {
		t.Fatalf("ANSWER holds %d records, want 0; the zone SOA is the proof of the denial, not the answer to it (got %s)",
			n, cw.got.Answer[0].String())
	}
	if len(cw.got.Ns) == 0 {
		t.Fatal("AUTHORITY is empty; the denial carries no proof")
	}
	if owner := cw.got.Ns[0].Header().Name; owner != "example." {
		t.Errorf("proof owner = %q, want example.", owner)
	}
	if !cw.got.AuthenticatedData {
		t.Error("AD is clear on a cached NODATA whose entry is ValidationStateSecure; " +
			"a validating client sees the denial as unauthenticated")
	}
}
