/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A response says when what it carries expires from the cache, so a caller
// that keeps the data, as peer discovery does, knows when to look again. The
// fresh answer and the cached one say the same: both are the entry's
// expiration.

// near reports whether got is within a few seconds of want.
func near(got, want time.Time) bool {
	d := got.Sub(want)
	return d > -3*time.Second && d < 3*time.Second
}

func TestImrResponseExpirationOfAnAnswer(t *testing.T) {
	const zone = "expiry.example."
	const qname = "www." + zone
	txt := &dns.TXT{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"x"}}
	port, stop := startAnswerDouble(t, zone, dns.TypeTXT, []dns.RR{txt})
	t.Cleanup(stop)
	imr := denialTestImr(t, zone, port)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	want := time.Now().Add(300 * time.Second)
	asks := []struct {
		name string
		ask  func() (*ImrResponse, error)
	}{
		{"fresh", func() (*ImrResponse, error) { return imr.ImrQuery(ctx, qname, dns.TypeTXT, dns.ClassINET, nil) }},
		{"cached", func() (*ImrResponse, error) { return imr.ImrQuery(ctx, qname, dns.TypeTXT, dns.ClassINET, nil) }},
		{"past the cache", func() (*ImrResponse, error) { return imr.ImrQueryFresh(ctx, qname, dns.TypeTXT, dns.ClassINET) }},
	}
	var first time.Time
	for i, a := range asks {
		resp, err := a.ask()
		if err != nil || resp == nil || resp.Error || resp.RRset == nil {
			t.Fatalf("%s: err=%v resp=%+v", a.name, err, resp)
		}
		if !near(resp.Expiration, want) {
			t.Errorf("%s: Expiration %v, want about %v (the TTL)", a.name, resp.Expiration, want)
		}
		if i == 0 {
			first = resp.Expiration
		} else if i == 1 && !resp.Expiration.Equal(first) {
			t.Errorf("cached: Expiration %v, fresh said %v: want the same entry's", resp.Expiration, first)
		}
	}
}

func TestImrResponseExpirationOfADenial(t *testing.T) {
	const zone = "expirydenial.example."
	const nxname = "nope." + zone
	for _, tc := range []struct {
		name  string
		qname string
	}{
		{"NODATA", "www." + zone},
		{"NXDOMAIN", nxname},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port, _ := startDenialAuthDouble(t, zone, nxname, tc.qname, dns.TypeTXT, 60)
			imr := denialTestImr(t, zone, port)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			want := time.Now().Add(60 * time.Second)
			for _, ask := range []string{"fresh", "cached"} {
				resp, err := imr.ImrQuery(ctx, tc.qname, dns.TypeTXT, dns.ClassINET, nil)
				if err != nil || resp == nil || resp.Error || resp.Denial == 0 {
					t.Fatalf("%s: err=%v resp=%+v", ask, err, resp)
				}
				if !near(resp.Expiration, want) {
					t.Errorf("%s: Expiration %v, want about %v (the negative TTL)", ask, resp.Expiration, want)
				}
			}
		})
	}
}

// A Secure answer expires with its signatures when they run out before its
// TTL: the response says when the signatures do.
func TestImrResponseExpirationOfASecureAnswerFollowsItsSignatures(t *testing.T) {
	const qname = "www.signed.example."
	imr := newTestImr(t)
	txt := &dns.TXT{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}, Txt: []string{"x"}}
	sigExpires := time.Now().Add(10 * time.Minute)
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: dns.TypeTXT, Algorithm: dns.ED25519, Labels: 3, OrigTtl: 3600, KeyTag: 4711, SignerName: "signed.example.",
		Inception: uint32(time.Now().Add(-time.Hour).Unix()), Expiration: uint32(sigExpires.Unix())}
	imr.Cache.Set(qname, dns.TypeTXT, &cache.CachedRRset{
		Name: qname, RRtype: dns.TypeTXT,
		RRset:   &core.RRset{Name: qname, Class: dns.ClassINET, RRtype: dns.TypeTXT, RRs: []dns.RR{txt}, RRSIGs: []dns.RR{sig}},
		Context: cache.ContextAnswer, State: cache.ValidationStateSecure,
		Transport: core.TransportDo53,
	})

	resp, err := imr.ImrQuery(context.Background(), qname, dns.TypeTXT, dns.ClassINET, nil)
	if err != nil || resp == nil || resp.Error || !resp.Validated {
		t.Fatalf("err=%v resp=%+v", err, resp)
	}
	if !near(resp.Expiration, sigExpires) {
		t.Errorf("Expiration %v, want about %v (the signatures' expiration, before the TTL's)", resp.Expiration, sigExpires)
	}
}

// expiresWith takes the entry's expiration only when the entry holds what the
// response says.
func TestImrResponseExpiresWith(t *testing.T) {
	exp := time.Now().Add(time.Minute)
	rrset := &core.RRset{Name: "x.example.", RRtype: dns.TypeTXT}
	answer := &cache.CachedRRset{RRset: rrset, Context: cache.ContextAnswer, Expiration: exp}
	nodata := &cache.CachedRRset{RRset: rrset, Context: cache.ContextNoErrNoAns, Expiration: exp}
	for _, tc := range []struct {
		name  string
		resp  ImrResponse
		entry *cache.CachedRRset
		want  bool
	}{
		{"answer, answer entry", ImrResponse{RRset: rrset}, answer, true},
		{"answer, denial entry", ImrResponse{RRset: rrset}, nodata, false},
		{"denial, same kind", ImrResponse{Denial: cache.ContextNoErrNoAns}, nodata, true},
		{"denial, other kind", ImrResponse{Denial: cache.ContextNXDOMAIN}, nodata, false},
		{"denial, answer entry", ImrResponse{Denial: cache.ContextNoErrNoAns}, answer, false},
		{"error", ImrResponse{RRset: rrset, Error: true}, answer, false},
		{"no entry", ImrResponse{RRset: rrset}, nil, false},
		{"nothing", ImrResponse{}, answer, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := tc.resp
			resp.expiresWith(tc.entry)
			if got := !resp.Expiration.IsZero(); got != tc.want {
				t.Errorf("Expiration set %v, want %v", got, tc.want)
			}
		})
	}
}

// The expiration comes from this lookup's entry only (CodeRabbit on #947): the
// one a cache hit read; for a fresh answer, the entry that holds its RRset;
// for a fresh denial, one stored since the lookup began. An entry another
// lookup left under the question gives none: an older denial, when a fresh
// denial comes from a CNAME and is not cached there, or the answer of a fresh
// lookup that overlaps this one.
func TestLookupEntryIsThisLookups(t *testing.T) {
	started := time.Now()
	rrA, rrB := &core.RRset{Name: "a."}, &core.RRset{Name: "b."}
	soa := &core.RRset{Name: "soa."}
	freshA := &cache.CachedRRset{RRset: rrA, Ttl: 60, Expiration: started.Add(61 * time.Second)}
	freshB := &cache.CachedRRset{RRset: rrB, Ttl: 60, Expiration: started.Add(61 * time.Second)}
	before := &cache.CachedRRset{RRset: rrA, Ttl: 600, Expiration: started.Add(500 * time.Second)}
	shortened := &cache.CachedRRset{RRset: rrA, Ttl: 30, Expiration: started.Add(30 * time.Second)}
	denialNow := &cache.CachedRRset{RRset: soa, Ttl: 60, Expiration: started.Add(61 * time.Second)}
	denialBefore := &cache.CachedRRset{RRset: soa, Ttl: 600, Expiration: started.Add(500 * time.Second)}
	for _, tc := range []struct {
		name       string
		entry, hit *cache.CachedRRset
		answer     *core.RRset
		want       *cache.CachedRRset
	}{
		{"a fresh answer, its entry", freshA, nil, rrA, freshA},
		{"a fresh answer, another lookup's entry", freshB, nil, rrA, nil},
		{"a fresh answer, no entry", nil, nil, rrA, nil},
		{"a fresh denial, stored by this lookup", denialNow, nil, nil, denialNow},
		{"a fresh denial, an entry from before", denialBefore, nil, nil, nil},
		{"a hit", before, before, rrA, before},
		{"a hit, stored again shorter", shortened, before, rrA, shortened},
		{"a hit, replaced since", freshB, before, rrA, before},
		{"a hit, gone since", nil, before, rrA, before},
	} {
		if got := lookupEntry(tc.entry, tc.hit, tc.answer, started); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}
