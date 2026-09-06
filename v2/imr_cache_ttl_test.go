/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The TTL a resolver puts on the wire is what is LEFT of the cached entry's
 * lifetime. Serving the stored TTL re-arms every downstream cache on every
 * fetch, so nothing ever expires.
 */
package tdns

import (
	"context"
	"testing"
	"time"

	"fmt"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// ageEntry rewinds an entry's expiry so it has `left` of its lifetime to run.
// It writes through the raw key because Set() recomputes Expiration from the
// stored records' TTLs and discards whatever the caller passed -- the same
// override handleNegative flags with an XXX where it wants an RFC 2308
// negative TTL.
func ageEntry(t *testing.T, imr *Imr, name string, qtype uint16, left time.Duration) {
	t.Helper()
	c := imr.Cache.Get(name, qtype)
	if c == nil {
		t.Fatalf("no cache entry for %s %s to age", name, dns.TypeToString[qtype])
	}
	c.Expiration = time.Now().Add(left)
	imr.Cache.RRsets.Set(fmt.Sprintf("%s::%d", core.CanonicalizeName(name), qtype), *c)
	if got := imr.Cache.Get(name, qtype); got == nil || !nearTTL(got.RemainingTTL(time.Now()), uint32(left/time.Second)) {
		t.Fatalf("aging %s %s did not take", name, dns.TypeToString[qtype])
	}
}

// nearTTL allows the one-second slack that comes from RemainingTTL rounding a
// sub-second remainder down: an entry given 600s and read back a moment later
// legitimately has 599.
func nearTTL(got, want uint32) bool { return got == want || got+1 == want }

// seedAnswer caches a positive answer with `left` of its `ttl`-second lifetime
// still to run, as though it had been fetched (ttl-left) seconds ago.
func seedAnswer(t *testing.T, imr *Imr, rrstr string, left time.Duration) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(rrstr)
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	h := rr.Header()
	imr.Cache.Set(h.Name, h.Rrtype, &cache.CachedRRset{
		Name:       h.Name,
		RRtype:     h.Rrtype,
		Rcode:      uint8(dns.RcodeSuccess),
		RRset:      &core.RRset{Name: h.Name, Class: dns.ClassINET, RRtype: h.Rrtype, RRs: []dns.RR{rr}},
		Context:    cache.ContextAnswer,
		State:      cache.ValidationStateSecure,
		Expiration: time.Now().Add(left),
		Transport:  core.TransportDo53,
	})
	return rr
}

// THE REGRESSION, at the wire. The issue observed the apex SOA served with
// TTL 900 on every repeat while demonstrably coming from cache -- a stale
// serial at full TTL.
func TestResponderServesRemainingTTLNotStoredTTL(t *testing.T) {
	imr := newTestImr(t)
	seedAnswer(t, imr, "example. 900 IN SOA ns1.example. hostmaster.example. 1 7200 1800 604800 900",
		900*time.Second)
	ageEntry(t, imr, "example.", dns.TypeSOA, 600*time.Second)

	r := new(dns.Msg)
	r.SetQuestion("example.", dns.TypeSOA)
	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, "example.", dns.TypeSOA, &edns0.MsgOptions{RD: true})

	if cw.got == nil {
		t.Fatal("responder wrote no response")
	}
	if len(cw.got.Answer) != 1 {
		t.Fatalf("ANSWER holds %d records, want 1", len(cw.got.Answer))
	}
	if got := cw.got.Answer[0].Header().Ttl; !nearTTL(got, 600) {
		t.Errorf("served TTL = %d, want 600; the entry was cached with 900 and has 600 left. "+
			"A downstream cache re-arms to the full TTL on every fetch, so the record never expires", got)
	}
}

// Repeating the query must keep counting down, not hand out the same number
// forever -- and must not decay the cached entry either.
func TestRepeatedHitsKeepCountingDown(t *testing.T) {
	imr := newTestImr(t)
	seedAnswer(t, imr, "host.example. 300 IN A 192.0.2.1", 300*time.Second)
	ageEntry(t, imr, "host.example.", dns.TypeA, 120*time.Second)

	serve := func() uint32 {
		r := new(dns.Msg)
		r.SetQuestion("host.example.", dns.TypeA)
		cw := &captureWriter{}
		imr.ImrResponder(context.Background(), cw, r, "host.example.", dns.TypeA, &edns0.MsgOptions{RD: true})
		if cw.got == nil || len(cw.got.Answer) != 1 {
			t.Fatal("responder did not serve the cached answer")
		}
		return cw.got.Answer[0].Header().Ttl
	}

	if first, second := serve(), serve(); !nearTTL(first, 120) || !nearTTL(second, 120) {
		t.Errorf("served TTLs %d then %d, want 120 both times (the same instant, so the same remainder)", first, second)
	}

	// The stored record keeps the TTL it was cached with: serving reads the
	// entry's expiry, it does not consume it.
	c := imr.Cache.Get("host.example.", dns.TypeA)
	if c == nil {
		t.Fatal("entry vanished from the cache")
	}
	if got := c.RRset.RRs[0].Header().Ttl; got != 300 {
		t.Errorf("cached record's TTL is %d, want the stored 300 -- serving rewrote the cache", got)
	}
}

// The proof of a denial is cached data too. Served at its original TTL it
// re-arms a downstream negative cache exactly as a positive answer would.
func TestNegativeProofIsServedWithRemainingTTL(t *testing.T) {
	imr := newTestImr(t)
	seedNodata(t, imr, "ns1.example.", dns.TypeSOA, "example.")

	ageEntry(t, imr, "ns1.example.", dns.TypeSOA, 600*time.Second)

	r := new(dns.Msg)
	r.SetQuestion("ns1.example.", dns.TypeSOA)
	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, "ns1.example.", dns.TypeSOA, &edns0.MsgOptions{RD: true})

	if cw.got == nil {
		t.Fatal("responder wrote no response")
	}
	if len(cw.got.Answer) != 0 {
		t.Fatalf("NODATA carried %d records in ANSWER, want 0", len(cw.got.Answer))
	}
	if len(cw.got.Ns) == 0 {
		t.Fatal("NODATA carried no proof in AUTHORITY")
	}
	if got := cw.got.Ns[0].Header().Ttl; !nearTTL(got, 600) {
		t.Errorf("proof SOA served with TTL %d, want 600", got)
	}
}
