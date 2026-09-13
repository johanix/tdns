/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"net"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

const verdictName = "www.verdict.example."

func verdictRRset(signed bool) *core.RRset {
	rrset := &core.RRset{
		Name:   verdictName,
		Class:  dns.ClassINET,
		RRtype: dns.TypeA,
		RRs: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: verdictName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.7"),
		}},
	}
	if signed {
		// A signature from a key nobody holds: validation cannot follow the
		// chain, which is what Indeterminate is.
		rrset.RRSIGs = []dns.RR{&dns.RRSIG{
			Hdr:         dns.RR_Header{Name: verdictName, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60},
			TypeCovered: dns.TypeA, Algorithm: dns.ED25519, Labels: 3, OrigTtl: 60,
			Inception:  uint32(time.Now().Add(-time.Hour).Unix()),
			Expiration: uint32(time.Now().Add(time.Hour).Unix()),
			KeyTag:     4242, SignerName: "verdict.example.", Signature: "AAAA",
		}}
	}
	return rrset
}

// verdictImr is a resolver with its own DNSKEY cache (the default one is
// process-wide), optionally holding a trust anchor.
func verdictImr(t *testing.T, anchored bool) *Imr {
	t.Helper()
	imr := newTestImr(t)
	imr.Cache.DnskeyCache = cache.NewDnskeyCache()
	if anchored {
		imr.Cache.DnskeyCache.Set(".", 1, &cache.CachedDnskeyRRset{Name: ".", Keyid: 1, TrustAnchor: true,
			State: cache.ValidationStateSecure, Expiration: time.Now().Add(time.Hour)})
	}
	return imr
}

func seedVerdict(imr *Imr, rrset *core.RRset, state cache.ValidationState) {
	imr.Cache.Set(verdictName, dns.TypeA, &cache.CachedRRset{
		Name: verdictName, RRtype: dns.TypeA, Rcode: uint8(dns.RcodeSuccess), RRset: rrset,
		Context: cache.ContextAnswer, State: state, Expiration: time.Now().Add(time.Minute),
	})
}

type verdictQuery struct{ do, cd, ad bool }

func (q verdictQuery) msg() (*dns.Msg, *edns0.MsgOptions) {
	r := new(dns.Msg)
	r.SetQuestion(verdictName, dns.TypeA)
	r.RecursionDesired = true
	r.AuthenticatedData = q.ad
	r.CheckingDisabled = q.cd
	r.SetEdns0(4096, q.do)
	return r, &edns0.MsgOptions{RD: true, DO: q.do, CD: q.cd}
}

// fresh answers the query the way the iterative path does, for an RRset whose
// verdict handleAnswer has just cached.
func fresh(t *testing.T, imr *Imr, rrset *core.RRset, q verdictQuery) *dns.Msg {
	t.Helper()
	r, opts := q.msg()
	w := &fakeResponseWriter{}
	_, _ = imr.ProcessAuthDNSResponse(context.Background(), verdictName, dns.TypeA,
		rrset, dns.RcodeSuccess, cache.ContextAnswer, opts, new(dns.Msg), w, r, core.TransportDo53)
	if w.msg == nil {
		t.Fatal("fresh path wrote nothing")
	}
	return w.msg
}

// cached answers the query from the cache entry.
func cached(t *testing.T, imr *Imr, q verdictQuery) *dns.Msg {
	t.Helper()
	r, opts := q.msg()
	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, verdictName, dns.TypeA, opts)
	if cw.got == nil {
		t.Fatal("cached path wrote nothing")
	}
	return cw.got
}

func edeOf(m *dns.Msg) uint16 {
	opt := m.IsEdns0()
	if opt == nil {
		return 0
	}
	for _, o := range opt.Option {
		if e, ok := o.(*dns.EDNS0_EDE); ok {
			return e.InfoCode
		}
	}
	return 0
}

// THE DEFECT. An answer from an insecure zone was SERVFAIL when fetched and
// NOERROR from the cache, so every name in an unsigned zone -- or a signed one
// with no DS -- failed on the first ask and worked on the second.
func TestAnInsecureAnswerIsServedFreshAndCached(t *testing.T) {
	imr := verdictImr(t, true)
	rrset := verdictRRset(false)
	seedVerdict(imr, rrset, cache.ValidationStateInsecure)
	q := verdictQuery{do: true}

	for name, m := range map[string]*dns.Msg{"fresh": fresh(t, imr, rrset, q), "cached": cached(t, imr, q)} {
		if m.Rcode != dns.RcodeSuccess || len(m.Answer) == 0 {
			t.Errorf("%s: rcode %s, %d answer RRs; an insecure answer must be served", name, dns.RcodeToString[m.Rcode], len(m.Answer))
		}
		if m.AuthenticatedData {
			t.Errorf("%s: AD set on an insecure answer", name)
		}
	}
}

// Every verdict gets the same response on both paths.
func TestFreshAndCachedAnswersAgree(t *testing.T) {
	cases := []struct {
		name     string
		state    cache.ValidationState
		signed   bool
		anchored bool
		q        verdictQuery
		rcode    int
		ad       bool
		ede      uint16
	}{
		{"secure, DO", cache.ValidationStateSecure, true, true, verdictQuery{do: true}, dns.RcodeSuccess, true, 0},
		{"secure, AD bit", cache.ValidationStateSecure, true, true, verdictQuery{ad: true}, dns.RcodeSuccess, true, 0},
		{"secure, plain query", cache.ValidationStateSecure, true, true, verdictQuery{}, dns.RcodeSuccess, false, 0},
		{"insecure", cache.ValidationStateInsecure, false, true, verdictQuery{do: true}, dns.RcodeSuccess, false, 0},
		{"bogus, DO", cache.ValidationStateBogus, true, true, verdictQuery{do: true}, dns.RcodeServerFailure, false, edns0.EDEDNSSECBogus},
		{"bogus, no DO", cache.ValidationStateBogus, true, true, verdictQuery{}, dns.RcodeServerFailure, false, edns0.EDEDNSSECBogus},
		{"bogus, CD", cache.ValidationStateBogus, true, true, verdictQuery{do: true, cd: true}, dns.RcodeSuccess, false, 0},
		{"indeterminate signed, anchored", cache.ValidationStateIndeterminate, true, true, verdictQuery{do: true}, dns.RcodeServerFailure, false, edns0.EDEDNSSECIndeterminate},
		{"indeterminate signed, no anchors", cache.ValidationStateIndeterminate, true, false, verdictQuery{do: true}, dns.RcodeSuccess, false, 0},
		{"indeterminate unsigned, anchored", cache.ValidationStateIndeterminate, false, true, verdictQuery{do: true}, dns.RcodeSuccess, false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			imr := verdictImr(t, c.anchored)
			rrset := verdictRRset(c.signed)
			seedVerdict(imr, rrset, c.state)
			for path, m := range map[string]*dns.Msg{"fresh": fresh(t, imr, rrset, c.q), "cached": cached(t, imr, c.q)} {
				if m.Rcode != c.rcode {
					t.Errorf("%s: rcode %s, want %s", path, dns.RcodeToString[m.Rcode], dns.RcodeToString[c.rcode])
				}
				if m.AuthenticatedData != c.ad {
					t.Errorf("%s: AD %v, want %v", path, m.AuthenticatedData, c.ad)
				}
				if c.ede != 0 && edeOf(m) != c.ede {
					t.Errorf("%s: EDE %d, want %d", path, edeOf(m), c.ede)
				}
			}
		})
	}
}
