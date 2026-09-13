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

func (q verdictQuery) msgFor(qname string, qtype uint16) (*dns.Msg, *edns0.MsgOptions) {
	r := new(dns.Msg)
	r.SetQuestion(qname, qtype)
	r.RecursionDesired = true
	r.AuthenticatedData = q.ad
	r.CheckingDisabled = q.cd
	r.SetEdns0(4096, q.do)
	return r, &edns0.MsgOptions{RD: true, DO: q.do, CD: q.cd}
}

// cachedAs answers a query for qname/qtype from the cache.
func cachedAs(t *testing.T, imr *Imr, qname string, qtype uint16, q verdictQuery) *dns.Msg {
	t.Helper()
	r, opts := q.msgFor(qname, qtype)
	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, qname, qtype, opts)
	if cw.got == nil {
		t.Fatal("cached path wrote nothing")
	}
	return cw.got
}

// Two more cache branches serve positive data: a DS straight from the parent's
// referral, and referral/glue/hint data served without upgrading. Both set AD
// from the entry's state for every client and served a bogus entry as NOERROR.
// They follow the same rule as any other answer.
func TestCachedDSAndIndirectAnswersFollowTheSameRule(t *testing.T) {
	const dsName = "child.verdict.example."
	const glueName = "ns.child.verdict.example."
	dsRRset := &core.RRset{
		Name: dsName, Class: dns.ClassINET, RRtype: dns.TypeDS,
		RRs: []dns.RR{&dns.DS{
			Hdr:    dns.RR_Header{Name: dsName, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 60},
			KeyTag: 4242, Algorithm: dns.ED25519, DigestType: dns.SHA256,
			Digest: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		}},
		RRSIGs: []dns.RR{&dns.RRSIG{
			Hdr:         dns.RR_Header{Name: dsName, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60},
			TypeCovered: dns.TypeDS, Algorithm: dns.ED25519, Labels: 3, OrigTtl: 60,
			Inception:  uint32(time.Now().Add(-time.Hour).Unix()),
			Expiration: uint32(time.Now().Add(time.Hour).Unix()),
			KeyTag:     4243, SignerName: "verdict.example.", Signature: "AAAA",
		}},
	}
	glueRRset := &core.RRset{
		Name: glueName, Class: dns.ClassINET, RRtype: dns.TypeA,
		RRs: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: glueName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.53"),
		}},
	}

	kinds := []struct {
		name     string
		qname    string
		qtype    uint16
		context  cache.CacheContext
		rrset    *core.RRset
		indirect bool
	}{
		{"DS from a referral", dsName, dns.TypeDS, cache.ContextReferral, dsRRset, false},
		{"glue served without upgrading", glueName, dns.TypeA, cache.ContextGlue, glueRRset, true},
	}
	verdicts := []struct {
		name  string
		state cache.ValidationState
		q     verdictQuery
		rcode int
		ad    bool
		ede   uint16
	}{
		{"secure, plain query", cache.ValidationStateSecure, verdictQuery{}, dns.RcodeSuccess, false, 0},
		{"secure, DO", cache.ValidationStateSecure, verdictQuery{do: true}, dns.RcodeSuccess, true, 0},
		{"bogus, no DO", cache.ValidationStateBogus, verdictQuery{}, dns.RcodeServerFailure, false, edns0.EDEDNSSECBogus},
		{"bogus, CD", cache.ValidationStateBogus, verdictQuery{do: true, cd: true}, dns.RcodeSuccess, false, 0},
	}
	for _, k := range kinds {
		for _, v := range verdicts {
			t.Run(k.name+"/"+v.name, func(t *testing.T) {
				imr := verdictImr(t, true)
				if k.indirect {
					upgrade := false
					imr.Tuning.UpgradeIndirectCacheHits = &upgrade
				}
				imr.Cache.Set(k.qname, k.qtype, &cache.CachedRRset{
					Name: k.qname, RRtype: k.qtype, Rcode: uint8(dns.RcodeSuccess), RRset: k.rrset,
					Context: k.context, State: v.state, Expiration: time.Now().Add(time.Minute),
				})
				m := cachedAs(t, imr, k.qname, k.qtype, v.q)
				if m.Rcode != v.rcode {
					t.Errorf("rcode %s, want %s", dns.RcodeToString[m.Rcode], dns.RcodeToString[v.rcode])
				}
				if m.AuthenticatedData != v.ad {
					t.Errorf("AD %v, want %v", m.AuthenticatedData, v.ad)
				}
				if v.ede != 0 && edeOf(m) != v.ede {
					t.Errorf("EDE %d, want %d", edeOf(m), v.ede)
				}
			})
		}
	}
}

// A denial gets the same response fresh and cached. Both used to set AD for a
// secure proof whatever the client asked for, and the cached path dropped the
// EDE the fresh one attaches. Denials do not SERVFAIL on Indeterminate: NSEC3
// proofs still validate to Indeterminate, and every NSEC3-signed zone would fail.
func TestFreshAndCachedDenialsAgree(t *testing.T) {
	const denied = "nx.verdict.example."
	soa, err := dns.NewRR("verdict.example. 900 IN SOA ns1.verdict.example. hostmaster.verdict.example. 1 7200 1800 604800 900")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	kinds := []struct {
		name    string
		context cache.CacheContext
		rcode   int
	}{
		{"NXDOMAIN", cache.ContextNXDOMAIN, dns.RcodeNameError},
		{"NODATA", cache.ContextNoErrNoAns, dns.RcodeSuccess},
	}
	verdicts := []struct {
		name    string
		state   cache.ValidationState
		edeCode uint16
		q       verdictQuery
		ad      bool
	}{
		{"secure, plain query", cache.ValidationStateSecure, 0, verdictQuery{}, false},
		{"secure, AD bit", cache.ValidationStateSecure, 0, verdictQuery{ad: true}, true},
		{"secure, DO", cache.ValidationStateSecure, 0, verdictQuery{do: true}, true},
		{"insecure, DO", cache.ValidationStateInsecure, 0, verdictQuery{do: true}, false},
		{"indeterminate, DO", cache.ValidationStateIndeterminate, 0, verdictQuery{do: true}, false},
		{"DNSKEY missing, DO", cache.ValidationStateNone, 9, verdictQuery{do: true}, false},
	}
	for _, k := range kinds {
		for _, v := range verdicts {
			t.Run(k.name+"/"+v.name, func(t *testing.T) {
				imr := verdictImr(t, true)
				entry := &cache.CachedRRset{
					Name: denied, RRtype: dns.TypeA, Rcode: uint8(k.rcode),
					RRset:   &core.RRset{Name: "verdict.example.", Class: dns.ClassINET, RRtype: dns.TypeSOA, RRs: []dns.RR{soa}},
					Context: k.context, State: v.state, Expiration: time.Now().Add(15 * time.Minute),
					Transport: core.TransportDo53,
				}
				if v.edeCode != 0 {
					entry.EDECode, entry.EDEText = v.edeCode, "no DNSKEY matches DS for zone verdict.example"
				}
				imr.Cache.Set(denied, dns.TypeA, entry)

				r, opts := v.q.msgFor(denied, dns.TypeA)
				fw := &fakeResponseWriter{}
				_, _ = imr.ProcessAuthDNSResponse(context.Background(), denied, dns.TypeA, nil, k.rcode, k.context,
					opts, new(dns.Msg), fw, r, core.TransportDo53)
				if fw.msg == nil {
					t.Fatal("fresh path wrote nothing")
				}
				for path, m := range map[string]*dns.Msg{"fresh": fw.msg, "cached": cachedAs(t, imr, denied, dns.TypeA, v.q)} {
					if m.Rcode != k.rcode {
						t.Errorf("%s: rcode %s, want %s", path, dns.RcodeToString[m.Rcode], dns.RcodeToString[k.rcode])
					}
					if m.AuthenticatedData != v.ad {
						t.Errorf("%s: AD %v, want %v", path, m.AuthenticatedData, v.ad)
					}
					if edeOf(m) != v.edeCode {
						t.Errorf("%s: EDE %d, want %d", path, edeOf(m), v.edeCode)
					}
				}
			})
		}
	}
}
