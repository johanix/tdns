/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// Denials from an NSEC3-signed zone, through the resolver: sec.example.,
// anchored, served by a validating upstream double the resolver forwards to
// and validates behind.

// n3RR is an NSEC3 in zone, with no salt and iterations, matching name, or,
// with cover, covering it with an interval that holds its hash and no other.
func n3RR(zone, name string, cover bool, flags uint8, iterations uint16, types ...uint16) *dns.NSEC3 {
	h := dns.HashName(name, dns.SHA1, iterations, "")
	owner := h
	if cover {
		owner = refHashStep(h, -1)
	}
	return &dns.NSEC3{Hdr: dns.RR_Header{Name: owner + "." + zone, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
		Hash: dns.SHA1, Flags: flags, Iterations: iterations, HashLength: 20, NextDomain: refHashStep(h, 1), TypeBitMap: types}
}

const (
	n3NX    = "nx." + fwdSecParent
	n3WWW   = "www." + fwdSecParent
	n3ENT   = "ent." + fwdSecParent
	n3Wild  = "wild." + fwdSecParent
	n3WildQ = "a." + n3Wild
)

// n3Denial is a denial from sec.example. with rcode: its SOA and each NSEC3,
// signed by zone.
func n3Denial(t *testing.T, zone *fwdSecKey, rcode int, recs ...*dns.NSEC3) *dns.Msg {
	t.Helper()
	ns := zone.sign(t, fwdSecRR(t, fwdSecParent+" 300 IN SOA ns."+fwdSecParent+" hostmaster."+fwdSecParent+" 1 7200 1800 604800 300"))
	for _, r := range recs {
		ns = append(ns, zone.sign(t, r)...)
	}
	return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: rcode}, Ns: ns}
}

// n3NameErrorRecs proves nx.sec.example. absent: the apex matched, nx and
// *.sec.example. covered.
func n3NameErrorRecs(flags uint8, iterations uint16) []*dns.NSEC3 {
	return []*dns.NSEC3{
		n3RR(fwdSecParent, fwdSecParent, false, 0, iterations, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM),
		n3RR(fwdSecParent, n3NX, true, flags, iterations),
		n3RR(fwdSecParent, "*."+fwdSecParent, true, flags, iterations),
	}
}

// n3Rig is a resolver forwarding "." to a double serving answers, keyed by
// "qname qtype", and the DNSKEY of sec.example., which the resolver holds a
// trust anchor for.
func n3Rig(t *testing.T, answers func(zone *fwdSecKey) map[string]*dns.Msg) *Imr {
	t.Helper()
	zone := newFwdSecKey(t, fwdSecParent)
	a := answers(zone)
	a[fwdSecParent+" DNSKEY"] = &dns.Msg{Answer: zone.sign(t, dns.Copy(zone.dnskey))}
	addr, port := startSignedForwardUpstream(t, a)
	imr := newForwardTestImr(t, []ImrForwardConf{{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}}})
	imr.Cache.DnskeyCache = cache.NewDnskeyCache() // not the process-wide one
	imr.DnskeyCache = imr.Cache.DnskeyCache
	if err := imr.Cache.PrimeFromHintsOnly(""); err != nil {
		t.Fatalf("PrimeFromHintsOnly: %v", err)
	}
	imr.Cache.DnskeyCache.Set(fwdSecParent, zone.dnskey.KeyTag(), &cache.CachedDnskeyRRset{
		Name: fwdSecParent, Keyid: zone.dnskey.KeyTag(), TrustAnchor: true, State: cache.ValidationStateSecure,
		Dnskey: *zone.dnskey, Expiration: time.Now().Add(time.Hour)})
	imr.Cache.AddTrustAnchorZone(fwdSecParent)
	imr.Cache.ZoneMap.Set(fwdSecParent, &cache.Zone{ZoneName: fwdSecParent, State: cache.ValidationStateSecure})
	return imr
}

// n3Ask asks imr for qname and qtype with EDNS, DO and CD as given.
func n3Ask(t *testing.T, imr *Imr, qname string, qtype uint16, do, cd bool) *dns.Msg {
	t.Helper()
	r := new(dns.Msg)
	r.SetQuestion(qname, qtype)
	r.SetEdns0(4096, do)
	r.CheckingDisabled = cd
	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, qname, qtype, &edns0.MsgOptions{RD: true, DO: do, CD: cd})
	if cw.got == nil {
		t.Fatalf("%s %s: nothing written", qname, dns.TypeToString[qtype])
	}
	return cw.got
}

func countType(rrs []dns.RR, t uint16) int {
	n := 0
	for _, rr := range rrs {
		if rr.Header().Rrtype == t {
			n++
		}
	}
	return n
}

// RFC 5155 section 8 through the resolver. A proof that holds is served with
// AD, one through an Opt-Out span without, one over the iteration limit
// without and with EDE 27, and one that does not hold is SERVFAIL with EDE 6.
// The same from the cache. A DO client gets the NSEC3 records and their
// signatures beside the SOA; a client without DO gets the SOA alone.
func TestNSEC3DenialsThroughTheResolver(t *testing.T) {
	cases := []struct {
		name   string
		qname  string
		qtype  uint16
		answer func(t *testing.T, zone *fwdSecKey) *dns.Msg
		rcode  int
		ad     bool
		ede    uint16
	}{
		{"name error", n3NX, dns.TypeA, func(t *testing.T, z *fwdSecKey) *dns.Msg {
			return n3Denial(t, z, dns.RcodeNameError, n3NameErrorRecs(0, 0)...)
		}, dns.RcodeNameError, true, 0},
		{"name error through Opt-Out", n3NX, dns.TypeA, func(t *testing.T, z *fwdSecKey) *dns.Msg {
			return n3Denial(t, z, dns.RcodeNameError, n3NameErrorRecs(1, 0)...)
		}, dns.RcodeNameError, false, 0},
		{"name error without the wildcard cover", n3NX, dns.TypeA, func(t *testing.T, z *fwdSecKey) *dns.Msg {
			return n3Denial(t, z, dns.RcodeNameError, n3NameErrorRecs(0, 0)[:2]...)
		}, dns.RcodeServerFailure, false, edns0.EDEDNSSECBogus},
		{"name error over the iteration limit", n3NX, dns.TypeA, func(t *testing.T, z *fwdSecKey) *dns.Msg {
			return n3Denial(t, z, dns.RcodeNameError, n3NameErrorRecs(0, cache.DefaultNSEC3MaxIterations+1)...)
		}, dns.RcodeNameError, false, edns0.EDEUnsupportedNSEC3Iterations},
		{"no data", n3WWW, dns.TypeMX, func(t *testing.T, z *fwdSecKey) *dns.Msg {
			return n3Denial(t, z, dns.RcodeSuccess, n3RR(fwdSecParent, n3WWW, false, 0, 0, dns.TypeA, dns.TypeRRSIG))
		}, dns.RcodeSuccess, true, 0},
		{"no data, the type in the bitmap", n3WWW, dns.TypeA, func(t *testing.T, z *fwdSecKey) *dns.Msg {
			return n3Denial(t, z, dns.RcodeSuccess, n3RR(fwdSecParent, n3WWW, false, 0, 0, dns.TypeA, dns.TypeRRSIG))
		}, dns.RcodeServerFailure, false, edns0.EDEDNSSECBogus},
		{"empty non-terminal", n3ENT, dns.TypeA, func(t *testing.T, z *fwdSecKey) *dns.Msg {
			return n3Denial(t, z, dns.RcodeSuccess, n3RR(fwdSecParent, n3ENT, false, 1, 0))
		}, dns.RcodeSuccess, true, 0},
		{"wildcard no data", n3WildQ, dns.TypeAAAA, func(t *testing.T, z *fwdSecKey) *dns.Msg {
			return n3Denial(t, z, dns.RcodeSuccess,
				n3RR(fwdSecParent, n3Wild, false, 0, 0),
				n3RR(fwdSecParent, n3WildQ, true, 0, 0),
				n3RR(fwdSecParent, "*."+n3Wild, false, 0, 0, dns.TypeA, dns.TypeRRSIG))
		}, dns.RcodeSuccess, true, 0},
		{"wildcard no data through Opt-Out", n3WildQ, dns.TypeAAAA, func(t *testing.T, z *fwdSecKey) *dns.Msg {
			return n3Denial(t, z, dns.RcodeSuccess,
				n3RR(fwdSecParent, n3Wild, false, 0, 0),
				n3RR(fwdSecParent, n3WildQ, true, 1, 0),
				n3RR(fwdSecParent, "*."+n3Wild, false, 0, 0, dns.TypeA, dns.TypeRRSIG))
		}, dns.RcodeSuccess, false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			imr := n3Rig(t, func(z *fwdSecKey) map[string]*dns.Msg {
				return map[string]*dns.Msg{c.qname + " " + dns.TypeToString[c.qtype]: c.answer(t, z)}
			})
			for _, from := range []string{"fresh", "cached"} {
				m := n3Ask(t, imr, c.qname, c.qtype, true, false)
				if m.Rcode != c.rcode || m.AuthenticatedData != c.ad || edeOf(m) != c.ede {
					t.Fatalf("%s, DO: %s AD=%v EDE %d, want %s AD=%v EDE %d", from, dns.RcodeToString[m.Rcode],
						m.AuthenticatedData, edeOf(m), dns.RcodeToString[c.rcode], c.ad, c.ede)
				}
				if c.rcode != dns.RcodeServerFailure && (countType(m.Ns, dns.TypeNSEC3) == 0 || countType(m.Ns, dns.TypeRRSIG) == 0) {
					t.Errorf("%s, DO: no NSEC3 proof with its signatures in the authority section", from)
				}
			}
			m := n3Ask(t, imr, c.qname, c.qtype, false, false)
			if m.Rcode != c.rcode || m.AuthenticatedData {
				t.Errorf("no DO: %s AD=%v, want %s without AD", dns.RcodeToString[m.Rcode], m.AuthenticatedData, dns.RcodeToString[c.rcode])
			}
			if n := countType(m.Ns, dns.TypeNSEC3) + countType(m.Ns, dns.TypeRRSIG); n != 0 {
				t.Errorf("no DO: %d NSEC3 and RRSIG records in the authority section, want none", n)
			}
		})
	}
}

// With CD set the client validates for itself: a denial whose proof does not
// hold is served, with its records, not SERVFAIL.
func TestAnNSEC3DenialThatDoesNotHoldIsServedWithCD(t *testing.T) {
	imr := n3Rig(t, func(z *fwdSecKey) map[string]*dns.Msg {
		return map[string]*dns.Msg{n3NX + " A": n3Denial(t, z, dns.RcodeNameError, n3NameErrorRecs(0, 0)[:2]...)}
	})
	m := n3Ask(t, imr, n3NX, dns.TypeA, true, true)
	if m.Rcode != dns.RcodeNameError || m.AuthenticatedData || countType(m.Ns, dns.TypeNSEC3) == 0 {
		t.Errorf("CD: %s AD=%v with %d NSEC3, want NXDOMAIN without AD, with the proof", dns.RcodeToString[m.Rcode],
			m.AuthenticatedData, countType(m.Ns, dns.TypeNSEC3))
	}
}

func TestNSEC3MaxIterationsTuningDefault(t *testing.T) {
	var tc ImrTuningConf
	LoadImrTuningDefaults(&tc)
	if tc.NSEC3MaxIterations == nil || *tc.NSEC3MaxIterations != cache.DefaultNSEC3MaxIterations {
		t.Errorf("default nsec3-max-iterations is %v, want %d", tc.NSEC3MaxIterations, cache.DefaultNSEC3MaxIterations)
	}
}

// The key decodes, 0 included, and a changed value is reported as needing a
// restart like every other tuning key.
func TestNSEC3MaxIterationsDecodesAndNeedsRestart(t *testing.T) {
	boot := ImrEngineConf{}
	imr := runningImr(t, boot)
	conf := writeImrConfig(t, `imrengine:
   tuning:
      nsec3-max-iterations: 0
   forward:
      - zone: .
        upstreams:
           - addr: 192.0.2.1
`)
	block, err := conf.reloadImrEngineFromFile()
	if err != nil {
		t.Fatalf("reloadImrEngineFromFile: %v", err)
	}
	if block.Tuning.NSEC3MaxIterations == nil || *block.Tuning.NSEC3MaxIterations != 0 {
		t.Fatalf("decoded nsec3-max-iterations %v, want 0", block.Tuning.NSEC3MaxIterations)
	}

	conf.Internal.ImrEngine = imr
	conf.Imr = boot
	res, err := conf.applyImrEngineReload()
	if err != nil {
		t.Fatalf("applyImrEngineReload: %v", err)
	}
	if len(res.RestartRequired) != 1 || res.RestartRequired[0] != "imrengine.tuning" {
		t.Errorf("RestartRequired = %v, want [imrengine.tuning]", res.RestartRequired)
	}
}

// The join: the limit set in the config is the one the cache validates with.
func TestNSEC3MaxIterationsReachesTheCache(t *testing.T) {
	addr, port, _, stop := startTestUpstream(t)
	defer stop()

	savedImr := Globals.ImrEngine
	savedLimits := cache.GetTTLLimits()
	t.Cleanup(func() {
		Globals.ImrEngine = savedImr
		cache.SetTTLLimits(savedLimits)
		cache.SetZoneStateRecheck(0)
		cache.SetNSEC3MaxIterations(cache.DefaultNSEC3MaxIterations)
	})

	conf := &Config{}
	conf.Imr.Forward = []ImrForwardConf{fwdConf(".", addr, port)}
	limit := uint16(20)
	conf.Imr.Tuning.NSEC3MaxIterations = &limit
	if err := conf.InitImrEngine(context.Background(), true); err != nil {
		t.Fatalf("InitImrEngine: %v", err)
	}
	if got := cache.NSEC3MaxIterations(); got != limit {
		t.Errorf("the cache validates with a limit of %d, want the configured %d", got, limit)
	}
}

// startForwardUpstreamFunc is startSignedForwardUpstream with the answer to
// each question from answer, which is called on the server's goroutine; nil
// is SERVFAIL.
func startForwardUpstreamFunc(t *testing.T, answer func(qname string, qtype uint16) *dns.Msg) (string, uint16) {
	t.Helper()
	h := func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		m := new(dns.Msg)
		m.SetReply(r)
		m.RecursionAvailable = true
		if a := answer(strings.ToLower(q.Name), q.Qtype); a != nil {
			m.Answer, m.Ns, m.Rcode = a.Answer, a.Ns, a.Rcode
		} else {
			m.Rcode = dns.RcodeServerFailure
		}
		_ = w.WriteMsg(m)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port := splitHostPort(t, pc.LocalAddr().String())
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(h), NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("test upstream did not start")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	})
	return host, port
}

// A signed denial whose signer's key cannot be followed to the trust anchor
// is Indeterminate, and SERVFAIL with EDE 5, fresh and from the cache. When
// the key can be followed again, the cached denial is validated again as it
// is served, and goes out Secure, with AD: a moment's gap does not fail the
// name for the whole negative TTL.
//
// The anchor is the zone's KSK; the denial is signed by a ZSK that the first
// DNSKEY RRset, with a TTL of one second, does not hold.
func TestAnIndeterminateDenialIsValidatedAgainFromTheCache(t *testing.T) {
	ksk, zsk := newFwdSecKey(t, fwdSecParent), newFwdSecKey(t, fwdSecParent)
	denial := n3Denial(t, zsk, dns.RcodeNameError, n3NameErrorRecs(0, 0)...)
	short := dns.Copy(ksk.dnskey).(*dns.DNSKEY)
	short.Hdr.Ttl = 1
	withoutZSK := &dns.Msg{Answer: ksk.sign(t, short)}
	withZSK := &dns.Msg{Answer: ksk.sign(t, dns.Copy(ksk.dnskey), dns.Copy(zsk.dnskey))}
	var keysBack atomic.Bool
	addr, port := startForwardUpstreamFunc(t, func(qname string, qtype uint16) *dns.Msg {
		switch {
		case qname == n3NX && qtype == dns.TypeA:
			return denial
		case qname == fwdSecParent && qtype == dns.TypeDNSKEY && keysBack.Load():
			return withZSK
		case qname == fwdSecParent && qtype == dns.TypeDNSKEY:
			return withoutZSK
		}
		return nil
	})
	imr := newForwardTestImr(t, []ImrForwardConf{{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}}})
	imr.Cache.DnskeyCache = cache.NewDnskeyCache() // not the process-wide one
	imr.DnskeyCache = imr.Cache.DnskeyCache
	if err := imr.Cache.PrimeFromHintsOnly(""); err != nil {
		t.Fatalf("PrimeFromHintsOnly: %v", err)
	}
	imr.addDirectDNSKEYTrustAnchors(map[string][]*dns.DNSKEY{fwdSecParent: {ksk.dnskey}})

	for _, from := range []string{"fresh", "cached"} {
		if m := n3Ask(t, imr, n3NX, dns.TypeA, true, false); m.Rcode != dns.RcodeServerFailure || edeOf(m) != edns0.EDEDNSSECIndeterminate {
			t.Fatalf("%s, the ZSK unknown: %s EDE %d, want SERVFAIL EDE %d", from, dns.RcodeToString[m.Rcode], edeOf(m), edns0.EDEDNSSECIndeterminate)
		}
	}
	if c := imr.Cache.Get(n3NX, dns.TypeA); c == nil || c.State != cache.ValidationStateIndeterminate {
		t.Fatalf("the denial is not cached as indeterminate")
	}
	expiry := imr.Cache.Get(n3NX, dns.TypeA).Expiration

	keysBack.Store(true)
	time.Sleep(1100 * time.Millisecond) // the DNSKEY RRset without the ZSK expires
	if m := n3Ask(t, imr, n3NX, dns.TypeA, true, false); m.Rcode != dns.RcodeNameError || !m.AuthenticatedData {
		t.Fatalf("the ZSK known: %s AD=%v EDE %d, want NXDOMAIN with AD", dns.RcodeToString[m.Rcode], m.AuthenticatedData, edeOf(m))
	}
	c := imr.Cache.Get(n3NX, dns.TypeA)
	if c == nil || c.State != cache.ValidationStateSecure {
		t.Fatalf("the cached denial was not updated to secure")
	}
	if !c.Expiration.Equal(expiry) {
		t.Errorf("validating the cached denial again moved its expiry from %v to %v", expiry, c.Expiration)
	}
}

// A cached denial held Indeterminate that, validated again, fails in a way
// the fresh path would not take -- signed, but with neither NSEC nor NSEC3 --
// is Bogus: SERVFAIL, not served.
func TestADenialThatFailsWhenValidatedAgainIsBogus(t *testing.T) {
	ksk, zsk := newFwdSecKey(t, fwdSecParent), newFwdSecKey(t, fwdSecParent)
	denial := n3Denial(t, zsk, dns.RcodeNameError) // the SOA alone
	short := dns.Copy(ksk.dnskey).(*dns.DNSKEY)
	short.Hdr.Ttl = 1
	withoutZSK := &dns.Msg{Answer: ksk.sign(t, short)}
	withZSK := &dns.Msg{Answer: ksk.sign(t, dns.Copy(ksk.dnskey), dns.Copy(zsk.dnskey))}
	var keysBack atomic.Bool
	addr, port := startForwardUpstreamFunc(t, func(qname string, qtype uint16) *dns.Msg {
		switch {
		case qname == n3NX && qtype == dns.TypeA:
			return denial
		case qname == fwdSecParent && qtype == dns.TypeDNSKEY && keysBack.Load():
			return withZSK
		case qname == fwdSecParent && qtype == dns.TypeDNSKEY:
			return withoutZSK
		}
		return nil
	})
	imr := newForwardTestImr(t, []ImrForwardConf{{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}}})
	imr.Cache.DnskeyCache = cache.NewDnskeyCache() // not the process-wide one
	imr.DnskeyCache = imr.Cache.DnskeyCache
	if err := imr.Cache.PrimeFromHintsOnly(""); err != nil {
		t.Fatalf("PrimeFromHintsOnly: %v", err)
	}
	imr.addDirectDNSKEYTrustAnchors(map[string][]*dns.DNSKEY{fwdSecParent: {ksk.dnskey}})

	if m := n3Ask(t, imr, n3NX, dns.TypeA, true, false); m.Rcode != dns.RcodeServerFailure {
		t.Fatalf("the ZSK unknown: %s, want SERVFAIL", dns.RcodeToString[m.Rcode])
	}
	if c := imr.Cache.Get(n3NX, dns.TypeA); c == nil || c.State != cache.ValidationStateIndeterminate {
		t.Fatalf("the denial is not cached as indeterminate")
	}

	keysBack.Store(true)
	time.Sleep(1100 * time.Millisecond) // the DNSKEY RRset without the ZSK expires
	if m := n3Ask(t, imr, n3NX, dns.TypeA, true, false); m.Rcode != dns.RcodeServerFailure || edeOf(m) != edns0.EDEDNSSECBogus {
		t.Errorf("validated again, without NSEC or NSEC3: %s EDE %d, want SERVFAIL EDE %d",
			dns.RcodeToString[m.Rcode], edeOf(m), edns0.EDEDNSSECBogus)
	}
	if c := imr.Cache.Get(n3NX, dns.TypeA); c == nil || c.State != cache.ValidationStateBogus {
		t.Errorf("the cached denial is not Bogus after validating it again")
	}
}

// A DNSKEY denial handleNegative did not validate is held as None, not
// Indeterminate, and is served as it is: validating it would call it Bogus
// (ValidateDenial does not validate DNSKEY denials).
func TestADNSKEYDenialIsNotValidatedAgain(t *testing.T) {
	zone := newFwdSecKey(t, fwdSecParent)
	imr := n3Rig(t, func(*fwdSecKey) map[string]*dns.Msg { return map[string]*dns.Msg{} })
	d := n3Denial(t, zone, dns.RcodeSuccess, n3RR(fwdSecParent, n3WWW, false, 0, 0, dns.TypeA, dns.TypeRRSIG))
	sets := authorityRRsets(d.Ns)
	imr.Cache.Set(n3WWW, dns.TypeDNSKEY, &cache.CachedRRset{Name: n3WWW, RRtype: dns.TypeDNSKEY, Rcode: uint8(dns.RcodeSuccess),
		RRset: sets[0], NegAuthority: sets, Context: cache.ContextNoErrNoAns, State: cache.ValidationStateNone,
		Expiration: time.Now().Add(time.Minute)})
	if m := n3Ask(t, imr, n3WWW, dns.TypeDNSKEY, true, false); m.Rcode != dns.RcodeSuccess {
		t.Errorf("DNSKEY denial: %s EDE %d, want NOERROR", dns.RcodeToString[m.Rcode], edeOf(m))
	}
	if c := imr.Cache.Get(n3WWW, dns.TypeDNSKEY); c == nil || c.State != cache.ValidationStateNone {
		t.Errorf("the DNSKEY denial's verdict changed")
	}
}
