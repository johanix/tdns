/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Answers synthesized from a wildcard, through the resolver: validated with
 * the proof that the name asked for does not exist, which is kept with the
 * answer and served beside it.
 */
package tdns

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// rrSigner signs records for a zone, returning them followed by their RRSIG.
type rrSigner interface {
	sign(t *testing.T, rrs ...dns.RR) []dns.RR
}

// wildcardSigned signs the record in text, owned by a wildcard, then serves it
// and its RRSIG owned by owner: an answer synthesized from the wildcard.
func wildcardSigned(t *testing.T, s rrSigner, text, owner string) []dns.RR {
	t.Helper()
	rrs := s.sign(t, fwdSecRR(t, text))
	for _, rr := range rrs {
		rr.Header().Name = owner
	}
	return rrs
}

// ----- NSEC3, through a forwarder (n3Rig: sec.example., anchored) -----

const (
	wcaWild = "*.w." + fwdSecParent
	wcaQ    = "a.z.w." + fwdSecParent
	wcaNC   = "z.w." + fwdSecParent
)

// wcaAnswer is wcaQ's A, synthesized from wcaWild, with recs in the authority
// section, each signed by z.
func wcaAnswer(t *testing.T, z *fwdSecKey, recs ...*dns.NSEC3) *dns.Msg {
	t.Helper()
	m := &dns.Msg{Answer: wildcardSigned(t, z, wcaWild+" 300 IN A 192.0.2.7", wcaQ)}
	for _, r := range recs {
		m.Ns = append(m.Ns, z.sign(t, r)...)
	}
	return m
}

// An answer synthesized from a wildcard, through a forwarder that sends the
// proof in the authority section: AD when it holds, none through Opt-Out,
// none and EDE 27 over the iteration limit, SERVFAIL with EDE 6 without it.
// The same from the cache. A DO client gets the proof with the answer; a
// client without DO does not. With CD the answer is served whatever the
// verdict, with AD only when it is Secure.
func TestForwardedWildcardAnswers(t *testing.T) {
	cases := []struct {
		name  string
		recs  func() []*dns.NSEC3
		rcode int
		ad    bool
		ede   uint16
	}{
		{"the proof holds", func() []*dns.NSEC3 { return []*dns.NSEC3{n3RR(fwdSecParent, wcaNC, true, 0, 0)} },
			dns.RcodeSuccess, true, 0},
		{"through Opt-Out", func() []*dns.NSEC3 { return []*dns.NSEC3{n3RR(fwdSecParent, wcaNC, true, 1, 0)} },
			dns.RcodeSuccess, false, 0},
		{"over the iteration limit", func() []*dns.NSEC3 {
			return []*dns.NSEC3{n3RR(fwdSecParent, wcaNC, true, 0, cache.DefaultNSEC3MaxIterations+1)}
		}, dns.RcodeSuccess, false, edns0.EDEUnsupportedNSEC3Iterations},
		{"no proof", func() []*dns.NSEC3 { return nil }, dns.RcodeServerFailure, false, edns0.EDEDNSSECBogus},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			imr := n3Rig(t, func(z *fwdSecKey) map[string]*dns.Msg {
				return map[string]*dns.Msg{wcaQ + " A": wcaAnswer(t, z, c.recs()...)}
			})
			for _, from := range []string{"fresh", "cached"} {
				m := n3Ask(t, imr, wcaQ, dns.TypeA, true, false)
				if m.Rcode != c.rcode || m.AuthenticatedData != c.ad || edeOf(m) != c.ede {
					t.Fatalf("%s, DO: %s AD=%v EDE %d, want %s AD=%v EDE %d", from, dns.RcodeToString[m.Rcode],
						m.AuthenticatedData, edeOf(m), dns.RcodeToString[c.rcode], c.ad, c.ede)
				}
				if c.rcode == dns.RcodeSuccess && (countType(m.Ns, dns.TypeNSEC3) != 1 || countType(m.Ns, dns.TypeRRSIG) != 1) {
					t.Errorf("%s, DO: authority %v; want the NSEC3 proof and its RRSIG", from, m.Ns)
				}
			}
			m := n3Ask(t, imr, wcaQ, dns.TypeA, false, false)
			if m.Rcode != c.rcode || m.AuthenticatedData || len(m.Ns) != 0 {
				t.Errorf("no DO: %s AD=%v authority %v, want %s, no AD, nothing in authority",
					dns.RcodeToString[m.Rcode], m.AuthenticatedData, m.Ns, dns.RcodeToString[c.rcode])
			}
			if m := n3Ask(t, imr, wcaQ, dns.TypeA, true, true); m.Rcode != dns.RcodeSuccess || m.AuthenticatedData != c.ad {
				t.Errorf("CD: %s AD=%v, want NOERROR, AD=%v", dns.RcodeToString[m.Rcode], m.AuthenticatedData, c.ad)
			}
		})
	}
}

// An answer synthesized from a wildcard whose signer's key cannot be followed
// to the trust anchor is Indeterminate, SERVFAIL with EDE 5. When the key can
// be followed again, the cached answer is validated again with the proof kept
// with it, and goes out Secure.
func TestAnIndeterminateWildcardAnswerIsValidatedAgainWithItsProof(t *testing.T) {
	ksk, zsk := newFwdSecKey(t, fwdSecParent), newFwdSecKey(t, fwdSecParent)
	answer := wcaAnswer(t, zsk, n3RR(fwdSecParent, wcaNC, true, 0, 0))
	short := dns.Copy(ksk.dnskey).(*dns.DNSKEY)
	short.Hdr.Ttl = 1
	withoutZSK := &dns.Msg{Answer: ksk.sign(t, short)}
	withZSK := &dns.Msg{Answer: ksk.sign(t, dns.Copy(ksk.dnskey), dns.Copy(zsk.dnskey))}
	var keysBack atomic.Bool
	addr, port := startForwardUpstreamFunc(t, func(qname string, qtype uint16) *dns.Msg {
		switch {
		case qname == wcaQ && qtype == dns.TypeA:
			return answer
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

	if m := n3Ask(t, imr, wcaQ, dns.TypeA, true, false); m.Rcode != dns.RcodeServerFailure || edeOf(m) != edns0.EDEDNSSECIndeterminate {
		t.Fatalf("the ZSK unknown: %s EDE %d, want SERVFAIL EDE %d", dns.RcodeToString[m.Rcode], edeOf(m), edns0.EDEDNSSECIndeterminate)
	}
	if c := imr.Cache.Get(wcaQ, dns.TypeA); c == nil || c.State != cache.ValidationStateIndeterminate || len(c.WildcardProof) == 0 {
		t.Fatalf("the answer is not cached Indeterminate with its proof: %+v", c)
	}
	keysBack.Store(true)
	time.Sleep(1100 * time.Millisecond) // the DNSKEY RRset without the ZSK expires
	if m := n3Ask(t, imr, wcaQ, dns.TypeA, true, false); m.Rcode != dns.RcodeSuccess || !m.AuthenticatedData {
		t.Errorf("the ZSK known: %s AD=%v EDE %d, want NOERROR with AD", dns.RcodeToString[m.Rcode], m.AuthenticatedData, edeOf(m))
	}
}

// ----- NSEC, iterative, through a stub to a double of wcnZone -----

// wcnZone is signed, and held Secure under a trust anchor for its key. Its
// wildcards: *.w and *.g (A, the proof with TTL 300), *.v (A, the proof with
// TTL 0), *.c (CNAME to y.d) and *.d (A). s1 is a CNAME to x.c, s2 one to
// np.c, for which the server sends no proof.
const wcnZone = "wcn.example."

func startWildcardDouble(t *testing.T, s *zoneSigner) string {
	t.Helper()
	z := wcnZone
	soa := mustRR(t, z+" 300 IN SOA ns."+z+" hostmaster."+z+" 1 7200 1800 604800 300")
	nsec := func(owner, next string, ttl int) []dns.RR {
		return s.sign(t, mustRR(t, owner+z+" "+strconv.Itoa(ttl)+" IN NSEC "+next+z+" A CNAME RRSIG NSEC"))
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		name := core.CanonicalizeName(q.Name)
		under := func(sub string) bool { return dns.IsSubDomain(sub+z, name) && name != sub+z }
		switch {
		case name == "s1."+z:
			m.Answer = s.sign(t, mustRR(t, q.Name+" 300 IN CNAME x.c."+z))
		case name == "s2."+z:
			m.Answer = s.sign(t, mustRR(t, q.Name+" 300 IN CNAME np.c."+z))
		case name == "np.c."+z:
			m.Answer = wildcardSigned(t, s, "*.c."+z+" 300 IN CNAME y.d."+z, q.Name)
		case under("c."):
			m.Answer = wildcardSigned(t, s, "*.c."+z+" 300 IN CNAME y.d."+z, q.Name)
			m.Ns = append(nsec("a.c.", "zz.c.", 300), nsec("a.d.", "zz.d.", 300)...)
		case under("d.") && q.Qtype == dns.TypeA:
			m.Answer = wildcardSigned(t, s, "*.d."+z+" 300 IN A 192.0.2.8", q.Name)
			m.Ns = nsec("a.d.", "zz.d.", 300)
		case under("w.") && q.Qtype == dns.TypeA:
			m.Answer = wildcardSigned(t, s, "*.w."+z+" 300 IN A 192.0.2.7", q.Name)
			m.Ns = nsec("x.w.", "zz.w.", 300)
		case under("g.") && q.Qtype == dns.TypeA:
			m.Answer = wildcardSigned(t, s, "*.g."+z+" 300 IN A 192.0.2.9", q.Name)
			m.Ns = nsec("a.g.", "zz.g.", 300)
		case under("v.") && q.Qtype == dns.TypeA:
			m.Answer = wildcardSigned(t, s, "*.v."+z+" 300 IN A 192.0.2.10", q.Name)
			m.Ns = nsec("x.v.", "zz.v.", 0)
		default:
			m.Ns = s.sign(t, soa)
		}
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.1: %v", err)
	}
	started := make(chan struct{})
	served := make(chan error, 1)
	srv := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: func() { close(started) }}
	go func() { served <- srv.ActivateAndServe() }()
	select {
	case <-started:
	case err := <-served:
		t.Fatalf("auth double failed to serve: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("auth double did not start")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.ShutdownContext(ctx); err != nil {
			t.Errorf("auth double shutdown: %v", err)
		}
		select {
		case <-served:
		case <-time.After(2 * time.Second):
			t.Error("auth double serve goroutine did not exit")
		}
	})
	return strconv.Itoa(pc.LocalAddr().(*net.UDPAddr).Port)
}

func wildcardImr(t *testing.T) *Imr {
	t.Helper()
	s := newZoneSigner(t, wcnZone)
	port := startWildcardDouble(t, s)
	imr := verdictImr(t, true)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, port, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, port, nil)
	if err := imr.Cache.AddStub(wcnZone, []cache.AuthServer{
		{Name: "ns." + wcnZone, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	imr.Cache.DnskeyCache.Set(wcnZone, s.key.KeyTag(), &cache.CachedDnskeyRRset{Name: wcnZone,
		Keyid: s.key.KeyTag(), TrustAnchor: true, State: cache.ValidationStateSecure, Dnskey: *s.key, Expiration: time.Now().Add(time.Hour)})
	imr.Cache.ZoneMap.Set(wcnZone, &cache.Zone{ZoneName: wcnZone, State: cache.ValidationStateSecure})
	return imr
}

// askWith asks imr for qname and qtype, with DO as given.
func askWith(t *testing.T, imr *Imr, qname string, qtype uint16, do bool) *dns.Msg {
	t.Helper()
	r, opts := verdictQuery{do: do}.msgFor(qname, qtype)
	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, qname, qtype, opts)
	if cw.got == nil {
		t.Fatalf("%s %s: responder wrote nothing", qname, dns.TypeToString[qtype])
	}
	return cw.got
}

// An NSEC proof, fresh and from the cache: AD, and the NSEC and its RRSIG in
// the authority section for a DO client, nothing there for one without DO.
func TestWildcardAnswerWithAnNSECProof(t *testing.T) {
	imr := wildcardImr(t)
	qname := "a.z.w." + wcnZone
	for _, from := range []string{"fresh", "cached"} {
		m := askWith(t, imr, qname, dns.TypeA, true)
		if m.Rcode != dns.RcodeSuccess || !m.AuthenticatedData || countType(m.Ns, dns.TypeNSEC) != 1 || countType(m.Ns, dns.TypeRRSIG) != 1 {
			t.Errorf("%s: %s AD=%v authority %v; want NOERROR, AD, the NSEC and its RRSIG",
				from, dns.RcodeToString[m.Rcode], m.AuthenticatedData, m.Ns)
		}
	}
	if m := askWith(t, imr, qname, dns.TypeA, false); m.Rcode != dns.RcodeSuccess || len(m.Ns) != 0 {
		t.Errorf("no DO: %s authority %v; want NOERROR and nothing in authority", dns.RcodeToString[m.Rcode], m.Ns)
	}
}

// A proof with TTL 0 gives the answer a lifetime of 0: it is stored already
// expired, and the query that fetched it is still answered from it, Secure,
// with the proof.
func TestWildcardAnswerWithAZeroTTLProof(t *testing.T) {
	imr := wildcardImr(t)
	qname := "a.z.v." + wcnZone
	m := askWith(t, imr, qname, dns.TypeA, true)
	if m.Rcode != dns.RcodeSuccess || !m.AuthenticatedData || countType(m.Ns, dns.TypeNSEC) != 1 {
		t.Errorf("%s AD=%v authority %v; want NOERROR, AD and the NSEC", dns.RcodeToString[m.Rcode], m.AuthenticatedData, m.Ns)
	}
	if c := imr.Cache.Peek(qname, dns.TypeA); c == nil || c.Expiration.After(cache.Now()) {
		t.Errorf("the answer outlives its proof: %+v", c)
	}
}

// A CNAME chain through two wildcards, as Deckard's
// val_nsec3_cnametocnamewctoposwc has it: AD, and each proof RRset once in the
// authority section, fresh and from the cache. A link the server sends no
// proof for fails the chain.
func TestCNAMEChainThroughWildcards(t *testing.T) {
	imr := wildcardImr(t)
	want := []string{"s1.wcn.example. CNAME", "x.c.wcn.example. CNAME", "y.d.wcn.example. A"}
	for _, from := range []string{"fresh", "cached"} {
		m := askWith(t, imr, "s1."+wcnZone, dns.TypeA, true)
		if m.Rcode != dns.RcodeSuccess || !m.AuthenticatedData || !sameOrder(answerOrder(m), want) {
			t.Fatalf("%s: %s AD=%v answer %v; want NOERROR, AD and %v", from, dns.RcodeToString[m.Rcode],
				m.AuthenticatedData, answerOrder(m), want)
		}
		if n := countType(m.Ns, dns.TypeNSEC); n != 2 {
			t.Errorf("%s: %d NSEC in authority (%v), want the proofs of x.c and y.d, once each", from, n, m.Ns)
		}
	}
	// A link held Indeterminate is validated again, with the proof kept with
	// it, as the chain is served.
	link := imr.Cache.Peek("x.c."+wcnZone, dns.TypeCNAME)
	if link == nil || !imr.Cache.SetVerdict(link, cache.ValidationStateIndeterminate, 0, "") {
		t.Fatalf("test setup: cannot hold the x.c link Indeterminate: %+v", link)
	}
	if m := askWith(t, imr, "s1."+wcnZone, dns.TypeA, true); m.Rcode != dns.RcodeSuccess || !m.AuthenticatedData {
		t.Errorf("a link validated again: %s AD=%v, want NOERROR with AD", dns.RcodeToString[m.Rcode], m.AuthenticatedData)
	}
	if m := askWith(t, imr, "s2."+wcnZone, dns.TypeA, true); m.Rcode != dns.RcodeServerFailure {
		t.Errorf("a link without its proof: %s answer %v, want SERVFAIL", dns.RcodeToString[m.Rcode], m.Answer)
	}
}

// revalidateGlueRR caches again an address it has just looked up; a glue
// address synthesized from a wildcard keeps the proof that came with it.
func TestRevalidatedGlueKeepsItsProof(t *testing.T) {
	imr := wildcardImr(t)
	host := "ns.g." + wcnZone
	servers, ok := imr.Cache.ServerMap.Get(wcnZone)
	if !ok || servers["ns."+wcnZone] == nil {
		t.Fatalf("test setup: no stub server for %s", wcnZone)
	}
	imr.revalidateGlueRR(context.Background(), wcnZone, host, dns.TypeA, servers["ns."+wcnZone], true)
	c := imr.Cache.Peek(host, dns.TypeA)
	if c == nil || c.State != cache.ValidationStateSecure || len(c.WildcardProof) == 0 {
		t.Errorf("after revalidateGlueRR: %+v; want Secure, with the proof", c)
	}
}

// ----- the server's own zone -----

// An answer the resolver takes from a zone the server is authoritative for is
// the server's own data, and is not held to the proof. A zone signed elsewhere
// with NSEC3 and served here as a secondary has no proof to give: the
// authoritative side does not serve NSEC3 (denial.go).
func TestOwnNSEC3ZoneWildcardAnswerValidates(t *testing.T) {
	zd, _ := presignedSecondary(t, func(text string) string {
		return dropRecords("", "NSEC")(text) + "example.\t3600\tIN\tNSEC3PARAM\t1 0 0 -\n"
	})
	if zd.signsHere() {
		t.Fatal("test setup: the secondary signs")
	}
	upLog := &upstreamLog{}
	upAddr, upPort := startLoggedSignedForwardUpstream(t, nil, upLog)
	imr := newForwardTestImr(t, rootForward(upAddr, upPort))
	imr.Cache.DnskeyCache = cache.NewDnskeyCache() // not the process-wide one
	imr.DnskeyCache = imr.Cache.DnskeyCache

	m := askWith(t, imr, "x.wild.example.", dns.TypeTXT, true)
	if m.Rcode != dns.RcodeSuccess || !m.AuthenticatedData || countType(m.Answer, dns.TypeTXT) != 1 {
		t.Errorf("%s AD=%v answer %v; want NOERROR, AD and the TXT", dns.RcodeToString[m.Rcode], m.AuthenticatedData, m.Answer)
	}
	if n := countType(m.Ns, dns.TypeNSEC) + countType(m.Ns, dns.TypeNSEC3); n != 0 {
		t.Errorf("test setup: %d NSEC/NSEC3 in authority; the zone was to send no proof", n)
	}
	requireUpstreamNotAsked(t, upLog, "example.")
}

// ----- EDE 27 on a positive answer -----

// EDE 27 on an answer that is Insecure goes out beside it, fresh and from the
// cache. Any other EDE on a positive entry fails it, as before.
func TestAnAnswerWithEDE27IsServedBesideIt(t *testing.T) {
	for _, c := range []struct {
		name  string
		ede   uint16
		rcode int
	}{
		{"EDE 27", edns0.EDEUnsupportedNSEC3Iterations, dns.RcodeSuccess},
		{"EDE 9", 9, dns.RcodeServerFailure},
	} {
		t.Run(c.name, func(t *testing.T) {
			imr := verdictImr(t, true)
			rrset := verdictRRset(true)
			imr.Cache.Set(verdictName, dns.TypeA, &cache.CachedRRset{
				Name: verdictName, RRtype: dns.TypeA, Rcode: uint8(dns.RcodeSuccess), RRset: rrset,
				Context: cache.ContextAnswer, State: cache.ValidationStateInsecure, EDECode: c.ede, EDEText: "test",
				Expiration: time.Now().Add(time.Minute),
			})
			q := verdictQuery{do: true}
			for path, m := range map[string]*dns.Msg{"fresh": fresh(t, imr, rrset, q), "cached": cached(t, imr, q)} {
				if m.Rcode != c.rcode || m.AuthenticatedData || edeOf(m) != c.ede {
					t.Errorf("%s: %s AD=%v EDE %d, want %s without AD, EDE %d", path, dns.RcodeToString[m.Rcode],
						m.AuthenticatedData, edeOf(m), dns.RcodeToString[c.rcode], c.ede)
				}
			}
		})
	}
}
