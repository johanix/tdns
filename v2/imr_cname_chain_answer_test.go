/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The answer to a query whose name is a CNAME (#717): every link of the chain
// in order, then the data or the denial at its last name; with DO, each
// RRset's RRSIGs; AD only if every part is Secure. Fresh and from the cache.

// answerOrder returns "owner TYPE" for each RR in the answer section, RRSIGs
// left out.
func answerOrder(m *dns.Msg) []string {
	var out []string
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		out = append(out, core.CanonicalizeName(rr.Header().Name)+" "+dns.TypeToString[rr.Header().Rrtype])
	}
	return out
}

func answerSigCount(m *dns.Msg) int {
	n := 0
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			n++
		}
	}
	return n
}

func sameOrder(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func nsHasSOA(m *dns.Msg) bool {
	for _, rr := range m.Ns {
		if rr.Header().Rrtype == dns.TypeSOA {
			return true
		}
	}
	return false
}

// The whole chain is answered, in order, and from the cache without asking the
// auth server again.
func TestCNAMEChainAnswerHasEveryLink(t *testing.T) {
	imr, d := chainImr(t)
	want := []string{"a.chain.test. CNAME", "b.chain.test. CNAME", "c.chain.test. A"}
	for _, path := range []string{"fresh", "cached"} {
		m, _ := askChain(t, imr, "a."+chainZone, dns.TypeA)
		if m.Rcode != dns.RcodeSuccess || !sameOrder(answerOrder(m), want) {
			t.Errorf("%s: rcode %s, answer %v; want NOERROR with %v", path, dns.RcodeToString[m.Rcode], answerOrder(m), want)
		}
	}
	for _, name := range []string{"a", "b", "c"} {
		if n := d.count(name+"."+chainZone, dns.TypeA); n != 1 {
			t.Errorf("%s.%s A was queried %d times for two answers, want 1", name, chainZone, n)
		}
	}
}

// A chain that ends in NODATA or NXDOMAIN answers with every CNAME, the last
// name's rcode, and its SOA in the authority section.
func TestCNAMEChainAnswerNegativeEnds(t *testing.T) {
	imr, _ := chainImr(t)
	for _, tc := range []struct {
		qname string
		qtype uint16
		rcode int
		want  []string
	}{
		{"a." + chainZone, dns.TypeTXT, dns.RcodeSuccess, []string{"a.chain.test. CNAME", "b.chain.test. CNAME"}},
		{"nx." + chainZone, dns.TypeA, dns.RcodeNameError, []string{"nx.chain.test. CNAME"}},
	} {
		for _, path := range []string{"fresh", "cached"} {
			m, _ := askChain(t, imr, tc.qname, tc.qtype)
			if m.Rcode != tc.rcode || !sameOrder(answerOrder(m), tc.want) || !nsHasSOA(m) {
				t.Errorf("%s %s %s: rcode %s, answer %v, authority %v; want %s, %v and the SOA",
					path, tc.qname, dns.TypeToString[tc.qtype], dns.RcodeToString[m.Rcode], answerOrder(m), m.Ns,
					dns.RcodeToString[tc.rcode], tc.want)
			}
		}
	}
}

// The signed zone for the tests below, and an unsigned stub zone on the same
// server:
//
//	s1 -> s2 -> s3 A                 every RRset signed
//	bad -> s3                        the CNAME's RRSIG stripped on the way
//	out -> www.plain.test. A         into an unsigned zone
//	sub  DNAME tgt; www.tgt A        the server synthesizes www.sub -> www.tgt
//	lie  DNAME tgt                   the server's CNAME for www.lie says evil
//	s3 also has a DS, as though it were a delegation, for the DS test
const (
	sigChainZone = "sigchain.example."
	plainZone    = "plain.test."
)

func startSigChainDouble(t *testing.T, s *zoneSigner) string {
	t.Helper()
	z := sigChainZone
	soa := mustRR(t, z+" 300 IN SOA ns."+z+" hostmaster."+z+" 1 7200 1800 604800 300")
	plainSOA := mustRR(t, plainZone+" 300 IN SOA ns."+plainZone+" hostmaster."+plainZone+" 1 7200 1800 604800 300")
	cnames := map[string]string{
		"s1." + z:  "s2." + z,
		"s2." + z:  "s3." + z,
		"bad." + z: "s3." + z,
		"out." + z: "www." + plainZone,
	}
	addrs := map[string]string{
		"s3." + z:      "192.0.2.3",
		"www.tgt." + z: "192.0.2.4",
		"evil." + z:    "192.0.2.66",
	}
	dnames := map[string]string{"sub." + z: "tgt." + z, "lie." + z: "tgt." + z}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		name := core.CanonicalizeName(q.Name)
		var dnameOwner string
		for owner := range dnames {
			if dns.IsSubDomain(owner, name) && name != owner {
				dnameOwner = owner
			}
		}
		switch {
		case dns.IsSubDomain(plainZone, name):
			if name == "www."+plainZone && q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, mustRR(t, q.Name+" 300 IN A 192.0.2.80"))
			} else {
				m.Ns = append(m.Ns, plainSOA)
			}
		case dnameOwner != "":
			dname := mustRR(t, dnameOwner+" 300 IN DNAME "+dnames[dnameOwner])
			target := synthesizeFromDNAME(name, dnameOwner, dnames[dnameOwner])
			if dnameOwner == "lie."+z {
				target = "evil." + z
			}
			m.Answer = append(s.sign(t, dname), mustRR(t, q.Name+" 300 IN CNAME "+target))
		case cnames[name] != "":
			cn := mustRR(t, q.Name+" 300 IN CNAME "+cnames[name])
			if name == "bad."+z {
				m.Answer = append(m.Answer, cn)
			} else {
				m.Answer = s.sign(t, cn)
			}
		case name == "s3."+z && q.Qtype == dns.TypeDS:
			m.Answer = s.sign(t, mustRR(t, q.Name+" 300 IN DS 12345 15 2 "+strings.Repeat("AB", 32)))
		case addrs[name] != "" && q.Qtype == dns.TypeA:
			m.Answer = s.sign(t, mustRR(t, q.Name+" 300 IN A "+addrs[name]))
		case q.Qtype == dns.TypeSOA && name == z:
			m.Answer = s.sign(t, soa)
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
	case <-time.After(2 * time.Second):
		t.Fatal("auth double did not start")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.ShutdownContext(ctx); err != nil {
			t.Errorf("auth double shutdown: %v", err)
		}
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("auth double serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("auth double serve goroutine did not exit")
		}
	})
	return strconv.Itoa(pc.LocalAddr().(*net.UDPAddr).Port)
}

// sigChainImr holds sigChainZone as Secure, under a trust anchor for its key,
// and reaches both zones through stubs pointing at the double.
func sigChainImr(t *testing.T) *Imr {
	t.Helper()
	s := newZoneSigner(t, sigChainZone)
	port := startSigChainDouble(t, s)
	imr := verdictImr(t, true)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, port, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, port, nil)
	for _, zone := range []string{sigChainZone, plainZone} {
		if err := imr.Cache.AddStub(zone, []cache.AuthServer{
			{Name: "ns." + zone, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
		}); err != nil {
			t.Fatalf("AddStub(%s): %v", zone, err)
		}
	}
	imr.Cache.DnskeyCache.Set(sigChainZone, s.key.KeyTag(), &cache.CachedDnskeyRRset{Name: sigChainZone,
		Keyid: s.key.KeyTag(), TrustAnchor: true, State: cache.ValidationStateSecure, Dnskey: *s.key, Expiration: time.Now().Add(time.Hour)})
	imr.Cache.ZoneMap.Set(sigChainZone, &cache.Zone{ZoneName: sigChainZone, State: cache.ValidationStateSecure})
	return imr
}

// A chain whose every RRset is signed is Secure: AD, and with DO the RRSIG of
// every link and of the data.
func TestSecureCNAMEChainIsAuthenticated(t *testing.T) {
	imr := sigChainImr(t)
	want := []string{"s1.sigchain.example. CNAME", "s2.sigchain.example. CNAME", "s3.sigchain.example. A"}
	for _, path := range []string{"fresh", "cached"} {
		m, _ := askChain(t, imr, "s1."+sigChainZone, dns.TypeA)
		if m.Rcode != dns.RcodeSuccess || !sameOrder(answerOrder(m), want) {
			t.Fatalf("%s: rcode %s, answer %v; want NOERROR with %v", path, dns.RcodeToString[m.Rcode], answerOrder(m), want)
		}
		if !m.AuthenticatedData {
			t.Errorf("%s: AD not set on a chain whose every link is signed", path)
		}
		if n := answerSigCount(m); n != 3 {
			t.Errorf("%s: %d RRSIGs in the answer, want 3 (two CNAMEs and the A)", path, n)
		}
	}
}

// A link whose RRSIG was stripped, in a zone held Secure, fails the answer.
func TestCNAMEChainWithAStrippedLinkIsBogus(t *testing.T) {
	imr := sigChainImr(t)
	for _, path := range []string{"fresh", "cached"} {
		m, _ := askChain(t, imr, "bad."+sigChainZone, dns.TypeA)
		if m.Rcode != dns.RcodeServerFailure || len(m.Answer) != 0 {
			t.Fatalf("%s: rcode %s with %d answer RRs; a stripped link must be SERVFAIL",
				path, dns.RcodeToString[m.Rcode], len(m.Answer))
		}
		if got := edeOf(m); got != edns0.EDEDNSSECBogus {
			t.Errorf("%s: EDE %d, want %d (DNSSEC Bogus)", path, got, edns0.EDEDNSSECBogus)
		}
	}
}

// A chain that leaves the signed zone for an unsigned one is served, without
// AD.
func TestCNAMEChainIntoAnUnsignedZoneIsNotAuthenticated(t *testing.T) {
	imr := sigChainImr(t)
	want := []string{"out.sigchain.example. CNAME", "www.plain.test. A"}
	for _, path := range []string{"fresh", "cached"} {
		m, _ := askChain(t, imr, "out."+sigChainZone, dns.TypeA)
		if m.Rcode != dns.RcodeSuccess || !sameOrder(answerOrder(m), want) {
			t.Fatalf("%s: rcode %s, answer %v; want NOERROR with %v", path, dns.RcodeToString[m.Rcode], answerOrder(m), want)
		}
		if m.AuthenticatedData {
			t.Errorf("%s: AD set on a chain that ends in an unsigned zone", path)
		}
	}
}

// A CNAME synthesized from a signed DNAME is unsigned; the DNAME's signature
// covers it (RFC 6672 §5.3.1). The answer is Secure and carries the DNAME.
func TestCNAMESynthesizedFromASignedDNAMEIsAuthenticated(t *testing.T) {
	imr := sigChainImr(t)
	want := []string{"sub.sigchain.example. DNAME", "www.sub.sigchain.example. CNAME", "www.tgt.sigchain.example. A"}
	for _, path := range []string{"fresh", "cached"} {
		m, _ := askChain(t, imr, "www.sub."+sigChainZone, dns.TypeA)
		if m.Rcode != dns.RcodeSuccess || !sameOrder(answerOrder(m), want) {
			t.Fatalf("%s: rcode %s, answer %v; want NOERROR with %v", path, dns.RcodeToString[m.Rcode], answerOrder(m), want)
		}
		if !m.AuthenticatedData {
			t.Errorf("%s: AD not set on an answer through a signed DNAME", path)
		}
	}
}

// A CNAME that differs from what its DNAME synthesizes is not followed: the
// chain goes where the signed DNAME says (RFC 6672 §3.2).
func TestCNAMEThatContradictsItsDNAMEIsNotFollowed(t *testing.T) {
	imr := sigChainImr(t)
	m, _ := askChain(t, imr, "www.lie."+sigChainZone, dns.TypeA)
	want := []string{"lie.sigchain.example. DNAME", "www.lie.sigchain.example. CNAME", "www.tgt.sigchain.example. A"}
	if m.Rcode != dns.RcodeSuccess || !sameOrder(answerOrder(m), want) {
		t.Fatalf("rcode %s, answer %v; want NOERROR with %v", dns.RcodeToString[m.Rcode], answerOrder(m), want)
	}
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok && a.A.Equal(net.ParseIP("192.0.2.66")) {
			t.Errorf("the answer carries evil's address %v: the server's CNAME was followed", a)
		}
	}
}

// A DS question is never answered through a CNAME: DS is parent-side data about
// a delegation, and the chain's target is another name. The double answers
// every question at s1 with its CNAME, DS included. Asked the way the
// validator asks (IterativeDNSQuery), the chase used to come back with the
// chain's links.
func TestDSQuestionDoesNotFollowACNAME(t *testing.T) {
	imr := sigChainImr(t)
	_, servers, _ := imr.Cache.FindClosestKnownZoneFor("s1."+sigChainZone, dns.TypeDS)
	rrset, _, _, _, _ := imr.IterativeDNSQuery(context.Background(), "s1."+sigChainZone, dns.TypeDS, servers, false, edns0.PrivacyNone)
	if rrset == nil {
		return
	}
	for _, rr := range rrset.RRs {
		if rr.Header().Rrtype != dns.TypeDS {
			t.Errorf("s1 DS: the result carries %s %s: the CNAME was followed",
				core.CanonicalizeName(rr.Header().Name), dns.TypeToString[rr.Header().Rrtype])
		}
	}
}
