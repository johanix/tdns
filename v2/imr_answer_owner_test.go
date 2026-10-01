/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * An answer is built only from the records owned by the name asked for.
 */
package tdns

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The zones for the tests below, on one server: aoZone signed, and held Secure
// under a trust anchor for its key; aoPlain unsigned.
const (
	aoZone  = "owner.example."
	aoPlain = "owner-plain.test."
	aoOther = "b." + aoZone // a name whose records answer questions for other names
)

// startAnswerOwnerDouble serves the two zones. Each question below gets the
// answer section its comment names; anything else gets the zone's SOA.
func startAnswerOwnerDouble(t *testing.T, s *zoneSigner) string {
	t.Helper()
	z := aoZone
	soa := mustRR(t, z+" 300 IN SOA ns."+z+" hostmaster."+z+" 1 7200 1800 604800 300")
	plainSOA := mustRR(t, aoPlain+" 300 IN SOA ns."+aoPlain+" hostmaster."+aoPlain+" 1 7200 1800 604800 300")
	other := func() []dns.RR { return s.sign(t, mustRR(t, aoOther+" 300 IN A 192.0.2.2")) }
	sigOnly := func(rrs []dns.RR) dns.RR { return rrs[len(rrs)-1] }

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		name := core.CanonicalizeName(q.Name)
		switch {
		case name == "other."+z && q.Qtype == dns.TypeA:
			// The asked type at another owner, signed.
			m.Answer = other()
		case name == "other."+aoPlain && q.Qtype == dns.TypeA:
			// The asked type at another owner, unsigned.
			m.Answer = []dns.RR{mustRR(t, "b."+aoPlain+" 300 IN A 192.0.2.9")}
		case name == "mixed."+z && q.Qtype == dns.TypeA:
			// The name's own A, and another name's.
			m.Answer = append(s.sign(t, mustRR(t, q.Name+" 300 IN A 192.0.2.3")), other()...)
		case name == "sigs."+z && q.Qtype == dns.TypeA:
			// The name's own A, an RRSIG of its own over another type, and
			// another name's RRSIG over an A.
			m.Answer = append(s.sign(t, mustRR(t, q.Name+" 300 IN A 192.0.2.4")),
				sigOnly(s.sign(t, mustRR(t, q.Name+` 300 IN TXT "x"`))), sigOnly(other()))
		case name == "s1."+z && q.Qtype == dns.TypeCNAME:
			// A CNAME query answered with the whole chain.
			m.Answer = append(append(s.sign(t, mustRR(t, q.Name+" 300 IN CNAME s2."+z)),
				s.sign(t, mustRR(t, "s2."+z+" 300 IN CNAME s3."+z))...),
				s.sign(t, mustRR(t, "s3."+z+" 300 IN A 192.0.2.5"))...)
		case name == "case."+z && q.Qtype == dns.TypeA:
			// The owner spelled in another case than the question.
			m.Answer = s.sign(t, mustRR(t, "CASE.Owner.Example. 300 IN A 192.0.2.6"))
		case dns.IsSubDomain(aoPlain, name):
			m.Ns = append(m.Ns, plainSOA)
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

// answerOwnerImr holds aoZone as Secure, under a trust anchor for its key, and
// reaches both zones through stubs pointing at the double.
func answerOwnerImr(t *testing.T) *Imr {
	t.Helper()
	s := newZoneSigner(t, aoZone)
	port := startAnswerOwnerDouble(t, s)
	imr := verdictImr(t, true)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, port, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, port, nil)
	for _, zone := range []string{aoZone, aoPlain} {
		if err := imr.Cache.AddStub(zone, []cache.AuthServer{
			{Name: "ns." + zone, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
		}); err != nil {
			t.Fatalf("AddStub(%s): %v", zone, err)
		}
	}
	imr.Cache.DnskeyCache.Set(aoZone, s.key.KeyTag(), &cache.CachedDnskeyRRset{Name: aoZone,
		Keyid: s.key.KeyTag(), TrustAnchor: true, State: cache.ValidationStateSecure, Dnskey: *s.key, Expiration: time.Now().Add(time.Hour)})
	imr.Cache.ZoneMap.Set(aoZone, &cache.Zone{ZoneName: aoZone, State: cache.ValidationStateSecure})
	return imr
}

// ownersOf lists the owner of every record of type t in rrs.
func ownersOf(rrs []dns.RR, t uint16) []string {
	var out []string
	for _, rr := range rrs {
		if rr.Header().Rrtype == t {
			out = append(out, core.CanonicalizeName(rr.Header().Name))
		}
	}
	return out
}

// sigsIn lists "owner covered" for every RRSIG in rrs.
func sigsIn(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		if sig, ok := rr.(*dns.RRSIG); ok {
			out = append(out, core.CanonicalizeName(sig.Hdr.Name)+" "+dns.TypeToString[sig.TypeCovered])
		}
	}
	return out
}

// A response whose records of the asked type are all owned by another name
// answers nothing: it is not used, signed or not, and the client gets no
// record of that name.
func TestAnAnswerOwnedByAnotherNameIsNotUsed(t *testing.T) {
	for _, qname := range []string{"other." + aoZone, "other." + aoPlain} {
		t.Run(qname, func(t *testing.T) {
			imr := answerOwnerImr(t)
			m, _ := askChain(t, imr, qname, dns.TypeA)
			if len(m.Answer) != 0 || m.Rcode == dns.RcodeSuccess {
				t.Errorf("rcode %s, answer %v; want no answer from records owned by another name",
					dns.RcodeToString[m.Rcode], m.Answer)
			}
			if c := imr.Cache.Peek(qname, dns.TypeA); c != nil && c.RRset != nil && len(c.RRset.RRs) > 0 {
				t.Errorf("cached under %s: %v", qname, c.RRset.RRs)
			}
		})
	}
}

// An answer section that holds the name's own records and another name's is
// answered with the name's own, which validate.
func TestAnAnswerKeepsOnlyTheRecordsOfTheNameAsked(t *testing.T) {
	imr := answerOwnerImr(t)
	qname := "mixed." + aoZone
	for _, path := range []string{"fresh", "cached"} {
		m, _ := askChain(t, imr, qname, dns.TypeA)
		got := ownersOf(m.Answer, dns.TypeA)
		if m.Rcode != dns.RcodeSuccess || !m.AuthenticatedData || len(got) != 1 || got[0] != qname {
			t.Errorf("%s: rcode %s, AD %v, A owners %v; want NOERROR, AD and %s only",
				path, dns.RcodeToString[m.Rcode], m.AuthenticatedData, got, qname)
		}
	}
}

// The RRSIGs kept with an answer are the name's own over the asked type.
// Others in the answer section are not served with it.
func TestAnAnswerKeepsOnlyItsOwnSignatures(t *testing.T) {
	imr := answerOwnerImr(t)
	qname := "sigs." + aoZone
	for _, path := range []string{"fresh", "cached"} {
		m, _ := askChain(t, imr, qname, dns.TypeA)
		got := sigsIn(m.Answer)
		if m.Rcode != dns.RcodeSuccess || !m.AuthenticatedData || len(got) != 1 || got[0] != qname+" A" {
			t.Errorf("%s: rcode %s, AD %v, RRSIGs %v; want NOERROR, AD and [%s A]",
				path, dns.RcodeToString[m.Rcode], m.AuthenticatedData, got, qname)
		}
	}
}

// A CNAME query answered with the whole chain is answered with the CNAME the
// name owns, which validates.
func TestACNAMEQueryAnsweredWithAWholeChainValidates(t *testing.T) {
	imr := answerOwnerImr(t)
	qname := "s1." + aoZone
	m, _ := askChain(t, imr, qname, dns.TypeCNAME)
	got := ownersOf(m.Answer, dns.TypeCNAME)
	if m.Rcode != dns.RcodeSuccess || !m.AuthenticatedData || len(got) != 1 || got[0] != qname ||
		len(ownersOf(m.Answer, dns.TypeA)) != 0 {
		t.Errorf("rcode %s, AD %v, answer %v; want NOERROR, AD and %s CNAME only",
			dns.RcodeToString[m.Rcode], m.AuthenticatedData, m.Answer, qname)
	}
}

// Owners are compared as DNS names: case does not matter.
func TestAnAnswerOwnerComparesWithoutCase(t *testing.T) {
	imr := answerOwnerImr(t)
	m, _ := askChain(t, imr, "case."+aoZone, dns.TypeA)
	if m.Rcode != dns.RcodeSuccess || !m.AuthenticatedData || len(ownersOf(m.Answer, dns.TypeA)) != 1 {
		t.Errorf("rcode %s, AD %v, answer %v; want NOERROR, AD and the A",
			dns.RcodeToString[m.Rcode], m.AuthenticatedData, m.Answer)
	}
}
