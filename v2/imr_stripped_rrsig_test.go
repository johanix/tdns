/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * An answer whose RRSIGs were stripped, from a zone the resolver holds as
 * Secure, is bogus -- not an insecure answer to serve.
 */
package tdns

import (
	"context"
	"crypto"
	"net"
	"strconv"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

const (
	strippedZone = "signed.example."     // signed, held Secure by the resolver
	strippedKid  = "kid." + strippedZone // unsigned child, on the same server
	strippedWWW  = "www." + strippedZone
	kidWWW       = "www." + strippedKid
)

// zoneSigner signs with a key the resolver holds as Secure for its zone, so what
// it signs validates for real.
type zoneSigner struct {
	zone string
	key  *dns.DNSKEY
	priv crypto.Signer
}

func newZoneSigner(t *testing.T, zone string) *zoneSigner {
	t.Helper()
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 256, Protocol: 3, Algorithm: dns.ED25519}
	p, err := k.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	return &zoneSigner{zone: zone, key: k, priv: p.(crypto.Signer)}
}

// sign returns rrs followed by their RRSIG.
func (s *zoneSigner) sign(t *testing.T, rrs ...dns.RR) []dns.RR {
	t.Helper()
	sig := &dns.RRSIG{Algorithm: dns.ED25519, KeyTag: s.key.KeyTag(), SignerName: s.zone,
		Inception:  uint32(time.Now().Add(-time.Hour).Unix()),
		Expiration: uint32(time.Now().Add(time.Hour).Unix())}
	if err := sig.Sign(s.priv, rrs); err != nil {
		t.Fatal(err)
	}
	return append(append([]dns.RR{}, rrs...), sig)
}

// startStrippingAuthDouble serves strippedZone, signed, and strippedKid, an
// unsigned child delegated from it, from one address -- so the resolver never
// sees a referral for the child. It answers the way an authoritative server
// behind an on-path attacker would: every A RRset goes out without its RRSIG,
// everything else as the zone has it. A DS query is answered from the parent
// side, with the NSEC that says whether the name is a delegation.
func startStrippingAuthDouble(t *testing.T, s *zoneSigner) int {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.1: %v", err)
	}
	soa := mustRR(t, strippedZone+" 300 IN SOA ns."+strippedZone+" hostmaster."+strippedZone+" 1 7200 1800 604800 300")
	kidSOA := mustRR(t, strippedKid+" 300 IN SOA ns."+strippedKid+" hostmaster."+strippedKid+" 1 7200 1800 604800 300")
	// The parent's NSEC chain: apex, the delegation, www.
	nsecAt := map[string]dns.RR{
		strippedKid: mustRR(t, strippedKid+" 300 IN NSEC "+strippedWWW+" NS RRSIG NSEC"),
		strippedWWW: mustRR(t, strippedWWW+" 300 IN NSEC "+strippedZone+" A RRSIG NSEC"),
	}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		inKid := dns.IsSubDomain(strippedKid, dns.CanonicalName(q.Name))
		switch {
		case q.Qtype == dns.TypeDS && nsecAt[dns.CanonicalName(q.Name)] != nil:
			m.Ns = append(s.sign(t, soa), s.sign(t, nsecAt[dns.CanonicalName(q.Name)])...)
		case q.Qtype == dns.TypeA && (core.EqualNames(q.Name, strippedWWW) || core.EqualNames(q.Name, kidWWW)):
			m.Answer = append(m.Answer, mustRR(t, q.Name+" 300 IN A 192.0.2.80"))
		case q.Qtype == dns.TypeSOA && core.EqualNames(q.Name, strippedZone):
			m.Answer = s.sign(t, soa)
		case q.Qtype == dns.TypeSOA && core.EqualNames(q.Name, strippedKid):
			m.Answer = append(m.Answer, kidSOA)
		case inKid:
			m.Ns = append(m.Ns, kidSOA)
		default:
			m.Ns = s.sign(t, soa)
		}
		_ = w.WriteMsg(m)
	})
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
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// strippingImr is a resolver that holds strippedZone as Secure, under a trust
// anchor for its key, and reaches it through a stub pointing at the double.
func strippingImr(t *testing.T) *Imr {
	t.Helper()
	s := newZoneSigner(t, strippedZone)
	port := strconv.Itoa(startStrippingAuthDouble(t, s))

	imr := verdictImr(t, true)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, port, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, port, nil)
	if err := imr.Cache.AddStub(strippedZone, []cache.AuthServer{
		{Name: "ns." + strippedZone, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	imr.Cache.DnskeyCache.Set(strippedZone, s.key.KeyTag(), &cache.CachedDnskeyRRset{Name: strippedZone,
		Keyid: s.key.KeyTag(), TrustAnchor: true, State: cache.ValidationStateSecure, Dnskey: *s.key, Expiration: time.Now().Add(time.Hour)})
	imr.Cache.ZoneMap.Set(strippedZone, &cache.Zone{ZoneName: strippedZone, State: cache.ValidationStateSecure})
	return imr
}

func askResponder(t *testing.T, imr *Imr, qname string, q verdictQuery) *dns.Msg {
	t.Helper()
	r, opts := q.msgFor(qname, dns.TypeA)
	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, qname, dns.TypeA, opts)
	if cw.got == nil {
		t.Fatalf("%s: responder wrote nothing", qname)
	}
	return cw.got
}

// THE DEFECT. The RRSIGs of an answer from a zone the resolver holds as Secure
// were stripped on the way, and the answer validated Insecure -- so it went to
// the client as NOERROR, fresh and from the cache, where it must be SERVFAIL.
// A client that does not validate for itself took the attacker's data.
func TestAStrippedAnswerFromASecureZoneIsNotServed(t *testing.T) {
	for name, q := range map[string]verdictQuery{"DO": {do: true}, "no DO": {}} {
		t.Run(name, func(t *testing.T) {
			imr := strippingImr(t)
			for _, path := range []string{"fresh", "cached"} {
				m := askResponder(t, imr, strippedWWW, q)
				if m.Rcode != dns.RcodeServerFailure || len(m.Answer) != 0 {
					t.Fatalf("%s: rcode %s with %d answer RRs; a stripped answer from a secure zone must be SERVFAIL",
						path, dns.RcodeToString[m.Rcode], len(m.Answer))
				}
				if got := edeOf(m); got != edns0.EDEDNSSECBogus {
					t.Errorf("%s: EDE %d, want %d (DNSSEC Bogus)", path, got, edns0.EDEDNSSECBogus)
				}
			}
		})
	}
}

// What the fix must not break: a child delegated insecurely from the secure zone,
// on the same server, so it has no ZoneMap entry of its own and the closest zone
// the resolver knows for its data is the secure parent. The parent's NSEC for
// the delegation proves there is no DS, and the data is served, without AD.
func TestUnsignedDataBelowAnUnreferredInsecureDelegationIsServed(t *testing.T) {
	imr := strippingImr(t)
	for _, path := range []string{"fresh", "cached"} {
		m := askResponder(t, imr, kidWWW, verdictQuery{do: true})
		if m.Rcode != dns.RcodeSuccess || len(m.Answer) == 0 {
			t.Fatalf("%s: rcode %s with %d answer RRs; data in an insecure child must be served",
				path, dns.RcodeToString[m.Rcode], len(m.Answer))
		}
		if m.AuthenticatedData {
			t.Errorf("%s: AD set on data from an insecure child", path)
		}
	}
}
