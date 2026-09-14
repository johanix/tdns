/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
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

// startAnswerDouble is an authoritative double for zone on 127.0.0.1 that
// answers every qtype query with answer, whatever the name asked, and anything
// else with NODATA and the zone SOA.
func startAnswerDouble(t *testing.T, zone string, qtype uint16, answer []dns.RR) (int, func()) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.1: %v", err)
	}
	soa := &dns.SOA{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:  "ns." + zone, Mbox: "hostmaster." + zone,
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if r.Question[0].Qtype == qtype {
			m.Answer = append(m.Answer, answer...)
		} else {
			m.Ns = append(m.Ns, soa)
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
		t.Fatalf("answer double failed to serve: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("answer double did not start")
	}
	return pc.LocalAddr().(*net.UDPAddr).Port, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.ShutdownContext(ctx); err != nil {
			t.Errorf("answer double shutdown: %v", err)
		}
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("answer double stopped serving with: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("answer double: serve goroutine did not exit")
		}
	}
}

// The answer for www.victim.example. comes back signed by a zone whose key the
// resolver rightly holds Secure -- a properly signed and delegated zone the
// attacker runs -- but that zone is not victim.example. or an ancestor of it.
// The responder must not serve it, least of all with AD.
func TestResponderRefusesAnOutOfBailiwickSigner(t *testing.T) {
	const zone = "victim.example."
	const qname = "www." + zone
	cases := []struct{ name, signer, owner string }{
		{"signer is a string suffix of the qname", "ictim.example.", qname},
		{"answer owned by a name in the signer's zone", "attacker.example.", "www.attacker.example."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: c.signer, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
				Flags: 256, Protocol: 3, Algorithm: dns.ED25519}
			priv, err := k.Generate(256)
			if err != nil {
				t.Fatal(err)
			}
			a := &dns.A{Hdr: dns.RR_Header{Name: c.owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A: net.IPv4(192, 0, 2, 66)}
			sig := &dns.RRSIG{Algorithm: dns.ED25519, KeyTag: k.KeyTag(), SignerName: c.signer,
				Inception:  uint32(time.Now().Add(-time.Hour).Unix()),
				Expiration: uint32(time.Now().Add(time.Hour).Unix())}
			if err := sig.Sign(priv.(crypto.Signer), []dns.RR{a}); err != nil {
				t.Fatal(err)
			}

			port, stop := startAnswerDouble(t, zone, dns.TypeA, []dns.RR{a, sig})
			t.Cleanup(stop)

			imr := verdictImr(t, true)
			imr.Cache.DnskeyCache.Set(c.signer, k.KeyTag(), &cache.CachedDnskeyRRset{Name: c.signer, Keyid: k.KeyTag(),
				State: cache.ValidationStateSecure, Dnskey: *k, Expiration: time.Now().Add(time.Hour)})
			p := strconv.Itoa(port)
			imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
			imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
			if err := imr.Cache.AddStub(zone, []cache.AuthServer{
				{Name: "ns." + zone, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
			}); err != nil {
				t.Fatalf("AddStub(%s): %v", zone, err)
			}

			r, opts := verdictQuery{do: true}.msgFor(qname, dns.TypeA)
			cw := &captureWriter{}
			imr.ImrResponder(context.Background(), cw, r, qname, dns.TypeA, opts)
			if cw.got == nil {
				t.Fatal("responder wrote no response")
			}
			if cw.got.AuthenticatedData {
				t.Errorf("served with AD: rcode %s, answer %v", dns.RcodeToString[cw.got.Rcode], cw.got.Answer)
			}
			if cw.got.Rcode != dns.RcodeServerFailure || edeOf(cw.got) != edns0.EDEDNSSECBogus {
				t.Errorf("rcode %s EDE %d, answer %v; want SERVFAIL with EDE %d",
					dns.RcodeToString[cw.got.Rcode], edeOf(cw.got), cw.got.Answer, edns0.EDEDNSSECBogus)
			}
		})
	}
}
