/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"log"
	"net"
	"os"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// End-to-end regression test for docs/2026-08-11-imr-stub-resolution-broken.md.
//
// The failure sequence was: during trust-anchor bootstrap the IMR sent a DS
// query for the stub zone to the stub's own (child-authoritative) server; the
// server answered REFUSED — correctly, a DS is parent-side data — and the
// refusal was booked as a lame delegation. That put the stub's only
// (addr, transport) into backoff, prioritizeServers had nothing left to offer,
// and every later query for the zone ended with zero auth-server attempts and
// SERVFAIL. Fixed by refusalIndicatesLameness (commit 27100698); this test
// replays the whole sequence through the real query path so the fix cannot
// regress silently.

// startStubAuthServer is an authoritative-server double for stub-zone tests:
// AA=1 answers for SOA/NS/A, REFUSED for DS (a child-auth server does not hold
// its own DS), NODATA for everything else.
func startStubAuthServer(t *testing.T, zone string) (string, string, func()) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port, _ := net.SplitHostPort(pc.LocalAddr().String())

	soa := &dns.SOA{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:  "ns." + zone, Mbox: "hostmaster." + zone,
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		switch q.Qtype {
		case dns.TypeDS:
			m.Rcode = dns.RcodeRefused
		case dns.TypeSOA:
			m.Answer = append(m.Answer, soa)
		case dns.TypeNS:
			m.Answer = append(m.Answer, &dns.NS{
				Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
				Ns:  "ns." + zone,
			})
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, 55),
			})
		default:
			m.Ns = append(m.Ns, soa)
		}
		_ = w.WriteMsg(m)
	})

	started := make(chan struct{})
	served := make(chan error, 1)
	srv := &dns.Server{PacketConn: pc, Handler: mux, NotifyStartedFunc: func() { close(started) }}
	go func() { served <- srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("stub auth double did not start")
	}
	return host, port, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.ShutdownContext(ctx); err != nil {
			t.Errorf("stub auth double shutdown: %v", err)
		}
		select {
		case <-served:
		case <-time.After(2 * time.Second):
			t.Error("stub auth double serve goroutine did not exit")
		}
	}
}

func TestStubZoneSurvivesRefusedDSQuery(t *testing.T) {
	const zone = "stubtest.example."
	addr, port, stop := startStubAuthServer(t, zone)
	defer stop()

	// Backoffs long enough that a booked lame delegation cannot expire
	// within the test: if the DS refusal poisons the server, the later
	// queries MUST fail. The policy is package-level state; restore it so
	// later tests don't inherit the one-hour values.
	prevPolicy := cache.GetBackoffPolicy()
	t.Cleanup(func() { cache.SetBackoffPolicy(prevPolicy) })
	cache.SetBackoffPolicy(cache.BackoffPolicy{
		FirstFailure:   15 * time.Second,
		MaxFailure:     time.Hour,
		Multiplier:     3.0,
		JitterFraction: 0.25,
		RoutingFailure: time.Hour,
		LameDelegation: time.Hour,
	})

	lg := log.New(os.Stderr, "test", log.LstdFlags)
	c := cache.NewRRsetCache(lg, false, false)
	// The stub machinery reaches its servers through the cache's shared
	// per-transport clients (fixed port 53); point them at the double.
	c.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, port, nil)
	c.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, port, nil)
	if err := c.AddStub(zone, []cache.AuthServer{
		{Name: "ns." + zone, Addrs: []string{addr}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	imr := &Imr{
		Cache: c,
		Quiet: true,
		FamilyTracker: cache.NewFamilyTracker(
			10*time.Minute, 10*time.Minute, 30*time.Second, 5),
	}
	ctx := context.Background()

	stubMap := func() map[string]*cache.AuthServer {
		t.Helper()
		bestmatch, servers, err := c.FindClosestKnownZone(zone)
		if err != nil || bestmatch != zone || len(servers) == 0 {
			t.Fatalf("FindClosestKnownZone(%s) = %q, %d servers, err=%v", zone, bestmatch, len(servers), err)
		}
		return servers
	}

	// Step 1 — the poisoning query from the original sequence: a DS query
	// for the stub zone, sent to the stub's own server (as trust-anchor
	// bootstrap's backfillDS did). The server answers REFUSED, and that
	// refusal must reach us as REFUSED — a transport failure here would
	// make the rest of the test vacuous. The walk error that comes with an
	// exhausted tuple list is expected; what matters is what the refusal
	// must NOT do.
	rrset, rcode, _, _, _ := imr.IterativeDNSQuery(ctx, zone, dns.TypeDS, stubMap(), false, false)
	if rrset != nil && len(rrset.RRs) > 0 {
		t.Fatalf("DS query unexpectedly returned data: %v", rrset.RRs)
	}
	if rcode != dns.RcodeRefused {
		t.Fatalf("DS query rcode = %s, want REFUSED from the stub's server", dns.RcodeToString[rcode])
	}

	// Step 2 — the queries that went dead on foffe: with the refusal booked
	// as a lame delegation, these made zero auth-server attempts and
	// SERVFAILed. They must answer.
	rrset, rcode, cctx, _, err := imr.IterativeDNSQuery(ctx, zone, dns.TypeSOA, stubMap(), false, false)
	if err != nil {
		t.Fatalf("SOA query after refused DS: %v", err)
	}
	if rcode != dns.RcodeSuccess || cctx != cache.ContextAnswer || rrset == nil || len(rrset.RRs) != 1 {
		t.Fatalf("SOA query after refused DS: rcode=%s context=%s rrset=%v",
			dns.RcodeToString[rcode], cache.CacheContextToString[cctx], rrset)
	}

	rrset, rcode, _, _, err = imr.IterativeDNSQuery(ctx, "www."+zone, dns.TypeA, stubMap(), false, false)
	if err != nil {
		t.Fatalf("A query after refused DS: %v", err)
	}
	if rcode != dns.RcodeSuccess || rrset == nil || len(rrset.RRs) != 1 {
		t.Fatalf("A query after refused DS: rcode=%s rrset=%v", dns.RcodeToString[rcode], rrset)
	}
}
