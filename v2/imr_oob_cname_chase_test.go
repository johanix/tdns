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
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// Regression test for tdns#675: a CNAME chain that stays inside a zone whose
// nameservers are all out-of-bailiwick (cloud.microsoft. -> *.azure-dns.*).
//
// The live failure: outlook.office365.com -> outlook.cloud.microsoft. ->
// acdcatm.outlook.mira.tm.svc.cloud.microsoft. -> ... ended with
// "zone=cloud.microsoft., no auth-server attempts made".
//
// A referral to such a zone carries no glue, and the zone's cached server map
// stays empty, so every hop of the chase starts with no servers and depends on
// expandServerMapWithMissingNS. The nameserver's shared AuthServer already has
// addresses; the helper reported that as nothing added, and the hop gave up
// without sending a query.
func TestCNAMEChaseInsideOutOfBailiwickZone(t *testing.T) {
	const (
		zone   = "oob.test."
		nsname = "ns1.other.test."
	)
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port, _ := net.SplitHostPort(pc.LocalAddr().String())

	soa := &dns.SOA{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:  nsname, Mbox: "hostmaster." + zone,
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
	}
	cname := map[string]string{
		"a." + zone: "b." + zone,
		"b." + zone: "c." + zone,
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		// One CNAME per response, as Azure DNS answered in the live case.
		if target, ok := cname[q.Name]; ok {
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: target,
			})
		} else if q.Name == "c."+zone && q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, 1),
			})
		} else {
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
		t.Fatal("auth double did not start")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.ShutdownContext(ctx); err != nil {
			t.Errorf("auth double shutdown: %v", err)
		}
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Error("auth double serve goroutine did not exit")
		}
	})

	lg := log.New(os.Stderr, "test", log.LstdFlags)
	c := cache.NewRRsetCache(lg, false, false)
	c.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, port, nil)
	c.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, port, nil)
	imr := &Imr{
		Cache: c,
		Quiet: true,
		FamilyTracker: cache.NewFamilyTracker(
			10*time.Minute, 10*time.Minute, 30*time.Second, 5),
	}
	ctx := context.Background()

	// The out-of-bailiwick nameserver's addresses are already known, as they
	// were in the live case after the first lookup.
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		rrset := &core.RRset{Name: nsname, Class: dns.ClassINET, RRtype: qt}
		if qt == dns.TypeA {
			rrset.RRs = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: nsname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
				A:   net.ParseIP(host),
			}}
			c.Set(nsname, qt, &cache.CachedRRset{
				Name: nsname, RRtype: qt, RRset: rrset, Context: cache.ContextAnswer,
				State: cache.ValidationStateInsecure, Expiration: time.Now().Add(time.Hour),
			})
		} else {
			c.Set(nsname, qt, &cache.CachedRRset{
				Name: nsname, RRtype: qt, Context: cache.ContextNoErrNoAns,
				State: cache.ValidationStateInsecure, Expiration: time.Now().Add(time.Hour),
			})
		}
	}

	// The parent's referral for the zone: NS only, no glue (it cannot have
	// any for an out-of-bailiwick name). Fed through the real referral path.
	ref := new(dns.Msg)
	ref.SetQuestion("a."+zone, dns.TypeA)
	ref.Response = true
	ref.Ns = []dns.RR{&dns.NS{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  nsname,
	}}

	rrset, rcode, cctx, _, err := imr.handleReferral(ctx, "a."+zone, dns.TypeA, ref, false,
		map[string]bool{}, core.TransportDo53, edns0.PrivacyNone)

	if sm, ok := c.ServerMap.Get(zone); ok {
		t.Logf("cache ServerMap[%s] after referral: %d servers", zone, len(sm))
	}
	if err != nil {
		t.Fatalf("a.%s A: %v", zone, err)
	}
	if rcode != dns.RcodeSuccess || cctx != cache.ContextAnswer || rrset == nil {
		t.Fatalf("a.%s A: rcode=%s context=%s rrset=%v", zone,
			dns.RcodeToString[rcode], cache.CacheContextToString[cctx], rrset)
	}
	var gotA bool
	for _, rr := range rrset.RRs {
		if a, ok := rr.(*dns.A); ok && a.A.Equal(net.IPv4(192, 0, 2, 1)) {
			gotA = true
		}
	}
	if !gotA {
		t.Fatalf("a.%s A: chain did not end in the A record: %v", zone, rrset.RRs)
	}
}
