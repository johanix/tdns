/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * NSEC no data proofs for a name that owns no NSEC of its own: an empty
 * non-terminal, and a wildcard without the type asked for.
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
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// ndZone is signed, and held Secure under a trust anchor for its key. In it,
// ent.ndZone and ent2.ndZone are empty non-terminals, and *.wild.ndZone holds
// an A and nothing else.
const ndZone = "nodata.example."

func startNoDataDouble(t *testing.T, s *zoneSigner) string {
	t.Helper()
	z := ndZone
	soa := mustRR(t, z+" 300 IN SOA ns."+z+" hostmaster."+z+" 1 7200 1800 604800 300")
	denial := func(nsecs ...string) []dns.RR {
		ns := s.sign(t, soa)
		for _, n := range nsecs {
			ns = append(ns, s.sign(t, mustRR(t, n))...)
		}
		return ns
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		switch name := core.CanonicalizeName(q.Name); {
		case name == "ent."+z:
			// NODATA: an NSEC covering the name, its next name below it.
			m.Ns = denial("a." + z + " 300 IN NSEC x.ent." + z + " A RRSIG NSEC")
		case name == "x.wild."+z && q.Qtype == dns.TypeAAAA:
			// NODATA: the wildcard's NSEC, which also covers the name.
			m.Ns = denial("*.wild." + z + " 300 IN NSEC z.wild." + z + " A RRSIG NSEC")
		case name == "ent2."+z:
			// NXDOMAIN, proved with a cover whose next name is below the
			// name, and the apex NSEC covering *.ndZone.
			m.Rcode = dns.RcodeNameError
			m.Ns = denial("a."+z+" 300 IN NSEC x.ent2."+z+" A RRSIG NSEC",
				z+" 300 IN NSEC a."+z+" SOA NS RRSIG NSEC DNSKEY")
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

func noDataImr(t *testing.T) *Imr {
	t.Helper()
	s := newZoneSigner(t, ndZone)
	port := startNoDataDouble(t, s)
	imr := verdictImr(t, true)
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, port, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, port, nil)
	if err := imr.Cache.AddStub(ndZone, []cache.AuthServer{
		{Name: "ns." + ndZone, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	imr.Cache.DnskeyCache.Set(ndZone, s.key.KeyTag(), &cache.CachedDnskeyRRset{Name: ndZone,
		Keyid: s.key.KeyTag(), TrustAnchor: true, State: cache.ValidationStateSecure, Dnskey: *s.key, Expiration: time.Now().Add(time.Hour)})
	imr.Cache.ZoneMap.Set(ndZone, &cache.Zone{ZoneName: ndZone, State: cache.ValidationStateSecure})
	return imr
}

func countNSEC(rrs []dns.RR) int {
	n := 0
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeNSEC {
			n++
		}
	}
	return n
}

// An empty non-terminal, and a name a wildcard answers for without the type
// asked for: NOERROR with AD and the proof, fresh and from the cache. An
// NXDOMAIN whose cover shows the name to have a descendant does not hold:
// SERVFAIL.
func TestNSECNoDataShapesThroughTheResolver(t *testing.T) {
	cases := []struct {
		name  string
		qname string
		qtype uint16
		rcode int
		ad    bool
		ede   uint16
	}{
		{"empty non-terminal", "ent." + ndZone, dns.TypeA, dns.RcodeSuccess, true, 0},
		{"wildcard no data", "x.wild." + ndZone, dns.TypeAAAA, dns.RcodeSuccess, true, 0},
		{"name error at an empty non-terminal", "ent2." + ndZone, dns.TypeA, dns.RcodeServerFailure, false, edns0.EDEDNSSECBogus},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			imr := noDataImr(t)
			for _, path := range []string{"fresh", "cached"} {
				m, _ := askChain(t, imr, c.qname, c.qtype)
				if m.Rcode != c.rcode || m.AuthenticatedData != c.ad {
					t.Errorf("%s: rcode %s AD %v; want %s AD %v", path,
						dns.RcodeToString[m.Rcode], m.AuthenticatedData, dns.RcodeToString[c.rcode], c.ad)
				}
				if c.rcode == dns.RcodeSuccess && countNSEC(m.Ns) == 0 {
					t.Errorf("%s: no NSEC in the authority section: %v", path, m.Ns)
				}
				if c.ede != 0 && edeOf(m) != c.ede {
					t.Errorf("%s: EDE %d, want %d", path, edeOf(m), c.ede)
				}
			}
		})
	}
}
