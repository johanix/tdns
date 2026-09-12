/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * A client's DS question is asked of the PARENT's servers (#150).
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
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// startDSAuthDouble is an authoritative double for zone on ip:port (port 0
// picks one). A DS query for ds's owner is answered with ds when ds is non-nil,
// which makes the double the parent; a DS query to a double without one is
// REFUSED, as a child-only server does. Anything else is NODATA with the zone
// SOA. The counter records the DS queries the double received.
func startDSAuthDouble(t *testing.T, ip net.IP, port int, zone string, ds dns.RR) (int, *atomic.Int32, func()) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		t.Skipf("cannot listen on %s port %d: %v", ip, port, err)
	}
	soa := &dns.SOA{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:  "ns." + zone, Mbox: "hostmaster." + zone,
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
	}
	var dsQueries atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		switch {
		case q.Qtype == dns.TypeDS && ds == nil:
			dsQueries.Add(1)
			m.Authoritative = false
			m.Rcode = dns.RcodeRefused
		case q.Qtype == dns.TypeDS && core.EqualNames(q.Name, ds.Header().Name):
			dsQueries.Add(1)
			m.Answer = append(m.Answer, ds)
		default:
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
		t.Fatalf("auth double on %s failed to serve: %v", ip, err)
	case <-time.After(2 * time.Second):
		t.Fatal("auth double did not start")
	}
	// The stop joins the serve goroutine, as startStubAuthServer does: a
	// double still serving after its test returns can answer the next test's
	// queries on a reused port, and a serve error nobody reads is a failure
	// nobody sees.
	return pc.LocalAddr().(*net.UDPAddr).Port, &dsQueries, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.ShutdownContext(ctx); err != nil {
			t.Errorf("auth double on %s shutdown: %v", ip, err)
		}
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("auth double on %s stopped serving with: %v", ip, err)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("auth double on %s: serve goroutine did not exit", ip)
		}
	}
}

// The resolver knows both sides of the cut: the parent on 127.0.0.1, the child
// on ::1 -- the same port, because the cache's clients use one port for every
// server. The child refuses DS queries, as tdns-auth did and a child-only
// server may. Asked for the child's DS, both the responder and ImrQuery must go
// to the parent: before the fix they went to the child and the client got
// SERVFAIL, while the validator's own DS fetch (backfillDS) went to the parent
// and succeeded, for the same zone in the same daemon.
func TestClientDSQueryGoesToTheParent(t *testing.T) {
	const parent = "dsparent.example."
	const child = "kid.dsparent.example."
	ds, err := dns.NewRR(child + " 3600 IN DS 12345 8 2 " +
		"E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CFC41A5766")
	if err != nil {
		t.Fatal(err)
	}

	setup := func(t *testing.T) (*Imr, *atomic.Int32, *atomic.Int32) {
		t.Helper()
		port, atParent, stopParent := startDSAuthDouble(t, net.IPv4(127, 0, 0, 1), 0, parent, ds)
		t.Cleanup(stopParent)
		_, atChild, stopChild := startDSAuthDouble(t, net.IPv6loopback, port, child, nil)
		t.Cleanup(stopChild)

		imr := newTestImr(t)
		p := strconv.Itoa(port)
		imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
		imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
		if err := imr.Cache.AddStub(parent, []cache.AuthServer{
			{Name: "ns." + parent, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
		}); err != nil {
			t.Fatalf("AddStub(%s): %v", parent, err)
		}
		if err := imr.Cache.AddStub(child, []cache.AuthServer{
			{Name: "ns." + child, Addrs: []string{"::1"}, Alpn: []string{"do53"}},
		}); err != nil {
			t.Fatalf("AddStub(%s): %v", child, err)
		}
		return imr, atParent, atChild
	}

	hasDS := func(rrs []dns.RR) bool {
		for _, rr := range rrs {
			if d, ok := rr.(*dns.DS); ok && d.KeyTag == 12345 {
				return true
			}
		}
		return false
	}

	t.Run("responder", func(t *testing.T) {
		imr, atParent, atChild := setup(t)
		r := new(dns.Msg)
		r.SetQuestion(child, dns.TypeDS)
		cw := &captureWriter{}
		imr.ImrResponder(context.Background(), cw, r, child, dns.TypeDS, &edns0.MsgOptions{RD: true})
		if cw.got == nil {
			t.Fatal("responder wrote no response")
		}
		if cw.got.Rcode != dns.RcodeSuccess || !hasDS(cw.got.Answer) {
			t.Fatalf("rcode %s answer %v, want NOERROR with the parent's DS",
				dns.RcodeToString[cw.got.Rcode], cw.got.Answer)
		}
		if n := atChild.Load(); n != 0 {
			t.Errorf("the child's server was asked for its own DS %d time(s)", n)
		}
		if n := atParent.Load(); n == 0 {
			t.Error("the parent's server was never asked")
		}
	})

	t.Run("ImrQuery", func(t *testing.T) {
		imr, atParent, atChild := setup(t)
		resp, err := imr.ImrQuery(context.Background(), child, dns.TypeDS, dns.ClassINET, nil)
		if err != nil {
			t.Fatalf("ImrQuery: %v", err)
		}
		if resp == nil || resp.RRset == nil || !hasDS(resp.RRset.RRs) {
			t.Fatalf("ImrQuery returned %+v, want the parent's DS", resp)
		}
		if n := atChild.Load(); n != 0 {
			t.Errorf("the child's server was asked for its own DS %d time(s)", n)
		}
		if n := atParent.Load(); n == 0 {
			t.Error("the parent's server was never asked")
		}
	})
}

// A DS query goes to the parent's servers, so the zone it is accounted to must
// be the parent's too: the zone whose backoff filters its tuples, and the zone
// whose NS set is widened when they run out. Both used to be the qname's own.
func TestDSQueryIsAccountedToTheParentZone(t *testing.T) {
	imr := newTestImr(t)
	zones := map[string]*cache.Zone{}
	for _, z := range []string{"example.", "kid.example."} {
		imr.Cache.ServerMap.Set(z, map[string]*cache.AuthServer{})
		zones[z] = &cache.Zone{ZoneName: z}
		imr.Cache.ZoneMap.Set(z, zones[z])
	}

	t.Run("prioritizeServers", func(t *testing.T) {
		// The parent's server has a backoff booked against the CHILD zone,
		// which must not keep it out of the parent's DS query -- and must
		// still filter it from a query that is the child's.
		const addr = "192.0.2.1"
		s := cache.NewAuthServer("ns1.example.")
		s.SetAddrs([]string{addr})
		s.SetTransports([]core.Transport{core.TransportDo53})
		s.SetTransportWeight(core.TransportDo53, 100)
		zones["kid.example."].RecordZoneAddressFailureForRcode(addr, core.TransportDo53, dns.RcodeRefused, false)
		sm := map[string]*cache.AuthServer{"ns1.example.": s}

		if zone, _, tuples := imr.prioritizeServers("kid.example.", dns.TypeDS, sm, edns0.PrivacyNone); zone != "example." || len(tuples) == 0 {
			t.Errorf("DS: zone %q with %d tuples; want the parent example. and its server", zone, len(tuples))
		}
		if zone, _, tuples := imr.prioritizeServers("kid.example.", dns.TypeA, sm, edns0.PrivacyNone); zone != "kid.example." || len(tuples) != 0 {
			t.Errorf("A: zone %q with %d tuples; want kid.example., whose backoff filters the server", zone, len(tuples))
		}
	})

	t.Run("expandServerMapWithMissingNS", func(t *testing.T) {
		for zone, ns := range map[string]string{"example.": "ns1.example.", "kid.example.": "ns.kid.example."} {
			imr.Cache.Set(zone, dns.TypeNS, &cache.CachedRRset{
				Name: zone, RRtype: dns.TypeNS, Context: cache.ContextAnswer,
				RRset: &core.RRset{Name: zone, Class: dns.ClassINET, RRtype: dns.TypeNS,
					RRs: []dns.RR{mustNSRR(t, zone+" 3600 IN NS "+ns)}},
			})
		}
		// A cancelled context stops the helper before it resolves anything,
		// but only after it has entered the missing NS name into the map --
		// which is exactly the choice under test, with no network.
		cctx, cancel := context.WithCancel(context.Background())
		cancel()
		for _, c := range []struct {
			qtype     uint16
			want, not string
		}{
			{dns.TypeDS, "ns1.example.", "ns.kid.example."},
			{dns.TypeA, "ns.kid.example.", "ns1.example."},
		} {
			sm := map[string]*cache.AuthServer{}
			imr.expandServerMapWithMissingNS(cctx, "kid.example.", c.qtype, sm)
			if _, ok := sm[cache.ServerKey(c.want)]; !ok {
				t.Errorf("%s: widened with %v, want %s", dns.TypeToString[c.qtype], keysOf(sm), c.want)
			}
			if _, ok := sm[cache.ServerKey(c.not)]; ok {
				t.Errorf("%s: widened with %s, which is the other side of the cut", dns.TypeToString[c.qtype], c.not)
			}
		}
	})
}

func keysOf(m map[string]*cache.AuthServer) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// FindClosestKnownZoneFor is the whole choice: the parent's zone for a DS, the
// qname's own for anything else, and the root for the root's DS.
func TestFindClosestKnownZoneForDS(t *testing.T) {
	imr := newTestImr(t)
	for _, z := range []string{".", "example.", "kid.example."} {
		if err := imr.Cache.AddStub(z, []cache.AuthServer{
			{Name: "ns." + z, Addrs: []string{"192.0.2.1"}, Alpn: []string{"do53"}},
		}); err != nil {
			t.Fatalf("AddStub(%s): %v", z, err)
		}
	}
	cases := []struct {
		qname string
		qtype uint16
		want  string
	}{
		{"kid.example.", dns.TypeDS, "example."},
		{"kid.example.", dns.TypeA, "kid.example."},
		{"www.kid.example.", dns.TypeDS, "kid.example."},
		{"example.", dns.TypeDS, "."},
		{".", dns.TypeDS, "."},
	}
	for _, c := range cases {
		got, _, err := imr.Cache.FindClosestKnownZoneFor(c.qname, c.qtype)
		if err != nil || got != c.want {
			t.Errorf("FindClosestKnownZoneFor(%s, %s) = %q, %v; want %q",
				c.qname, dns.TypeToString[c.qtype], got, err, c.want)
		}
	}
}
