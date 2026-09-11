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
	srv := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("auth double did not start")
	}
	return pc.LocalAddr().(*net.UDPAddr).Port, &dsQueries, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
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
