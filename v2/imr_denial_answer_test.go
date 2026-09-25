/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A denial is the answer "no such data", and ImrQuery gives it the same way on
// the first ask and on every later one within the negative TTL (#698). The
// cache-hit branch used to hand back the SOA that proves the denial as the
// answer RRset, so a caller testing for records saw none on the first ask and
// the enclosing zone's SOA on the second.

// startDenialAuthDouble is an authoritative double for zone on 127.0.0.1 that
// has no data: NXDOMAIN for nxname, NODATA for any other name, both with the
// zone SOA in AUTHORITY. The counter records the queries for <qname, qtype>,
// so the validator's own lookups do not count.
func startDenialAuthDouble(t *testing.T, zone, nxname, qname string, qtype uint16) (int, *atomic.Int32) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.1: %v", err)
	}
	soa := &dns.SOA{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:  "ns." + zone, Mbox: "hostmaster." + zone,
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
	}
	var asked atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		if core.EqualNames(q.Name, qname) && q.Qtype == qtype {
			asked.Add(1)
		}
		if core.EqualNames(q.Name, nxname) {
			m.Rcode = dns.RcodeNameError
		}
		m.Ns = append(m.Ns, soa)
		_ = w.WriteMsg(m)
	})
	started := make(chan struct{})
	served := make(chan error, 1)
	srv := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: func() { close(started) }}
	go func() { served <- srv.ActivateAndServe() }()
	select {
	case <-started:
	case err := <-served:
		t.Fatalf("denial double failed to serve: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("denial double did not start")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.ShutdownContext(ctx); err != nil {
			t.Errorf("denial double shutdown: %v", err)
		}
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("denial double stopped serving with: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("denial double: serve goroutine did not exit")
		}
	})
	return pc.LocalAddr().(*net.UDPAddr).Port, &asked
}

func TestImrQueryAnswersADenialTheSameWayTwice(t *testing.T) {
	const zone = "denial.example."
	const nxname = "nope." + zone
	for _, tc := range []struct {
		name  string
		qname string
		want  cache.CacheContext
	}{
		{"NODATA", "www." + zone, cache.ContextNoErrNoAns},
		{"NXDOMAIN", nxname, cache.ContextNXDOMAIN},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port, asked := startDenialAuthDouble(t, zone, nxname, tc.qname, dns.TypeTXT)
			imr := newTestImr(t)
			p := strconv.Itoa(port)
			imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, p, nil)
			imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, p, nil)
			if err := imr.Cache.AddStub(zone, []cache.AuthServer{
				{Name: "ns." + zone, Addrs: []string{"127.0.0.1"}, Alpn: []string{"do53"}},
			}); err != nil {
				t.Fatalf("AddStub(%s): %v", zone, err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var resps [2]*ImrResponse
			for i := range resps {
				resp, err := imr.ImrQuery(ctx, tc.qname, dns.TypeTXT, dns.ClassINET, nil)
				if err != nil || resp == nil || resp.Error {
					t.Fatalf("ask %d: err=%v resp=%+v", i+1, err, resp)
				}
				resps[i] = resp
			}
			if n := asked.Load(); n != 1 {
				t.Fatalf("the double was asked %d time(s), want 1: the second ask did not come from the cache", n)
			}

			for i, resp := range resps {
				if resp.RRset != nil {
					t.Errorf("ask %d: RRset %v, want none for a denial", i+1, resp.RRset.RRs)
				}
				if resp.Denial != tc.want {
					t.Errorf("ask %d: Denial %q, want %q", i+1,
						cache.CacheContextToString[resp.Denial], cache.CacheContextToString[tc.want])
				}
			}
			first, second := resps[0], resps[1]
			if first.ValidationState != second.ValidationState || first.Validated != second.Validated || first.Msg != second.Msg {
				t.Errorf("fresh %s/%v/%q, cached %s/%v/%q: want the same",
					cache.ValidationStateToString[first.ValidationState], first.Validated, first.Msg,
					cache.ValidationStateToString[second.ValidationState], second.Validated, second.Msg)
			}
		})
	}
}

// The verdict on a cached denial is the entry's own. The SOA in it proves the
// denial together with the NSECs, and validating it alone replaced that verdict:
// a denial whose proof had failed came back Secure once its SOA validated.
func TestCachedDenialKeepsItsVerdict(t *testing.T) {
	const qname = "_dsync.child.example."
	soa, err := dns.NewRR("example. 60 IN SOA ns.example. hostmaster.example. 1 3600 600 86400 60")
	if err != nil {
		t.Fatal(err)
	}
	seed := func(imr *Imr) {
		imr.Cache.Set(qname, core.TypeDSYNC, &cache.CachedRRset{
			Name:       qname,
			RRtype:     core.TypeDSYNC,
			Rcode:      uint8(dns.RcodeNameError),
			RRset:      &core.RRset{Name: "example.", Class: dns.ClassINET, RRtype: dns.TypeSOA, RRs: []dns.RR{soa}},
			Context:    cache.ContextNXDOMAIN,
			State:      cache.ValidationStateBogus,
			Expiration: time.Now().Add(time.Hour),
			Transport:  core.TransportDo53,
		})
	}
	check := func(t *testing.T, resp *ImrResponse) {
		t.Helper()
		if resp.RRset != nil {
			t.Errorf("RRset %v, want none for a denial", resp.RRset.RRs)
		}
		if resp.Denial != cache.ContextNXDOMAIN {
			t.Errorf("Denial %q, want NXDOMAIN", cache.CacheContextToString[resp.Denial])
		}
		if resp.ValidationState != cache.ValidationStateBogus || resp.Validated {
			t.Errorf("verdict %s/%v, want bogus/false", cache.ValidationStateToString[resp.ValidationState], resp.Validated)
		}
	}

	t.Run("ImrQuery", func(t *testing.T) {
		imr := newTestImr(t)
		seed(imr)
		resp, err := imr.ImrQuery(context.Background(), qname, core.TypeDSYNC, dns.ClassINET, nil)
		if err != nil {
			t.Fatalf("ImrQuery: %v", err)
		}
		check(t, resp)
	})

	// The engine's request loop, which the imr CLI asks, has a cache-hit
	// branch of its own.
	t.Run("request loop", func(t *testing.T) {
		imr := newTestImr(t)
		seed(imr)
		ch := make(chan ImrResponse, 1)
		imr.handleRecursorRequest(context.Background(), ImrRequest{
			Qname: qname, Qclass: dns.ClassINET, Qtype: core.TypeDSYNC, ResponseCh: ch,
		})
		select {
		case resp := <-ch:
			check(t, &resp)
		case <-time.After(5 * time.Second):
			t.Fatal("no response from the request loop")
		}
	})
}
