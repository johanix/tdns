/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testServers spins up paired UDP + TCP listeners on the same loopback port
// and runs the supplied handlers. Returns the port and a cleanup func.
func testServers(t *testing.T, udpHandler, tcpHandler dns.HandlerFunc) (port string, cleanup func()) {
	t.Helper()

	// Reserve a free port via a temporary UDP socket bind, then close it. There
	// is an inherent race (port may be reused before the real listeners bind),
	// but it is acceptable for in-process loopback tests.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving port: %v", err)
	}
	host, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())
	pc.Close()
	_ = host

	udpReady := make(chan struct{})
	tcpReady := make(chan struct{})

	udpSrv := &dns.Server{
		Addr:              net.JoinHostPort("127.0.0.1", portStr),
		Net:               "udp",
		Handler:           udpHandler,
		NotifyStartedFunc: func() { close(udpReady) },
	}
	tcpSrv := &dns.Server{
		Addr:              net.JoinHostPort("127.0.0.1", portStr),
		Net:               "tcp",
		Handler:           tcpHandler,
		NotifyStartedFunc: func() { close(tcpReady) },
	}

	var wg sync.WaitGroup
	if udpHandler != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := udpSrv.ListenAndServe(); err != nil {
				t.Logf("udp server stopped: %v", err)
			}
		}()
		<-udpReady
	} else {
		close(udpReady)
	}
	if tcpHandler != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := tcpSrv.ListenAndServe(); err != nil {
				t.Logf("tcp server stopped: %v", err)
			}
		}()
		<-tcpReady
	} else {
		close(tcpReady)
	}

	cleanup = func() {
		if udpHandler != nil {
			_ = udpSrv.Shutdown()
		}
		if tcpHandler != nil {
			_ = tcpSrv.Shutdown()
		}
		wg.Wait()
	}
	return portStr, cleanup
}

func mustQuery(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}

func aRR(name, ip string) dns.RR {
	rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", dns.Fqdn(name), ip))
	if err != nil {
		panic(err)
	}
	return rr
}

// TestExchange_Do53_TCBitFallback: UDP returns TC=1, TCP returns answer.
// Exchange must return the TCP answer.
func TestExchange_Do53_TCBitFallback(t *testing.T) {
	const qname = "tc.example."
	udp := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		_ = w.WriteMsg(m)
	})
	tcp := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{aRR(qname, "192.0.2.1")}
		_ = w.WriteMsg(m)
	})
	port, cleanup := testServers(t, udp, tcp)
	defer cleanup()

	c := NewDNSClient(TransportDo53, port, nil)
	c.Timeout = 2 * time.Second
	c.DNSClientUDP.Timeout = c.Timeout
	c.DNSClientTCP.Timeout = c.Timeout

	resp, _, err := c.Exchange(mustQuery(qname), "127.0.0.1", false)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("expected TCP answer, got %v", resp)
	}
	if resp.Truncated {
		t.Fatalf("response still marked truncated; fallback did not run")
	}
}

// TestExchange_Do53_TimeoutFallback: UDP handler hangs (or never responds);
// TCP returns an answer. Exchange must fall back to TCP on the UDP timeout.
func TestExchange_Do53_TimeoutFallback(t *testing.T) {
	const qname = "to.example."
	// UDP handler: write nothing, let the client time out.
	udp := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		time.Sleep(2 * time.Second)
	})
	tcp := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{aRR(qname, "192.0.2.2")}
		_ = w.WriteMsg(m)
	})
	port, cleanup := testServers(t, udp, tcp)
	defer cleanup()

	c := NewDNSClient(TransportDo53, port, nil)
	c.Timeout = 200 * time.Millisecond
	c.DNSClientUDP.Timeout = c.Timeout
	c.DNSClientTCP.Timeout = 2 * time.Second

	start := time.Now()
	resp, _, err := c.Exchange(mustQuery(qname), "127.0.0.1", false)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Exchange: %v (after %s)", err, elapsed)
	}
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("expected TCP answer, got %v", resp)
	}
}

// TestExchange_Do53_DisableFallback: with DisableFallback set, neither TC=1
// nor timeout triggers TCP. Exchange returns the unmodified UDP response (or
// the UDP error).
func TestExchange_Do53_DisableFallback_TC(t *testing.T) {
	const qname = "nofb.example."
	udp := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		_ = w.WriteMsg(m)
	})
	tcpCalled := false
	tcp := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		tcpCalled = true
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{aRR(qname, "192.0.2.3")}
		_ = w.WriteMsg(m)
	})
	port, cleanup := testServers(t, udp, tcp)
	defer cleanup()

	c := NewDNSClient(TransportDo53, port, nil, WithDisableFallback())
	c.Timeout = 2 * time.Second
	c.DNSClientUDP.Timeout = c.Timeout
	c.DNSClientTCP.Timeout = c.Timeout

	resp, _, err := c.Exchange(mustQuery(qname), "127.0.0.1", false)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp == nil || !resp.Truncated {
		t.Fatalf("expected truncated UDP response without TCP fallback, got %v", resp)
	}
	if tcpCalled {
		t.Fatalf("TCP handler was invoked despite DisableFallback")
	}
}

func TestExchange_Do53_DisableFallback_Timeout(t *testing.T) {
	const qname = "nofbto.example."
	udp := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		time.Sleep(2 * time.Second)
	})
	tcpCalled := false
	tcp := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		tcpCalled = true
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})
	port, cleanup := testServers(t, udp, tcp)
	defer cleanup()

	c := NewDNSClient(TransportDo53, port, nil, WithDisableFallback())
	c.Timeout = 200 * time.Millisecond
	c.DNSClientUDP.Timeout = c.Timeout
	c.DNSClientTCP.Timeout = 2 * time.Second

	_, _, err := c.Exchange(mustQuery(qname), "127.0.0.1", false)
	if err == nil {
		t.Fatalf("expected timeout error with DisableFallback set, got nil")
	}
	if tcpCalled {
		t.Fatalf("TCP handler was invoked despite DisableFallback")
	}
}

// TestFakeDNSClient_Lookup covers wildcard precedence and the query log.
func TestFakeDNSClient_Lookup(t *testing.T) {
	f := NewFakeDNSClient(TransportDo53)
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{aRR("hit.example.", "192.0.2.42")}
	f.Set("hit.example.", "127.0.0.1", FakeResponse{Msg: msg})

	q := mustQuery("hit.example")
	resp, _, err := f.Exchange(q, "127.0.0.1", false)
	if err != nil || resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("exact match failed: resp=%v err=%v", resp, err)
	}

	calls := f.Calls()
	if len(calls) != 1 || calls[0].Qname != "hit.example." || calls[0].Addr != "127.0.0.1" {
		t.Fatalf("query log not recorded as expected: %+v", calls)
	}

	// Wildcard (qname-only) precedence over default
	f.Set("other.example.", "", FakeResponse{Msg: msg})
	if _, _, err := f.Exchange(mustQuery("other.example"), "9.9.9.9", false); err != nil {
		t.Fatalf("qname-only wildcard miss: %v", err)
	}

	// Unprogrammed query yields error
	if _, _, err := f.Exchange(mustQuery("miss.example"), "5.5.5.5", false); err == nil {
		t.Fatalf("expected error for unprogrammed query")
	}
}

// Compile-time check that the concrete and fake satisfy the interface.
var (
	_ DNSClienter = (*DNSClient)(nil)
	_ DNSClienter = (*FakeDNSClient)(nil)
)
