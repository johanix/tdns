/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestExchangeWithResult_Do53_WirePaths drives the REAL DNSClient over the test
// UDP+TCP servers and asserts the ExchangeResult for the three Do53 outcomes:
//   - TC=1 UDP → TCP: WireTransport=Do53TCP, Truncated=true
//   - clean UDP:      WireTransport=Do53,    Truncated=false
//   - UDP timeout → TCP (transient fallback): WireTransport=Do53TCP, Truncated=false
func TestExchangeWithResult_Do53_WirePaths(t *testing.T) {
	newClient := func(port string, udpTimeout, tcpTimeout time.Duration) *DNSClient {
		c := NewDNSClient(TransportDo53, port, nil)
		c.Timeout = 2 * time.Second
		c.DNSClientUDP.Timeout = udpTimeout
		c.DNSClientTCP.Timeout = tcpTimeout
		return c
	}

	t.Run("truncation", func(t *testing.T) {
		const qname = "tcr.example."
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
		_, _, res, err := newClient(port, 2*time.Second, 2*time.Second).
			ExchangeWithResult(mustQuery(qname), "127.0.0.1", false)
		if err != nil {
			t.Fatalf("ExchangeWithResult: %v", err)
		}
		if res.WireTransport != TransportDo53TCP || !res.Truncated {
			t.Fatalf("truncation: got %+v, want {Do53TCP, Truncated:true}", res)
		}
	})

	t.Run("clean", func(t *testing.T) {
		const qname = "ok.example."
		udp := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Answer = []dns.RR{aRR(qname, "192.0.2.2")}
			_ = w.WriteMsg(m)
		})
		tcp := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			_ = w.WriteMsg(m)
		})
		port, cleanup := testServers(t, udp, tcp)
		defer cleanup()
		_, _, res, err := newClient(port, 2*time.Second, 2*time.Second).
			ExchangeWithResult(mustQuery(qname), "127.0.0.1", false)
		if err != nil {
			t.Fatalf("ExchangeWithResult: %v", err)
		}
		if res.WireTransport != TransportDo53 || res.Truncated {
			t.Fatalf("clean: got %+v, want {Do53, Truncated:false}", res)
		}
	})

	t.Run("timeout_fallback", func(t *testing.T) {
		const qname = "tof.example."
		udp := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			time.Sleep(2 * time.Second) // force UDP timeout → transient fallback to TCP
		})
		tcp := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Answer = []dns.RR{aRR(qname, "192.0.2.3")}
			_ = w.WriteMsg(m)
		})
		port, cleanup := testServers(t, udp, tcp)
		defer cleanup()
		_, _, res, err := newClient(port, 200*time.Millisecond, 2*time.Second).
			ExchangeWithResult(mustQuery(qname), "127.0.0.1", false)
		if err != nil {
			t.Fatalf("ExchangeWithResult: %v", err)
		}
		// TCP was used, but a transient-error fallback is NOT a truncation.
		if res.WireTransport != TransportDo53TCP || res.Truncated {
			t.Fatalf("timeout_fallback: got %+v, want {Do53TCP, Truncated:false}", res)
		}
	})
}

// The retry over TCP after truncation goes to the address and port that
// truncated, not to the client's default port: a signal that gives udp port
// P arrives here as "addr:P" (AuthServer.DialAddr) on a client whose port is
// 53, and the TCP retry must reach P too (the alternative-endpoint design,
// section 3; step S5 of its plan).
func TestTruncationRetryGoesToTheAddressAndPortThatTruncated(t *testing.T) {
	const qname = "tcport.example."
	udp := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		_ = w.WriteMsg(m)
	})
	tcpHits := make(chan struct{}, 4)
	tcp := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		tcpHits <- struct{}{}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{aRR(qname, "192.0.2.9")}
		_ = w.WriteMsg(m)
	})
	port, cleanup := testServers(t, udp, tcp)
	defer cleanup()
	c := NewDNSClient(TransportDo53, "53", nil)
	c.Timeout = 2 * time.Second
	c.DNSClientUDP.Timeout = 2 * time.Second
	c.DNSClientTCP.Timeout = 2 * time.Second
	r, _, res, err := c.ExchangeWithResult(mustQuery(qname), "127.0.0.1:"+port, false)
	if err != nil {
		t.Fatalf("ExchangeWithResult: %v", err)
	}
	if res.WireTransport != TransportDo53TCP || !res.Truncated {
		t.Fatalf("got %+v, want {Do53TCP, Truncated:true}", res)
	}
	if len(tcpHits) != 1 || r == nil || len(r.Answer) != 1 {
		t.Fatalf("TCP on port %s answered %d times, reply %v; want the retry there, once", port, len(tcpHits), r)
	}
}
