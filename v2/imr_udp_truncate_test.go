/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * An IMR answer over UDP fits the buffer the client advertised (512 without
 * EDNS), or comes back truncated with TC set. RFC 1035 §4.2.1, RFC 6891 §6.2.3.
 */
package tdns

import (
	"context"
	"encoding/base64"
	"net"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const bigOwner = "big.example."

// seedBigDNSKEYSet caches a DNSKEY RRset of about 4 KB at bigOwner: three
// keys the size of an ML-DSA-44 public key (1312 bytes). The key material is
// filler; only the size matters.
func seedBigDNSKEYSet(t *testing.T, imr *Imr) int {
	t.Helper()
	pub := make([]byte, 1312)
	for i := range pub {
		pub[i] = byte(i)
	}
	var rrs []dns.RR
	for flags := uint16(256); flags <= 258; flags++ {
		rrs = append(rrs, &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: bigOwner, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags:     flags,
			Protocol:  3,
			Algorithm: dns.ED25519,
			PublicKey: base64.StdEncoding.EncodeToString(pub),
		})
	}
	imr.Cache.Set(bigOwner, dns.TypeDNSKEY, &cache.CachedRRset{
		Name:       bigOwner,
		RRtype:     dns.TypeDNSKEY,
		Rcode:      uint8(dns.RcodeSuccess),
		RRset:      &core.RRset{Name: bigOwner, Class: dns.ClassINET, RRtype: dns.TypeDNSKEY, RRs: rrs},
		Context:    cache.ContextAnswer,
		State:      cache.ValidationStateSecure,
		Expiration: time.Now().Add(time.Hour),
		Transport:  core.TransportDo53,
	})
	return len(rrs)
}

// serveDo53 serves mux on loopback UDP and TCP, as the IMR's Do53 listeners
// do, and returns the two addresses. Shut down at test cleanup.
func serveDo53(t *testing.T, mux *dns.ServeMux) (udpAddr, tcpAddr string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		pc.Close()
		t.Fatalf("tcp listen: %v", err)
	}
	for _, s := range []*dns.Server{
		{PacketConn: pc, Handler: mux},
		{Listener: l, Handler: mux},
	} {
		started := make(chan struct{})
		s.NotifyStartedFunc = func() { close(started) }
		go func() { _ = s.ActivateAndServe() }()
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("test Do53 server did not start")
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = s.ShutdownContext(ctx)
		})
	}
	return pc.LocalAddr().String(), l.Addr().String()
}

// bufsizeQuery builds what dig sends: bufsize 0 means +noedns.
func bufsizeQuery(qname string, qtype uint16, rd bool, bufsize uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(qname, qtype)
	q.RecursionDesired = rd
	if bufsize > 0 {
		q.SetEdns0(bufsize, false)
	}
	return q
}

// exchangeEnforcing sends q the way a client that enforces its buffer size
// does: over UDP it reads at most the size it advertised (512 without EDNS),
// so an oversized answer fails to unpack.
func exchangeEnforcing(t *testing.T, network, addr string, q *dns.Msg) *dns.Msg {
	t.Helper()
	c := &dns.Client{Net: network, Timeout: 2 * time.Second}
	m, _, err := c.Exchange(q, addr)
	if err != nil {
		t.Fatalf("%s exchange with %s: %v (an answer larger than the advertised buffer?)", network, addr, err)
	}
	return m
}

// checkTruncated asserts a UDP answer fits limit and carries TC.
func checkTruncated(t *testing.T, m *dns.Msg, limit int) {
	t.Helper()
	if !m.Truncated {
		t.Errorf("TC not set on an answer that cannot fit %d bytes", limit)
	}
	if n := m.Len(); n > limit {
		t.Errorf("answer is %d bytes, over the %d the client can take", n, limit)
	}
	if len(m.Question) != 1 {
		t.Errorf("question section lost: %v", m.Question)
	}
}

// THE REGRESSION. The IMR's Do53 mux served every answer at full size over
// UDP: a 4 KB DNSKEY RRset went out whole to a client that asked for 1232,
// 512, or no EDNS at all, and TC was never set. Driven through the same mux
// constructor ImrEngine uses, on real sockets.
func TestImrDo53TruncatesOversizedUDPAnswers(t *testing.T) {
	imr := newTestImr(t)
	nkeys := seedBigDNSKEYSet(t, imr)
	seedAnswer(t, imr, "small.example. 300 IN A 192.0.2.1", 300*time.Second)
	udp, tcp := serveDo53(t, newImrDo53Mux(imr.createImrHandler(context.Background(), &Config{})))

	for _, tc := range []struct {
		name    string
		bufsize uint16
		limit   int
	}{
		{"edns 1232", 1232, 1232},
		{"edns 512", 512, 512},
		{"no edns", 0, dns.MinMsgSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkTruncated(t, exchangeEnforcing(t, "udp", udp, bufsizeQuery(bigOwner, dns.TypeDNSKEY, true, tc.bufsize)), tc.limit)
		})
	}

	// TCP carries the whole RRset: no truncation there.
	m := exchangeEnforcing(t, "tcp", tcp, bufsizeQuery(bigOwner, dns.TypeDNSKEY, true, 1232))
	if m.Truncated || len(m.Answer) != nkeys {
		t.Errorf("TCP answer: TC=%v, %d DNSKEYs; want the whole RRset (%d) and no TC", m.Truncated, len(m.Answer), nkeys)
	}

	// An answer that fits goes out untouched.
	m = exchangeEnforcing(t, "udp", udp, bufsizeQuery("small.example.", dns.TypeA, true, 512))
	if m.Truncated || len(m.Answer) != 1 {
		t.Errorf("small UDP answer: TC=%v, %d records; want 1 record and no TC", m.Truncated, len(m.Answer))
	}
}

// The imr-debug-address window serves Do53 too, and its +norec cache peek
// hands back whole cached RRsets. Driven through the real listener.
func TestImrDebugListenerTruncatesOversizedUDPAnswers(t *testing.T) {
	imr := newTestImr(t)
	nkeys := seedBigDNSKEYSet(t, imr)
	ctx, cancel := context.WithCancel(context.Background())
	const addr = "127.0.0.1:5963"
	done, err := imr.startImrDebugListener(ctx, addr, &Config{})
	if err != nil {
		cancel()
		t.Fatalf("start: %v", err)
	}
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Error("debug listener did not exit within the shutdown bound")
		}
	}()

	checkTruncated(t, exchangeEnforcing(t, "udp", addr, bufsizeQuery(bigOwner, dns.TypeDNSKEY, false, 1232)), 1232)

	m := exchangeEnforcing(t, "tcp", addr, bufsizeQuery(bigOwner, dns.TypeDNSKEY, false, 1232))
	if m.Truncated || len(m.Answer) != nkeys {
		t.Errorf("TCP peek: TC=%v, %d DNSKEYs; want the whole RRset (%d) and no TC", m.Truncated, len(m.Answer), nkeys)
	}
}
