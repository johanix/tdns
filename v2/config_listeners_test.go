/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The pre-#446 schema is a HARD error with the migration in the message —
// on every decode path, daemon and checker alike.
func TestRejectMovedConfigKeys(t *testing.T) {
	cases := []struct {
		name    string
		m       map[string]interface{}
		wantErr string // "" = accepted
	}{
		{"new schema accepted", map[string]interface{}{
			"listeners": map[string]interface{}{"addresses": []string{"127.0.0.1:53"}},
			"imrengine": map[string]interface{}{"active": true, "root-hints": "/x"},
		}, ""},
		{"dnsengine block rejected", map[string]interface{}{
			"dnsengine": map[string]interface{}{"addresses": []string{"127.0.0.1:53"}},
		}, "listener keys (addresses, transports, certfile, keyfile, ports) moved to listeners:"},
		{"imrengine.addresses rejected", map[string]interface{}{
			"imrengine": map[string]interface{}{"addresses": []string{"127.0.0.1:53"}},
		}, "imrengine.addresses moved to listeners.addresses"},
		{"imrengine.certfile rejected", map[string]interface{}{
			"imrengine": map[string]interface{}{"certfile": "/x"},
		}, "imrengine.certfile moved to listeners.certfile"},
	}
	for _, c := range cases {
		err := rejectMovedConfigKeys(c.m)
		if c.wantErr == "" {
			if err != nil {
				t.Errorf("%s: rejected: %v", c.name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: accepted, want error", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: error %q does not carry the migration %q", c.name, err.Error(), c.wantErr)
		}
	}

	// And the decoder itself enforces it (the daemon/checker shared path).
	var conf Config
	err := decodeConfigMap(map[string]interface{}{
		"dnsengine": map[string]interface{}{"addresses": []string{"127.0.0.1:53"}},
	}, &conf, nil)
	if err == nil || !strings.Contains(err.Error(), "listeners:") {
		t.Errorf("decodeConfigMap accepted a dnsengine: block: %v", err)
	}
}

// The debug window is loopback or nothing.
func TestValidateImrDebugAddress(t *testing.T) {
	for _, ok := range []string{"", "127.0.0.1:5959", "127.0.0.2:53", "[::1]:5959"} {
		if err := validateImrDebugAddress(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"192.0.2.1:5959", "[2001:db8::1]:53", "localhost:5959", "127.0.0.1", "0.0.0.0:5959"} {
		if err := validateImrDebugAddress(bad); err == nil {
			t.Errorf("%q accepted, want error", bad)
		}
	}
}

// The debug handler: ANY+norec enumerates the owner's cached RRsets,
// +norec on a specific type serves the entry WHATEVER its context (the
// normal responder refuses indirect entries), TTLs reflect remaining
// lifetime, and the entry's metadata rides as a TXT in Additional.
func TestImrDebugCachePeek(t *testing.T) {
	imr := newForwardTestImr(t, nil)
	owner := "www.debug.example."
	mk := func(rrtype uint16, rr dns.RR, ctx cache.CacheContext, ttl time.Duration) {
		imr.Cache.Set(owner, rrtype, &cache.CachedRRset{
			Name: owner, RRtype: rrtype, Rcode: uint8(dns.RcodeSuccess),
			RRset:      &core.RRset{Name: owner, RRtype: rrtype, RRs: []dns.RR{rr}},
			Context:    ctx,
			State:      cache.ValidationStateSecure,
			Expiration: time.Now().Add(ttl),
		})
	}
	mk(dns.TypeA, &dns.A{
		Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{192, 0, 2, 1},
	}, cache.ContextAnswer, 100*time.Second)
	mk(dns.TypeAAAA, &dns.AAAA{
		Hdr:  dns.RR_Header{Name: owner, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
		AAAA: make([]byte, 16),
	}, cache.ContextGlue, 100*time.Second) // indirect context, deliberately

	// ttlAdjusted itself: header TTL becomes remaining lifetime.
	src := []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{192, 0, 2, 9},
	}}
	adj := ttlAdjusted(src, time.Now().Add(100*time.Second))
	if ttl := adj[0].Header().Ttl; ttl == 0 || ttl > 100 {
		t.Errorf("ttlAdjusted: %d, want ~100", ttl)
	}
	if src[0].Header().Ttl != 300 {
		t.Error("ttlAdjusted mutated its input")
	}
	if exp := ttlAdjusted(src, time.Now().Add(-time.Minute)); exp[0].Header().Ttl != 0 {
		t.Errorf("expired entry TTL = %d, want 0", exp[0].Header().Ttl)
	}

	// ANY+norec: both entries, metadata TXTs, sane TTLs.
	q := new(dns.Msg)
	q.SetQuestion(owner, dns.TypeANY)
	q.RecursionDesired = false
	w := &fakeResponseWriter{}
	imr.serveDebugANY(w, q, owner)
	if w.msg == nil || len(w.msg.Answer) != 2 {
		t.Fatalf("ANY answer = %+v", w.msg)
	}
	for _, rr := range w.msg.Answer {
		if ttl := rr.Header().Ttl; ttl == 0 || ttl > 300 {
			t.Errorf("TTL outside remaining lifetime: %d", ttl)
		}
	}
	if len(w.msg.Extra) != 2 {
		t.Fatalf("want 2 metadata TXTs, got %d", len(w.msg.Extra))
	}
	metaAll := ""
	for _, rr := range w.msg.Extra {
		metaAll += rr.String()
	}
	if !strings.Contains(metaAll, "context=glue") || !strings.Contains(metaAll, "state=secure") {
		t.Errorf("metadata TXTs lack context/state: %s", metaAll)
	}

	// +norec peek serves the INDIRECT entry the normal responder refuses.
	q2 := new(dns.Msg)
	q2.SetQuestion(owner, dns.TypeAAAA)
	q2.RecursionDesired = false
	w2 := &fakeResponseWriter{}
	if !imr.serveDebugCachePeek(w2, q2, owner, dns.TypeAAAA) {
		t.Fatal("peek missed a cached (indirect) entry")
	}
	if len(w2.msg.Answer) != 1 || !w2.msg.AuthenticatedData {
		t.Errorf("peek answer = %+v", w2.msg)
	}

	// Miss → false (the caller falls back to the normal REFUSED path).
	w3 := &fakeResponseWriter{}
	if imr.serveDebugCachePeek(w3, q2, "other.example.", dns.TypeA) {
		t.Error("peek served a miss")
	}
}

// fakeResponseWriter captures the written message.
type fakeResponseWriter struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (f *fakeResponseWriter) WriteMsg(m *dns.Msg) error { f.msg = m; return nil }

// Lifecycle: the debug listener binds synchronously (a bind failure is an
// error, not a log line), serves, and exits within the five-second shutdown
// bound when the root context is cancelled — with the sockets released.
func TestImrDebugListenerShutdown(t *testing.T) {
	imr := newForwardTestImr(t, nil)
	conf := &Config{}
	ctx, cancel := context.WithCancel(context.Background())

	const addr = "127.0.0.1:5961"
	done, err := imr.startImrDebugListener(ctx, addr, conf)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	// Second bind on the same address must fail synchronously: the port is
	// genuinely held.
	if _, err := imr.startImrDebugListener(ctx, addr, conf); err == nil {
		t.Fatal("double bind accepted")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("debug listener did not exit within the shutdown bound")
	}

	// Sockets released: the address is bindable again.
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("udp port not released: %v", err)
	}
	pc.Close()

	// And a non-loopback address never binds at all.
	if _, err := imr.startImrDebugListener(context.Background(), "0.0.0.0:5962", conf); err == nil {
		t.Fatal("non-loopback debug listener accepted")
	}
}
