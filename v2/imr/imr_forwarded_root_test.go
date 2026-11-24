/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package imr

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A forwarded root is neither primed nor refreshed (#722;
// docs/2026-09-22-forwarding-and-priming.md, S2). With "." forwarded nothing
// is iterated: the root NS is never used to send a query, so there is nothing
// to prime, and a refresh through the forward only ever gets the upstream's
// copy, which counts down. RefreshRoot idles while "." is forwarded, and a
// reload that removes the forward wakes it to prime the way start-up does.

// countingRootNSQuery is a ". NS" query double that counts its calls and, as
// a force=true query does, stores a root NS RRset with the given TTL in c.
func countingRootNSQuery(c *cache.RRsetCacheT, ttl uint32, calls *atomic.Int32) func(context.Context, map[string]*cache.AuthServer) (*core.RRset, error) {
	return func(context.Context, map[string]*cache.AuthServer) (*core.RRset, error) {
		calls.Add(1)
		rr := &dns.NS{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
			Ns:  "a.root.",
		}
		set := &core.RRset{Name: ".", RRtype: dns.TypeNS, RRs: []dns.RR{rr}}
		c.Set(".", dns.TypeNS, &cache.CachedRRset{Name: ".", RRtype: dns.TypeNS, Context: cache.ContextAnswer, RRset: set})
		return set, nil
	}
}

// runRefreshRootLoop runs the root refresh loop with query until the test
// ends.
func runRefreshRootLoop(t *testing.T, imr *Imr, query func(context.Context, map[string]*cache.AuthServer) (*core.RRset, error)) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func(ctx context.Context) {
		defer close(done)
		imr.refreshRootLoop(ctx, "", query)
	}(ctx)
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("the root refresh loop did not stop")
		}
	})
}

// RefreshRoot neither seeds nor queries a forwarded root. With only a zone
// below the root forwarded, the root is iterated and refreshed as before.
func TestRefreshRootIdlesWhileTheRootIsForwarded(t *testing.T) {
	t.Run(". forwarded", func(t *testing.T) {
		imr := newForwardTestImr(t, rootForward("192.0.2.53", 53))
		var calls atomic.Int32
		runRefreshRootLoop(t, imr, countingRootNSQuery(imr.Cache, 900, &calls))
		time.Sleep(200 * time.Millisecond)
		if crr := imr.Cache.Peek(".", dns.TypeNS); crr != nil {
			t.Errorf("RefreshRoot cached a root NS for a forwarded root (context %s)",
				cache.CacheContextToString[crr.Context])
		}
		if n := calls.Load(); n != 0 {
			t.Errorf("RefreshRoot queried . NS %d time(s) for a forwarded root", n)
		}
	})

	t.Run("fwd.example. forwarded", func(t *testing.T) {
		imr := newForwardTestImr(t, []ImrForwardConf{
			{Zone: "fwd.example.", Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.53", Port: 53}}},
		})
		imr.Cache = rootNSCache(t, 30) // inside the refresh lead
		seedRootServers(t, imr.Cache)
		imr.attachCacheHooks()
		var calls atomic.Int32
		runRefreshRootLoop(t, imr, countingRootNSQuery(imr.Cache, 900, &calls))
		waitFor(t, 2*time.Second, "a refresh of the iterated root", func() bool { return calls.Load() > 0 })
	})
}

// A reload that removes the "." forward wakes RefreshRoot, which primes at
// once, not on a timer: the hints, then a live ". NS". A reload that adds it
// back puts RefreshRoot to sleep with no timer: a root NS that is due is not
// refreshed.
func TestReloadMovesTheRootBetweenForwardedAndIterated(t *testing.T) {
	imr := newForwardTestImr(t, rootForward("192.0.2.53", 53))
	var calls atomic.Int32
	runRefreshRootLoop(t, imr, countingRootNSQuery(imr.Cache, 900, &calls))

	time.Sleep(100 * time.Millisecond)
	if imr.Cache.Peek(".", dns.TypeNS) != nil || calls.Load() != 0 {
		t.Fatalf("a forwarded root was primed or queried before any reload (queries: %d)", calls.Load())
	}

	if _, err := imr.ReloadZones(nil, nil); err != nil {
		t.Fatalf("reload without the . forward: %v", err)
	}
	waitFor(t, 2*time.Second, "priming after the . forward was removed", func() bool { return calls.Load() == 1 })
	if !imr.Cache.IsPrimed() {
		t.Error("the cache is not marked primed after the . forward was removed")
	}
	if crr := imr.Cache.Get(".", dns.TypeNS); crr == nil || crr.Context == cache.ContextHint {
		t.Errorf("the root NS after priming is not the live one: %+v", crr)
	}

	// Due now: a turn of an iterating root would refresh it at once.
	rr := &dns.NS{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 30}, Ns: "a.root."}
	imr.Cache.Set(".", dns.TypeNS, &cache.CachedRRset{Name: ".", RRtype: dns.TypeNS, Context: cache.ContextAnswer,
		RRset: &core.RRset{Name: ".", RRtype: dns.TypeNS, RRs: []dns.RR{rr}}})
	if _, err := imr.ReloadZones(nil, rootForward("192.0.2.53", 53)); err != nil {
		t.Fatalf("reload with the . forward: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if n := calls.Load(); n != 1 {
		t.Errorf("RefreshRoot queried . NS %d more time(s) after the . forward was added back", n-1)
	}
}

// startGatedSignedForwardUpstream is startSignedForwardUpstream that answers
// only while open is set, and otherwise drops the query: an upstream that is
// down, and comes back.
func startGatedSignedForwardUpstream(t *testing.T, answers map[string]*dns.Msg, open *atomic.Bool) (string, uint16) {
	t.Helper()
	h := func(w dns.ResponseWriter, r *dns.Msg) {
		if !open.Load() {
			return
		}
		q := r.Question[0]
		m := new(dns.Msg)
		m.SetReply(r)
		m.RecursionAvailable = true
		if a, ok := answers[strings.ToLower(q.Name)+" "+dns.TypeToString[q.Qtype]]; ok {
			m.Answer, m.Ns = a.Answer, a.Ns
		} else {
			m.Rcode = dns.RcodeServerFailure
		}
		_ = w.WriteMsg(m)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port := splitHostPort(t, pc.LocalAddr().String())
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(h), NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("test upstream did not start")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	})
	return host, port
}

// Trust-anchor set-up for a forwarded anchor zone skips the NS step. It
// validates a delegation the resolver never uses, and for a forwarded root it
// sent a forced ". NS" through the forward and cached the upstream's
// short-lived copy.
func TestForwardedAnchorZoneSkipsTheNSStep(t *testing.T) {
	root := newFwdSecKey(t, ".")
	logr := &upstreamLog{}
	addr, port := startLoggedSignedForwardUpstream(t, map[string]*dns.Msg{
		". DNSKEY": {Answer: root.sign(t, dns.Copy(root.dnskey))},
		". NS":     {Answer: root.sign(t, fwdSecRR(t, ". 10 IN NS a.root."))},
	}, logr)
	imr := newForwardTestImr(t, rootForward(addr, port))
	imr.Cache.DnskeyCache = cache.NewDnskeyCache() // not the process-wide one
	imr.DnskeyCache = imr.Cache.DnskeyCache

	ic := Config{}
	ic.TrustAnchorDNSKEY = root.dnskey.String()
	imr.loadConfiguredTrustAnchors(ic)
	if err := imr.initializeImrTrustAnchors(context.Background(), ic); err != nil {
		t.Fatalf("initializeImrTrustAnchors: %v", err)
	}
	if seen := logr.find(".", dns.TypeNS); len(seen) != 0 {
		t.Errorf("trust-anchor set-up asked the upstream for . NS %d time(s)", len(seen))
	}
	if crr := imr.Cache.Peek(".", dns.TypeNS); crr != nil {
		t.Errorf("trust-anchor set-up cached a root NS for a forwarded root: %+v", crr)
	}
	requireAsked(t, logr, ".", dns.TypeDNSKEY)
}

// config status says that a forwarded root is not primed and keeps no root NS,
// instead of a root NS expiry that means nothing for it.
func TestStatusReportsAForwardedRoot(t *testing.T) {
	if st := newForwardTestImr(t, rootForward("192.0.2.53", 53)).StatusReport(); !st.RootForwarded {
		t.Error("a forwarded root is not reported as forwarded")
	}
	sub := newForwardTestImr(t, []ImrForwardConf{
		{Zone: "fwd.example.", Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.53", Port: 53}}},
	})
	if st := sub.StatusReport(); st.RootForwarded {
		t.Error("an iterated root is reported as forwarded")
	}
}
