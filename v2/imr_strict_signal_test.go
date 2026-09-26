/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The zone a strict-privacy query has just been referred to (#776), with the
// one nameserver the referral named.
const (
	strictChildZone  = "child.example."
	strictChildNS    = "ns.child.example."
	strictChildOwner = "_dns.ns.child.example."
	strictPrecheck   = "no servers have encrypted transports available"
)

// newStrictTestImr is an IMR that has just followed a referral to
// child.example.: the zone's one server has an address, and nothing is known
// yet about its transports. Its cache has no DNS clients, so nothing here can
// reach the network: an attempt to send a query fails at once.
func newStrictTestImr(t *testing.T, wait time.Duration) (*Imr, *cache.AuthServer, map[string]*cache.AuthServer) {
	t.Helper()
	imr := newTestImr(t)
	imr.Cache.DNSClient = map[core.Transport]core.DNSClienter{}
	imr.Options = map[ImrOption]string{}
	imr.TransportSignalDiscovery = cache.NewDiscoveryTracker(time.Minute, 3)
	imr.Tuning.Discovery.StrictWait = wait
	server := imr.Cache.GetOrCreateAuthServer(strictChildNS)
	server.AddAddr("192.0.2.53")
	serverMap := map[string]*cache.AuthServer{cache.ServerKey(strictChildNS): server}
	if err := imr.Cache.AddServers(strictChildZone, serverMap); err != nil {
		t.Fatalf("setup: AddServers: %v", err)
	}
	return imr, server, serverMap
}

// startSignalLookup marks the server's signal lookup as running, as the
// referral's always-query-for-transport lookup would have, so the code under
// test joins it instead of starting a real one. The returned function ends it
// after delay the way the lookup goroutine does: the signal is applied to the
// server first, then the tracker is told. A nil weights map is a lookup that
// found no signal.
func startSignalLookup(t *testing.T, imr *Imr, server *cache.AuthServer) func(delay time.Duration, weights map[core.Transport]uint8) {
	t.Helper()
	if !imr.TransportSignalDiscovery.Begin(strictChildOwner) {
		t.Fatal("setup: could not mark the signal lookup as running")
	}
	return func(delay time.Duration, weights map[core.Transport]uint8) {
		go func() {
			time.Sleep(delay)
			if weights == nil {
				imr.TransportSignalDiscovery.Fail(strictChildOwner, errors.New("NXDOMAIN"))
				return
			}
			var transports []core.Transport
			for tr := range weights {
				transports = append(transports, tr)
			}
			server.SetTransportSignal(transports, nil, weights)
			imr.TransportSignalDiscovery.Succeed(strictChildOwner)
		}()
	}
}

// privacyErrZone is the zone a strict-privacy error names, or "" when it is
// not one or names none.
func privacyErrZone(err error) string {
	var pe *PrivacyUnavailableError
	if errors.As(err, &pe) {
		return pe.Zone
	}
	return ""
}

// The first strict query to a zone met a moment ago used to fail at once
// (#776): the referral had started the lookup of the server's transport
// signal, and the precheck did not wait for it. It must wait, and then go on
// to use the transport the signal offers.
func TestStrictPrecheckWaitsForARunningSignalLookup(t *testing.T) {
	imr, server, serverMap := newStrictTestImr(t, 5*time.Second)
	end := startSignalLookup(t, imr, server)
	end(50*time.Millisecond, map[core.Transport]uint8{core.TransportDoT: 50, core.TransportDo53: 100})

	start := time.Now()
	_, _, _, _, err := imr.IterativeDNSQuery(context.Background(), "www."+strictChildZone, dns.TypeA, serverMap, true, edns0.PrivacyStrict)
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Errorf("waited %s, the whole bound: the lookup's end went unnoticed", elapsed)
	}
	if err == nil {
		t.Fatal("no error, but the test cache has no DNS client to send the query with")
	}
	if strings.Contains(err.Error(), strictPrecheck) {
		t.Fatalf("the precheck gave up although the signal arrived: %v", err)
	}
	// The query was sent over DoT and failed only for want of a client. The
	// walk then ran out of encrypted servers, which is a privacy failure, and
	// it belongs to the child.
	if !strings.Contains(err.Error(), "attempts=1") || !strings.Contains(err.Error(), "/dot") {
		t.Errorf("got %v, want one attempt over DoT", err)
	}
	if got := privacyErrZone(err); got != strictChildZone {
		t.Errorf("error names zone %q, want %q: %v", got, strictChildZone, err)
	}
}

// A zone whose servers signal no encrypted transport fails, as before, but
// only once the lookup has said so, and the error names that zone: the
// responder used to name the zone it had started from (#776).
func TestStrictPrecheckNamesTheZoneWithoutASignal(t *testing.T) {
	imr, server, serverMap := newStrictTestImr(t, 5*time.Second)
	end := startSignalLookup(t, imr, server)
	end(20*time.Millisecond, nil)

	start := time.Now()
	_, rcode, _, _, err := imr.IterativeDNSQuery(context.Background(), "www."+strictChildZone, dns.TypeA, serverMap, true, edns0.PrivacyStrict)
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Errorf("waited %s, the whole bound, for a lookup that had failed", elapsed)
	}
	if !errors.Is(err, ErrPrivacyUnavailable) || !strings.Contains(err.Error(), strictPrecheck) {
		t.Fatalf("got %v, want the precheck's privacy error", err)
	}
	if got := privacyErrZone(err); got != strictChildZone {
		t.Errorf("error names zone %q, want %q", got, strictChildZone)
	}
	if rcode != dns.RcodeServerFailure {
		t.Errorf("got rcode %s, want SERVFAIL", dns.RcodeToString[rcode])
	}
}

// A lookup that never ends costs the query strict-wait, and no more.
func TestAwaitTransportSignalsStopsAtTheBound(t *testing.T) {
	imr, server, serverMap := newStrictTestImr(t, 100*time.Millisecond)
	startSignalLookup(t, imr, server)

	start := time.Now()
	if imr.awaitTransportSignals(context.Background(), "www."+strictChildZone, serverMap) {
		t.Error("a server can carry the query, but no signal ever arrived")
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond || elapsed > 2*time.Second {
		t.Errorf("waited %s, want about the 100ms bound", elapsed)
	}
}

// The query's own deadline cuts the wait short.
func TestAwaitTransportSignalsStopsWithTheQuery(t *testing.T) {
	imr, server, serverMap := newStrictTestImr(t, 5*time.Second)
	startSignalLookup(t, imr, server)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	imr.awaitTransportSignals(ctx, "www."+strictChildZone, serverMap)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("waited %s after the query's deadline", elapsed)
	}
}

// A signal the cache already holds is applied to the server there and then,
// without a lookup: the server may have missed it only because it was in no
// zone's server map when the answer came in.
func TestAwaitTransportSignalsAppliesACachedSignal(t *testing.T) {
	imr, _, serverMap := newStrictTestImr(t, 5*time.Second)
	rr, err := dns.NewRR(strictChildOwner + ` 3600 IN SVCB 1 . oots="do53:100,dot:50"`)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	imr.Cache.Set(strictChildOwner, dns.TypeSVCB, &cache.CachedRRset{
		Name:       strictChildOwner,
		RRtype:     dns.TypeSVCB,
		RRset:      &core.RRset{Name: strictChildOwner, Class: dns.ClassINET, RRtype: dns.TypeSVCB, RRs: []dns.RR{rr}},
		Context:    cache.ContextAnswer,
		State:      cache.ValidationStateNone,
		Expiration: time.Now().Add(time.Hour),
	})

	if !imr.awaitTransportSignals(context.Background(), "www."+strictChildZone, serverMap) {
		t.Fatal("the cached dot:50 signal did not make the server usable")
	}
	if snap := imr.TransportSignalDiscovery.Snapshot(); len(snap) != 0 {
		t.Errorf("a lookup was started although the signal was cached: %v", snap)
	}
}

// A server whose signal is known is not looked up again, even when the signal
// offers nothing encrypted: otherwise every strict query to a Do53-only zone
// would wait.
func TestAwaitTransportSignalsLeavesKnownServersAlone(t *testing.T) {
	imr, server, serverMap := newStrictTestImr(t, 5*time.Second)
	server.SetTransportSignal([]core.Transport{core.TransportDo53}, []string{"do53"}, map[core.Transport]uint8{core.TransportDo53: 100})

	start := time.Now()
	if imr.awaitTransportSignals(context.Background(), "www."+strictChildZone, serverMap) {
		t.Error("a Do53-only server was found usable under strict privacy")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("waited %s for a server whose signal is known", elapsed)
	}
	if snap := imr.TransportSignalDiscovery.Snapshot(); len(snap) != 0 {
		t.Errorf("a lookup was started for a server whose signal is known: %v", snap)
	}
}

// With transport signals turned off there is nothing to look up.
func TestAwaitTransportSignalsOffWhenSignalsAreOff(t *testing.T) {
	imr, _, serverMap := newStrictTestImr(t, 5*time.Second)
	imr.Options[ImrOptUseTransportSignals] = "false"

	if imr.awaitTransportSignals(context.Background(), "www."+strictChildZone, serverMap) {
		t.Error("a server was found usable with transport signals off")
	}
	if snap := imr.TransportSignalDiscovery.Snapshot(); len(snap) != 0 {
		t.Errorf("a lookup was started with transport signals off: %v", snap)
	}
}

// A strict query looks the signal up itself when neither query-for-transport
// option is set. Without that, strict privacy could never reach a zone the
// resolver had only met through strict queries: they never go out in
// cleartext, so they never bring a signal back in the Additional section.
//
// The lookup here is real. It goes to the child's server and fails at once,
// since the test cache has no client to send it with.
func TestStrictLookupRunsWithoutTheDiscoveryOptions(t *testing.T) {
	imr, _, serverMap := newStrictTestImr(t, 5*time.Second)

	start := time.Now()
	if imr.awaitTransportSignals(context.Background(), "www."+strictChildZone, serverMap) {
		t.Error("a server was found usable, but its lookup cannot succeed here")
	}
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Errorf("waited %s, the whole bound, for a lookup that failed at once", elapsed)
	}
	st, ok := imr.TransportSignalDiscovery.Snapshot()[strictChildOwner]
	if !ok {
		t.Fatal("no lookup was started")
	}
	if st.AttemptCount != 1 || st.Status != cache.DiscoveryFailed {
		t.Errorf("got %d attempts, status %s; want 1, failed",
			st.AttemptCount, cache.DiscoveryStatusToString[st.Status])
	}
}

// The EDE names the zone the error carries, through walkErr's wrapping, and
// falls back to the responder's own zone only when the error names none.
func TestPrivacyUnavailableZone(t *testing.T) {
	carried := walkErr(strictChildZone, strictChildNS, "192.0.2.53", core.TransportDoT, 1, nil,
		privacyUnavailable(strictChildZone, "no answers found"))
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"zone carried":       {carried, strictChildZone},
		"no zone in it":      {privacyUnavailable("", "no answers found"), "example."},
		"bare sentinel":      {fmt.Errorf("%w: old style", ErrPrivacyUnavailable), "example."},
		"not privacy at all": {errors.New("timeout"), "example."},
	} {
		if got := privacyUnavailableZone(tc.err, "example."); got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
	if !errors.Is(carried, ErrPrivacyUnavailable) {
		t.Error("the error with a zone no longer matches the sentinel")
	}
}

// childSOA is the child zone's SOA, with ttl as both its TTL and MINIMUM.
func childSOA(t *testing.T, ttl uint32) *core.RRset {
	t.Helper()
	soa, err := dns.NewRR(fmt.Sprintf("%s %d IN SOA ns.%s hostmaster.%s 1 3600 600 86400 %d",
		strictChildZone, ttl, strictChildZone, strictChildZone, ttl))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	return &core.RRset{Name: strictChildZone, Class: dns.ClassINET, RRtype: dns.TypeSOA, RRs: []dns.RR{soa}}
}

// cacheSignalDenial caches the child zone's denial that strictChildOwner has
// a transport signal, as handleNegative stores one: an NXDOMAIN entry whose
// RRset is the SOA that proves it. The entry lives for the SOA's TTL.
func cacheSignalDenial(t *testing.T, imr *Imr, ttl uint32) {
	t.Helper()
	soaRRset := childSOA(t, ttl)
	imr.Cache.Set(strictChildOwner, dns.TypeSVCB, &cache.CachedRRset{
		Name:       strictChildOwner,
		RRtype:     dns.TypeSVCB,
		Rcode:      uint8(dns.RcodeNameError),
		RRset:      soaRRset,
		Context:    cache.ContextNXDOMAIN,
		State:      cache.ValidationStateNone,
		Expiration: time.Now().Add(time.Duration(ttl) * time.Second),
	})
}

// A zone that signalled nothing when first asked, and publishes a signal
// afterwards, must be seen to. The order is the natural one: a strict query
// meets the zone, its signal lookup is denied, the zone publishes, the client
// asks again. The "no signal" verdict stood for good: a lookup that met the
// cached denial got its proving SOA back from ImrQuery as the answer (#698,
// since fixed there) and was recorded as a success, which the tracker never
// retries.
//
// The denial holds the verdict while it is cached, so a strict query fails at
// once and nothing is looked up. Not a moment longer: once it expires, the
// next strict query looks again, waits, and goes out encrypted.
func TestStrictPrivacySeesASignalPublishedAfterADenial(t *testing.T) {
	imr, server, serverMap := newStrictTestImr(t, 5*time.Second)
	cacheSignalDenial(t, imr, 1)
	// The first lookup meets the cached denial. It runs as the lookup
	// goroutine runs it: through ImrQuery, which answers from the cache.
	if !imr.TransportSignalDiscovery.Begin(strictChildOwner) {
		t.Fatal("setup: could not start the first lookup")
	}
	resp, err := imr.ImrQuery(context.Background(), strictChildOwner, dns.TypeSVCB, dns.ClassINET, nil)
	if err != nil || resp == nil || resp.Denial != cache.ContextNXDOMAIN {
		t.Fatalf("setup: ImrQuery did not answer with the cached denial: %+v, %v", resp, err)
	}
	imr.settleTransportSignalLookup(strictChildOwner, resp, err)

	start := time.Now()
	_, _, _, _, err = imr.IterativeDNSQuery(context.Background(), "www."+strictChildZone, dns.TypeA, serverMap, true, edns0.PrivacyStrict)
	if err == nil || !strings.Contains(err.Error(), strictPrecheck) {
		t.Fatalf("while the denial is cached: got %v, want the precheck's error", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("waited %s while the denial was cached", elapsed)
	}
	if snap := imr.TransportSignalDiscovery.Snapshot(); len(snap) != 0 {
		t.Errorf("while the denial is cached the tracker holds state of its own (a lookup, or a verdict): %v", snap)
	}

	// The zone publishes its signal, and the denial expires.
	time.Sleep(1100 * time.Millisecond)

	// The next strict query must be free to look again. The lookup here is
	// the test's (nothing reaches the network), and brings the new signal.
	if !imr.TransportSignalDiscovery.Begin(strictChildOwner) {
		t.Fatal("the denial has expired, but the tracker still holds the owner back: no lookup can start")
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		server.SetTransportSignal([]core.Transport{core.TransportDoT, core.TransportDo53}, nil,
			map[core.Transport]uint8{core.TransportDoT: 50, core.TransportDo53: 100})
		imr.TransportSignalDiscovery.Succeed(strictChildOwner)
	}()
	_, _, _, _, err = imr.IterativeDNSQuery(context.Background(), "www."+strictChildZone, dns.TypeA, serverMap, true, edns0.PrivacyStrict)
	if err != nil && strings.Contains(err.Error(), strictPrecheck) {
		t.Fatalf("after the denial expired: the precheck still gave up: %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "/dot") {
		t.Errorf("after the denial expired: got %v, want an attempt over DoT", err)
	}
}

// How a lookup's end is recorded. Only a signal is a success, and a success is
// never retried. A denial is neither: its cached entry carries the verdict for
// its lifetime, and the tracker must not outlive it with state of its own. A
// denial with TTL 0 is not cached at all, and must leave no state either.
func TestSettleTransportSignalLookup(t *testing.T) {
	signal, err := dns.NewRR(strictChildOwner + ` 3600 IN SVCB 1 . oots="do53:100,dot:50"`)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	svcb := &core.RRset{Name: strictChildOwner, Class: dns.ClassINET, RRtype: dns.TypeSVCB, RRs: []dns.RR{signal}}

	for name, tc := range map[string]struct {
		resp *ImrResponse
		err  error
		want string // tracker status, or "" for no state
	}{
		"signal found":       {resp: &ImrResponse{RRset: svcb}, want: "succeeded"},
		"NXDOMAIN":           {resp: &ImrResponse{Denial: cache.ContextNXDOMAIN}, want: ""},
		"NODATA":             {resp: &ImrResponse{Denial: cache.ContextNoErrNoAns}, want: ""},
		"an SOA, no denial":  {resp: &ImrResponse{RRset: childSOA(t, 3600)}, want: "failed"},
		"lookup error":       {resp: &ImrResponse{Error: true}, err: errors.New("timeout"), want: "failed"},
		"nothing, no denial": {resp: &ImrResponse{}, want: "failed"},
	} {
		imr, _, _ := newStrictTestImr(t, time.Second)
		imr.TransportSignalDiscovery.Begin(strictChildOwner)
		imr.settleTransportSignalLookup(strictChildOwner, tc.resp, tc.err)
		got := ""
		if st, ok := imr.TransportSignalDiscovery.Snapshot()[strictChildOwner]; ok {
			got = cache.DiscoveryStatusToString[st.Status]
		}
		if got != tc.want {
			t.Errorf("%s: tracker says %q, want %q", name, got, tc.want)
		}
	}
}
