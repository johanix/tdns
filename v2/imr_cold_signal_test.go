/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// A query that a referral has just brought to a server whose transport signal
// is not known yet (#1065). The server's one transport so far is Do53, and
// Do53 to it is in backoff: the server has no Do53, and the query and the
// signal lookup both tried it there first. Uses newStrictTestImr and
// startSignalLookup of imr_strict_signal_test.go.

const coldNoTuples = "no auth-server attempts made"

// newColdTestImr is newStrictTestImr with Do53 to the child's server in
// backoff.
func newColdTestImr(t *testing.T, wait time.Duration) (*Imr, *cache.AuthServer, map[string]*cache.AuthServer) {
	t.Helper()
	imr, server, serverMap := newStrictTestImr(t, wait)
	server.RecordAddressFailure("192.0.2.53", core.TransportDo53, errors.New("read: connection refused"))
	return imr, server, serverMap
}

// coldQuery sends the query a client without PRIVACY sends, and returns its
// error and how long it took.
func coldQuery(ctx context.Context, imr *Imr, serverMap map[string]*cache.AuthServer) (time.Duration, error) {
	start := time.Now()
	_, _, _, _, err := imr.IterativeDNSQuery(ctx, "www."+strictChildZone, dns.TypeA, serverMap, true, edns0.PrivacyNone)
	return time.Since(start), err
}

// The query waits for the running lookup, and then uses the transport the
// signal offers. It used to fail at once with no attempt at all.
func TestColdQueryWaitsForARunningSignalLookup(t *testing.T) {
	imr, server, serverMap := newColdTestImr(t, 5*time.Second)
	end := startSignalLookup(t, imr, server)
	end(50*time.Millisecond, map[core.Transport]uint8{core.TransportDoT: 50, core.TransportDo53: 100})

	elapsed, err := coldQuery(context.Background(), imr, serverMap)
	if elapsed >= 5*time.Second {
		t.Errorf("waited %s, the whole bound: the lookup's end went unnoticed", elapsed)
	}
	if err == nil {
		t.Fatal("no error, but the test cache has no DNS client to send the query with")
	}
	if strings.Contains(err.Error(), coldNoTuples) {
		t.Fatalf("the query gave up without waiting for the signal: %v", err)
	}
	// Sent over DoT, failed only for want of a client.
	if !strings.Contains(err.Error(), "attempts=1") || !strings.Contains(err.Error(), "/dot") {
		t.Errorf("got %v, want one attempt over DoT", err)
	}
}

// A server never looked up gets its lookup started by the query, whatever the
// discovery options say. The lookup here is real and fails at once, as the
// test cache has no client to send it with.
func TestColdQueryStartsTheSignalLookup(t *testing.T) {
	imr, _, serverMap := newColdTestImr(t, 5*time.Second)

	elapsed, err := coldQuery(context.Background(), imr, serverMap)
	if elapsed >= 5*time.Second {
		t.Errorf("waited %s, the whole bound, for a lookup that failed at once", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), coldNoTuples) {
		t.Errorf("got %v, want no attempt: the server has no transport left", err)
	}
	st, ok := imr.TransportSignalDiscovery.Snapshot()[strictChildOwner]
	if !ok {
		t.Fatal("no signal lookup was started")
	}
	if st.AttemptCount != 1 || st.Status != cache.DiscoveryFailed {
		t.Errorf("got %d attempts, status %s; want 1, failed",
			st.AttemptCount, cache.DiscoveryStatusToString[st.Status])
	}
}

// A cached denial of the signal means no signal until it expires: nothing to
// look up, nothing to wait for.
func TestColdQueryDoesNotWaitOnADenial(t *testing.T) {
	imr, _, serverMap := newColdTestImr(t, 5*time.Second)
	imr.Cache.Set(strictChildOwner, dns.TypeSVCB, &cache.CachedRRset{
		Name:       strictChildOwner,
		RRtype:     dns.TypeSVCB,
		Context:    cache.ContextNXDOMAIN,
		State:      cache.ValidationStateNone,
		Expiration: time.Now().Add(time.Hour),
	})

	elapsed, err := coldQuery(context.Background(), imr, serverMap)
	if elapsed > time.Second {
		t.Errorf("waited %s on a denied signal", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), coldNoTuples) {
		t.Errorf("got %v, want no attempt", err)
	}
	if snap := imr.TransportSignalDiscovery.Snapshot(); len(snap) != 0 {
		t.Errorf("a lookup was started although the signal is denied: %v", snap)
	}
}

// A lookup that failed and is cooling down is not retried, nor waited for.
func TestColdQueryDoesNotWaitOnAFailedLookup(t *testing.T) {
	imr, _, serverMap := newColdTestImr(t, 5*time.Second)
	if !imr.TransportSignalDiscovery.Begin(strictChildOwner) {
		t.Fatal("setup: could not start the lookup")
	}
	imr.TransportSignalDiscovery.Fail(strictChildOwner, errors.New("timeout"))

	elapsed, err := coldQuery(context.Background(), imr, serverMap)
	if elapsed > time.Second {
		t.Errorf("waited %s on a failed lookup", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), coldNoTuples) {
		t.Errorf("got %v, want no attempt", err)
	}
	if st := imr.TransportSignalDiscovery.Snapshot()[strictChildOwner]; st.AttemptCount != 1 {
		t.Errorf("the lookup was retried during its cooldown: %d attempts", st.AttemptCount)
	}
}

// A lookup that never ends costs the query strict-wait, and no more.
func TestColdQueryStopsAtTheBound(t *testing.T) {
	imr, server, serverMap := newColdTestImr(t, 100*time.Millisecond)
	startSignalLookup(t, imr, server)

	elapsed, err := coldQuery(context.Background(), imr, serverMap)
	if elapsed < 100*time.Millisecond || elapsed > 2*time.Second {
		t.Errorf("waited %s, want about the 100ms bound", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), coldNoTuples) {
		t.Errorf("got %v, want no attempt", err)
	}
}

// A server with a transport it may use is used at once, lookup or no lookup.
func TestColdQueryWithDo53DoesNotWait(t *testing.T) {
	imr, server, serverMap := newStrictTestImr(t, 5*time.Second)
	startSignalLookup(t, imr, server)

	elapsed, err := coldQuery(context.Background(), imr, serverMap)
	if elapsed > time.Second {
		t.Errorf("waited %s with Do53 available", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), "attempts=1") || !strings.Contains(err.Error(), "/do53") {
		t.Errorf("got %v, want one attempt over Do53", err)
	}
}

// A server without an address is not waited for: its signal cannot make it
// usable, and the address fallback after the first pass is what can.
func TestColdQueryDoesNotWaitForAServerWithoutAddresses(t *testing.T) {
	imr, _, _ := newColdTestImr(t, 5*time.Second)
	const bareNS = "ns3.child.example."
	bare := imr.Cache.GetOrCreateAuthServer(bareNS)
	serverMap := map[string]*cache.AuthServer{cache.ServerKey(bareNS): bare}
	if !imr.TransportSignalDiscovery.Begin(transportOwnerForNS(bareNS)) {
		t.Fatal("setup: could not start the lookup")
	}

	elapsed, _ := coldQuery(context.Background(), imr, serverMap)
	if elapsed >= time.Second {
		t.Errorf("waited %s for the signal of a server with no address", elapsed)
	}
}

// With transport signals turned off there is nothing to look up.
func TestColdQueryOffWhenSignalsAreOff(t *testing.T) {
	imr, _, serverMap := newColdTestImr(t, 5*time.Second)
	imr.Options[ImrOptUseTransportSignals] = "false"

	if _, err := coldQuery(context.Background(), imr, serverMap); err == nil || !strings.Contains(err.Error(), coldNoTuples) {
		t.Errorf("got %v, want no attempt", err)
	}
	if snap := imr.TransportSignalDiscovery.Snapshot(); len(snap) != 0 {
		t.Errorf("a lookup was started with transport signals off: %v", snap)
	}
}

// A transport-signal lookup does not wait for signal lookups: it could be
// waiting for itself.
func TestSignalLookupDoesNotWaitForSignals(t *testing.T) {
	imr, server, serverMap := newColdTestImr(t, 5*time.Second)
	startSignalLookup(t, imr, server)

	elapsed, err := coldQuery(withTransportSignalLookup(context.Background()), imr, serverMap)
	if elapsed > time.Second {
		t.Errorf("a signal lookup waited %s for a signal lookup", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), coldNoTuples) {
		t.Errorf("got %v, want no attempt", err)
	}
}

// Whichever lookup ends first is looked at first: a server whose lookup never
// ends does not hold up one whose signal has come in.
func TestColdQueryTakesTheFirstSignal(t *testing.T) {
	imr, server, serverMap := newColdTestImr(t, 5*time.Second)
	const stuckNS = "ns2.child.example."
	stuck := imr.Cache.GetOrCreateAuthServer(stuckNS)
	stuck.AddAddr("192.0.2.54")
	stuck.RecordAddressFailure("192.0.2.54", core.TransportDo53, errors.New("read: connection refused"))
	serverMap[cache.ServerKey(stuckNS)] = stuck
	if err := imr.Cache.AddServers(strictChildZone, serverMap); err != nil {
		t.Fatalf("setup: AddServers: %v", err)
	}
	if !imr.TransportSignalDiscovery.Begin(transportOwnerForNS(stuckNS)) {
		t.Fatal("setup: could not start the stuck lookup")
	}
	end := startSignalLookup(t, imr, server)
	end(50*time.Millisecond, map[core.Transport]uint8{core.TransportDoT: 50, core.TransportDo53: 100})

	elapsed, err := coldQuery(context.Background(), imr, serverMap)
	if elapsed >= time.Second {
		t.Errorf("waited %s: the stuck lookup held up the one that ended", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), "/dot") {
		t.Errorf("got %v, want an attempt over DoT", err)
	}
}

// startRefusingDouble is a loopback Do53 server that refuses every query
// with EDE 18, as tdns-auth does with debug-do53-queries-refused (#1066).
func startRefusingDouble(t *testing.T) (host, port string) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port, _ = net.SplitHostPort(pc.LocalAddr().String())
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		if opt := r.IsEdns0(); opt != nil {
			m.SetEdns0(1232, opt.Do())
			m.IsEdns0().Option = append(m.IsEdns0().Option, &dns.EDNS0_EDE{
				InfoCode: dns.ExtendedErrorCodeProhibited, ExtraText: "use an encrypted transport"})
		}
		_ = w.WriteMsg(m)
	})
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("refusing double did not start")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	})
	return host, port
}

// The query's own Do53 attempt is refused, before the server's signal is
// in: the pass runs out of tuples, but the signal lookup is still running.
// The query waits for it and goes again over DoT. It used to give up after
// the refusal (the rig's encns suite against a server that refuses queries
// over Do53).
func TestColdQueryWaitsAfterItsOwnDo53IsRefused(t *testing.T) {
	host, port := startRefusingDouble(t)
	imr := newTestImr(t)
	imr.Cache.DNSClient = map[core.Transport]core.DNSClienter{
		core.TransportDo53: core.NewDNSClient(core.TransportDo53, port, nil),
	}
	imr.TransportSignalDiscovery = cache.NewDiscoveryTracker(time.Minute, 3)
	imr.Tuning.Discovery.StrictWait = 5 * time.Second
	server := imr.Cache.GetOrCreateAuthServer(strictChildNS)
	server.AddAddr(host)
	serverMap := map[string]*cache.AuthServer{cache.ServerKey(strictChildNS): server}
	if err := imr.Cache.AddServers(strictChildZone, serverMap); err != nil {
		t.Fatalf("setup: AddServers: %v", err)
	}
	end := startSignalLookup(t, imr, server)
	end(300*time.Millisecond, map[core.Transport]uint8{core.TransportDoT: 50, core.TransportDo53: 100})

	elapsed, err := coldQuery(context.Background(), imr, serverMap)
	if elapsed >= 5*time.Second {
		t.Errorf("waited %s, the whole bound", elapsed)
	}
	// Do53, refused; then DoT, which fails only for want of a client.
	if err == nil || !strings.Contains(err.Error(), "attempts=2") || !strings.Contains(err.Error(), "/dot") {
		t.Errorf("got %v, want a refused Do53 attempt and then one over DoT", err)
	}
}

// startSignalAuthDouble is a loopback server for oobNSZone that gives
// oobNSName an address (its own) and a transport signal offering DoT.
func startSignalAuthDouble(t *testing.T) *oobAuthDouble {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	d := &oobAuthDouble{}
	d.host, d.port, _ = net.SplitHostPort(pc.LocalAddr().String())
	owner := transportOwnerForNS(oobNSName)
	signal, err := dns.NewRR(owner + ` 3600 IN SVCB 1 . oots="do53:100,dot:50"`)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(oobNSZone, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		switch {
		case core.EqualNames(q.Name, oobNSName) && q.Qtype == dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
				A:   net.ParseIP(d.host),
			})
		case core.EqualNames(q.Name, owner) && q.Qtype == dns.TypeSVCB:
			m.Answer = append(m.Answer, signal)
		default:
			m.Ns = append(m.Ns, &dns.SOA{
				Hdr: dns.RR_Header{Name: oobNSZone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
				Ns:  "ns." + oobNSZone, Mbox: "hostmaster." + oobNSZone,
				Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
			})
		}
		_ = w.WriteMsg(m)
	})
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: mux, NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("auth double did not start")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	})
	return d
}

// gluelessLookup runs the background address lookup a referral to oobZone
// starts for its nameserver without glue, and returns the nameserver's
// transport weights as soon as it has any, or after wait.
func gluelessLookup(t *testing.T, alwaysQuery bool, wait time.Duration) (*Imr, map[core.Transport]uint8) {
	t.Helper()
	d := startSignalAuthDouble(t)
	imr := newOOBTestImr(t, d)
	imr.TransportSignalDiscovery = cache.NewDiscoveryTracker(time.Minute, 3)
	if alwaysQuery {
		imr.Options[ImrOptAlwaysQueryForTransport] = "true"
	}
	cacheDelegation(imr.Cache, oobZone)

	select {
	case <-imr.nsLookup(context.Background(), oobNSName, oobZone):
	case <-time.After(5 * time.Second):
		t.Fatal("the address lookup did not end")
	}
	server := imr.Cache.GetOrCreateAuthServer(oobNSName)
	if len(server.GetAddrs()) == 0 {
		t.Fatal("setup: the address lookup found no address")
	}
	deadline := time.Now().Add(wait)
	for {
		if w := server.GetTransportWeights(); len(w) > 0 || time.Now().After(deadline) {
			return imr, w
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// With always-query-for-transport, a nameserver without glue has its signal
// looked up beside its address, and the server it is stored as carries the
// signal. Only servers created from glue used to be looked up.
func TestGluelessNameserverSignalIsLookedUp(t *testing.T) {
	_, weights := gluelessLookup(t, true, 3*time.Second)
	if weights[core.TransportDoT] != 50 {
		t.Errorf("got weights %v, want the signal's dot:50", weights)
	}
}

// Without the option, the address lookup starts no signal lookup.
func TestGluelessNameserverSignalNeedsTheOption(t *testing.T) {
	imr, weights := gluelessLookup(t, false, 300*time.Millisecond)
	if len(weights) != 0 {
		t.Errorf("got weights %v, want none: no signal lookup was asked for", weights)
	}
	if snap := imr.TransportSignalDiscovery.Snapshot(); len(snap) != 0 {
		t.Errorf("a signal lookup was started without the option: %v", snap)
	}
}
