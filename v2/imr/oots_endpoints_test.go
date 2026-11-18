/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package imr

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

const dotTarget = "dot-ns." + stateZone

// redirectRecords is one nameserver's signal: DoT on another host at port
// 1234, DoQ on the nameserver itself.
func redirectRecords(t *testing.T) []dns.RR {
	return []dns.RR{
		mustRR(t, pathOwner+` 3600 IN SVCB 1 `+dotTarget+` port=1234 oots="dot:30"`),
		mustRR(t, pathOwner+` 3600 IN SVCB 1 . oots="doq:20"`),
	}
}

// A record with a target is honoured on every path once the RRset validated
// Secure: its transports go to the target, at its port. Otherwise it is
// ignored whole, weight and port included (R1, R2), and counted; the record
// with TargetName "." is honoured either way (R4).
func TestOOTSRedirectHonouredOnlyWhenSecure(t *testing.T) {
	dkc := signerTestDnskeyCache(t)
	held := newSignerTestKey(t, stateZone, 256)
	held.holdSecure(dkc)
	records := redirectRecords(t)
	signed := signedSection(t, held, records, pathOwner)
	tampered := copyRRs(signed)
	tampered[1] = mustRR(t, pathOwner+` 3600 IN SVCB 1 . oots="doq:90"`)

	for _, tc := range []struct {
		name     string
		section  []dns.RR
		lookup   cache.ValidationState
		redirect bool
		doq      uint8
	}{
		{"secure", signed, cache.ValidationStateSecure, true, 20},
		{"undecided", records, cache.ValidationStateIndeterminate, false, 20},
		{"insecure", records, cache.ValidationStateInsecure, false, 20},
		{"bogus", tampered, cache.ValidationStateBogus, false, 90},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for via, server := range stateOnEachPath(t, tc.section, tc.lookup, nil) {
				rec := server.GetReceivedSignal()
				if rec == nil {
					t.Fatalf("%s: no signal", via)
				}
				ep := server.GetTransportEndpoint(core.TransportDoT)
				_, hasDoT := rec.Weights[core.TransportDoT]
				if tc.redirect {
					if ep != (cache.Endpoint{Target: dotTarget, Port: 1234}) || rec.Weights[core.TransportDoT] != 30 {
						t.Errorf("%s: DoT endpoint %v weight %d, want %s:1234 weight 30", via, ep, rec.Weights[core.TransportDoT], dotTarget)
					}
					if rec.Targets[core.TransportDoT] != dotTarget {
						t.Errorf("%s: received targets %v", via, rec.Targets)
					}
				} else {
					if !ep.IsDefault() || hasDoT || rec.Targets != nil {
						t.Errorf("%s: an unvalidated redirect left endpoint %v, DoT weight %v, targets %v", via, ep, hasDoT, rec.Targets)
					}
					if got := server.SnapshotTransportStats().IgnoredRedirects; got != 1 {
						t.Errorf("%s: ignored redirects %d, want 1", via, got)
					}
				}
				if got := rec.Weights[core.TransportDoQ]; got != tc.doq {
					t.Errorf("%s: DoQ weight %d, want %d", via, got, tc.doq)
				}
				if ep := server.GetTransportEndpoint(core.TransportDoQ); !ep.IsDefault() {
					t.Errorf("%s: DoQ endpoint %v, want the default", via, ep)
				}
			}
		})
	}
}

// On equal SvcPriority the record about the nameserver itself wins a
// transport over one with a target (section 2); the target record still
// supplies its other transports. do53 in a record with a target is ignored.
func TestOOTSRedirectTieBreakAndDo53(t *testing.T) {
	recs := []ootsRecord{
		ootsRecordOf(t, pathOwner+` 3600 IN SVCB 1 `+dotTarget+` port=1234 oots="do53:5,dot:30,doh:10"`),
		ootsRecordOf(t, pathOwner+` 3600 IN SVCB 1 . oots="dot:40"`),
	}
	raw, ports, targets := combineOOTSEndpoints(recs)
	if raw["dot"] != 40 || raw["doh"] != 10 {
		t.Errorf("weights %v, want dot from the \".\" record and doh from the target", raw)
	}
	if _, ok := raw["do53"]; ok {
		t.Errorf("do53 taken from a record with a target: %v", raw)
	}
	if targets[core.TransportDoT] != "" || targets[core.TransportDoH] != dotTarget {
		t.Errorf("targets %v, want DoH only", targets)
	}
	if ports[core.TransportDoT] != 0 || ports[core.TransportDoH] != 1234 {
		t.Errorf("ports %v, want DoH:1234 only", ports)
	}
}

// Once the lookup of _dns.<ns> has validated the RRset, an equal harvest from
// an Additional section is the same validated copy, RRSIG or not: its
// redirect is honoured. A harvest that differs is not.
func TestOOTSEqualHarvestIsSecure(t *testing.T) {
	signerTestDnskeyCache(t)
	records := redirectRecords(t)
	prep := func(imr *Imr) {
		imr.Cache.Set(pathOwner, dns.TypeSVCB, &cache.CachedRRset{
			Name: pathOwner, RRtype: dns.TypeSVCB, Context: cache.ContextAnswer,
			RRset: &core.RRset{Name: pathOwner, Class: dns.ClassINET, RRtype: dns.TypeSVCB, RRs: copyRRs(records)},
			State: cache.ValidationStateSecure, Expiration: time.Now().Add(time.Hour),
		})
	}
	servers := stateOnEachPath(t, records, cache.ValidationStateIndeterminate, prep)
	for _, via := range []string{cache.SignalViaReferral, cache.SignalViaResponse} {
		if ep := servers[via].GetTransportEndpoint(core.TransportDoT); ep.Target != dotTarget {
			t.Errorf("%s: equal harvest: DoT endpoint %v", via, ep)
		}
	}
	changed := []dns.RR{mustRR(t, pathOwner+` 3600 IN SVCB 1 `+dotTarget+` port=1235 oots="dot:30"`)}
	servers = stateOnEachPath(t, changed, cache.ValidationStateIndeterminate, prep)
	for _, via := range []string{cache.SignalViaReferral, cache.SignalViaResponse} {
		if ep := servers[via].GetTransportEndpoint(core.TransportDoT); !ep.IsDefault() {
			t.Errorf("%s: a changed harvest kept a redirect: %v", via, ep)
		}
	}
}

// A redirect ignored because the Additional section could not decide its path
// asks for the verifying lookup; one ignored on a decided verdict does not.
func TestOOTSUndecidedRedirectAwaitsLookup(t *testing.T) {
	for _, tc := range []struct {
		state cache.ValidationState
		want  bool
	}{
		{cache.SignalStateUnknown, true},
		{cache.ValidationStateInsecure, false},
		{cache.ValidationStateBogus, false},
		{cache.ValidationStateSecure, false},
	} {
		imr := newTestImr(t)
		set := &svcbSignalSet{}
		for _, rr := range redirectRecords(t) {
			set.add(rr.(*dns.SVCB))
		}
		set.via = cache.SignalViaResponse
		set.path = []cache.SignalHop{{Owner: pathOwner, State: tc.state}}
		imr.installSVCBSignal(cache.NewAuthServer(pathNS), set)
		if set.awaitsLookup != tc.want {
			t.Errorf("state %s: awaits lookup %v, want %v", cache.SignalStateString(tc.state), set.awaitsLookup, tc.want)
		}
	}
}

// endpointTestRig is a resolver with fake DoT and Do53 clients, and a server
// whose DoT a validated signal sent to dotTarget at port 1234.
func endpointTestRig(t *testing.T) (*Imr, *cache.AuthServer, *core.FakeDNSClient, *core.FakeDNSClient, *dns.Msg) {
	t.Helper()
	imr := newTestImr(t)
	q := new(dns.Msg)
	q.SetQuestion("example.", dns.TypeA)
	reply := new(dns.Msg)
	reply.SetReply(q)
	dot := core.NewFakeDNSClient(core.TransportDoT)
	do53 := core.NewFakeDNSClient(core.TransportDo53)
	for _, addr := range []string{"192.0.2.1", "192.0.2.53:1234", "[2001:db8::53]:1234"} {
		dot.Set("example.", addr, core.FakeResponse{Msg: reply})
		do53.Set("example.", addr, core.FakeResponse{Msg: reply})
	}
	imr.Cache.DNSClient[core.TransportDoT] = dot
	imr.Cache.DNSClient[core.TransportDo53] = do53
	server := cache.NewAuthServer(pathNS)
	installTransportMap(server, map[string]uint8{"dot": 30}, map[core.Transport]uint16{core.TransportDoT: 1234},
		map[core.Transport]string{core.TransportDoT: dotTarget}, cache.SignalViaLookup,
		[]cache.SignalHop{{Owner: pathOwner, State: cache.ValidationStateSecure}})
	return imr, server, dot, do53, q
}

func lastDial(f *core.FakeDNSClient) string {
	calls := f.Calls()
	if len(calls) == 0 {
		return ""
	}
	return calls[len(calls)-1].Addr
}

// Until the target's addresses are known, DoT uses the default endpoint, the
// nameserver's own address at the usual port, and the lookup of the target is
// started. Once known, DoT goes to the target at the endpoint's port, and the
// answer counts as redirected.
func TestTryServerRedirectWaitsForTargetAddrs(t *testing.T) {
	imr, server, dot, _, q := endpointTestRig(t)
	looked := make(chan string, 1)
	saved := endpointAddrLookupHook
	endpointAddrLookupHook = func(_ *Imr, target string) ([]string, time.Time) {
		looked <- target
		return []string{"192.0.2.53"}, time.Now().Add(time.Hour)
	}
	t.Cleanup(func() { endpointAddrLookupHook = saved })
	ctx := context.Background()

	if _, _, _, _, err := imr.tryServer(ctx, server, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone); err != nil {
		t.Fatalf("before the lookup: %v", err)
	}
	if got := lastDial(dot); got != "192.0.2.1" {
		t.Errorf("before the lookup dialed %q, want the nameserver at the default port", got)
	}
	select {
	case got := <-looked:
		if got != dotTarget {
			t.Errorf("looked up %q, want %q", got, dotTarget)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the target's addresses were not looked up")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, known := imr.endpointAddrs.get(dotTarget, time.Now()); known {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the lookup's addresses never arrived")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if _, _, _, _, err := imr.tryServer(ctx, server, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone); err != nil {
		t.Fatalf("after the lookup: %v", err)
	}
	if got := lastDial(dot); got != "192.0.2.53:1234" {
		t.Errorf("after the lookup dialed %q, want 192.0.2.53:1234", got)
	}
	if got := server.SnapshotTransportStats().Redirected[core.TransportDoT]; got != 1 {
		t.Errorf("redirected DoT answers %d, want 1", got)
	}
	if _, ok := server.GetEndpointAddrRTT("192.0.2.53", 1234, core.TransportDoT); !ok {
		t.Errorf("no RTT kept under the target's address and port")
	}
	if _, ok := server.GetRTT("192.0.2.1", core.TransportDoT); !ok {
		t.Errorf("the default-endpoint attempt kept no RTT under the nameserver's address")
	}
}

// A failure at one of the target's addresses backs off that address at that
// port and transport, not the nameserver's own; the next attempt takes the
// target's other address. With both backed off, no attempt is made, and Do53
// still goes to the nameserver itself on port 53.
func TestTryServerRedirectBackoffAndFallback(t *testing.T) {
	imr, server, dot, do53, q := endpointTestRig(t)
	imr.endpointAddrs.set(dotTarget, []string{"192.0.2.99", "2001:db8::53"}, time.Now().Add(time.Hour))
	ctx := context.Background()
	server.RecordEndpointAddrRTT("192.0.2.99", 1234, core.TransportDoT, time.Millisecond) // the faster one, tried first

	if _, _, _, _, err := imr.tryServer(ctx, server, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone); err == nil {
		t.Fatal("192.0.2.99 has no programmed answer; want a failure")
	}
	if got := lastDial(dot); got != "192.0.2.99:1234" {
		t.Errorf("first dial %q", got)
	}
	if server.IsEndpointAddrAvailable("192.0.2.99", 1234, core.TransportDoT) {
		t.Errorf("the failing target address is not backed off")
	}
	if !server.IsAddrXportAvailable("192.0.2.1", core.TransportDoT) {
		t.Errorf("a target's failure backed off the nameserver's own address")
	}
	_, _, _, ep, err := imr.tryServer(ctx, server, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone)
	if err != nil {
		t.Fatalf("second attempt: %v", err)
	}
	if got := lastDial(dot); got != "[2001:db8::53]:1234" || ep.dialAddr() != got {
		t.Errorf("second dial %q (returned %q), want the target's other address", got, ep.dialAddr())
	}
	// A lame answer from the target is kept at the nameserver's own tuple.
	if !ep.redirect || ep.lamenessPort() != 0 {
		t.Errorf("returned endpoint %+v: want a redirect with lameness at port 0", ep)
	}

	server.RecordEndpointAddrFailure("2001:db8::53", 1234, core.TransportDoT, nil)
	n := len(dot.Calls())
	_, _, _, _, err = imr.tryServer(ctx, server, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone)
	if _, ok := err.(errEndpointUnavailable); !ok {
		t.Errorf("every target address backed off: err %v, want errEndpointUnavailable", err)
	}
	if len(dot.Calls()) != n {
		t.Errorf("an attempt was dialed with every target address backed off")
	}
	if _, _, _, _, err := imr.tryServer(ctx, server, "192.0.2.1", core.TransportDo53, q, "example.", dns.TypeA, false, cache.ClassNone); err != nil {
		t.Fatalf("Do53 fallback: %v", err)
	}
	if got := lastDial(do53); got != "192.0.2.1" {
		t.Errorf("Do53 fallback dialed %q, want the nameserver on port 53", got)
	}
}

// The lookups of a target's addresses go to every server's default endpoint:
// the nameserver's own address at the usual port, whatever its signal says.
func TestTryServerDefaultEndpointsContext(t *testing.T) {
	imr, server, dot, _, q := endpointTestRig(t)
	imr.endpointAddrs.set(dotTarget, []string{"192.0.2.53"}, time.Now().Add(time.Hour))
	ctx := withDefaultEndpoints(context.Background())
	if _, _, _, _, err := imr.tryServer(ctx, server, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone); err != nil {
		t.Fatalf("%v", err)
	}
	if got := lastDial(dot); got != "192.0.2.1" {
		t.Errorf("dialed %q, want the default endpoint", got)
	}
}

// A target's address is chosen as a nameserver's is: never one on this host
// without allow-loopback-nameservers, never one in backoff, the lowest RTT
// first.
func TestChooseEndpointAddr(t *testing.T) {
	imr := newTestImr(t)
	server := cache.NewAuthServer(pathNS)
	addrs := []string{"127.0.0.1", "192.0.2.10", "192.0.2.11", "192.0.2.12"}
	server.RecordEndpointAddrRTT("127.0.0.1", 853, core.TransportDoT, time.Microsecond)
	server.RecordEndpointAddrRTT("192.0.2.11", 853, core.TransportDoT, 5*time.Millisecond)
	server.RecordEndpointAddrRTT("192.0.2.12", 853, core.TransportDoT, time.Millisecond)
	server.RecordEndpointAddrFailure("192.0.2.12", 853, core.TransportDoT, nil)

	imr.Options[ImrOptAllowLoopbackNameservers] = "false"
	if got := imr.chooseEndpointAddr(server, addrs, 853, core.TransportDoT); got != "192.0.2.11" {
		t.Errorf("chose %q, want 192.0.2.11", got)
	}
	imr.Options[ImrOptAllowLoopbackNameservers] = "true"
	if got := imr.chooseEndpointAddr(server, addrs, 853, core.TransportDoT); got != "127.0.0.1" {
		t.Errorf("with loopback allowed chose %q, want 127.0.0.1", got)
	}
	if got := imr.chooseEndpointAddr(server, []string{"192.0.2.12"}, 853, core.TransportDoT); got != "" {
		t.Errorf("only a backed-off address: chose %q", got)
	}
	if got := imr.chooseEndpointAddr(server, []string{"192.0.2.12"}, 1234, core.TransportDoT); got != "192.0.2.12" {
		t.Errorf("another port is not backed off: chose %q", got)
	}
}

// The tracker serves addresses until they expire, runs one lookup at a time,
// and waits endpointAddrRetry after a lookup that found nothing.
func TestEndpointAddrTracker(t *testing.T) {
	var tr endpointAddrTracker
	now := time.Now()
	if _, ok := tr.get(dotTarget, now); ok {
		t.Fatal("known before any lookup")
	}
	if !tr.begin(dotTarget, now) || tr.begin(dotTarget, now) {
		t.Fatal("begin: want one lookup in flight")
	}
	tr.finish(dotTarget, nil, time.Time{}, now)
	if tr.begin(dotTarget, now.Add(endpointAddrRetry/2)) {
		t.Error("a failed lookup retried before endpointAddrRetry")
	}
	if !tr.begin(dotTarget, now.Add(endpointAddrRetry)) {
		t.Fatal("not retried after endpointAddrRetry")
	}
	tr.finish(dotTarget, []string{"192.0.2.53"}, now.Add(time.Minute), now)
	if addrs, ok := tr.get("DOT-NS.kid.p.test.", now); !ok || len(addrs) != 1 {
		t.Errorf("get after a lookup: %v %v", addrs, ok)
	}
	if _, ok := tr.get(dotTarget, now.Add(time.Minute)); ok {
		t.Error("served after the addresses expired")
	}
}

// A record with a target gives the ALPN order only the tokens it may carry:
// do53 comes from a record with TargetName "." alone.
func TestAlpnOrderTargetCarriesNoDo53(t *testing.T) {
	targeted := ootsRecord{alpn: []string{"do53", "dot"}, target: dotTarget, priority: 1}
	self := ootsRecord{alpn: []string{"do53"}, priority: 2}
	if got := alpnOrder([]ootsRecord{targeted}); !reflect.DeepEqual(got, []string{"dot"}) {
		t.Errorf("targeted record alone: %v, want [dot]", got)
	}
	if got := alpnOrder([]ootsRecord{targeted, self}); !reflect.DeepEqual(got, []string{"dot", "do53"}) {
		t.Errorf("with a \".\" record: %v, want [dot do53]", got)
	}

	server := cache.NewAuthServer(pathNS)
	_, ports, targets := combineOOTSEndpoints([]ootsRecord{targeted})
	installAlpnSignal(server, alpnOrder([]ootsRecord{targeted}), ports, targets, cache.SignalViaLookup,
		[]cache.SignalHop{{Owner: pathOwner, State: cache.ValidationStateSecure}})
	if w, ok := server.GetReceivedSignal().Weights[core.TransportDo53]; ok {
		t.Errorf("the targeted record's do53 reached the signal, weight %d", w)
	}
}

// A backoff left on the nameserver's own address by an attempt at the default
// endpoint does not keep a redirected transport from the target once the
// target's addresses are known; the backoff of the target's addresses does.
// The lookups of a target's addresses still see the own address's backoff.
func TestPrioritizeServersRedirectBackoff(t *testing.T) {
	imr, server, _, _, _ := endpointTestRig(t)
	server.SetAddrs([]string{"192.0.2.1"})
	server.RecordEndpointAddrFailure("192.0.2.1", 0, core.TransportDoT, nil)
	serverMap := map[string]*cache.AuthServer{pathNS: server}
	saved := endpointAddrLookupHook
	endpointAddrLookupHook = func(*Imr, string) ([]string, time.Time) { return nil, time.Time{} }
	t.Cleanup(func() { endpointAddrLookupHook = saved })
	hasDoT := func(ctx context.Context) bool {
		_, _, tuples := imr.prioritizeServersFor(ctx, "example.", dns.TypeA, serverMap, edns0.PrivacyNone)
		for _, tup := range tuples {
			if tup.Transport == core.TransportDoT {
				return true
			}
		}
		return false
	}
	ctx := context.Background()
	if hasDoT(ctx) {
		t.Error("the target's addresses unknown: DoT offered at the backed-off own address")
	}
	imr.endpointAddrs.set(dotTarget, []string{"192.0.2.53"}, time.Now().Add(time.Hour))
	if !hasDoT(ctx) {
		t.Error("the target's address usable: DoT held back by the own address's backoff")
	}
	if hasDoT(withDefaultEndpoints(ctx)) {
		t.Error("a default-endpoint lookup: DoT offered at the backed-off own address")
	}
	server.RecordEndpointAddrFailure("192.0.2.53", 1234, core.TransportDoT, nil)
	if hasDoT(ctx) {
		t.Error("every target address backed off: DoT still offered")
	}
}

// The stub probe dials the endpoint a query would: the target's address at
// the endpoint's port once known, the nameserver's own address before. It
// looks nothing up, and with every target address backed off it reports that
// without a dial.
func TestProbeStubServersFollowsRedirect(t *testing.T) {
	const zone = "stubredirect.example."
	imr := newTestImr(t)
	q := new(dns.Msg)
	q.SetQuestion(zone, dns.TypeSOA)
	reply := new(dns.Msg)
	reply.SetReply(q)
	reply.Authoritative = true
	dot := core.NewFakeDNSClient(core.TransportDoT)
	dot.Set(zone, "192.0.2.1", core.FakeResponse{Msg: reply})
	dot.Set(zone, "192.0.2.53:1234", core.FakeResponse{Msg: reply})
	for tr := range imr.Cache.DNSClient {
		delete(imr.Cache.DNSClient, tr)
	}
	imr.Cache.DNSClient[core.TransportDoT] = dot
	if err := imr.Cache.AddStub(zone, []cache.AuthServer{
		{Name: "ns." + zone, Addrs: []string{"192.0.2.1"}, Alpn: []string{"dot"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	imr.setZoneTable(nil, []string{zone}, nil)
	servers := imr.stubServers(zone)
	if len(servers) != 1 {
		t.Fatalf("stub servers %v", servers)
	}
	installTransportMap(servers[0], map[string]uint8{"dot": 100}, map[core.Transport]uint16{core.TransportDoT: 1234},
		map[core.Transport]string{core.TransportDoT: dotTarget}, cache.SignalViaLookup,
		[]cache.SignalHop{{Owner: pathOwner, State: cache.ValidationStateSecure}})
	saved := endpointAddrLookupHook
	endpointAddrLookupHook = func(*Imr, string) ([]string, time.Time) { return nil, time.Time{} }
	t.Cleanup(func() { endpointAddrLookupHook = saved })
	probe := func() ImrStubProbeResult {
		t.Helper()
		results, err := imr.ProbeStubServers(context.Background(), zone)
		if err != nil || len(results) != 1 {
			t.Fatalf("ProbeStubServers: %v %+v", err, results)
		}
		return results[0]
	}

	if res := probe(); res.Addr != "192.0.2.1" || !res.OK {
		t.Errorf("before the target is known: %+v, want the default endpoint", res)
	}
	// A lookup started would be in flight or have failed: either way begin
	// could not claim it now.
	if !imr.endpointAddrs.begin(dotTarget, time.Now()) {
		t.Error("the probe started a lookup")
	}
	imr.endpointAddrs.set(dotTarget, []string{"192.0.2.53"}, time.Now().Add(time.Hour))
	if res := probe(); res.Addr != "192.0.2.53:1234" || !res.OK {
		t.Errorf("target known: %+v, want 192.0.2.53:1234", res)
	}
	servers[0].RecordEndpointAddrFailure("192.0.2.53", 1234, core.TransportDoT, nil)
	n := len(dot.Calls())
	if res := probe(); res.OK || !strings.Contains(res.Error, "no usable address") {
		t.Errorf("every target address backed off: %+v", res)
	}
	if len(dot.Calls()) != n {
		t.Error("the probe dialed with every target address backed off")
	}
}

// finish drops the entries and retry marks that have run out, of every
// target, not only the one it ends.
func TestEndpointAddrTrackerPrunes(t *testing.T) {
	var tr endpointAddrTracker
	now := time.Now()
	tr.finish("a.example.", []string{"192.0.2.1"}, now.Add(time.Minute), now)
	tr.finish("b.example.", nil, time.Time{}, now)
	tr.finish("c.example.", []string{"192.0.2.3"}, now.Add(time.Hour), now)
	later := now.Add(2 * time.Minute)
	tr.finish("d.example.", []string{"192.0.2.4"}, later.Add(time.Hour), later)
	if _, ok := tr.entries["a.example."]; ok {
		t.Error("an expired entry was kept")
	}
	if _, ok := tr.retry["b.example."]; ok {
		t.Error("an elapsed retry mark was kept")
	}
	if len(tr.entries) != 2 {
		t.Errorf("entries %v, want c and d", tr.entries)
	}
}

// Addresses found through a CNAME chain are kept no longer than the chain's
// first link to run out, as the lookup carried it with its answer
// (Response.ChainExpiration); when it carried none, not at all.
func TestEndpointAddrsExpireWithTheChain(t *testing.T) {
	imr := newTestImr(t)
	const alias, final = "dot-alias." + stateZone, "dot-host.example.net."
	addrs := &core.RRset{Name: final, Class: dns.ClassINET, RRtype: dns.TypeA,
		RRs: []dns.RR{mustRR(t, final+` 3600 IN A 192.0.2.53`)}}
	resp := &Response{RRset: addrs, Expiration: time.Now().Add(time.Hour), ChainExpiration: time.Now().Add(time.Minute)}

	exp := imr.addrsExpiry(alias, dns.TypeA, resp)
	if exp.After(time.Now().Add(time.Minute)) || exp.Before(time.Now().Add(50*time.Second)) {
		t.Errorf("through the chain: expires in %v, want the link's minute", time.Until(exp))
	}
	if exp := imr.addrsExpiry(final, dns.TypeA, resp); exp.Before(time.Now().Add(59 * time.Minute)) {
		t.Errorf("no chain: expires in %v, want the address TTL", time.Until(exp))
	}
	if got, _ := imr.endpointAddrsOf(alias, dns.TypeA, resp, time.Now()); len(got) != 1 {
		t.Errorf("chain expiry carried: kept %v, want the address", got)
	}

	// An answer reached through a chain the lookup carried no expiry for: the
	// address is not kept.
	unknown := &Response{RRset: addrs, Expiration: time.Now().Add(time.Hour)}
	if exp := imr.addrsExpiry(alias, dns.TypeA, unknown); !exp.IsZero() {
		t.Errorf("chain expiry unknown: expires in %v, want the zero time", time.Until(exp))
	}
	if got, exp := imr.endpointAddrsOf(alias, dns.TypeA, unknown, time.Now()); len(got) != 0 {
		t.Errorf("chain expiry unknown: kept %v until %v, want nothing", got, exp)
	}
}

// Query carries the expiry of the chain it followed with its answer: the
// earliest link's, on the wire path and from the cache. Once the lookup has
// returned, a link that changes target does not change it: the address the old
// chain led to is kept no longer than the old link (CodeRabbit on #1055: the
// expiry read back from the cache after the lookup could be the new chain's).
func TestImrQueryCarriesTheChainExpiry(t *testing.T) {
	imr, _ := sigChainImr(t)
	ctx := context.Background()

	// The wire path: s1 -> s2 -> s3 A, every record 300 s.
	resp, err := imr.Query(ctx, "s1."+sigChainZone, dns.TypeA, dns.ClassINET)
	if err != nil || resp == nil || resp.RRset == nil {
		t.Fatalf("s1 A: %v, %v", resp, err)
	}
	if left := time.Until(resp.ChainExpiration); left <= 0 || left > 300*time.Second {
		t.Errorf("s1 A over the wire: chain expires in %v, want within the links' 300 s", left)
	}
	// Asked for the data's own name, no chain is followed.
	direct, err := imr.Query(ctx, "s3."+sigChainZone, dns.TypeA, dns.ClassINET)
	if err != nil || direct == nil {
		t.Fatalf("s3 A: %v, %v", direct, err)
	}
	if !direct.ChainExpiration.IsZero() {
		t.Errorf("s3 A: chain expiry %v; want none", direct.ChainExpiration)
	}

	// The cache path: c1 -> c2 A, the link for a minute, the data for an hour.
	c1, c2, c3 := "c1."+sigChainZone, "c2."+sigChainZone, "c3."+sigChainZone
	put := func(name string, rr dns.RR, ttl time.Duration) {
		imr.Cache.Set(name, rr.Header().Rrtype, &cache.CachedRRset{Name: name, RRtype: rr.Header().Rrtype,
			Context: cache.ContextAnswer, State: cache.ValidationStateSecure, Ttl: uint32(ttl / time.Second),
			Expiration: time.Now().Add(ttl), RRset: &core.RRset{Name: name, Class: dns.ClassINET,
				RRtype: rr.Header().Rrtype, RRs: []dns.RR{rr}}})
	}
	put(c1, mustRR(t, c1+` 60 IN CNAME `+c2), time.Minute)
	put(c2, mustRR(t, c2+` 3600 IN A 192.0.2.62`), time.Hour)
	resp, err = imr.Query(ctx, c1, dns.TypeA, dns.ClassINET)
	if err != nil || resp == nil || resp.RRset == nil || !core.EqualNames(resp.RRset.Name, c2) {
		t.Fatalf("c1 A: %v, %v", resp, err)
	}
	if left := time.Until(resp.ChainExpiration); left <= 50*time.Second || left > time.Minute {
		t.Errorf("c1 A from the cache: chain expires in %v, want the link's minute", left)
	}

	// The link now leads elsewhere, for an hour. The address c1 led to still
	// runs out with the old link.
	put(c1, mustRR(t, c1+` 3600 IN CNAME `+c3), time.Hour)
	put(c3, mustRR(t, c3+` 3600 IN A 192.0.2.63`), time.Hour)
	exp := imr.addrsExpiry(c1, dns.TypeA, resp)
	if left := time.Until(exp); left <= 50*time.Second || left > time.Minute {
		t.Errorf("after the link changed target: the old address expires in %v, want the old link's minute", left)
	}
}

// A link the cache keeps for less than its TTL (cache-max-ttl) carries the
// cache's lifetime, not its TTL: the address it led to does not outlive the
// cached link (CodeRabbit on #1055).
func TestImrQueryChainExpiryHonoursCacheMaxTTL(t *testing.T) {
	prev := cache.GetTTLLimits()
	t.Cleanup(func() { cache.SetTTLLimits(prev) })
	cache.SetTTLLimits(cache.TTLLimits{Max: 60})

	imr, _ := sigChainImr(t)
	// s1 -> s2 -> s3 A, every record 300 s, kept for 60.
	resp, err := imr.Query(context.Background(), "s1."+sigChainZone, dns.TypeA, dns.ClassINET)
	if err != nil || resp == nil || resp.RRset == nil {
		t.Fatalf("s1 A: %v, %v", resp, err)
	}
	if left := time.Until(resp.ChainExpiration); left <= 0 || left > 60*time.Second {
		t.Errorf("chain expires in %v, want within cache-max-ttl's 60 s", left)
	}
	if link := imr.Cache.Peek("s1."+sigChainZone, dns.TypeCNAME); link == nil || resp.ChainExpiration.After(link.Expiration) {
		t.Errorf("chain expiry %v outlives the cached link %+v", resp.ChainExpiration, link)
	}
}

// On a chain read from the cache, the addresses run out with their own cache
// entry, not a full TTL from now: here the entry is kept for 60 s
// (cache-max-ttl) while its records say an hour, and the link lasts an hour
// (CodeRabbit on #1055).
func TestAddrsExpiryOnACachedChainUsesTheAddressEntry(t *testing.T) {
	imr, _ := sigChainImr(t)
	c1, c2 := "c1."+sigChainZone, "c2."+sigChainZone
	put := func(name string, rr dns.RR) {
		imr.Cache.Set(name, rr.Header().Rrtype, &cache.CachedRRset{Name: name, RRtype: rr.Header().Rrtype,
			Context: cache.ContextAnswer, State: cache.ValidationStateSecure, RRset: &core.RRset{Name: name,
				Class: dns.ClassINET, RRtype: rr.Header().Rrtype, RRs: []dns.RR{rr}}})
	}
	put(c1, mustRR(t, c1+` 3600 IN CNAME `+c2))
	prev := cache.GetTTLLimits()
	t.Cleanup(func() { cache.SetTTLLimits(prev) })
	cache.SetTTLLimits(cache.TTLLimits{Max: 60})
	put(c2, mustRR(t, c2+` 3600 IN A 192.0.2.62`))
	cache.SetTTLLimits(prev)

	resp, err := imr.Query(context.Background(), c1, dns.TypeA, dns.ClassINET)
	if err != nil || resp == nil || resp.RRset == nil || !core.EqualNames(resp.RRset.Name, c2) {
		t.Fatalf("c1 A: %v, %v", resp, err)
	}
	if left := time.Until(resp.ChainExpiration); left <= 50*time.Minute {
		t.Fatalf("chain expires in %v, want the link's hour", left)
	}
	if left := time.Until(imr.addrsExpiry(c1, dns.TypeA, resp)); left <= 0 || left > 60*time.Second {
		t.Errorf("the address expires in %v, want within its entry's 60 s", left)
	}
}

// udp and tcp go to a target like any transport, each to its own endpoint;
// the do53 shorthand in a record with a target is dropped (section 2).
func TestOOTSUDPAndTCPRedirected(t *testing.T) {
	const tcpTarget = "tcp-ns." + stateZone
	recs := []ootsRecord{
		ootsRecordOf(t, pathOwner+` 3600 IN SVCB 1 `+dotTarget+` port=5353 oots="udp:100,do53:7"`),
		ootsRecordOf(t, pathOwner+` 3600 IN SVCB 1 `+tcpTarget+` oots="tcp:30"`),
	}
	raw, ports, targets := combineOOTSEndpoints(recs)
	if _, ok := raw["do53"]; ok {
		t.Errorf("do53 taken from a record with a target: %v", raw)
	}
	if raw["udp"] != 100 || raw["tcp"] != 30 {
		t.Errorf("weights %v, want udp:100 and tcp:30", raw)
	}
	if targets[core.TransportDo53] != dotTarget || targets[core.TransportDo53TCP] != tcpTarget {
		t.Errorf("targets %v, want udp to %s and tcp to %s", targets, dotTarget, tcpTarget)
	}
	if ports[core.TransportDo53] != 5353 || ports[core.TransportDo53TCP] != 0 {
		t.Errorf("ports %v, want udp:5353 only", ports)
	}
	server := cache.NewAuthServer(pathNS)
	installTransportMap(server, raw, ports, targets, cache.SignalViaLookup,
		[]cache.SignalHop{{Owner: pathOwner, State: cache.ValidationStateSecure}})
	if ep := server.GetTransportEndpoint(core.TransportDo53); ep.Target != dotTarget || ep.Port != 5353 {
		t.Errorf("udp endpoint %v", ep)
	}
	if ep := server.GetTransportEndpoint(core.TransportDo53TCP); ep.Target != tcpTarget || ep.Port != 0 {
		t.Errorf("tcp endpoint %v", ep)
	}
}

// A udp endpoint with no usable address gives way to the nameserver's own
// address on port 53, the one the delegation guarantees; DoT has no such
// fallback, and its attempt is not made.
func TestEndpointFallsBackToPort53(t *testing.T) {
	imr := newTestImr(t)
	server := cache.NewAuthServer(pathNS)
	installTransportMap(server, map[string]uint8{"udp": 100, "dot": 30},
		map[core.Transport]uint16{core.TransportDo53: 5353, core.TransportDoT: 1234},
		map[core.Transport]string{core.TransportDo53: dotTarget, core.TransportDoT: dotTarget}, cache.SignalViaLookup,
		[]cache.SignalHop{{Owner: pathOwner, State: cache.ValidationStateSecure}})
	imr.endpointAddrs.set(dotTarget, []string{"192.0.2.53"}, time.Now().Add(time.Hour))
	server.RecordEndpointAddrFailure("192.0.2.53", 5353, core.TransportDo53, nil)
	server.RecordEndpointAddrFailure("192.0.2.53", 1234, core.TransportDoT, nil)
	ctx := context.Background()

	d, err := imr.endpointFor(ctx, server, "192.0.2.1", core.TransportDo53)
	if err != nil || d.addr != "192.0.2.1" || d.port != 0 || d.keyPort != 0 || d.redirect {
		t.Errorf("udp: %+v %v, want the nameserver on port 53", d, err)
	}
	if _, err := imr.endpointFor(ctx, server, "192.0.2.1", core.TransportDoT); err == nil {
		t.Error("DoT: an attempt with every target address backed off")
	}

	// At the server's own name: the udp port backed off, port 53 is used.
	self := cache.NewAuthServer(pathNS)
	applyTransportMapWithPorts(self, map[string]uint8{"udp": 100}, map[core.Transport]uint16{core.TransportDo53: 5353})
	if d, _ := imr.endpointFor(ctx, self, "192.0.2.1", core.TransportDo53); d.port != 5353 || d.keyPort != 5353 {
		t.Errorf("udp endpoint usable: %+v, want port 5353", d)
	}
	self.RecordEndpointAddrFailure("192.0.2.1", 5353, core.TransportDo53, nil)
	if d, _ := imr.endpointFor(ctx, self, "192.0.2.1", core.TransportDo53); d.port != 0 || d.keyPort != 0 {
		t.Errorf("udp endpoint backed off: %+v, want port 53", d)
	}
}
