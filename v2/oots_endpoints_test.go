/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
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
		imr.Quiet = true
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
	imr.Quiet = true
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

	if _, _, _, err := imr.tryServer(ctx, server, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone); err != nil {
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

	if _, _, _, err := imr.tryServer(ctx, server, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone); err != nil {
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

	if _, _, _, err := imr.tryServer(ctx, server, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone); err == nil {
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
	if _, _, _, err := imr.tryServer(ctx, server, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone); err != nil {
		t.Fatalf("second attempt: %v", err)
	}
	if got := lastDial(dot); got != "[2001:db8::53]:1234" {
		t.Errorf("second dial %q, want the target's other address", got)
	}

	server.RecordEndpointAddrFailure("2001:db8::53", 1234, core.TransportDoT, nil)
	n := len(dot.Calls())
	_, _, _, err := imr.tryServer(ctx, server, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone)
	if _, ok := err.(errEndpointUnavailable); !ok {
		t.Errorf("every target address backed off: err %v, want errEndpointUnavailable", err)
	}
	if len(dot.Calls()) != n {
		t.Errorf("an attempt was dialed with every target address backed off")
	}
	if _, _, _, err := imr.tryServer(ctx, server, "192.0.2.1", core.TransportDo53, q, "example.", dns.TypeA, false, cache.ClassNone); err != nil {
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
	if _, _, _, err := imr.tryServer(ctx, server, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone); err != nil {
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

// stats auth-transports shows where a validated signal sent each transport,
// the answers a target carried, and the redirects ignored.
func TestAuthTransportsReportRedirects(t *testing.T) {
	imr := newTestImr(t)
	server := imr.Cache.GetOrCreateAuthServer(pathNS)
	installTransportMap(server, map[string]uint8{"dot": 30}, nil, map[core.Transport]string{core.TransportDoT: dotTarget},
		cache.SignalViaLookup, []cache.SignalHop{{Owner: pathOwner, State: cache.ValidationStateSecure}})
	server.IncrementUsedCounter(core.TransportDoT, cache.ClassNone)
	server.IncrementRedirectedCounter(core.TransportDoT)
	server.AddIgnoredRedirects(3)
	report := ImrAuthTransportsSnapshot(imr.Cache, []string{pathNS}, "", false)
	if len(report.Rows) != 1 {
		t.Fatalf("rows %d, want 1", len(report.Rows))
	}
	row := report.Rows[0]
	if row.SignalTargets["dot"] != dotTarget || row.Redirected["dot"] != 1 || row.IgnoredRedirects != 3 {
		t.Errorf("targets %v, redirected %v, ignored %d", row.SignalTargets, row.Redirected, row.IgnoredRedirects)
	}
}
