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

// With use-transport-signals: false an answer for _dns.<ns> SVCB is an answer
// like any other: it installs no signal on the nameserver's servers.
func TestASignalAnswerInstallsNothingWithSignalsOff(t *testing.T) {
	imr := newTestImr(t)
	imr.Quiet = true
	if imr.Options == nil {
		imr.Options = map[ImrOption]string{}
	}
	imr.Options[ImrOptUseTransportSignals] = "false"
	server := cache.NewAuthServer(pathNS)
	imr.Cache.ServerMap.Set(stateZone, map[string]*cache.AuthServer{cache.ServerKey(pathNS): server})
	rrset := svcbRRset(pathOwner, []dns.RR{mustRR(t, pathOwner+` 3600 IN SVCB 1 . oots="dot:100"`)})

	imr.applyTransportRRsetFromAnswer(pathOwner, rrset, cache.ValidationStateSecure)

	if w := server.GetTransportWeights(); len(w) != 0 {
		t.Errorf("the answer installed weights %v with signals off", w)
	}
}

// A stub's configured transports are the operator's: neither an answer for
// _dns.<ns> nor a signal in an Additional section replaces them, while the
// shared instance of the same name takes the answer.
func TestASignalKeepsAStubsConfiguredTransports(t *testing.T) {
	const zone = "stubsig.example."
	const ns = "ns." + zone
	owner := transportOwnerForNS(ns)
	imr := newTestImr(t)
	imr.Quiet = true
	if err := imr.Cache.AddStub(zone, []cache.AuthServer{
		{Name: ns, Addrs: []string{"192.0.2.1"}, TransportSignal: "doq:100"},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	imr.setZoneTable(nil, []string{zone}, nil)
	stubs := imr.stubServers(zone)
	if len(stubs) != 1 {
		t.Fatalf("stub servers %v", stubs)
	}
	stub := stubs[0]
	shared := cache.NewAuthServer(ns)
	imr.Cache.ServerMap.Set("other.example.", map[string]*cache.AuthServer{cache.ServerKey(ns): shared})
	svcb := mustRR(t, owner+` 3600 IN SVCB 1 . oots="dot:100"`)

	imr.applyTransportRRsetFromAnswer(owner, svcbRRset(owner, []dns.RR{svcb}), cache.ValidationStateSecure)
	set := &svcbSignalSet{}
	set.add(svcb.(*dns.SVCB))
	set.via = cache.SignalViaResponse
	set.path = []cache.SignalHop{{Owner: owner, State: cache.ValidationStateSecure}}
	imr.applySVCBSignalSet(context.Background(), stub, set)

	if w := stub.GetTransportWeights(); w[core.TransportDoQ] != 100 || w[core.TransportDoT] != 0 {
		t.Errorf("stub weights %v, want its configured doq:100", w)
	}
	if rec := stub.GetReceivedSignal(); rec == nil || rec.Source != cache.SignalSourceConfig {
		t.Errorf("stub signal %+v, want the configured one", rec)
	}
	if w := shared.GetTransportWeights(); w[core.TransportDoT] != 100 {
		t.Errorf("shared instance weights %v, want the answer's dot:100", w)
	}
}

// Replaying the cached signal onto the server a query holds leaves alone a
// server of that name that holds a signal installed since, from a newer
// answer: only a server that still needs a signal takes the cached one.
func TestACachedSignalReplayLeavesANewerSignalInPlace(t *testing.T) {
	imr := newTestImr(t)
	imr.Quiet = true
	cacheSignal(imr, pathOwner, []dns.RR{mustRR(t, pathOwner+` 3600 IN SVCB 1 . oots="dot:100"`)}, cache.ValidationStateSecure)
	listed := cache.NewAuthServer(pathNS)
	installTransportMap(listed, map[string]uint8{"doq": 100}, nil, nil, cache.SignalViaLookup,
		[]cache.SignalHop{{Owner: pathOwner, State: cache.ValidationStateSecure}}, notConfigured)
	imr.Cache.ServerMap.Set(stateZone, map[string]*cache.AuthServer{cache.ServerKey(pathNS): listed})
	held := cache.NewAuthServer(pathNS)

	if c := imr.applyCachedTransportSignal(aliasWalk{}, pathOwner, held); !c.signal {
		t.Errorf("replay reported %+v, want a signal", c)
	}
	if w := held.GetTransportWeights(); w[core.TransportDoT] != 100 {
		t.Errorf("held server weights %v, want the cached dot:100", w)
	}
	if w := listed.GetTransportWeights(); w[core.TransportDoQ] != 100 || w[core.TransportDoT] != 0 {
		t.Errorf("listed server weights %v, want its newer doq:100 kept", w)
	}
}

// A strict query whose server's cached signal is an alias whose hop is not
// cached waits for the hop's lookup, and then uses the signal the alias leads
// to, though its server is in no zone map for the hop's end to reach.
func TestAStrictWaitFollowsACachedAliasWhoseHopIsBeingLookedUp(t *testing.T) {
	imr, _, _ := aliasHopImr(t)
	imr.Tuning.Discovery.StrictWait = 5 * time.Second
	held := cache.NewAuthServer(pathNS)
	serverMap := map[string]*cache.AuthServer{cache.ServerKey(pathNS): held}
	found := foundProvider(t)
	release := make(chan struct{})
	signalAliasHopLookupHook = func(_ context.Context, imr *Imr, target string) (*ImrResponse, error) {
		<-release
		return found(imr, target)
	}
	t.Cleanup(func() {
		signalAliasHopLookupHook = nil
	})
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(release)
	}()
	ready := func() bool { return held.GetTransportWeights()[core.TransportDoQ] > 0 }

	if !imr.awaitTransportSignalsUntil(context.Background(), serverMap, transportQueryReasonStrictPrivacy, ready) {
		t.Errorf("the wait ended without the alias's signal: weights %v", held.GetTransportWeights())
	}
	waitAliasHopsEnded(t, imr)
}

// A strict query whose server holds a signal that came with a redirect the
// Additional section could not validate, leaving it nothing the query may
// use, waits for the lookup that verifies it, and takes what that lookup
// found, though its server is in no zone map for the lookup to reach.
func TestAStrictWaitJoinsTheLookupVerifyingARedirect(t *testing.T) {
	imr, _, _ := newStrictTestImr(t, 5*time.Second)
	held := cache.NewAuthServer(strictChildNS)
	held.AddAddr("192.0.2.54")
	installTransportMap(held, map[string]uint8{"udp": 100}, nil, nil, cache.SignalViaReferral,
		[]cache.SignalHop{{Owner: strictChildOwner, State: cache.SignalStateUnknown}}, notConfigured)
	serverMap := map[string]*cache.AuthServer{cache.ServerKey(strictChildNS): held}
	if !imr.TransportSignalDiscovery.Begin(strictChildOwner) {
		t.Fatal("setup: could not mark the verifying lookup as running")
	}
	verified := []dns.RR{mustRR(t, strictChildOwner+` 3600 IN SVCB 1 . oots="dot:100"`)}
	go func() {
		time.Sleep(50 * time.Millisecond)
		cacheSignal(imr, strictChildOwner, verified, cache.ValidationStateSecure)
		imr.TransportSignalDiscovery.Succeed(strictChildOwner)
	}()

	if !imr.awaitTransportSignals(context.Background(), "www."+strictChildZone, serverMap) {
		t.Errorf("the wait ended without the verified signal: weights %v", held.GetTransportWeights())
	}
}
