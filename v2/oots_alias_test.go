/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const providerDoT = "dot.provider.example."

// providerRecords is the signal a provider publishes at its own name and
// customers alias to: DoT on another host, DoQ on the nameserver itself.
func providerRecords(t *testing.T) []dns.RR {
	return []dns.RR{
		mustRR(t, providerOwner+` 3600 IN SVCB 1 `+providerDoT+` port=1234 oots="dot:30"`),
		mustRR(t, providerOwner+` 3600 IN SVCB 1 . oots="doq:20"`),
	}
}

// Through an alias in the Additional section the nameserver takes the
// provider's signal. A target at the end of the path is honoured only when
// every hop validated Secure (R5); the provider's records with TargetName "."
// are inherited whatever the state (R4).
func TestOOTSAliasAdditionalR5(t *testing.T) {
	dkc := signerTestDnskeyCache(t)
	kid := newSignerTestKey(t, stateZone, 256)
	kid.holdSecure(dkc)
	provider := newSignerTestKey(t, providerZone, 256)
	provider.holdSecure(dkc)
	alias := mustRR(t, pathOwner+` 3600 IN SVCB 0 `+providerOwner)
	target := providerRecords(t)
	aliasSig := kid.sign(t, dns.Copy(alias)).RRSIGs
	targetSig := provider.sign(t, copyRRs(target)...).RRSIGs

	for _, tc := range []struct {
		name     string
		section  []dns.RR
		redirect bool
		awaits   bool
	}{
		{"every hop secure", append(append(append([]dns.RR{alias}, aliasSig...), target...), targetSig...), true, false},
		{"the alias unsigned", append(append([]dns.RR{alias}, target...), targetSig...), false, true},
		{"the target unsigned", append(append([]dns.RR{alias}, aliasSig...), target...), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			imr := newTestImr(t)
			imr.Quiet = true
			set := &svcbSignalSet{}
			for _, rr := range svcbAt(tc.section, pathOwner) {
				set.add(rr.(*dns.SVCB))
			}
			imr.decideAdditionalPath(set, tc.section, cache.SignalViaResponse)
			server := cache.NewAuthServer(pathNS)
			if installed, _ := imr.installSVCBSignal(server, set); !installed {
				t.Fatal("nothing installed through the alias")
			}
			rec := server.GetReceivedSignal()
			if len(rec.Path) != 2 || rec.Path[1].Owner != providerOwner {
				t.Errorf("path %s, want the alias and the provider's RRset", cache.FormatSignalPath(rec.Path))
			}
			if rec.Weights[core.TransportDoQ] != 20 {
				t.Errorf("DoQ weight %d, want 20 from the provider's \".\" record", rec.Weights[core.TransportDoQ])
			}
			ep := server.GetTransportEndpoint(core.TransportDoT)
			if tc.redirect != (ep.Target == providerDoT) {
				t.Errorf("DoT endpoint %v, redirect wanted: %v", ep, tc.redirect)
			}
			if set.awaitsLookup != tc.awaits {
				t.Errorf("awaits lookup %v, want %v", set.awaitsLookup, tc.awaits)
			}
		})
	}
}

// An alias whose target is "." says the service is not available
// (RFC 9460 section 2.5.1), and one whose path ends at another alias to "."
// says the same: nothing is installed.
func TestOOTSAliasToNothing(t *testing.T) {
	for _, section := range [][]dns.RR{
		{mustRR(t, pathOwner+` 3600 IN SVCB 0 .`)},
		{mustRR(t, pathOwner+` 3600 IN SVCB 0 `+providerOwner), mustRR(t, providerOwner+` 3600 IN SVCB 0 .`)},
	} {
		imr := newTestImr(t)
		imr.Quiet = true
		set := &svcbSignalSet{}
		for _, rr := range svcbAt(section, pathOwner) {
			set.add(rr.(*dns.SVCB))
		}
		imr.decideAdditionalPath(set, section, cache.SignalViaResponse)
		if installed, _ := imr.installSVCBSignal(cache.NewAuthServer(pathNS), set); installed {
			t.Errorf("%v: installed", section)
		}
	}
}

// cacheSignal puts an SVCB RRset in the cache as the lookup of its owner would
// have left it, with that lookup's verdict.
func cacheSignal(imr *Imr, owner string, rrs []dns.RR, state cache.ValidationState) {
	imr.Cache.Set(owner, dns.TypeSVCB, &cache.CachedRRset{
		Name: owner, RRtype: dns.TypeSVCB, Context: cache.ContextAnswer,
		RRset: &core.RRset{Name: owner, Class: dns.ClassINET, RRtype: dns.TypeSVCB, RRs: copyRRs(rrs)},
		State: state, Expiration: time.Now().Add(time.Hour),
	})
}

// The lookup path follows the alias through the cache: each hop with the
// verdict of the lookup that brought it, R5 deciding the target at the end.
func TestOOTSAliasLookupFromCache(t *testing.T) {
	alias := []dns.RR{mustRR(t, pathOwner+` 3600 IN SVCB 0 `+providerOwner)}
	for _, tc := range []struct {
		name     string
		hop      cache.ValidationState
		redirect bool
	}{
		{"provider secure", cache.ValidationStateSecure, true},
		{"provider insecure", cache.ValidationStateInsecure, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			imr := newTestImr(t)
			imr.Quiet = true
			cacheSignal(imr, providerOwner, providerRecords(t), tc.hop)
			server := cache.NewAuthServer(pathNS)
			imr.Cache.ServerMap.Set(stateZone, map[string]*cache.AuthServer{cache.ServerKey(pathNS): server})
			imr.applyTransportRRsetFromAnswer(pathOwner, &core.RRset{Name: pathOwner, RRtype: dns.TypeSVCB, RRs: copyRRs(alias)},
				cache.ValidationStateSecure)
			rec := server.GetReceivedSignal()
			if rec == nil {
				t.Fatal("nothing installed through the alias")
			}
			wantPath := []cache.SignalHop{{Owner: pathOwner, State: cache.ValidationStateSecure}, {Owner: providerOwner, State: tc.hop}}
			if got, want := cache.FormatSignalPath(rec.Path), cache.FormatSignalPath(wantPath); got != want {
				t.Errorf("path %q, want %q", got, want)
			}
			if rec.Via != cache.SignalViaLookup || rec.Weights[core.TransportDoQ] != 20 {
				t.Errorf("via %q, DoQ weight %d", rec.Via, rec.Weights[core.TransportDoQ])
			}
			if ep := server.GetTransportEndpoint(core.TransportDoT); tc.redirect != (ep.Target == providerDoT) {
				t.Errorf("DoT endpoint %v, redirect wanted: %v", ep, tc.redirect)
			}
		})
	}
}

// A hop the cache does not hold is looked up off the query path, and when
// that lookup has filled the cache, the alias is followed again and the
// signal installed.
func TestOOTSAliasLookupFetchesHop(t *testing.T) {
	imr := newTestImr(t)
	imr.Quiet = true
	imr.TransportSignalDiscovery = cache.NewDiscoveryTracker(time.Minute, 3)
	alias := []dns.RR{mustRR(t, pathOwner+` 3600 IN SVCB 0 `+providerOwner)}
	cacheSignal(imr, pathOwner, alias, cache.ValidationStateSecure)
	server := cache.NewAuthServer(pathNS)
	imr.Cache.ServerMap.Set(stateZone, map[string]*cache.AuthServer{cache.ServerKey(pathNS): server})

	fetched := make(chan string, 1)
	release := make(chan struct{})
	saved := signalAliasHopLookupHook
	signalAliasHopLookupHook = func(_ context.Context, imr *Imr, target string) (*ImrResponse, error) {
		<-release
		cacheSignal(imr, target, providerRecords(t), cache.ValidationStateSecure)
		fetched <- target
		rrset := imr.Cache.Get(target, dns.TypeSVCB).RRset
		return &ImrResponse{RRset: rrset, ValidationState: cache.ValidationStateSecure}, nil
	}
	t.Cleanup(func() { signalAliasHopLookupHook = saved })

	imr.applyTransportRRsetFromAnswer(pathOwner, &core.RRset{Name: pathOwner, RRtype: dns.TypeSVCB, RRs: copyRRs(alias)},
		cache.ValidationStateSecure)
	if server.GetReceivedSignal() != nil {
		t.Fatal("installed before the hop was looked up")
	}
	close(release)
	select {
	case got := <-fetched:
		if got != providerOwner {
			t.Errorf("looked up %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the hop was not looked up")
	}
	deadline := time.Now().Add(5 * time.Second)
	for server.GetTransportEndpoint(core.TransportDoT).Target != providerDoT {
		if time.Now().After(deadline) {
			t.Fatalf("not installed after the hop's lookup: %+v", server.GetReceivedSignal())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A loop through the cache, or a path longer than the cap, installs nothing
// and looks nothing up.
func TestOOTSAliasLookupLoopAndCap(t *testing.T) {
	imr := newTestImr(t)
	imr.Quiet = true
	saved := signalAliasHopLookupHook
	signalAliasHopLookupHook = func(context.Context, *Imr, string) (*ImrResponse, error) {
		t.Error("a hop was looked up")
		return nil, nil
	}
	t.Cleanup(func() { signalAliasHopLookupHook = saved })
	imr.TransportSignalDiscovery = cache.NewDiscoveryTracker(time.Minute, 3)

	cacheSignal(imr, providerOwner, []dns.RR{mustRR(t, providerOwner+` 3600 IN SVCB 0 `+pathOwner)}, cache.ValidationStateSecure)
	server := cache.NewAuthServer(pathNS)
	imr.Cache.ServerMap.Set(stateZone, map[string]*cache.AuthServer{cache.ServerKey(pathNS): server})
	imr.applyTransportRRsetFromAnswer(pathOwner, &core.RRset{Name: pathOwner, RRtype: dns.TypeSVCB,
		RRs: []dns.RR{mustRR(t, pathOwner+` 3600 IN SVCB 0 `+providerOwner)}}, cache.ValidationStateSecure)
	if server.GetReceivedSignal() != nil {
		t.Errorf("a loop installed a signal")
	}

	prev := pathOwner
	var first []dns.RR
	for i := 1; i <= 4; i++ {
		next := "_dns.ns.c" + string(rune('0'+i)) + ".example."
		rr := mustRR(t, prev+` 3600 IN SVCB 0 `+next)
		if i == 1 {
			first = []dns.RR{rr}
		} else {
			cacheSignal(imr, prev, []dns.RR{rr}, cache.ValidationStateSecure)
		}
		prev = next
	}
	cacheSignal(imr, prev, providerRecords(t), cache.ValidationStateSecure)
	imr.applyTransportRRsetFromAnswer(pathOwner, &core.RRset{Name: pathOwner, RRtype: dns.TypeSVCB, RRs: first},
		cache.ValidationStateSecure)
	if server.GetReceivedSignal() != nil {
		t.Errorf("a path longer than the cap installed a signal")
	}
}

// A hop that is denied, with the denial not cached under the question, is not
// followed again at once: one lookup, not a loop of them. The next query that
// brings the owner's RRset after signalAliasHopRetry looks again.
func TestOOTSAliasDeniedHopNotRefollowed(t *testing.T) {
	imr := newTestImr(t)
	imr.Quiet = true
	imr.signalAliasHops.retry = 300 * time.Millisecond
	imr.TransportSignalDiscovery = cache.NewDiscoveryTracker(time.Minute, 3)
	alias := []dns.RR{mustRR(t, pathOwner+` 3600 IN SVCB 0 `+providerOwner)}
	cacheSignal(imr, pathOwner, alias, cache.ValidationStateSecure)
	server := cache.NewAuthServer(pathNS)
	imr.Cache.ServerMap.Set(stateZone, map[string]*cache.AuthServer{cache.ServerKey(pathNS): server})

	var calls atomic.Int32
	first := make(chan struct{}, 1)
	saved := signalAliasHopLookupHook
	signalAliasHopLookupHook = func(context.Context, *Imr, string) (*ImrResponse, error) {
		if calls.Add(1) == 1 {
			first <- struct{}{}
		}
		return &ImrResponse{Denial: cache.ContextNXDOMAIN}, nil
	}
	t.Cleanup(func() { signalAliasHopLookupHook = saved })

	apply := func() {
		imr.applyTransportRRsetFromAnswer(pathOwner, &core.RRset{Name: pathOwner, RRtype: dns.TypeSVCB, RRs: copyRRs(alias)},
			cache.ValidationStateSecure)
	}
	apply()
	select {
	case <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("the hop was not looked up")
	}
	until := aliasHopRetryAt(t, imr, providerOwner)
	time.Sleep(100 * time.Millisecond)
	if n := calls.Load(); n != 1 {
		t.Fatalf("%d lookups after one denial, want 1", n)
	}
	time.Sleep(time.Until(until) + 20*time.Millisecond)
	apply()
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the next query did not look the hop up again")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// aliasHopRetryAt waits until the lookup of target has ended, and returns when
// target may be looked up again. The hook that answers the lookup returns
// before the tracker records its end, so a test must not count from the hook.
func aliasHopRetryAt(t *testing.T, imr *Imr, target string) time.Time {
	t.Helper()
	key := core.CanonicalizeName(target)
	deadline := time.Now().Add(5 * time.Second)
	for {
		imr.signalAliasHops.mu.Lock()
		_, inFlight := imr.signalAliasHops.waiting[key]
		at := imr.signalAliasHops.next[key]
		imr.signalAliasHops.mu.Unlock()
		if !inFlight && !at.IsZero() {
			return at
		}
		if time.Now().After(deadline) {
			t.Fatalf("the lookup of %s did not end", target)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// hookAliasHop stands in for the lookups of alias hops for one test: answer
// fills the cache for the target and returns what the lookup would. It
// returns the count of lookups made.
func hookAliasHop(t *testing.T, answer func(imr *Imr, target string) (*ImrResponse, error)) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	saved := signalAliasHopLookupHook
	signalAliasHopLookupHook = func(_ context.Context, imr *Imr, target string) (*ImrResponse, error) {
		calls.Add(1)
		return answer(imr, target)
	}
	t.Cleanup(func() { signalAliasHopLookupHook = saved })
	return &calls
}

// waitRedirect waits until server's DoT goes to the provider's target.
func waitRedirect(t *testing.T, server *cache.AuthServer, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for server.GetTransportEndpoint(core.TransportDoT).Target != providerDoT {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not installed: %+v", what, server.GetReceivedSignal())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Many nameservers' aliases lead to one provider's signal. One lookup of the
// provider's hop serves them all: an owner whose alias reaches the hop while
// its lookup is in flight waits for it, and is followed again when it ends
// (CodeRabbit on #1056).
func TestOOTSAliasSharedHopServesEveryOwner(t *testing.T) {
	imr := newTestImr(t)
	imr.Quiet = true
	imr.TransportSignalDiscovery = cache.NewDiscoveryTracker(time.Minute, 3)
	const ns2 = "ns2.kid.p.test."
	owner2 := "_dns." + ns2
	alias1 := []dns.RR{mustRR(t, pathOwner+` 3600 IN SVCB 0 `+providerOwner)}
	alias2 := []dns.RR{mustRR(t, owner2+` 3600 IN SVCB 0 `+providerOwner)}
	cacheSignal(imr, pathOwner, alias1, cache.ValidationStateSecure)
	cacheSignal(imr, owner2, alias2, cache.ValidationStateSecure)
	s1, s2 := cache.NewAuthServer(pathNS), cache.NewAuthServer(ns2)
	imr.Cache.ServerMap.Set(stateZone, map[string]*cache.AuthServer{cache.ServerKey(pathNS): s1, cache.ServerKey(ns2): s2})

	release := make(chan struct{})
	calls := hookAliasHop(t, func(imr *Imr, target string) (*ImrResponse, error) {
		<-release
		cacheSignal(imr, target, providerRecords(t), cache.ValidationStateSecure)
		return &ImrResponse{RRset: imr.Cache.Get(target, dns.TypeSVCB).RRset, ValidationState: cache.ValidationStateSecure}, nil
	})
	imr.applyTransportRRsetFromAnswer(pathOwner, &core.RRset{Name: pathOwner, RRtype: dns.TypeSVCB, RRs: copyRRs(alias1)},
		cache.ValidationStateSecure)
	imr.applyTransportRRsetFromAnswer(owner2, &core.RRset{Name: owner2, RRtype: dns.TypeSVCB, RRs: copyRRs(alias2)},
		cache.ValidationStateSecure)
	close(release)
	waitRedirect(t, s1, "the first owner")
	waitRedirect(t, s2, "the owner that waited")
	if n := calls.Load(); n != 1 {
		t.Errorf("%d lookups of the shared hop, want 1", n)
	}
}

// A hop that is a CNAME is read through its chain, as the lookup of
// <hop, SVCB> follows and caches it: the alias is installed after one lookup,
// not looked up again and again. The hop is held in the weakest state of the
// link and the RRset it leads to (R5) (CodeRabbit on #1056).
func TestOOTSAliasHopThroughACNAME(t *testing.T) {
	for _, tc := range []struct {
		name     string
		link     cache.ValidationState
		redirect bool
	}{
		{"link secure", cache.ValidationStateSecure, true},
		{"link insecure", cache.ValidationStateInsecure, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			imr := newTestImr(t)
			imr.Quiet = true
			imr.TransportSignalDiscovery = cache.NewDiscoveryTracker(time.Minute, 3)
			const elsewhere = "_dns.ns.elsewhere.example."
			alias := []dns.RR{mustRR(t, pathOwner+` 3600 IN SVCB 0 `+providerOwner)}
			cacheSignal(imr, pathOwner, alias, cache.ValidationStateSecure)
			server := cache.NewAuthServer(pathNS)
			imr.Cache.ServerMap.Set(stateZone, map[string]*cache.AuthServer{cache.ServerKey(pathNS): server})

			calls := hookAliasHop(t, func(imr *Imr, target string) (*ImrResponse, error) {
				link := mustRR(t, target+` 3600 IN CNAME `+elsewhere)
				imr.Cache.Set(target, dns.TypeCNAME, &cache.CachedRRset{Name: target, RRtype: dns.TypeCNAME,
					Context: cache.ContextAnswer, State: tc.link, Expiration: time.Now().Add(time.Hour),
					RRset: &core.RRset{Name: target, Class: dns.ClassINET, RRtype: dns.TypeCNAME, RRs: []dns.RR{link}}})
				recs := []dns.RR{
					mustRR(t, elsewhere+` 3600 IN SVCB 1 `+providerDoT+` port=1234 oots="dot:30"`),
					mustRR(t, elsewhere+` 3600 IN SVCB 1 . oots="doq:20"`),
				}
				cacheSignal(imr, elsewhere, recs, cache.ValidationStateSecure)
				return &ImrResponse{RRset: imr.Cache.Get(elsewhere, dns.TypeSVCB).RRset, ValidationState: tc.link}, nil
			})
			imr.applyTransportRRsetFromAnswer(pathOwner, &core.RRset{Name: pathOwner, RRtype: dns.TypeSVCB, RRs: copyRRs(alias)},
				cache.ValidationStateSecure)
			deadline := time.Now().Add(5 * time.Second)
			for server.GetReceivedSignal() == nil {
				if time.Now().After(deadline) {
					t.Fatal("nothing installed through the CNAME'd hop")
				}
				time.Sleep(10 * time.Millisecond)
			}
			rec := server.GetReceivedSignal()
			if rec.Weights[core.TransportDoQ] != 20 {
				t.Errorf("DoQ weight %d, want 20", rec.Weights[core.TransportDoQ])
			}
			if ep := server.GetTransportEndpoint(core.TransportDoT); tc.redirect != (ep.Target == providerDoT) {
				t.Errorf("DoT endpoint %v, redirect wanted: %v (path %s)", ep, tc.redirect, cache.FormatSignalPath(rec.Path))
			}
			time.Sleep(100 * time.Millisecond)
			if n := calls.Load(); n != 1 {
				t.Errorf("%d lookups of the hop, want 1", n)
			}
		})
	}
}

// A hop whose cached RRset has expired is looked up again: a lookup that
// found it once does not keep it from being looked up for good (CodeRabbit on
// #1056).
func TestOOTSAliasExpiredHopLookedUpAgain(t *testing.T) {
	imr := newTestImr(t)
	imr.Quiet = true
	imr.signalAliasHops.retry = 50 * time.Millisecond
	imr.TransportSignalDiscovery = cache.NewDiscoveryTracker(time.Minute, 3)
	alias := []dns.RR{mustRR(t, pathOwner+` 3600 IN SVCB 0 `+providerOwner)}
	cacheSignal(imr, pathOwner, alias, cache.ValidationStateSecure)
	server := cache.NewAuthServer(pathNS)
	imr.Cache.ServerMap.Set(stateZone, map[string]*cache.AuthServer{cache.ServerKey(pathNS): server})
	calls := hookAliasHop(t, func(imr *Imr, target string) (*ImrResponse, error) {
		cacheSignal(imr, target, providerRecords(t), cache.ValidationStateSecure)
		return &ImrResponse{RRset: imr.Cache.Get(target, dns.TypeSVCB).RRset, ValidationState: cache.ValidationStateSecure}, nil
	})
	apply := func() {
		imr.applyTransportRRsetFromAnswer(pathOwner, &core.RRset{Name: pathOwner, RRtype: dns.TypeSVCB, RRs: copyRRs(alias)},
			cache.ValidationStateSecure)
	}
	apply()
	waitRedirect(t, server, "after the first lookup")

	// The hop's RRset runs out: stored again with TTL 0, it is stored
	// already expired.
	expired := []dns.RR{
		mustRR(t, providerOwner+` 0 IN SVCB 1 `+providerDoT+` port=1234 oots="dot:30"`),
		mustRR(t, providerOwner+` 0 IN SVCB 1 . oots="doq:20"`),
	}
	cacheSignal(imr, providerOwner, expired, cache.ValidationStateSecure)
	if imr.Cache.Get(providerOwner, dns.TypeSVCB) != nil {
		t.Fatal("the hop's RRset did not expire")
	}
	time.Sleep(100 * time.Millisecond)
	apply()
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the expired hop was not looked up again")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
