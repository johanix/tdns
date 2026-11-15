/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
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
	signalAliasHopLookupHook = func(imr *Imr, target string) (*ImrResponse, error) {
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
	signalAliasHopLookupHook = func(*Imr, string) (*ImrResponse, error) {
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
