/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package imr

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// aliasHopImr is a resolver that does discovery, with one nameserver, pathNS,
// in a zone server map, and the alias from its _dns owner to the provider's
// signal in the cache. It returns the alias and the server.
func aliasHopImr(t *testing.T) (*Imr, []dns.RR, *cache.AuthServer) {
	t.Helper()
	imr := newTestImr(t)
	imr.Quiet = true
	imr.TransportSignalDiscovery = cache.NewDiscoveryTracker(time.Minute, 3)
	alias := []dns.RR{mustRR(t, pathOwner+` 3600 IN SVCB 0 `+providerOwner)}
	cacheSignal(imr, pathOwner, alias, cache.ValidationStateSecure)
	server := cache.NewAuthServer(pathNS)
	imr.Cache.ServerMap.Set(stateZone, map[string]*cache.AuthServer{cache.ServerKey(pathNS): server})
	return imr, alias, server
}

// svcbRRset is rrs as the SVCB RRset at owner.
func svcbRRset(owner string, rrs []dns.RR) *core.RRset {
	return &core.RRset{Name: owner, Class: dns.ClassINET, RRtype: dns.TypeSVCB, RRs: copyRRs(rrs)}
}

// foundProvider is the hook answer of a hop lookup that finds the provider's
// signal at target.
func foundProvider(t *testing.T) func(imr *Imr, target string) (*ImrResponse, error) {
	recs := providerRecords(t)
	return func(imr *Imr, target string) (*ImrResponse, error) {
		cacheSignal(imr, target, recs, cache.ValidationStateSecure)
		return &ImrResponse{RRset: imr.Cache.Get(target, dns.TypeSVCB).RRset, ValidationState: cache.ValidationStateSecure}, nil
	}
}

// waitAliasHopsEnded waits until the alias hop lookups imr runs have ended,
// each with the walks of the owners that waited for it, and every lookup those
// walks started.
func waitAliasHopsEnded(t *testing.T, imr *Imr) {
	t.Helper()
	ended := make(chan struct{})
	go func() {
		imr.signalAliasHops.running.Wait()
		close(ended)
	}()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the alias hop lookups did not end")
	}
}

// With use-transport-signals: false the answer to a query for an AliasMode
// _dns SVCB is cached, but its alias is not followed: nothing is installed
// through it, and no hop is looked up.
func TestOOTSAliasOptOutFollowsNothing(t *testing.T) {
	imr, alias, server := aliasHopImr(t)
	imr.Options[ImrOptUseTransportSignals] = "false"
	calls := hookAliasHop(t, foundProvider(t))

	cacheSignal(imr, providerOwner, providerRecords(t), cache.ValidationStateSecure)
	imr.applyTransportRRsetFromAnswer(pathOwner, svcbRRset(pathOwner, alias), cache.ValidationStateSecure)
	if rec := server.GetReceivedSignal(); rec != nil {
		t.Errorf("installed through the alias with signals turned off: %+v", rec)
	}

	const ns2 = "ns2.kid.p.test."
	owner2 := "_dns." + ns2
	alias2 := []dns.RR{mustRR(t, owner2+` 3600 IN SVCB 0 _dns.ns.elsewhere.example.`)}
	imr.applyTransportRRsetFromAnswer(owner2, svcbRRset(owner2, alias2), cache.ValidationStateSecure)
	time.Sleep(100 * time.Millisecond)
	if n := calls.Load(); n != 0 {
		t.Errorf("%d hop lookups with signals turned off, want 0", n)
	}
}

// An owner whose walk misses the hop, while another owner's lookup of that hop
// ends before this one joins it, is not left behind: the hop is cooling down,
// so it is read from the cache once more, and nothing is looked up again.
func TestOOTSAliasHopFoundBetweenMissAndJoin(t *testing.T) {
	imr, alias, server := aliasHopImr(t)
	calls := hookAliasHop(t, func(*Imr, string) (*ImrResponse, error) {
		t.Error("the hop was looked up again")
		return nil, nil
	})
	recs := providerRecords(t)
	saved := testHookAliasHopMissed
	testHookAliasHopMissed = func(target string) {
		// Another owner's lookup of the hop ends here: it has cached the hop
		// and recorded its end, and has followed its own owners again.
		cacheSignal(imr, target, recs, cache.ValidationStateSecure)
		if got := imr.signalAliasHops.join(target, "_dns.ns.other.example.", time.Now()); got != hopStarted {
			t.Errorf("the other owner's join: %v", got)
		}
		imr.signalAliasHops.done(target, time.Now())
	}
	t.Cleanup(func() { testHookAliasHopMissed = saved })

	imr.applyTransportRRsetFromAnswer(pathOwner, svcbRRset(pathOwner, alias), cache.ValidationStateSecure)
	if ep := server.GetTransportEndpoint(core.TransportDoT); ep.Target != providerDoT {
		t.Errorf("DoT endpoint %v: the owner that missed the hop was not followed to it", ep)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("%d lookups, want 0", n)
	}
}

// A CNAME'd hop whose link has expired is read only by the walk that follows
// the owners again after the hop's own lookup, as the query that has just
// resolved the chain: a record with TTL 0 is stored already expired, and is
// still that lookup's answer. Any other walk reads the cache as it stands, and
// an expired link is not there, even within the grace.
func TestOOTSAliasExpiredHopReadOnlyAfterItsLookup(t *testing.T) {
	const elsewhere = "_dns.ns.elsewhere.example."
	// The link has TTL 0: the cache stores it already expired.
	setLink := func(t *testing.T, imr *Imr, from string) {
		link := mustRR(t, from+` 0 IN CNAME `+elsewhere)
		imr.Cache.Set(from, dns.TypeCNAME, &cache.CachedRRset{Name: from, RRtype: dns.TypeCNAME,
			Context: cache.ContextAnswer, State: cache.ValidationStateSecure,
			RRset: &core.RRset{Name: from, Class: dns.ClassINET, RRtype: dns.TypeCNAME, RRs: []dns.RR{link}}})
		// Peek, not Get: Get removes an expired entry.
		if e := imr.Cache.Peek(from, dns.TypeCNAME); e == nil || e.Expiration.After(cache.Now()) {
			t.Error("the link is not stored expired")
		}
	}
	terminal := func(t *testing.T, owner, ttl string) []dns.RR {
		return []dns.RR{
			mustRR(t, owner+` `+ttl+` IN SVCB 1 `+providerDoT+` port=1234 oots="dot:30"`),
			mustRR(t, owner+` `+ttl+` IN SVCB 1 . oots="doq:20"`),
		}
	}

	t.Run("a walk that did not resolve the hop", func(t *testing.T) {
		imr, alias, server := aliasHopImr(t)
		imr.TransportSignalDiscovery = nil // nothing is looked up
		setLink(t, imr, providerOwner)
		cacheSignal(imr, elsewhere, terminal(t, elsewhere, "3600"), cache.ValidationStateSecure)
		imr.applyTransportRRsetFromAnswer(pathOwner, svcbRRset(pathOwner, alias), cache.ValidationStateSecure)
		if rec := server.GetReceivedSignal(); rec != nil {
			t.Errorf("installed through an expired link: %s", cache.FormatSignalPath(rec.Path))
		}
	})

	t.Run("the walk after the hop's lookup, through a CNAME with TTL 0", func(t *testing.T) {
		imr, alias, server := aliasHopImr(t)
		recs := terminal(t, elsewhere, "0")
		hookAliasHop(t, func(imr *Imr, target string) (*ImrResponse, error) {
			setLink(t, imr, target)
			cacheSignal(imr, elsewhere, recs, cache.ValidationStateSecure)
			return &ImrResponse{RRset: svcbRRset(elsewhere, recs), ValidationState: cache.ValidationStateSecure}, nil
		})
		imr.applyTransportRRsetFromAnswer(pathOwner, svcbRRset(pathOwner, alias), cache.ValidationStateSecure)
		waitRedirect(t, server, "the hop's lookup through a CNAME with TTL 0")
	})

	t.Run("the walk after the hop's lookup, TTL 0", func(t *testing.T) {
		imr, alias, server := aliasHopImr(t)
		recs := terminal(t, providerOwner, "0")
		hookAliasHop(t, func(imr *Imr, target string) (*ImrResponse, error) {
			cacheSignal(imr, target, recs, cache.ValidationStateSecure)
			return &ImrResponse{RRset: svcbRRset(target, recs), ValidationState: cache.ValidationStateSecure}, nil
		})
		imr.applyTransportRRsetFromAnswer(pathOwner, svcbRRset(pathOwner, alias), cache.ValidationStateSecure)
		waitRedirect(t, server, "the hop's lookup with TTL 0")
	})
}

// A chain of AliasMode records at _dns. owners longer than the cap is looked
// up only as far as the cap from the owner: the answer to a hop's own lookup
// follows its alias through the cache only, and the walk of the owner that
// waits for it decides what is looked up next.
func TestOOTSAliasChainLookupsStayCapped(t *testing.T) {
	imr, _, server := aliasHopImr(t)
	const chainLen = 8
	hop := func(i int) string { return fmt.Sprintf("_dns.ns.c%d.example.", i) }
	answers := map[string][]dns.RR{}
	for i := 1; i < chainLen; i++ {
		answers[hop(i)] = []dns.RR{mustRR(t, hop(i)+` 3600 IN SVCB 0 `+hop(i+1))}
	}
	answers[hop(chainLen)] = []dns.RR{mustRR(t, hop(chainLen)+` 3600 IN SVCB 1 . oots="doq:20"`)}
	alias := []dns.RR{mustRR(t, pathOwner+` 3600 IN SVCB 0 `+hop(1))}
	cacheSignal(imr, pathOwner, alias, cache.ValidationStateSecure)

	var mu sync.Mutex
	var looked []string
	saved := signalAliasHopLookupHook
	signalAliasHopLookupHook = func(ctx context.Context, imr *Imr, target string) (*ImrResponse, error) {
		mu.Lock()
		looked = append(looked, target)
		mu.Unlock()
		rrs, ok := answers[target]
		if !ok {
			return nil, errors.New("no such hop")
		}
		cacheSignal(imr, target, rrs, cache.ValidationStateSecure)
		rrset := imr.Cache.Get(target, dns.TypeSVCB).RRset
		// The answer to the lookup is applied as handleAnswer applies it.
		imr.applyTransportRRsetWalk(aliasWalkFor(ctx), target, rrset, cache.ValidationStateSecure)
		return &ImrResponse{RRset: rrset, ValidationState: cache.ValidationStateSecure}, nil
	}
	t.Cleanup(func() { signalAliasHopLookupHook = saved })

	imr.applyTransportRRsetFromAnswer(pathOwner, svcbRRset(pathOwner, alias), cache.ValidationStateSecure)
	waitAliasHopsEnded(t, imr)
	mu.Lock()
	defer mu.Unlock()
	if len(looked) != maxSignalAliasDepth {
		t.Errorf("looked up %v, want the first %d hops only", looked, maxSignalAliasDepth)
	}
	if rec := server.GetReceivedSignal(); rec != nil {
		t.Errorf("a path longer than the cap installed a signal: %s", cache.FormatSignalPath(rec.Path))
	}
}

// A query that is part of an alias hop's lookup follows a cached alias it
// applies while it waits for signals through the cache only, as it does the
// alias in its answer: a hop the cache does not hold is for a walk outside
// any hop lookup to look up. Any other query looks it up.
func TestOOTSAliasHopQueryFollowsCachedAliasCacheOnly(t *testing.T) {
	imr, _, server := aliasHopImr(t)
	calls := hookAliasHop(t, foundProvider(t))
	servers := map[string]*cache.AuthServer{cache.ServerKey(pathNS): server}
	never := func() bool { return false }

	imr.awaitTransportSignalsUntil(withSignalAliasHopLookup(context.Background()), servers, transportQueryReasonNewServer, never)
	waitAliasHopsEnded(t, imr)
	if n := calls.Load(); n != 0 {
		t.Fatalf("a query in a hop's lookup looked up %d hop(s) through a cached alias", n)
	}

	imr.awaitTransportSignalsUntil(context.Background(), servers, transportQueryReasonNewServer, never)
	waitAliasHopsEnded(t, imr)
	if n := calls.Load(); n != 1 {
		t.Fatalf("a query outside any hop's lookup looked up %d hop(s), want 1", n)
	}
	waitRedirect(t, server, "the hop that query looked up")
}

// The transport-signal lookup that a query starts is part of an alias hop's
// lookup when the query is: the AliasMode record in its answer is followed
// through the cache only (aliasWalkFor). Any other query's signal lookup
// follows it with lookups. Both are signal lookups.
func TestOOTSSignalLookupKeepsAliasHopMark(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want bool
	}{
		{"in a hop's lookup", withSignalAliasHopLookup(context.Background()), true},
		{"outside any hop's lookup", context.Background(), false},
	} {
		queryCtx, cancel := transportSignalQueryContext(tc.ctx)
		if got := aliasWalkFor(queryCtx).cacheOnly; got != tc.want {
			t.Errorf("%s: the signal lookup follows an alias cache-only=%v, want %v", tc.name, got, tc.want)
		}
		if !inTransportSignalLookup(queryCtx) {
			t.Errorf("%s: the signal lookup's context is not marked as a signal lookup's", tc.name)
		}
		if _, ok := queryCtx.Deadline(); !ok {
			t.Errorf("%s: the signal lookup has no deadline", tc.name)
		}
		cancel()
	}
}

// The owner's RRset is replaced, and the newer answer installed, while the
// walk after a hop's lookup holds the alias it read: what stays installed is
// the newer answer, not the older alias's result.
func TestOOTSAliasRefollowYieldsToNewerAnswer(t *testing.T) {
	imr, alias, server := aliasHopImr(t)
	hookAliasHop(t, foundProvider(t))
	newer := []dns.RR{mustRR(t, pathOwner+` 3600 IN SVCB 1 . oots="dot:10"`)}
	ran := make(chan struct{})
	var once sync.Once
	saved := testHookAliasRefollowRead
	testHookAliasRefollowRead = func(owner string) {
		once.Do(func() {
			// As handleAnswer does with the newer answer: cache it, then
			// install it.
			cacheSignal(imr, pathOwner, newer, cache.ValidationStateSecure)
			imr.applyTransportRRsetFromAnswer(pathOwner, svcbRRset(pathOwner, newer), cache.ValidationStateSecure)
			close(ran)
		})
	}
	t.Cleanup(func() { testHookAliasRefollowRead = saved })

	imr.applyTransportRRsetFromAnswer(pathOwner, svcbRRset(pathOwner, alias), cache.ValidationStateSecure)
	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("the owner was not followed again after the hop's lookup")
	}
	waitAliasHopsEnded(t, imr)
	rec := server.GetReceivedSignal()
	if rec == nil {
		t.Fatal("nothing installed")
	}
	if ep := server.GetTransportEndpoint(core.TransportDoT); ep.Target != "" || rec.Weights[core.TransportDoT] != 10 {
		t.Errorf("DoT endpoint %v, weight %d: the older alias's result stayed over the newer answer (path %s)",
			ep, rec.Weights[core.TransportDoT], cache.FormatSignalPath(rec.Path))
	}
}

// After a hop's lookup has failed, a server that still holds an earlier signal
// is followed to the hop again once signalAliasHopRetry has passed: the verify
// lookup that an Additional section holding only the alias asks for follows
// the cached alias again, which looks the hop up, rather than stopping at it
// until the owner's RRset expires.
func TestOOTSAliasVerifyLooksFailedHopUpAgain(t *testing.T) {
	imr, alias, server := aliasHopImr(t)
	imr.signalAliasHops.retry = 100 * time.Millisecond
	earlier := []dns.RR{mustRR(t, pathOwner+` 3600 IN SVCB 1 . oots="do53:100"`)}
	imr.applyTransportRRsetFromAnswer(pathOwner, svcbRRset(pathOwner, earlier), cache.ValidationStateSecure)
	if server.GetReceivedSignal() == nil {
		t.Fatal("the earlier signal was not installed")
	}

	var mu sync.Mutex
	fail := true
	found := foundProvider(t)
	calls := hookAliasHop(t, func(imr *Imr, target string) (*ImrResponse, error) {
		mu.Lock()
		f := fail
		mu.Unlock()
		if f {
			return nil, errors.New("the hop's servers did not answer")
		}
		return found(imr, target)
	})
	imr.applyTransportRRsetFromAnswer(pathOwner, svcbRRset(pathOwner, alias), cache.ValidationStateSecure)
	until := aliasHopRetryAt(t, imr, providerOwner)
	mu.Lock()
	fail = false
	mu.Unlock()
	time.Sleep(time.Until(until) + 20*time.Millisecond)

	r := new(dns.Msg)
	r.SetQuestion("www."+stateZone, dns.TypeA)
	r.Extra = copyRRs(alias)
	imr.parseTransportForServerFromAdditional(context.Background(), server, r)
	waitRedirect(t, server, "the verify lookup after the hop's retry")
	if n := calls.Load(); n != 2 {
		t.Errorf("%d hop lookups, want 2", n)
	}
}
