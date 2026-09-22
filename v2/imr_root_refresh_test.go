/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"context"
	"io"
	"log"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// rootNSCache builds a cache holding a root NS RRset with the given TTL.
//
// TTL, not an Expiration: RRsetCacheT.Set always recomputes Expiration from the
// RRset's minimum TTL, so setting the field directly is silently ignored.
func rootNSCache(t *testing.T, ttl uint32) *cache.RRsetCacheT {
	t.Helper()
	c := cache.NewRRsetCache(log.New(io.Discard, "", 0), false, false)
	rr := &dns.NS{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
		Ns:  "a.root.",
	}
	c.Set(".", dns.TypeNS, &cache.CachedRRset{
		Name:   ".",
		RRtype: dns.TypeNS,
		RRset:  &core.RRset{Name: ".", RRtype: dns.TypeNS, RRs: []dns.RR{rr}},
	})
	return c
}

// The status must describe the cache NOW, not the boot-time priming event.
//
// "primed via hints+fetch at 08:00:28" stayed true for nearly three hours
// while the resolver could not resolve anything it had not already cached.
// That line is about the past; this one is about whether an iteration can be
// started at all.
func TestRootNSStatusReportsThePresent(t *testing.T) {
	t.Run("present, with its expiry", func(t *testing.T) {
		imr := &Imr{Cache: rootNSCache(t, 600)}

		present, expires, count := imr.RootNSStatus()
		if !present {
			t.Fatal("a live root NS was reported absent")
		}
		if count != 1 {
			t.Errorf("count = %d, want 1", count)
		}
		if left := time.Until(expires); left <= 0 || left > 600*time.Second {
			t.Errorf("expires in %s, want a positive value no more than the 600s TTL", left)
		}
	})

	// The failure state: the RRset has aged out. Nothing can start an
	// iteration, and the status has to say so rather than report the boot-time
	// priming and look healthy.
	t.Run("expired reads as absent", func(t *testing.T) {
		// TTL 0: Set stamps Expiration at time.Now(), so it is already in
		// the past by the time anything reads it.
		imr := &Imr{Cache: rootNSCache(t, 0)}

		if present, _, _ := imr.RootNSStatus(); present {
			t.Error("an expired root NS was reported present; that is exactly" +
				" the reassurance that hid this failure")
		}
	})

	t.Run("no cache at all", func(t *testing.T) {
		imr := &Imr{}
		if present, _, _ := imr.RootNSStatus(); present {
			t.Error("reported present with no cache")
		}
	})
}

// The refresher must wake up BEFORE expiry, not after: refreshing against the
// live roots is only possible while they are still there. Once the RRset is
// gone the only route left is the hints file, which is the cold-start path we
// are trying not to depend on.
func TestRefreshLeadIsBeforeExpiry(t *testing.T) {
	if rootRefreshLead <= 0 {
		t.Fatal("the lead must be positive, or the refresh runs after expiry")
	}
	if rootRefreshRetry >= rootRefreshLead {
		t.Errorf("retry (%s) >= lead (%s): a single failure would leave no"+
			" time for another attempt before the RRset expires",
			rootRefreshRetry, rootRefreshLead)
	}
}

// seedRootServers gives the cache a root ServerMap, so ServerMapCopy has
// something to hand the query.
func seedRootServers(t *testing.T, c *cache.RRsetCacheT) {
	t.Helper()
	srv := c.GetOrCreateAuthServer("a.root.")
	srv.AddAddr("192.0.2.1")
	if err := c.AddServers(".", map[string]*cache.AuthServer{
		cache.ServerKey("a.root."): srv,
	}); err != nil {
		t.Fatalf("AddServers: %v", err)
	}
}

// A refresh must QUERY.
//
// The first version of this called IterativeDNSQueryFetcher, which passes
// force=false, and IterativeDNSQuery with force=false returns a cached
// ContextAnswer without touching the network. Since the refresher runs only
// while the current RRset is still valid, it read back the entry it was trying
// to replace, saw the expiry had not moved, called that failure, and retried
// until the RRset expired -- recover-after-expiry, the opposite of the intent.
//
// Tests that pin the constants and the status line cannot see that. This one
// can, because the query is a parameter.
func TestRefreshRootActuallyQueries(t *testing.T) {
	t.Run("a query that returns fresher data is a refresh", func(t *testing.T) {
		c := rootNSCache(t, 120)
		seedRootServers(t, c)
		imr := &Imr{Cache: c}

		called := 0
		query := func(ctx context.Context, servers map[string]*cache.AuthServer) (*core.RRset, error) {
			called++
			if len(servers) == 0 {
				t.Error("the query was handed no root servers")
			}
			// What a real force=true query does: store the new RRset.
			rr := &dns.NS{
				Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 900},
				Ns:  "a.root.",
			}
			set := &core.RRset{Name: ".", RRtype: dns.TypeNS, RRs: []dns.RR{rr}}
			c.Set(".", dns.TypeNS, &cache.CachedRRset{Name: ".", RRtype: dns.TypeNS, RRset: set})
			return set, nil
		}

		if !imr.refreshRootFromLiveRoots(context.Background(), query) {
			t.Error("a successful refresh was reported as failure")
		}
		if called != 1 {
			t.Errorf("the query ran %d times, want exactly 1", called)
		}
	})

	// The exact shape of the bug: a "query" that returns the still-valid
	// cached entry without moving the expiry. That must be a failure, not a
	// success, or the loop would believe it had refreshed.
	t.Run("a query that does not move the expiry is a failure", func(t *testing.T) {
		c := rootNSCache(t, 120)
		seedRootServers(t, c)
		imr := &Imr{Cache: c}

		before := c.Get(".", dns.TypeNS)
		query := func(ctx context.Context, servers map[string]*cache.AuthServer) (*core.RRset, error) {
			return before.RRset, nil // the cache hit force=false produced
		}

		if imr.refreshRootFromLiveRoots(context.Background(), query) {
			t.Error("a cache hit was reported as a successful refresh; that is" +
				" how the refresher spun until expiry")
		}
	})

	t.Run("no root servers to query against", func(t *testing.T) {
		imr := &Imr{Cache: rootNSCache(t, 120)} // NS present, ServerMap empty
		query := func(context.Context, map[string]*cache.AuthServer) (*core.RRset, error) {
			t.Error("queried with no servers")
			return nil, nil
		}
		if imr.refreshRootFromLiveRoots(context.Background(), query) {
			t.Error("reported success with no servers")
		}
	})
}

// Why force=true is required, pinned against the code it depends on: a cached
// ContextAnswer short-circuits a force=false query, returning without any
// network access. If that ever stops being true, the comment on rootNSQuery is
// wrong and this test should be revisited rather than deleted.
func TestForceFalseIsSatisfiedFromCache(t *testing.T) {
	c := cache.NewRRsetCache(log.New(io.Discard, "", 0), false, false)
	rr := &dns.NS{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 900},
		Ns:  "a.root.",
	}
	c.Set(".", dns.TypeNS, &cache.CachedRRset{
		Name: ".", RRtype: dns.TypeNS, Context: cache.ContextAnswer,
		RRset: &core.RRset{Name: ".", RRtype: dns.TypeNS, RRs: []dns.RR{rr}},
	})
	imr := &Imr{Cache: c}

	// No servers at all: if this reached the network it could not succeed.
	rrset, _, cctx, _, err := imr.IterativeDNSQuery(context.Background(), ".",
		dns.TypeNS, map[string]*cache.AuthServer{}, false, edns0.PrivacyNone)
	if err != nil || rrset == nil {
		t.Fatalf("force=false did not return the cached answer: rrset=%v err=%v", rrset, err)
	}
	if cctx != cache.ContextAnswer {
		t.Errorf("context = %v, want ContextAnswer", cctx)
	}
}

// rootNSQuery itself must not be satisfiable from the cache.
//
// This is the test that fails if someone swaps it back to
// IterativeDNSQueryFetcher. The discriminator needs no network: given a valid
// cached ContextAnswer and NO servers,
//
//	force=false -> returns the cached RRset, no error   (the bug)
//	force=true  -> cannot use the cache, has nowhere to ask, fails
func TestRootNSQueryIsNotSatisfiedFromCache(t *testing.T) {
	c := cache.NewRRsetCache(log.New(io.Discard, "", 0), false, false)
	rr := &dns.NS{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 900},
		Ns:  "a.root.",
	}
	c.Set(".", dns.TypeNS, &cache.CachedRRset{
		Name: ".", RRtype: dns.TypeNS, Context: cache.ContextAnswer,
		RRset: &core.RRset{Name: ".", RRtype: dns.TypeNS, RRs: []dns.RR{rr}},
	})
	imr := &Imr{Cache: c}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rrset, err := imr.rootNSQuery(ctx, map[string]*cache.AuthServer{})
	if err == nil && rrset != nil {
		t.Error("rootNSQuery returned data with no servers to ask: it was" +
			" satisfied from the cache, so force is not set — the refresher" +
			" would read back the entry it is trying to replace")
	}
}

// rootNSAnswer returns a query double that stores a root NS RRset with the
// given TTL, as a force=true query does, and hands it back.
func rootNSAnswer(c *cache.RRsetCacheT, ttl uint32) func(context.Context, map[string]*cache.AuthServer) (*core.RRset, error) {
	return func(ctx context.Context, servers map[string]*cache.AuthServer) (*core.RRset, error) {
		rr := &dns.NS{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
			Ns:  "a.root.",
		}
		set := &core.RRset{Name: ".", RRtype: dns.TypeNS, RRs: []dns.RR{rr}}
		c.Set(".", dns.TypeNS, &cache.CachedRRset{Name: ".", RRtype: dns.TypeNS, RRset: set})
		return set, nil
	}
}

// failingRootNSQuery is a query double for a refresh that gets no answer.
func failingRootNSQuery(context.Context, map[string]*cache.AuthServer) (*core.RRset, error) {
	return nil, context.DeadlineExceeded
}

// An answer whose expiry moved, but not out of the lead window, is not a
// refresh (#722). A cache -- a forward's upstream -- answers ". NS" with a TTL
// that counts down: every answer moves the expiry by the round trip and no
// further. Counted as success, the next turn refreshed again at once, and the
// loop spun at query rate until the RRset expired. (From #723.)
func TestRefreshWithinTheLeadIsNotARefresh(t *testing.T) {
	c := rootNSCache(t, 20)
	seedRootServers(t, c)
	imr := &Imr{Cache: c}

	if imr.refreshRootFromLiveRoots(context.Background(), rootNSAnswer(c, 30)) {
		t.Error("a refreshed root NS that expires inside the lead window was" +
			" counted as a refresh; the loop would query again at once")
	}
}

// After a turn that did not renew the root NS, the loop waits the retry
// interval, but never past the expiry of the root NS the cache holds after the
// turn, and never less than a second (#722). Sleeping a full interval through
// that expiry left the resolver with no root NS until the interval ran out,
// and the copy that expires first can be the one the turn itself stored: an
// answer with a TTL that counts down, or a TTL of 0. (From #723, which took the
// expiry from before the turn.)
func TestRootRetryWaitStopsAtTheExpiry(t *testing.T) {
	cases := []struct {
		name     string
		ttl      uint32 // of the root NS the turn starts with
		query    func(c *cache.RRsetCacheT) func(context.Context, map[string]*cache.AuthServer) (*core.RRset, error)
		min, max time.Duration
	}{
		{"a failure far from the expiry waits the retry interval", 40,
			func(*cache.RRsetCacheT) func(context.Context, map[string]*cache.AuthServer) (*core.RRset, error) {
				return failingRootNSQuery
			}, rootRefreshRetry, rootRefreshRetry},
		{"a failure 5s before the expiry wakes at the expiry", 5,
			func(*cache.RRsetCacheT) func(context.Context, map[string]*cache.AuthServer) (*core.RRset, error) {
				return failingRootNSQuery
			}, time.Second, 5 * time.Second},
		{"an answer that expires sooner wakes at its expiry", 40,
			func(c *cache.RRsetCacheT) func(context.Context, map[string]*cache.AuthServer) (*core.RRset, error) {
				return rootNSAnswer(c, 8)
			}, time.Second, 8 * time.Second},
		{"an answer of TTL 0 waits one second", 40,
			func(c *cache.RRsetCacheT) func(context.Context, map[string]*cache.AuthServer) (*core.RRset, error) {
				return rootNSAnswer(c, 0)
			}, time.Second, time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := rootNSCache(t, tc.ttl)
			seedRootServers(t, c)
			imr := &Imr{Cache: c}
			if w := imr.rootRefreshPass(context.Background(), "", tc.query(c)); w < tc.min || w > tc.max {
				t.Errorf("waits %s, want between %s and %s", w, tc.min, tc.max)
			}
		})
	}
}

// A TTL-0 answer is stored already expired. Reading it back with Get dropped
// it, and the root server map with it, and the resolver then waited the retry
// interval with neither (#722). The turn that stored it leaves both, and the
// next turn drops the expired copy and re-primes from the hints at once.
func TestAnExpiredRefreshLeavesTheRootServerMapToTheNextTurn(t *testing.T) {
	c := rootNSCache(t, 40)
	seedRootServers(t, c)
	imr := &Imr{Cache: c}

	if w := imr.rootRefreshPass(context.Background(), "", rootNSAnswer(c, 0)); w > time.Second {
		t.Errorf("waits %s after a TTL-0 answer", w)
	}
	if _, ok := c.ServerMapCopy("."); !ok {
		t.Error("the turn that stored a TTL-0 root NS dropped the root server map")
	}

	notCalled := func(context.Context, map[string]*cache.AuthServer) (*core.RRset, error) {
		t.Error("the next turn queried instead of re-priming")
		return nil, nil
	}
	if w := imr.rootRefreshPass(context.Background(), "", notCalled); w > 0 {
		t.Errorf("the next turn waits %s after re-priming; want an immediate re-read", w)
	}
	if c.Get(".", dns.TypeNS) == nil {
		t.Error("no root NS after the next turn")
	}
	if _, ok := c.ServerMapCopy("."); !ok {
		t.Error("no root server map after the next turn")
	}
}
