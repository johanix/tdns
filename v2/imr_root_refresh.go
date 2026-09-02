/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"context"
	"time"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// Root refresh: keeping the one RRset whose expiry cannot be recovered from.
//
// Every other expired RRset is re-fetched on demand, by walking down from the
// root. The root NS has nothing above it: fetching ". NS" requires already
// knowing a root server's address, and the cache drops the root ServerMap
// entry along with the NS RRset when it expires (RRsetCacheT.Get). So once it
// goes, iteration has no starting point, resolveNSAddresses reports an empty
// bestmatch, and EVERY lookup that is not already cached returns SERVFAIL --
// permanently, while the cache keeps answering for the names it still holds.
//
// Priming ran exactly once, at startup, behind `if !rrcache.IsPrimed()`, and
// IsPrimed was never consulted again outside status reporting. A resolver that
// went idle past the root NS TTL therefore became a husk that still looked
// healthy: "primed via hints+fetch at <boot time>" stayed true and said
// nothing about whether the root was still there.
//
// Observed 2026-09-01: primed 08:00:28 with a 900s root NS TTL, no traffic for
// nearly three hours, and the first query needing the root at 10:54:03 failed.
// It had been unable to resolve since roughly 08:15.
const (
	// rootRefreshLead is how long before expiry the refresh runs. Early
	// enough that a failure leaves room to retry while the current RRset is
	// still valid, which is the whole point of refreshing rather than
	// recovering.
	rootRefreshLead = 60 * time.Second

	// rootRefreshRetry is the gap between attempts once inside the lead
	// window. Short relative to the lead, so a transient failure gets several
	// tries before anything expires.
	rootRefreshRetry = 15 * time.Second
)

// RefreshRoot keeps the root NS RRset alive for as long as the daemon runs.
//
// It refreshes AGAINST THE LIVE ROOTS, not from the hints file: the cached
// delegation is the better source, and a hints file that has gone stale should
// not quietly become the source of truth. Hints stay what they are -- the
// cold-start mechanism -- and are used here only if the root is already gone,
// which is the state this function exists to prevent.
func (imr *Imr) RefreshRoot(ctx context.Context, hintsfile string) {
	if imr == nil || imr.Cache == nil {
		return
	}

	for {
		var wait time.Duration

		switch crrset := imr.Cache.Get(".", dns.TypeNS); {
		case crrset == nil:
			// Already gone. Nothing can be fetched without a root server
			// address, so this is the one case that needs the hints -- and
			// reaching it at all means a refresh was missed.
			lgImr.Warn("RefreshRoot: the root NS RRset is gone; re-priming from hints",
				"hintsfile", hintsfile)
			if err := imr.Cache.PrimeFromHintsOnly(hintsfile); err != nil {
				lgImr.Error("RefreshRoot: re-priming from hints failed", "err", err)
				wait = rootRefreshRetry
			} else {
				imr.PrimedVia = "hints (re-primed after expiry)"
				imr.PrimedAt = time.Now()
				lgImr.Info("RefreshRoot: re-primed from hints; the next refresh" +
					" will upgrade to the live roots")
				wait = 0
			}

		case time.Until(crrset.Expiration) > rootRefreshLead:
			// Healthy, and not due yet. Sleep until the lead window opens.
			wait = time.Until(crrset.Expiration) - rootRefreshLead

		default:
			// Inside the lead window: refresh from the roots we still have.
			if imr.refreshRootFromLiveRoots(ctx, imr.rootNSQuery) {
				wait = 0 // re-read the new expiry on the next pass
			} else {
				wait = rootRefreshRetry
			}
		}

		if wait <= 0 {
			wait = time.Millisecond // yield, then re-evaluate
		}
		select {
		case <-ctx.Done():
			lgImr.Info("RefreshRoot: terminating (context cancelled)")
			return
		case <-time.After(wait):
		}
	}
}

// rootNSQuery issues the actual ". NS" query for a refresh.
//
// force=true, and that is the entire point. IterativeDNSQueryFetcher passes
// force=false, and IterativeDNSQuery with force=false returns a cached
// ContextAnswer without touching the network:
//
//	if !force {
//	    crrset := imr.Cache.Get(qname, qtype)
//	    switch crrset.Context {
//	    case cache.ContextAnswer, ...:  return crrset.RRset, ...
//
// The refresher runs only while the current RRset is still VALID -- that is
// what the 60s lead is for -- so with force=false it read back the very entry
// it was trying to replace, saw the expiry had not moved, treated that as
// failure, and retried until the RRset expired. Recover-after-expiry, which is
// the opposite of what this file exists to do.
//
// Priming survives that trap only by accident: seedFromHints stores
// ContextHint, which is NOT in the short-circuit above and falls through to a
// real query. PrimeWithHints' own comment says "force re-query bypassing
// cache" -- the fetcher it calls does not pass force. This is where copying
// that fetcher went wrong.
func (imr *Imr) rootNSQuery(ctx context.Context, servers map[string]*cache.AuthServer) (*core.RRset, error) {
	rrset, _, _, _, err := imr.IterativeDNSQuery(ctx, ".", dns.TypeNS, servers, true, edns0.PrivacyNone) // privacy is a client signal; root refresh is our own traffic
	return rrset, err
}

// refreshRootFromLiveRoots re-queries ". NS" using the root servers already in
// the cache. Reports whether the cache now holds a root NS RRset that is
// further from expiry than the one we started with.
//
// query is a parameter so a test can assert that a refresh actually QUERIES.
// Pinning the constants and the status line, as the first version did, cannot
// see a refresher that never leaves the cache.
func (imr *Imr) refreshRootFromLiveRoots(ctx context.Context,
	query func(context.Context, map[string]*cache.AuthServer) (*core.RRset, error)) bool {

	before := imr.Cache.Get(".", dns.TypeNS)

	// A COPY. The query writes into the server map it is handed -- resolved
	// addresses in, expired entries out -- and the map stored under "." is the
	// published root delegation every other lookup depends on. PrimeWithHints
	// makes the same copy for the same reason.
	servers, ok := imr.Cache.ServerMapCopy(".")
	if !ok || len(servers) == 0 {
		lgImr.Warn("RefreshRoot: no root servers in the cache to refresh against")
		return false
	}

	rrset, err := query(ctx, servers)
	if err != nil || rrset == nil {
		lgImr.Warn("RefreshRoot: refreshing the root NS failed; will retry while"+
			" the current RRset is still valid", "err", err)
		return false
	}

	after := imr.Cache.Get(".", dns.TypeNS)
	if after == nil {
		lgImr.Warn("RefreshRoot: the fetch succeeded but the cache still holds no root NS")
		return false
	}
	// A fetch that returned the same near-expiry entry has not bought us
	// anything, and treating it as success would spin until it expired.
	if before != nil && !after.Expiration.After(before.Expiration) {
		lgImr.Warn("RefreshRoot: the root NS was re-fetched but its expiry did not move",
			"expiration", after.Expiration)
		return false
	}

	lgImr.Info("RefreshRoot: root NS refreshed from the live roots",
		"servers", len(servers), "expiration", after.Expiration)
	return true
}

// RootNSStatus reports what the cache currently holds for the root NS, for
// `imr config status`. Reporting that priming once happened is not the same
// claim as "the resolver can still start an iteration", and conflating them is
// what made this failure invisible.
func (imr *Imr) RootNSStatus() (present bool, expires time.Time, count int) {
	if imr == nil || imr.Cache == nil {
		return false, time.Time{}, 0
	}
	crrset := imr.Cache.Get(".", dns.TypeNS)
	if crrset == nil {
		return false, time.Time{}, 0
	}
	if crrset.RRset != nil {
		count = len(crrset.RRset.RRs)
	}
	return true, crrset.Expiration, count
}
