/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"slices"
	"sync"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A referral cannot carry addresses for a nameserver outside the delegated
// zone, so a zone whose nameservers are all out-of-bailiwick arrives with none.
// The functions here put those servers into the zone's cached server map once
// their addresses are known, so the next query into the zone starts with a
// server to send to (#682). Without them the map stayed empty for as long as
// the delegation was cached, and every query repeated the address lookups.

// storeZoneServers adds to zone's cached server map every server in servers
// that has addresses and is named in zone's cached NS RRset.
//
// The NS check keeps out a server resolved for a delegation that has since
// expired or changed. A configured stub or forward zone is left alone: its
// servers are the ones the operator named, and a server found by resolving its
// NS RRset must not route queries for it.
func (imr *Imr) storeZoneServers(zone string, servers map[string]*cache.AuthServer) {
	if imr == nil || imr.Cache == nil || zone == "" || len(servers) == 0 {
		return
	}
	if imr.configuredZone(zone) {
		return
	}
	nsset := imr.Cache.Get(zone, dns.TypeNS)
	if nsset == nil || nsset.RRset == nil {
		return
	}
	named := make(map[string]bool, len(nsset.RRset.RRs))
	for _, rr := range nsset.RRset.RRs {
		if ns, ok := rr.(*dns.NS); ok {
			named[cache.ServerKey(ns.Ns)] = true
		}
	}
	store := map[string]*cache.AuthServer{}
	for name, srv := range servers {
		key := cache.ServerKey(name)
		if srv == nil || !named[key] || len(srv.GetAddrs()) == 0 {
			continue
		}
		store[key] = srv
	}
	if len(store) == 0 {
		return
	}
	if err := imr.Cache.AddServers(zone, store); err != nil {
		lgDns.Debug("storeZoneServers: AddServers failed", "zone", zone, "err", err)
		return
	}
	lgDns.Debug("storeZoneServers: stored servers", "zone", zone, "count", len(store))
}

// lookupServerAddrs resolves nsname's A and AAAA records, the two at once, and
// adds the addresses to srv.
func (imr *Imr) lookupServerAddrs(ctx context.Context, srv *cache.AuthServer, nsname string) {
	var wg sync.WaitGroup
	for _, atype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		wg.Add(1)
		go func(atype uint16) {
			defer wg.Done()
			resp, err := imr.ImrQuery(ctx, nsname, atype, dns.ClassINET, nil)
			if err != nil || resp == nil || resp.RRset == nil {
				return
			}
			for _, addrRR := range resp.RRset.RRs {
				// AuthServer.Addrs stores BARE IPs (no port). Exchange
				// adds the port via JoinHostPort when dialing. Double-
				// porting here would produce e.g. "[1.2.3.4:53]:53" and
				// Dial would try to resolve "1.2.3.4:53" as a hostname.
				switch a := addrRR.(type) {
				case *dns.A:
					srv.AddAddr(a.A.String())
				case *dns.AAAA:
					srv.AddAddr(a.AAAA.String())
				}
			}
		}(atype)
	}
	wg.Wait()
}

// nsAddrLookups records the nameserver address lookups in flight. One lookup
// runs per nameserver name at a time, however many referrals and fallbacks
// want it: a second caller joins the running one instead of sending the same
// queries again.
type nsAddrLookups struct {
	mu      sync.Mutex
	running map[string]*nsAddrLookup // nameserver -> its lookup
}

// nsAddrLookup is one running lookup.
type nsAddrLookup struct {
	done  chan struct{}   // closed when the lookup has ended and stored its result
	zones map[string]bool // zones to add the server to when it has an address
}

// begin registers zone (if any) with nsname's lookup, and returns that lookup.
// start is true when there was none and the caller is to run it.
func (l *nsAddrLookups) begin(nsname, zone string) (lookup *nsAddrLookup, start bool) {
	key := cache.ServerKey(nsname)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.running == nil {
		l.running = map[string]*nsAddrLookup{}
	}
	lookup, running := l.running[key]
	if !running {
		lookup = &nsAddrLookup{done: make(chan struct{}), zones: map[string]bool{}}
		l.running[key] = lookup
	}
	if zone != "" {
		lookup.zones[core.CanonicalizeName(zone)] = true
	}
	return lookup, !running
}

// end removes nsname's lookup and returns the zones registered with it. A
// caller that begins after this starts a new lookup.
func (l *nsAddrLookups) end(nsname string) []string {
	key := cache.ServerKey(nsname)
	l.mu.Lock()
	defer l.mu.Unlock()
	lookup := l.running[key]
	delete(l.running, key)
	if lookup == nil {
		return nil
	}
	zones := make([]string, 0, len(lookup.zones))
	for zone := range lookup.zones {
		zones = append(zones, zone)
	}
	return zones
}

// nsLookupChainKey carries, on a lookup's context, the nameservers whose
// lookups it is nested in: the lookup's own name last.
type nsLookupChainKey struct{}

// ended is the channel nsLookup returns when it starts nothing.
var ended = func() chan struct{} { c := make(chan struct{}); close(c); return c }()

// nsAddrLookupFallbackBudget is the per-lookup budget when the IMR's tuning
// has none: the query-budget default.
const nsAddrLookupFallbackBudget = 8 * time.Second

// nsLookup starts the address lookup for nsname, or joins the one already
// running, and registers zone to receive the server when it has an address.
// It does not wait: the returned channel is closed when the lookup has ended
// and its server is stored. The server is the shared instance for nsname.
//
// The lookup runs on a detached context with its own deadline (twice the query
// budget, one per address type), so a caller that stops waiting leaves it
// running, and its result is stored all the same.
//
// A lookup can come to need its own name: resolving ns1.example. may start at
// example., which is served by ns1.example. (a nameserver without glue), or by
// a zone that is served by names in example. (a cycle). Joining the running
// lookup would then wait on itself until its deadline. So a lookup's context
// carries the chain of names it is nested in, and nsLookup starts nothing for
// a name already on ctx's chain. Two lookups that were started independently
// can still wait on each other; those waits end when the lookups' own queries
// run out of budget, and such a delegation has no address to find anyway.
func (imr *Imr) nsLookup(ctx context.Context, nsname, zone string) <-chan struct{} {
	key := cache.ServerKey(nsname)
	chain, _ := ctx.Value(nsLookupChainKey{}).([]string)
	if slices.Contains(chain, key) {
		lgDns.Debug("nsLookup: nameserver is already being looked up on this chain",
			"ns", nsname, "chain", chain)
		return ended
	}
	lookup, start := imr.nsAddrLookups.begin(nsname, zone)
	if !start {
		return lookup.done
	}
	budget := imr.Tuning.QueryBudget
	if budget <= 0 {
		budget = nsAddrLookupFallbackBudget
	}
	go func() {
		defer close(lookup.done)
		lctx, cancel := detachedContext(2 * budget)
		defer cancel()
		lctx = context.WithValue(lctx, nsLookupChainKey{}, append(slices.Clone(chain), key))
		srv := imr.Cache.GetOrCreateAuthServer(nsname)
		srv.SetSrc("ns-lookup")
		imr.lookupServerAddrs(lctx, srv, nsname)
		zones := imr.nsAddrLookups.end(nsname)
		if len(srv.GetAddrs()) == 0 {
			lgDns.Debug("nsLookup: no address for nameserver", "ns", nsname, "zones", zones)
			return
		}
		for _, z := range zones {
			imr.storeZoneServers(z, map[string]*cache.AuthServer{key: srv})
		}
	}()
	return lookup.done
}

// resolveZoneServersInBackground resolves the addresses of nsnames, the
// out-of-bailiwick nameservers a referral to zone carried no addresses for,
// and adds each one that gets an address to zone's server map. It does not
// wait for them: the query that met the referral goes on without.
func (imr *Imr) resolveZoneServersInBackground(ctx context.Context, zone string, nsnames []string) {
	for _, nsname := range nsnames {
		imr.nsLookup(ctx, nsname, zone)
	}
}
