/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
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

// lookupServerAddrs resolves nsname's A and AAAA records and adds the
// addresses to srv. It reports false if ctx ended before both lookups ran.
func (imr *Imr) lookupServerAddrs(ctx context.Context, srv *cache.AuthServer, nsname string) bool {
	for _, atype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		resp, err := imr.ImrQuery(ctx, nsname, atype, dns.ClassINET, nil)
		if err != nil || resp == nil || resp.RRset == nil {
			continue
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
	}
	return true
}

// nsAddrLookups records the background nameserver address lookups in flight,
// with the zones waiting for each. One lookup runs per nameserver name at a
// time, however many referrals name it. That also bounds a cycle -- zone A
// served by names in zone B, served by names in zone A -- where each lookup
// meets a referral that would otherwise start the other one again.
type nsAddrLookups struct {
	mu      sync.Mutex
	waiting map[string]map[string]bool // nameserver -> zones to add it to
}

// begin registers zone as waiting for nsname. It reports whether the caller
// is to run the lookup: false when one is already running, which adds the
// server to zone as well when it ends.
func (l *nsAddrLookups) begin(nsname, zone string) bool {
	key := cache.ServerKey(nsname)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.waiting == nil {
		l.waiting = map[string]map[string]bool{}
	}
	zones, running := l.waiting[key]
	if !running {
		zones = map[string]bool{}
		l.waiting[key] = zones
	}
	zones[core.CanonicalizeName(zone)] = true
	return !running
}

// end removes nsname's lookup and returns the zones that waited for it.
func (l *nsAddrLookups) end(nsname string) []string {
	key := cache.ServerKey(nsname)
	l.mu.Lock()
	defer l.mu.Unlock()
	zones := make([]string, 0, len(l.waiting[key]))
	for zone := range l.waiting[key] {
		zones = append(zones, zone)
	}
	delete(l.waiting, key)
	return zones
}

// nsAddrLookupFallbackBudget is the per-lookup budget when the IMR's tuning
// has none: the query-budget default.
const nsAddrLookupFallbackBudget = 8 * time.Second

// resolveZoneServersInBackground resolves the addresses of nsnames, the
// out-of-bailiwick nameservers a referral to zone carried no addresses for,
// and adds each one that gets an address to zone's server map.
//
// The lookups run on a detached context (detachedContext): the query that met
// the referral returns long before they finish, and its deferred cancel used
// to end every one of them. Each nameserver gets its own deadline, the query
// budget per address type.
func (imr *Imr) resolveZoneServersInBackground(zone string, nsnames []string) {
	budget := imr.Tuning.QueryBudget
	if budget <= 0 {
		budget = nsAddrLookupFallbackBudget
	}
	for _, nsname := range nsnames {
		if !imr.nsAddrLookups.begin(nsname, zone) {
			lgDns.Debug("resolveZoneServersInBackground: address lookup already running",
				"ns", nsname, "zone", zone)
			continue
		}
		go func(nsname string) {
			lctx, cancel := detachedContext(2 * budget)
			defer cancel()
			srv := imr.Cache.GetOrCreateAuthServer(nsname)
			srv.SetSrc("referral-oob")
			imr.lookupServerAddrs(lctx, srv, nsname)
			zones := imr.nsAddrLookups.end(nsname)
			if len(srv.GetAddrs()) == 0 {
				lgDns.Debug("resolveZoneServersInBackground: no address for nameserver",
					"ns", nsname, "zones", zones)
				return
			}
			for _, z := range zones {
				imr.storeZoneServers(z, map[string]*cache.AuthServer{cache.ServerKey(nsname): srv})
			}
		}(nsname)
	}
}
