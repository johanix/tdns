/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const (
	transportQueryReasonObservation   = "opportunistic-signal"
	transportQueryReasonNewServer     = "new-auth-server"
	transportQueryReasonStrictPrivacy = "strict-privacy"
	// transportQueryReasonVerify is the verifying lookup for a signal record
	// with a target, which waits for a Secure verdict (R1).
	transportQueryReasonVerify = "verify-redirect"
	// transportQueryReasonNoUsableTransport is the lookup a query starts, or
	// joins, when none of its servers has a transport it may use now
	// (IterativeDNSQuery, #1065).
	transportQueryReasonNoUsableTransport = "no-usable-transport"
)

// detachedContext returns the context for fire-and-forget background work
// spawned during a query (NS revalidation, transport-signal and TLSA
// discovery, out-of-bailiwick nameserver addresses). The timeout bounds it, so
// a stuck background goroutine cannot leak forever.
//
// It is not derived from the query's context. The query's deferred cancel
// fires as soon as the foreground returns, and every in-flight DNS query in
// the background then failed with "context canceled": validation of an apex
// NS RRset, for one, never reached the signer's DNSKEYs.
//
// Nor does it keep the query's values. Those describe the query: a DS proof
// marks the context it asks its DS questions under, so that a referral met
// there is judged from the cache alone (cache.ReferralChildState). Background
// work that inherited the mark judged every referral of its own walk that way,
// and stored the verdicts.
func detachedContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

func (imr *Imr) TransportSignalRRType() uint16 {
	if imr == nil {
		return dns.TypeSVCB
	}
	if val, ok := imr.Options[ImrOptTransportSignalType]; ok {
		switch strings.ToLower(val) {
		case "tsync":
			return core.TypeTSYNC
		}
	}
	return dns.TypeSVCB
}

// TransportSignalCached reports whether the cache holds owner's transport
// signal. A cached denial is not one (cachedTransportSignal).
func (imr *Imr) TransportSignalCached(owner string) bool {
	if owner == "" || imr == nil {
		return false
	}
	signal, _ := imr.cachedTransportSignal(owner)
	return signal != nil
}

// cachedTransportSignal reads what the cache holds for owner's transport
// signal: the signal itself, or a denial that there is one.
//
// A denial stands for "signals nothing" until its entry expires, and no
// lookup is made before then: RFC 2308 negative caching, with the lifetime
// the cache gives denials (#523). Nothing else may keep that verdict longer,
// or a zone that publishes a signal afterwards is never seen to (#776).
//
// Only an answer of the signal's own type is a signal: a denial's entry holds
// the SOA that proves it, in the place the signal would have.
func (imr *Imr) cachedTransportSignal(owner string) (signal *cache.CachedRRset, denied bool) {
	if imr.Cache == nil || owner == "" {
		return nil, false
	}
	rrtype := imr.TransportSignalRRType()
	c := imr.Cache.Get(owner, rrtype)
	if c == nil {
		return nil, false
	}
	switch c.Context {
	case cache.ContextAnswer:
		if c.RRset != nil && c.RRset.RRtype == rrtype && len(c.RRset.RRs) > 0 {
			return c, false
		}
	case cache.ContextNXDOMAIN, cache.ContextNoErrNoAns:
		return nil, true
	}
	return nil, false
}

// settleTransportSignalLookup records in the tracker how a lookup of owner's
// transport signal ended.
//
// A signal found is a success. A denial is not a failure: the zone has
// answered, and its cached denial says "no signal" for as long as it lives.
// The tracker forgets the owner, so the first query after the denial expires
// looks again at once. A denial with TTL 0 is not cached at all, and the next
// query looks again straight away. Recording a denial as a success was
// terminal (ImrQuery used to hand back a cached denial's SOA as the answer,
// #698), and as a failure it added the backoff meant for servers that do not
// answer; either way the verdict outlived the denial. Anything else is a
// failure, retried after the backoff.
func (imr *Imr) settleTransportSignalLookup(owner string, resp *ImrResponse, err error) {
	switch {
	case err == nil && resp != nil && resp.RRset != nil &&
		resp.RRset.RRtype == imr.TransportSignalRRType() && len(resp.RRset.RRs) > 0:
		imr.TransportSignalDiscovery.Succeed(owner)
	case err == nil && resp != nil && resp.Denial != 0:
		imr.TransportSignalDiscovery.Reset(owner)
	default:
		imr.TransportSignalDiscovery.Fail(owner, err)
	}
}

func (imr *Imr) maybeQueryTransportSignal(ctx context.Context, owner string, reason string) {
	if owner == "" || imr.Cache == nil || ctx == nil {
		return
	}
	// With transport signals turned off, a signal would not be used, so
	// none is looked up, whatever the discovery options say.
	if imr.Options[ImrOptUseTransportSignals] == "false" {
		return
	}
	switch reason {
	case transportQueryReasonObservation:
		// Proceed if either option is enabled
		if imr.Options[ImrOptQueryForTransport] == "true" || imr.Options[ImrOptAlwaysQueryForTransport] == "true" {
			imr.launchTransportSignalQuery(ctx, owner, reason)
		}
	case transportQueryReasonNewServer:
		// Only proceed if always-query option is enabled
		if imr.Options[ImrOptAlwaysQueryForTransport] == "true" {
			imr.launchTransportSignalQuery(ctx, owner, reason)
		}
	case transportQueryReasonVerify:
		// A redirect is honoured only once its path validates. Where the
		// Additional section could not tell, this lookup can, whether or not
		// the options ask for discovery. Only use-transport-signals: false
		// turns it off.
		if imr.Options[ImrOptUseTransportSignals] != "false" {
			imr.launchTransportSignalQuery(ctx, owner, reason)
		}
	case transportQueryReasonStrictPrivacy, transportQueryReasonNoUsableTransport:
		// A strict query cannot use a server whose transports it does not
		// know, nor can any query whose servers have nothing else left (the
		// server's Do53 in backoff, say), so they look the transports up
		// whether or not the options ask for discovery. Only
		// use-transport-signals: false turns signals off.
		if imr.Options[ImrOptUseTransportSignals] != "false" {
			imr.launchTransportSignalQuery(ctx, owner, reason)
		}
	default:
		// Proceed if either option is enabled
		if imr.Options[ImrOptQueryForTransport] == "true" || imr.Options[ImrOptAlwaysQueryForTransport] == "true" {
			imr.launchTransportSignalQuery(ctx, owner, reason)
		}
	}
}

func (imr *Imr) launchTransportSignalQuery(ctx context.Context, owner string, reason string) {
	if owner == "" || ctx == nil || imr.Cache == nil {
		return
	}
	if signal, denied := imr.cachedTransportSignal(owner); signal != nil || denied {
		// The cache holds owner's signal, so there is nothing to look up
		// at owner. When it is an alias the Additional section could not
		// follow to its end, a hop on its path may be missing from the
		// cache: the alias is followed again from the cache, which looks
		// such a hop up once signalAliasHopRetry has passed, rather than
		// only after owner's RRset expires.
		if reason == transportQueryReasonVerify && signal != nil {
			imr.refollowAliasOwner(aliasWalkFor(ctx), owner)
		}
		return
	}
	if !imr.TransportSignalDiscovery.Begin(owner) {
		return
	}
	go func() {
		queryCtx, cancel := transportSignalQueryContext(ctx)
		defer cancel()
		rrtype := imr.TransportSignalRRType()
		if imr.Cache.Debug {
			imr.Cache.Logger.Printf("Transport signal query (%s): querying %s %s", reason, owner, dns.TypeToString[rrtype])
		}
		resp, err := imr.ImrQuery(queryCtx, owner, rrtype, dns.ClassINET, nil)
		if imr.Cache.Debug && (err != nil || resp == nil || resp.RRset == nil || resp.RRset.RRtype != rrtype) {
			imr.Cache.Logger.Printf("Transport signal query (%s) found no signal for %s %s: %v", reason, owner, dns.TypeToString[rrtype], err)
		}
		imr.settleTransportSignalLookup(owner, resp, err)
	}()
}

// transportSignalQueryContext is the context of the transport-signal lookup
// that launchTransportSignalQuery starts for a query made on ctx: detached,
// with a deadline of its own, and marked as a signal lookup's. When ctx is
// part of an alias hop's lookup, so is the signal lookup (aliasWalkFor): the
// AliasMode record in its answer is followed through the cache only, and its
// next hop is left to the walk of an owner outside any hop lookup.
func transportSignalQueryContext(ctx context.Context) (context.Context, context.CancelFunc) {
	queryCtx, cancel := detachedContext(5 * time.Second)
	queryCtx = withTransportSignalLookup(queryCtx)
	if aliasWalkFor(ctx).cacheOnly {
		queryCtx = withSignalAliasHopLookup(queryCtx)
	}
	return queryCtx, cancel
}

// transportSignalLookupKey marks the context of a transport-signal lookup
// (launchTransportSignalQuery), and of everything that lookup asks on the way.
type transportSignalLookupKey struct{}

// withTransportSignalLookup marks ctx as a transport-signal lookup's.
func withTransportSignalLookup(ctx context.Context) context.Context {
	return context.WithValue(ctx, transportSignalLookupKey{}, true)
}

// inTransportSignalLookup reports whether ctx is a transport-signal lookup's.
func inTransportSignalLookup(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	in, _ := ctx.Value(transportSignalLookupKey{}).(bool)
	return in
}

// applyCachedTransportSignal applies the transport signal the cache holds at
// owner, and reports what the cache holds there: the signal, or a denial that
// there is one. With transport signals turned off it applies nothing and
// reports nothing.
//
// A signal reaches a server through the zone server maps it is listed in
// (applyTransportRRsetFromAnswer). A server that was in none when the answer
// came in, because the zone was met afterwards or its address lookup had not
// ended, missed it. It is applied to those servers, and to servers, the ones
// a caller holds, whether or not they are in a zone map yet.
//
// walk is how an AliasMode record in the signal is followed: the caller's
// (aliasWalkFor), so that a query that is part of an alias hop's lookup
// follows a cached alias through the cache only, as it does the one in an
// answer.
func (imr *Imr) applyCachedTransportSignal(walk aliasWalk, owner string, servers ...*cache.AuthServer) (signal, denied bool) {
	if imr.Options[ImrOptUseTransportSignals] == "false" {
		return false, false
	}
	cached, denied := imr.cachedTransportSignal(owner)
	if cached != nil {
		imr.applyTransportRRsetWalk(walk, owner, cached.RRset, cached.State, servers...)
		return true, false
	}
	return false, denied
}

// testHookSignalLookupStarted, when set, runs in awaitTransportSignalsUntil
// between starting or joining a server's signal lookup and asking whether it
// is still running. A test ends the lookup there, in the window a real one
// can end in.
var testHookSignalLookupStarted func(owner string)

// awaitTransportSignals learns the transports of the servers in serverMap
// that have signalled none, for a strict-privacy query that has no server it
// may use. It waits as awaitTransportSignalsUntil does, until a server can
// carry the query under strict privacy.
//
// Without it the first strict query to a zone just met through a referral
// always failed (#776). With always-query-for-transport the referral started
// the lookups, but nothing waited for them; without it nothing looked at all,
// and a strict query, which never goes out in cleartext, could not bring the
// signal in the Additional section either.
func (imr *Imr) awaitTransportSignals(ctx context.Context, qname string, serverMap map[string]*cache.AuthServer) bool {
	return imr.awaitTransportSignalsUntil(ctx, serverMap, transportQueryReasonStrictPrivacy,
		func() bool { return hasStrictCandidate(serverMap, qname) })
}

// awaitTransportSignalsUntil learns the transports of the servers in
// serverMap that have signalled none, for a query that has no server it may
// use. It starts the _dns lookup of each such server, or joins the one
// already running, and waits until ready says a server can carry the query,
// every lookup has ended, the tuning's strict-wait has passed, or ctx is
// done. It reports what ready says then. reason is the lookup's, for
// maybeQueryTransportSignal: strict-privacy and no-usable-transport start a
// lookup whatever the discovery options say, and only
// use-transport-signals: false turns them off; new-auth-server starts one
// only with always-query-for-transport (awaitRunningSignalLookups).
//
// A server whose signal is known is not looked up again, whatever the signal
// says. Nor is one whose signal the cache holds a denial of, until the
// denial expires, or one whose lookup failed and is cooling down. For a zone
// that signals nothing, only the first query after each denial expires
// waits.
//
// A transport-signal lookup, and what it asks on the way, never waits here:
// it could be waiting for itself, or for a lookup that waits for it. Strict
// queries could not anyway: ImrQuery never asks for privacy.
func (imr *Imr) awaitTransportSignalsUntil(ctx context.Context, serverMap map[string]*cache.AuthServer, reason string, ready func() bool) bool {
	if imr.Cache == nil || imr.Options[ImrOptUseTransportSignals] == "false" || inTransportSignalLookup(ctx) {
		return ready()
	}
	type lookup struct {
		server *cache.AuthServer
		owner  string
		done   <-chan struct{}
	}
	var pending []lookup
	for _, server := range serverMap {
		if server == nil || len(server.GetTransportWeights()) > 0 {
			continue
		}
		owner := transportOwnerForNS(server.Name)
		if owner == "" {
			continue
		}
		// A signal already in the cache that never reached this server, or
		// a cached denial: the server signals nothing, until it expires.
		if signal, denied := imr.applyCachedTransportSignal(aliasWalkFor(ctx), owner, server); signal || denied {
			continue
		}
		imr.maybeQueryTransportSignal(ctx, owner, reason)
		if testHookSignalLookupStarted != nil {
			testHookSignalLookupStarted(owner)
		}
		ch := imr.TransportSignalDiscovery.Pending(owner)
		if ch == nil {
			// The lookup may have ended since the check above. Its signal
			// reached the servers in the zone server maps, which this one
			// need not be in yet.
			if len(server.GetTransportWeights()) == 0 {
				imr.applyCachedTransportSignal(aliasWalkFor(ctx), owner, server)
			}
			continue
		}
		pending = append(pending, lookup{server: server, owner: owner, done: ch})
	}
	if ok := ready(); ok || len(pending) == 0 {
		return ok
	}

	wait := imr.Tuning.Discovery.StrictWait
	if wait <= 0 {
		wait = defaultDiscoveryStrictWait
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	// Whichever lookup ends first is looked at first: one that never ends
	// must not hold up the one that has already made a server usable.
	ended := make(chan lookup, len(pending))
	stop := make(chan struct{})
	defer close(stop)
	for _, l := range pending {
		go func(l lookup) {
			select {
			case <-l.done:
				ended <- l
			case <-stop:
			}
		}(l)
	}
	for range pending {
		select {
		case l := <-ended:
			// The lookup applied its signal to the servers in the zone
			// server maps; this one may have been in none.
			if len(l.server.GetTransportWeights()) == 0 {
				imr.applyCachedTransportSignal(aliasWalkFor(ctx), l.owner, l.server)
			}
		case <-timer.C:
			return ready()
		case <-ctx.Done():
			return ready()
		}
		if ready() {
			return true
		}
	}
	return ready()
}

func (imr *Imr) maybeQueryTLSA(ctx context.Context, base string) {
	if imr.Cache == nil || ctx == nil || imr.Options[ImrOptQueryForTransportTLSA] != "true" {
		return
	}
	base = dns.Fqdn(strings.TrimSpace(base))
	if base == "." || base == "" {
		return
	}
	targets := []string{
		dns.Fqdn(fmt.Sprintf("_853._udp.%s", base)),
		dns.Fqdn(fmt.Sprintf("_853._tcp.%s", base)),
	}
	for _, owner := range targets {
		if !imr.TLSADiscovery.Begin(owner) {
			continue
		}
		go func(owner string) {
			queryCtx, cancel := detachedContext(5 * time.Second)
			defer cancel()
			resp, err := imr.ImrQuery(queryCtx, owner, dns.TypeTLSA, dns.ClassINET, nil)
			if err != nil || resp == nil || resp.RRset == nil || len(resp.RRset.RRs) == 0 {
				imr.TLSADiscovery.Fail(owner, err)
				return
			}
			rr := resp.RRset
			vstate := cache.ValidationStateNone
			if len(rr.RRSIGs) > 0 {
				vstate, err = imr.Cache.ValidateRRsetWithParentZone(queryCtx, rr, imr.IterativeDNSQueryFetcher(), imr.ParentZone)
				if err != nil {
					lgImr.Warn("maybeQueryTLSA: failed to validate TLSA RRset", "err", err)
					imr.TLSADiscovery.Fail(owner, err)
					return
				}
			}
			baseHint := baseFromTLSAOwner(owner)
			imr.Cache.StoreTLSAForServer(baseHint, owner, rr, vstate)
			imr.TLSADiscovery.Succeed(owner)
		}(owner)
	}
}

func tlsaOwnersForServer(base string, server *cache.AuthServer) []string {
	base = dns.Fqdn(strings.TrimSpace(base))
	if base == "." || base == "" {
		return nil
	}
	owners := map[string]struct{}{}
	addOwner := func(proto string) {
		owner := dns.Fqdn(fmt.Sprintf("_853._%s.%s", proto, base))
		owners[owner] = struct{}{}
	}
	if server != nil {
		for _, t := range server.GetTransports() {
			switch t {
			case core.TransportDoT:
				addOwner("tcp")
			case core.TransportDoQ:
				addOwner("udp")
			}
		}
	}
	if len(owners) == 0 {
		addOwner("tcp")
	}
	var result []string
	for owner := range owners {
		result = append(result, owner)
	}
	sort.Strings(result)
	return result
}

func baseFromTLSAOwner(owner string) string {
	owner = dns.Fqdn(strings.TrimSpace(owner))
	if owner == "." || owner == "" {
		return ""
	}
	prefixes := []string{"_853._udp.", "_853._tcp."}
	canon := core.CanonicalizeName(owner)
	for _, prefix := range prefixes {
		if strings.HasPrefix(canon, prefix) {
			return core.TrimLeadingLabels(owner, dns.CountLabel(prefix))
		}
	}
	return ""
}

func cloneRRs(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		out = append(out, dns.Copy(rr))
	}
	return out
}
