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

func (imr *Imr) TransportSignalCached(owner string) bool {
	if owner == "" || imr == nil {
		return false
	}
	if c := imr.Cache.Get(owner, imr.TransportSignalRRType()); c != nil && c.RRset != nil && len(c.RRset.RRs) > 0 {
		return true
	}
	return false
}

func (imr *Imr) maybeQueryTransportSignal(ctx context.Context, owner string, reason string) {
	if owner == "" || imr.Cache == nil || ctx == nil {
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
	case transportQueryReasonStrictPrivacy:
		// A strict query cannot use a server whose transports it does not
		// know, so it looks them up whether or not the options ask for
		// discovery. Only use-transport-signals: false turns signals off.
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
	if imr.TransportSignalCached(owner) {
		return
	}
	if !imr.TransportSignalDiscovery.Begin(owner) {
		return
	}
	go func() {
		queryCtx, cancel := detachedContext(5 * time.Second)
		defer cancel()
		rrtype := imr.TransportSignalRRType()
		if imr.Cache.Debug {
			imr.Cache.Logger.Printf("Transport signal query (%s): querying %s %s", reason, owner, dns.TypeToString[rrtype])
		}
		resp, err := imr.ImrQuery(queryCtx, owner, rrtype, dns.ClassINET, nil)
		if err != nil || resp == nil || resp.RRset == nil || len(resp.RRset.RRs) == 0 {
			if imr.Cache.Debug {
				imr.Cache.Logger.Printf("Transport signal query (%s) failed for %s %s: %v", reason, owner, dns.TypeToString[rrtype], err)
			}
			imr.TransportSignalDiscovery.Fail(owner, err)
			return
		}
		imr.TransportSignalDiscovery.Succeed(owner)
	}()
}

// awaitTransportSignals learns the transports of the servers in serverMap
// that have signalled none, for a strict-privacy query that has no server it
// may use. It starts the _dns lookup of each such server, or joins the one
// already running, and waits until a server can carry the query, every lookup
// has ended, the tuning's strict-wait has passed, or ctx is done. It reports
// whether a server can carry the query now.
//
// Without it the first strict query to a zone just met through a referral
// always failed (#776). With always-query-for-transport the referral started
// the lookups, but nothing waited for them; without it nothing looked at all,
// and a strict query, which never goes out in cleartext, could not bring the
// signal in the Additional section either.
//
// The lookup itself goes out through ImrQuery, which never asks for privacy,
// so it cannot come back here and wait on itself. A server whose signal is
// known is not looked up again, whatever the signal says, and neither is one
// whose lookup failed and is cooling down: for a zone that signals nothing,
// only the first query waits.
func (imr *Imr) awaitTransportSignals(ctx context.Context, qname string, serverMap map[string]*cache.AuthServer) bool {
	if imr.Cache == nil || imr.Options[ImrOptUseTransportSignals] == "false" {
		return false
	}
	var pending []<-chan struct{}
	for _, server := range serverMap {
		if server == nil || len(server.GetTransportWeights()) > 0 {
			continue
		}
		owner := transportOwnerForNS(server.Name)
		if owner == "" {
			continue
		}
		// A signal already in the cache that never reached this server: the
		// server was not in any zone's map when the answer was applied.
		if c := imr.Cache.Get(owner, imr.TransportSignalRRType()); c != nil && c.RRset != nil && len(c.RRset.RRs) > 0 {
			imr.applyTransportRRsetFromAnswer(owner, c.RRset, c.State)
			continue
		}
		imr.maybeQueryTransportSignal(ctx, owner, transportQueryReasonStrictPrivacy)
		if ch := imr.TransportSignalDiscovery.Pending(owner); ch != nil {
			pending = append(pending, ch)
		}
	}
	if ok := hasStrictCandidate(serverMap, qname); ok || len(pending) == 0 {
		return ok
	}

	wait := imr.Tuning.Discovery.StrictWait
	if wait <= 0 {
		wait = defaultDiscoveryStrictWait
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for _, ch := range pending {
		select {
		case <-ch:
		case <-timer.C:
			return hasStrictCandidate(serverMap, qname)
		case <-ctx.Done():
			return hasStrictCandidate(serverMap, qname)
		}
		if hasStrictCandidate(serverMap, qname) {
			return true
		}
	}
	return hasStrictCandidate(serverMap, qname)
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
		for _, t := range server.Transports {
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
			return owner[len(prefix):]
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
