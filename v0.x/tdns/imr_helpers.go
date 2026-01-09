/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	cache "github.com/johanix/tdns/v0.x/tdns/cache"
	core "github.com/johanix/tdns/v0.x/tdns/core"
	"github.com/miekg/dns"
)

const (
	transportQueryReasonObservation = "opportunistic-signal"
	transportQueryReasonNewServer   = "new-auth-server"
)

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
	if !imr.Cache.MarkTransportQuery(owner) {
		return
	}
	go func() {
		defer imr.Cache.ClearTransportQuery(owner)
		queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		rrtype := imr.TransportSignalRRType()
		if imr.Cache.Debug {
			imr.Cache.Logger.Printf("Transport signal query (%s): querying %s %s", reason, owner, dns.TypeToString[rrtype])
		}
		if _, err := imr.ImrQuery(queryCtx, owner, rrtype, dns.ClassINET, nil); err != nil {
			if imr.Cache.Debug {
				imr.Cache.Logger.Printf("Transport signal query (%s) failed for %s %s: %v", reason, owner, dns.TypeToString[rrtype], err)
			}
		}
	}()
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
		if !imr.Cache.MarkTLSAQuery(owner) {
			continue
		}
		go func(owner string) {
			defer imr.Cache.ClearTLSAQuery(owner)
			queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			resp, err := imr.ImrQuery(queryCtx, owner, dns.TypeTLSA, dns.ClassINET, nil)
			if err != nil || resp == nil || resp.RRset == nil || len(resp.RRset.RRs) == 0 {
				return
			}
			rr := resp.RRset
			vstate := cache.ValidationStateNone
			if len(rr.RRSIGs) > 0 {
				vstate, err = imr.Cache.ValidateRRsetWithParentZone(queryCtx, rr, imr.IterativeDNSQueryFetcher(), imr.ParentZone)
				if err != nil {
					log.Printf("maybeQueryTLSA: failed to validate TLSA RRset: %v", err)
					return
				}
			}
			baseHint := baseFromTLSAOwner(owner)
			imr.Cache.StoreTLSAForServer(baseHint, owner, rr, vstate)
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
	for _, prefix := range prefixes {
		if strings.HasPrefix(owner, prefix) {
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
