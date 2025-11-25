/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	core "github.com/johanix/tdns/tdns/core"
	cache "github.com/johanix/tdns/tdns/cache"
	"github.com/miekg/dns"
)

const (
	transportQueryReasonObservation = "opportunistic-signal"
	transportQueryReasonNewServer   = "new-auth-server"
)

func (imr *Imr) maybeQueryTransportSignal(ctx context.Context, owner string, reason string) {
	if owner == "" || imr.Cache == nil || ctx == nil {
		return
	}
	switch reason {
	case transportQueryReasonObservation:
		if !(imr.Options[ImrOptQueryForTransport] != "true" || imr.Options[ImrOptAlwaysQueryForTransport] != "true") {
			return
		}
	case transportQueryReasonNewServer:
		if imr.Options[ImrOptAlwaysQueryForTransport] != "true" {
			return
		}
	default:
		if !(imr.Options[ImrOptQueryForTransport] != "true" || imr.Options[ImrOptAlwaysQueryForTransport] != "true") {
			return
		}
	}
	imr.launchTransportSignalQuery(ctx, owner, reason)
}

func (imr *Imr) launchTransportSignalQuery(ctx context.Context, owner string, reason string) {
	if owner == "" || ctx == nil || imr.Cache == nil {
		return
	}
	if imr.Cache.TransportSignalCached(owner) {
		return
	}
	if !imr.Cache.MarkTransportQuery(owner) {
		return
	}
	go func() {
		defer imr.Cache.ClearTransportQuery(owner)
		queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		rrtype := imr.Cache.TransportSignalRRType()
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
			validated := false
			if len(rr.RRSIGs) > 0 {
				if ok, _ := imr.Cache.ValidateRRset(queryCtx, cache.DnskeyCache, rr, imr.IterativeDNSQueryFetcher(), imr.Cache.Debug); ok {
					validated = true
				}
			}
			baseHint := baseFromTLSAOwner(owner)
			imr.Cache.StoreTLSAForServer(baseHint, owner, rr, validated)
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

// XXX: Is this still in use?
func (imr *Imr) PrimeWithHints(hintsfile string) error {
	// Verify root hints file exists
	if _, err := os.Stat(hintsfile); err != nil {
		return fmt.Errorf("Root hints file %s not found: %v", hintsfile, err)
	}

	log.Printf("PrimeWithHints: reading root hints %s", hintsfile)
	// Read and parse root hints file
	data, err := os.ReadFile(hintsfile)
	if err != nil {
		return fmt.Errorf("Error reading root hints file %s: %v", hintsfile, err)
	}
	zp := dns.NewZoneParser(strings.NewReader(string(data)), ".", hintsfile)
	zp.SetIncludeAllowed(true)

	// Maps to collect NS and A/AAAA records
	nsRecords := []dns.RR{}
	glueRecords := map[string][]dns.RR{}
	nsMap := map[string]bool{}
	authMap := map[string]*cache.AuthServer{}

	var rootns []string

	// Parse all records from the root hints file
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		switch rr.Header().Rrtype {
		case dns.TypeNS:
			if rr.Header().Name != "." {
				log.Printf("Non-root NS record among hints: %v. Ignored.", rr.String())
				continue
			}
			nsRecords = append(nsRecords, rr)
			nsname := rr.(*dns.NS).Ns
			nsMap[nsname] = true
			authMap[nsname] = &cache.AuthServer{
				Name:          nsname,
				Alpn:          []string{"do53"},
				Transports:    []core.Transport{core.TransportDo53},
				Src:           "hint",
				PrefTransport: core.TransportDo53,
			}
			rootns = append(rootns, nsname)
			log.Printf("PrimeWithHints: adding server for root: name %q: %+v", nsname, authMap[nsname])

		case dns.TypeA, dns.TypeAAAA:
			// log.Printf("PWH: read address RR: %s", rr.String())
			name := rr.Header().Name
			glueRecords[name] = append(glueRecords[name], rr)
		}
	}

	if err := zp.Err(); err != nil {
		return fmt.Errorf("Error parsing root hints file %s: %v", hintsfile, err)
	}

	// Store NS records for root
	if len(nsRecords) > 0 {
		log.Printf("Found %d NS RRs", len(nsRecords))
		imr.Cache.Set(".", dns.TypeNS, &cache.CachedRRset{
			Name:    ".",
			RRtype:  dns.TypeNS,
			Context: cache.ContextHint,
			RRset: &core.RRset{
				Name:   ".",
				RRtype: dns.TypeNS,
				Class:  dns.ClassINET,
				RRs:    nsRecords,
				RRSIGs: nil, // No DNSSEC in root hints
			},
		})
	} else {
		return fmt.Errorf("No NS records found in root hints file %s", hintsfile)
	}

	// Store root zone data
	// cache.Data["."] = rootData
	var servers []string

	// Store glue records for root nameservers
	log.Printf("Found %d glue records", len(glueRecords))
	for name, rrs := range glueRecords {
		if !nsMap[name] {
			log.Printf("*** Glue record for a non-root nameserver found: %v. Ignored.", name)
			continue
		}

		// Group records by type (A or AAAA)
		typeGroups := map[uint16][]dns.RR{}
		tmpsrv := authMap[name]
		for _, rr := range rrs {
			rrtype := rr.Header().Rrtype
			typeGroups[rrtype] = append(typeGroups[rrtype], rr)
			switch rr.Header().Rrtype {
			case dns.TypeA:
				servers = append(servers, net.JoinHostPort(rr.(*dns.A).A.String(), "53"))
				tmpsrv.Addrs = append(tmpsrv.Addrs, rr.(*dns.A).A.String())
			case dns.TypeAAAA:
				servers = append(servers, net.JoinHostPort(rr.(*dns.AAAA).AAAA.String(), "53"))
				tmpsrv.Addrs = append(tmpsrv.Addrs, rr.(*dns.AAAA).AAAA.String())
			}
		}
		authMap[name] = tmpsrv
		log.Printf("PrimeWithHints: adding addrs to server for root: name %q: %+v", name, authMap[name])

		// Create RRset for each type
		for rrtype, records := range typeGroups {
			imr.Cache.Set(name, rrtype, &cache.CachedRRset{
				Name:    name,
				RRtype:  rrtype,
				Context: cache.ContextHint,
				RRset: &core.RRset{
					Name:   name,
					Class:  dns.ClassINET,
					RRtype: rrtype,
					RRs:    records,
					RRSIGs: nil, // No DNSSEC in root hints
				},
			})
		}

		// cache.Data[name] = ownerData
	}

	imr.Cache.ServerMap.Set(".", authMap)
	imr.Cache.Servers.Set(".", servers)

	log.Printf("PrimeWithHints: serverMap:")
	for k, v := range authMap {
		log.Printf("server: %q data: %+v", k, v)
	}

	// dump.P(authMap)

	// rrset, _, _, err := rrcache.IterativeDNSQuery(".", dns.TypeNS, rootns, true) // force re-query bypassing cache
	rrset, _, _, err := imr.IterativeDNSQuery(context.Background(), ".", dns.TypeNS, authMap, Globals.Debug) // force re-query bypassing cache
	if err != nil {
		return fmt.Errorf("Error priming RRsetCache with root hints: %v", err)
	}
	if rrset == nil {
		return fmt.Errorf("No NS records found in root hints file %s", hintsfile)
	}

	log.Printf("*** RRsetCache: primed with these roots: %v", rootns)

	imr.Cache.SetPrimed(true)

	return nil
}

func XXXgetMinTTL(rrs []dns.RR) time.Duration {
	if len(rrs) == 0 {
		return 0
	}
	min := rrs[0].Header().Ttl
	for _, rr := range rrs[1:] {
		if rr.Header().Ttl < min {
			min = rr.Header().Ttl
		}
	}
	return time.Duration(min) * time.Second
}
