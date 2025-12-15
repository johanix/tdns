/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	core "github.com/johanix/tdns/tdns/core"
	"github.com/miekg/dns"
	cmap "github.com/orcaman/concurrent-map/v2"
)

// This is still global, but also present in the RRsetCacheT struct
var DnskeyCache = NewDnskeyCache()

func NewDnskeyCache() *DnskeyCacheT {
	return &DnskeyCacheT{
		Map: cmap.New[CachedDnskeyRRset](),
	}
}

func (dkc *DnskeyCacheT) Get(zonename string, keyid uint16) *CachedDnskeyRRset {
	lookupKey := fmt.Sprintf("%s::%d", zonename, keyid)
	tmp, ok := dkc.Map.Get(lookupKey)
	if !ok {
		return nil
	}
	if tmp.Expiration.Before(time.Now()) {
		dkc.Map.Remove(lookupKey)
		// if dkc.Debug {
		//	log.Printf("DnskeyCache: Removed expired key %s", lookupKey)
		//}
		return nil
	}
	return &tmp
}

func (dkc *DnskeyCacheT) Set(zonename string, keyid uint16, cdr *CachedDnskeyRRset) {
	lookupKey := fmt.Sprintf("%s::%d", zonename, keyid)
	dkc.Map.Set(lookupKey, *cdr)
}

// var RRsetCache = NewRRsetCache()

// func NewRRsetCache(lg *log.Logger, verbose, debug bool, options map[ImrOption]string) *RRsetCacheT {
func NewRRsetCache(lg *log.Logger, verbose, debug bool) *RRsetCacheT {
	var client = map[core.Transport]*core.DNSClient{}

	client[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, "53", nil)
	client[core.TransportDoT] = core.NewDNSClient(core.TransportDoT, "853", nil)
	client[core.TransportDoH] = core.NewDNSClient(core.TransportDoH, "443", nil)
	client[core.TransportDoQ] = core.NewDNSClient(core.TransportDoQ, "8853", nil)

	return &RRsetCacheT{
		RRsets:                 core.NewCmap[CachedRRset](),
		Servers:                core.NewCmap[[]string](),               // servers stored as []string{ "1.2.3.4:53", "9.8.7.6:53"}
		ServerMap:              core.NewCmap[map[string]*AuthServer](), // servers stored as map[nsname]*AuthServer{}
		AuthServerMap:          core.NewCmap[*AuthServer](),            // Global map: nsname -> *AuthServer (ensures single instance per nameserver)
		ZoneMap:                core.NewCmap[*Zone](),                  // zone -> *Zone
		DnskeyCache:            DnskeyCache,
		Logger:                 lg,
		LineWidth:              130, // default line width for truncating long lines in logging and output
		Verbose:                verbose,
		Debug:                  debug,
		DNSClient:              client,
		transportQueryInFlight: make(map[string]struct{}),
		nsRevalidateInFlight:   make(map[string]struct{}),
		tlsaQueryInFlight:      make(map[string]struct{}),
	}
}

func (rrcache *RRsetCacheT) Get(qname string, qtype uint16) *CachedRRset {

	lookupKey := fmt.Sprintf("%s::%d", qname, qtype)
	crrset, ok := rrcache.RRsets.Get(lookupKey)
	if !ok {
		return nil
	}
	// Expiration-based eviction
	if crrset.Expiration.Before(time.Now()) {
		rrcache.RRsets.Remove(lookupKey)
		if rrcache.Debug {
			log.Printf("RRsetCache: Removed expired key %s (%s)", lookupKey, dns.TypeToString[qtype])
		}
		// If an NS RRset expired, also remove its server mappings for that zone
		if qtype == dns.TypeNS {
			rrcache.ServerMap.Remove(qname)
			if rrcache.Debug {
				log.Printf("RRsetCache: Removed ServerMap entry for zone %s due to NS expiry", qname)
			}
		}
		return nil
	}
	return &crrset
}

func (rrcache *RRsetCacheT) Set(qname string, qtype uint16, crrset *CachedRRset) {
	lookupKey := fmt.Sprintf("%s::%d", qname, qtype)
	if rrcache.Debug {
		fmt.Printf("rrcache: Adding key %s (%s) to cache\n", lookupKey, dns.TypeToString[qtype])
	}

	if crrset == nil {
		log.Printf("RRsetCache:Set: nil crrset for key %s - ignored", lookupKey)
		return
	}

	// Compute min TTL and set Expiration accordingly when RRset present
	if crrset.RRset != nil && len(crrset.RRset.RRs) > 0 {
		minTTL := crrset.RRset.RRs[0].Header().Ttl
		for _, rr := range crrset.RRset.RRs[1:] {
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
		// Apply a small TTL floor for NS RRsets only when learned via referral, to avoid instant drop
		if qtype == dns.TypeNS && crrset.Context == ContextReferral && minTTL == 0 {
			if rrcache.Debug {
				log.Printf("RRsetCache:Set: NS minTTL was 0 for %q (Context=Referral); applying floor 10s", qname)
			}
			minTTL = 10
		}
		if rrcache.Debug && qtype == dns.TypeNS {
			log.Printf("RRsetCache:Set: NS minTTL=%ds for zone %q (Context=%s)", minTTL, qname, CacheContextToString[crrset.Context])
		}
		crrset.Ttl = minTTL
		crrset.Expiration = time.Now().Add(time.Duration(minTTL) * time.Second)
	} else if crrset.Expiration.IsZero() && crrset.Ttl > 0 {
		// For negative/no-RRset entries, if Expiration not set but TTL is provided
		crrset.Expiration = time.Now().Add(time.Duration(crrset.Ttl) * time.Second)
	}

	rrcache.RRsets.Set(lookupKey, *crrset)
}

// FlushDomain removes cached RRsets at or below the provided domain.
// When keepStructural is true, NS/DS/DNSKEY RRsets and the address
// records for their nameservers are preserved.
func (rrcache *RRsetCacheT) FlushDomain(domain string, keepStructural bool) (int, error) {
	if rrcache == nil {
		return 0, fmt.Errorf("rrcache is nil")
	}
	domain = dns.CanonicalName(domain)
	if domain == "" || domain == "." {
		return 0, fmt.Errorf("invalid domain %q", domain)
	}

	var nsHosts map[string]struct{}
	if keepStructural {
		nsHosts = make(map[string]struct{})
		for item := range rrcache.RRsets.IterBuffered() {
			cr := item.Val
			if cr.Name == "" || !isSubdomainOf(cr.Name, domain) {
				continue
			}
			if cr.RRtype != dns.TypeNS || cr.RRset == nil {
				continue
			}
			for _, rr := range cr.RRset.RRs {
				ns, ok := rr.(*dns.NS)
				if !ok {
					continue
				}
				nsHosts[dns.CanonicalName(ns.Ns)] = struct{}{}
			}
		}
	}

	var keysToRemove []string
	for item := range rrcache.RRsets.IterBuffered() {
		key := item.Key
		cr := item.Val
		if cr.Name == "" || !isSubdomainOf(cr.Name, domain) {
			continue
		}
		if keepStructural && isStructuralRRset(&cr, nsHosts) {
			continue
		}
		keysToRemove = append(keysToRemove, key)
	}

	for _, key := range keysToRemove {
		rrcache.RRsets.Remove(key)
	}
	removed := len(keysToRemove)

	if !keepStructural && removed > 0 {
		var auxKeys []string
		for item := range rrcache.Servers.IterBuffered() {
			if isSubdomainOf(item.Key, domain) {
				auxKeys = append(auxKeys, item.Key)
			}
		}
		for _, key := range auxKeys {
			rrcache.Servers.Remove(key)
		}
		auxKeys = auxKeys[:0]
		for item := range rrcache.ServerMap.IterBuffered() {
			if isSubdomainOf(item.Key, domain) {
				auxKeys = append(auxKeys, item.Key)
			}
		}
		for _, key := range auxKeys {
			rrcache.ServerMap.Remove(key)
		}
	}

	return removed, nil
}

func isStructuralRRset(cr *CachedRRset, nsHosts map[string]struct{}) bool {
	if cr == nil {
		return false
	}
	switch cr.RRtype {
	case dns.TypeNS, dns.TypeDS, dns.TypeDNSKEY:
		return true
	case dns.TypeA, dns.TypeAAAA:
		if nsHosts == nil {
			return false
		}
		_, ok := nsHosts[dns.CanonicalName(cr.Name)]
		return ok
	default:
		return false
	}
}

func isSubdomainOf(name, parent string) bool {
	name = dns.CanonicalName(name)
	parent = dns.CanonicalName(parent)
	if parent == "." {
		return true
	}
	if name == parent {
		return true
	}
	suffix := "." + strings.TrimSuffix(parent, ".") + "."
	return strings.HasSuffix(name, suffix)
}

const (
	transportQueryReasonObservation = "opportunistic-signal"
	transportQueryReasonNewServer   = "new-auth-server"
)

func (rrcache *RRsetCacheT) MarkTransportQuery(owner string) bool {
	rrcache.transportQueryMu.Lock()
	defer rrcache.transportQueryMu.Unlock()
	if rrcache.transportQueryInFlight == nil {
		rrcache.transportQueryInFlight = make(map[string]struct{})
	}
	if _, exist := rrcache.transportQueryInFlight[owner]; exist {
		return false
	}
	rrcache.transportQueryInFlight[owner] = struct{}{}
	return true
}

func (rrcache *RRsetCacheT) ClearTransportQuery(owner string) {
	rrcache.transportQueryMu.Lock()
	defer rrcache.transportQueryMu.Unlock()
	if rrcache.transportQueryInFlight == nil {
		return
	}
	delete(rrcache.transportQueryInFlight, owner)
}

func (rrcache *RRsetCacheT) lookupSOARRset(name string) *core.RRset {
	if rrcache == nil {
		return nil
	}
	cur := dns.Fqdn(strings.TrimSpace(name))
	visitedRoot := false
	for cur != "" {
		if c := rrcache.Get(cur, dns.TypeSOA); c != nil && c.RRset != nil && len(c.RRset.RRs) > 0 {
			return c.RRset
		}
		if cur == "." {
			if visitedRoot {
				break
			}
			visitedRoot = true
			continue
		}
		labels := dns.SplitDomainName(cur)
		if len(labels) <= 1 {
			cur = "."
			continue
		}
		cur = strings.Join(labels[1:], ".") + "."
	}
	return nil
}

func (rrcache *RRsetCacheT) MarkTLSAQuery(owner string) bool {
	rrcache.tlsaQueryMu.Lock()
	defer rrcache.tlsaQueryMu.Unlock()
	if rrcache.tlsaQueryInFlight == nil {
		rrcache.tlsaQueryInFlight = make(map[string]struct{})
	}
	if _, ok := rrcache.tlsaQueryInFlight[owner]; ok {
		return false
	}
	rrcache.tlsaQueryInFlight[owner] = struct{}{}
	return true
}

func (rrcache *RRsetCacheT) ClearTLSAQuery(owner string) {
	rrcache.tlsaQueryMu.Lock()
	defer rrcache.tlsaQueryMu.Unlock()
	if rrcache.tlsaQueryInFlight == nil {
		return
	}
	delete(rrcache.tlsaQueryInFlight, owner)
}

// A stub is a static mapping from a zone name to a list of addresses (later probably AuthServers)
func (rrcache *RRsetCacheT) AddStub(zone string, servers []AuthServer) error {
	authservers := map[string]*AuthServer{}
	for _, server := range servers {
		tmpauthserver := &AuthServer{
			Name:     server.Name,
			Addrs:    server.Addrs,
			Alpn:     server.Alpn,
			Src:      "stub",
			ConnMode: server.ConnMode,
		}
		// New: prefer explicit transport signal string when provided
		if server.TransportSignal != "" {
			kvMap, err := core.ParseTransportString(server.TransportSignal)
			if err != nil {
				log.Printf("AddStub: invalid transport string for %s: %q: %v", server.Name, server.TransportSignal, err)
			} else {
				// build weights and order by weight desc (stable)
				type pair struct {
					k string
					w uint8
				}
				var pairs []pair
				for k, v := range kvMap {
					pairs = append(pairs, pair{k: k, w: v})
				}
				slices.SortFunc(pairs, func(a, b pair) int {
					if a.w == b.w {
						if a.k < b.k {
							return -1
						}
						if a.k > b.k {
							return 1
						}
						return 0
					}
					if a.w > b.w {
						return -1
					}
					return 1
				})
				var transports []core.Transport
				var alpnOrder []string
				weights := map[core.Transport]uint8{}
				for _, p := range pairs {
					t, err := core.StringToTransport(p.k)
					if err != nil {
						log.Printf("AddStub: unknown transport %q for %s", p.k, server.Name)
						continue
					}
					transports = append(transports, t)
					alpnOrder = append(alpnOrder, p.k)
					weights[t] = p.w
				}
				tmpauthserver.Alpn = alpnOrder
				tmpauthserver.Transports = transports
				if len(transports) > 0 {
					tmpauthserver.PrefTransport = transports[0]
				}
				tmpauthserver.TransportWeights = weights
			}
		} else {
			// Back-compat: use ALPN order to set transports (no weights)
			if len(server.Alpn) == 0 {
				tmpauthserver.Alpn = []string{"do53"}
				tmpauthserver.Transports = []core.Transport{core.TransportDo53}
				tmpauthserver.TransportWeights = map[core.Transport]uint8{core.TransportDo53: 100}
				tmpauthserver.PrefTransport = core.TransportDo53
			} else {
				tmpauthserver.Alpn = server.Alpn
				var transports []core.Transport
				weights := map[core.Transport]uint8{}
				for _, alpn := range server.Alpn {
					if t, err := core.StringToTransport(alpn); err == nil {
						transports = append(transports, t)
						weights[t] = 100
					}
				}
				tmpauthserver.Transports = transports
				tmpauthserver.TransportWeights = weights
				if len(transports) > 0 {
					tmpauthserver.PrefTransport = transports[0]
				}
			}
		}
		authservers[server.Name] = tmpauthserver
	}
	if rrcache.Debug {
		fmt.Printf("rrcache: Adding stubs for zone %s to cache\n", zone)
	}
	rrcache.ServerMap.Set(zone, authservers)
	return nil
}

func (rrcache *RRsetCacheT) AddServers(zone string, sm map[string]*AuthServer) error {
	serverMapOrig, ok := rrcache.ServerMap.Get(zone)

	// Create a copy of the map to avoid concurrent map read/write errors
	// The original map is stored in a concurrent map and may be read by other goroutines
	serverMap := make(map[string]*AuthServer)
	if ok {
		for k, v := range serverMapOrig {
			serverMap[k] = v
		}
	}

	for name, server := range sm {
		// Ensure we use a shared AuthServer instance across all zones
		sharedServer := rrcache.GetOrCreateAuthServer(name)

		// Merge data from the input server into the shared instance
		for _, addr := range server.Addrs {
			if !slices.Contains(sharedServer.Addrs, addr) {
				sharedServer.Addrs = append(sharedServer.Addrs, addr)
			}
		}
		for _, alpn := range server.Alpn {
			t, err := core.StringToTransport(alpn)
			if err != nil {
				log.Printf("rrcache.AddServers: error from StringToTransport: %v", err)
				continue
			}
			if !slices.Contains(sharedServer.Alpn, alpn) {
				sharedServer.Alpn = append(sharedServer.Alpn, alpn)
			}
			if !slices.Contains(sharedServer.Transports, t) {
				sharedServer.Transports = append(sharedServer.Transports, t)
			}
		}
		// Merge/overwrite transport weights if provided
		if len(server.TransportWeights) > 0 {
			if sharedServer.TransportWeights == nil {
				sharedServer.TransportWeights = make(map[core.Transport]uint8)
			}
			for k, v := range server.TransportWeights {
				sharedServer.TransportWeights[k] = v
			}
		}
		// Update other fields if they're more specific
		if server.Src != "" && (sharedServer.Src == "" || sharedServer.Src == "unknown") {
			sharedServer.Src = server.Src
		}
		if server.ConnMode != ConnModeLegacy && sharedServer.ConnMode == ConnModeLegacy {
			sharedServer.ConnMode = server.ConnMode
		}
		if server.Debug && !sharedServer.Debug {
			sharedServer.Debug = server.Debug
		}

		// Always assign the shared instance to this zone's map
		serverMap[name] = sharedServer

		// Set preferred transport if we have valid transports
		if len(sharedServer.Transports) > 0 {
			sharedServer.PrefTransport = sharedServer.Transports[0]
		}
	}
	if rrcache.Debug {
		fmt.Printf("rrcache: Adding servers for zone %s to cache\n", zone)
	}
	rrcache.ServerMap.Set(zone, serverMap)
	return nil
}

// GetOrCreateAuthServer returns an existing AuthServer instance for the given nameserver name,
// or creates a new one if it doesn't exist. This ensures there is only one AuthServer instance
// per nameserver name across all zones. Uses O(1) map lookup instead of iterating through zones.
func (rrcache *RRsetCacheT) GetOrCreateAuthServer(nsname string) *AuthServer {
	// Try to get existing instance from global map (O(1) lookup)
	if existing, ok := rrcache.AuthServerMap.Get(nsname); ok {
		return existing
	}

	// No instance exists - create a new one
	newServer := &AuthServer{
		Name:       nsname,
		Alpn:       []string{"do53"},
		Transports: []core.Transport{core.TransportDo53},
		Src:        "unknown",
		ConnMode:   ConnModeLegacy,
	}

	// Store it in the global map (use SetIfAbsent to handle race conditions)
	if rrcache.AuthServerMap.SetIfAbsent(nsname, newServer) {
		// We successfully added the new server
		return newServer
	}

	// Another goroutine created it between our Get and SetIfAbsent - get the existing one
	existing, _ := rrcache.AuthServerMap.Get(nsname)
	return existing
}

func tlsaOwnersForServer(base string, server *AuthServer) []string {
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

func (rrcache *RRsetCacheT) StoreTLSAForServer(base, owner string, rrset *core.RRset, vstate ValidationState) {
	if rrcache == nil || rrset == nil || len(rrset.RRs) == 0 {
		return
	}
	base = dns.Fqdn(strings.TrimSpace(base))
	if base == "." || base == "" {
		return
	}
	owner = dns.Fqdn(strings.TrimSpace(owner))
	if owner == "." || owner == "" {
		return
	}
	for zone, sm := range rrcache.ServerMap.Items() {
		server, ok := sm[base]
		if !ok {
			continue
		}
		server.mu.Lock()
		if server.TLSARecords == nil {
			server.TLSARecords = make(map[string]*CachedRRset)
		}
		server.TLSARecords[owner] = &CachedRRset{
			Name:   owner,
			RRtype: dns.TypeTLSA,
			RRset: &core.RRset{
				Name:   owner,
				Class:  dns.ClassINET,
				RRtype: dns.TypeTLSA,
				RRs:    cloneRRs(rrset.RRs),
				RRSIGs: cloneRRs(rrset.RRSIGs),
			},
			Context:    ContextAnswer,
			State:      vstate,
			Expiration: time.Now().Add(GetMinTTL(rrset.RRs)),
		}
		server.mu.Unlock()
		rrcache.ServerMap.Set(zone, sm)
	}
}

func (rrcache *RRsetCacheT) SetPrimed(primed bool) {
	rrcache.Primed = primed
}

func (rrcache *RRsetCacheT) IsPrimed() bool {
	return rrcache.Primed
}

func (rrcache *RRsetCacheT) PrimeWithHints(hintsfile string, fetcher RRsetFetcher) error {
	var data []byte
	var err error
	var source string

	// If no hints file is configured, use compiled-in hints
	if hintsfile == "" || strings.TrimSpace(hintsfile) == "" {
		if !rrcache.Quiet {
			log.Printf("PrimeWithHints: no root-hints config provided, using compiled-in root hints")
		}
		data = []byte(CompiledInRootHints)
		source = "compiled-in"
	} else {
		// Verify root hints file exists
		if _, err := os.Stat(hintsfile); err != nil {
			return fmt.Errorf("Root hints file %s not found: %v", hintsfile, err)
		}

		log.Printf("PrimeWithHints: reading root hints from file %s", hintsfile)
		// Read and parse root hints file
		data, err = os.ReadFile(hintsfile)
		if err != nil {
			return fmt.Errorf("Error reading root hints file %s: %v", hintsfile, err)
		}
		source = hintsfile
	}

	zp := dns.NewZoneParser(strings.NewReader(string(data)), ".", source)
	zp.SetIncludeAllowed(true)

	// Maps to collect NS and A/AAAA records
	nsRecords := []dns.RR{}
	glueRecords := map[string][]dns.RR{}
	nsMap := map[string]bool{}
	authMap := map[string]*AuthServer{}

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
			// Use shared AuthServer instance (ensures single instance per nameserver)
			server := rrcache.GetOrCreateAuthServer(nsname)
			if server.Src == "" || server.Src == "unknown" {
				server.Src = "hint"
			}
			if len(server.Transports) == 0 {
				server.Transports = []core.Transport{core.TransportDo53}
			}
			if server.PrefTransport == 0 {
				server.PrefTransport = core.TransportDo53
			}
			authMap[nsname] = server
			rootns = append(rootns, nsname)
			if rrcache.Debug {
				log.Printf("PrimeWithHints: adding server for root: name %q: %+v", nsname, authMap[nsname])
			}

		case dns.TypeA, dns.TypeAAAA:
			// log.Printf("PWH: read address RR: %s", rr.String())
			name := rr.Header().Name
			glueRecords[name] = append(glueRecords[name], rr)
		}
	}

	if err := zp.Err(); err != nil {
		return fmt.Errorf("Error parsing root hints from %s: %v", source, err)
	}

	// Store NS records for root
	if len(nsRecords) > 0 {
		if !rrcache.Quiet {
			log.Printf("Found %d NS RRs quiet: %v", len(nsRecords), rrcache.Quiet)
		}
		rrcache.Set(".", dns.TypeNS, &CachedRRset{
			Name:    ".",
			RRtype:  dns.TypeNS,
			Context: ContextHint,
			State:   ValidationStateIndeterminate,
			RRset: &core.RRset{
				Name:   ".",
				RRtype: dns.TypeNS,
				Class:  dns.ClassINET,
				RRs:    nsRecords,
				RRSIGs: nil, // No DNSSEC in root hints
			},
		})
	} else {
		return fmt.Errorf("No NS records found in root hints from %s", source)
	}

	// Store root zone data
	// cache.Data["."] = rootData
	var servers []string

	// Store glue records for root nameservers
	if !rrcache.Quiet {
		log.Printf("Found %d glue records", len(glueRecords))
	}
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
		if rrcache.Debug {
			log.Printf("PrimeWithHints: adding addrs to server for root: name %q: %+v", name, authMap[name])
		}

		// Create RRset for each type
		for rrtype, records := range typeGroups {
			rrcache.Set(name, rrtype, &CachedRRset{
				Name:    name,
				RRtype:  rrtype,
				Context: ContextHint,
				State:   ValidationStateIndeterminate,
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

	rrcache.ServerMap.Set(".", authMap)
	rrcache.Servers.Set(".", servers)

	rrset, err := fetcher(context.Background(), ".", dns.TypeNS, authMap) // force re-query bypassing cache
	if err != nil {
		return fmt.Errorf("Error priming RRsetCache with root hints: %v", err)
	}
	if rrset == nil {
		return fmt.Errorf("No NS records found in root hints from %s", source)
	}

	if rrcache.Debug {
		log.Printf("*** RRsetCache: primed with these roots: %v", rootns)
	}

	rrcache.Primed = true

	return nil
}

func (rrcache *RRsetCacheT) FindClosestKnownZone(qname string) (string, map[string]*AuthServer, error) {
	// Iterate through known zone names and return the longest match.
	var bestmatch string
	// var servers []string
	var servers map[string]*AuthServer
	if rrcache.Debug {
		log.Printf("FindClosestKnownZone: checking qname %q against %d zones with data in cache", qname, rrcache.Servers.Count())
	}

	for item := range rrcache.ServerMap.IterBuffered() {
		z := item.Key
		ss := item.Val
		if strings.HasSuffix(qname, z) && len(z) > len(bestmatch) {
			bestmatch = z
			servers = ss
		}
	}

	if rrcache.Debug {
		auths := []string{}
		for name := range servers {
			auths = append(auths, name)
		}
		log.Printf("FindClosestKnownZone: authservers for zone %q: %s", qname, strings.Join(auths, ", "))
	}
	return bestmatch, servers, nil
}

func GetMinTTL(rrs []dns.RR) time.Duration {
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

func (rrcache *RRsetCacheT) MarkNSRevalidation(zone string) bool {
	rrcache.nsRevalidateMu.Lock()
	defer rrcache.nsRevalidateMu.Unlock()
	if rrcache.nsRevalidateInFlight == nil {
		rrcache.nsRevalidateInFlight = make(map[string]struct{})
	}
	if _, ok := rrcache.nsRevalidateInFlight[zone]; ok {
		return false
	}
	rrcache.nsRevalidateInFlight[zone] = struct{}{}
	return true
}

func (rrcache *RRsetCacheT) ClearNSRevalidation(zone string) {
	rrcache.nsRevalidateMu.Lock()
	defer rrcache.nsRevalidateMu.Unlock()
	if rrcache.nsRevalidateInFlight == nil {
		return
	}
	delete(rrcache.nsRevalidateInFlight, zone)
}

func (rrcache *RRsetCacheT) MarkRRsetBogus(qname string, qtype uint16, rrset *core.RRset, dnssecOK bool) (uint16, string) {
	if rrcache == nil || qname == "" {
		return 0, ""
	}
	var edeCode uint16
	var edeText string
	if dnssecOK {
		if code, text, ok := rrcache.lookupDnskeyEDE(rrset); ok {
			edeCode = code
			edeText = text
		}
	}
	var cached *CachedRRset
	if cached = rrcache.Get(qname, qtype); cached == nil {
		cached = &CachedRRset{
			Name:    qname,
			RRtype:  qtype,
			Rcode:   uint8(dns.RcodeSuccess),
			Context: ContextAnswer,
		}
	}
	cached.State = ValidationStateBogus
	if edeCode != 0 {
		cached.EDECode = edeCode
		cached.EDEText = edeText
	}
	if rrset != nil {
		cached.RRset = rrset.Clone()
	}
	rrcache.Set(qname, qtype, cached)
	return edeCode, edeText
}

func (rrcache *RRsetCacheT) lookupDnskeyEDE(rrset *core.RRset) (uint16, string, bool) {
	if rrcache == nil || rrset == nil {
		return 0, "", false
	}

	for _, raw := range rrset.RRSIGs {
		sig, ok := raw.(*dns.RRSIG)
		if !ok || sig == nil {
			continue
		}
		signer := dns.CanonicalName(sig.SignerName)
		if signer == "" {
			continue
		}
		ds := rrcache.Get(signer, dns.TypeDS)
		if ds == nil || ds.RRset == nil || len(ds.RRset.RRs) == 0 || ds.State != ValidationStateSecure {
			continue
		}
		dnskey := rrcache.Get(signer, dns.TypeDNSKEY)
		if dnskey == nil || dnskey.EDECode == 0 {
			continue
		}
		text := dnskey.EDEText
		if text == "" && dnskey.EDECode == 9 {
			zone := strings.TrimSuffix(signer, ".")
			if zone == "" {
				zone = "."
			}
			text = fmt.Sprintf("no DNSKEY matches DS for zone %s", zone)
		}
		return dnskey.EDECode, text, true
	}
	return 0, "", false
}
