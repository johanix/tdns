/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	cmap "github.com/orcaman/concurrent-map/v2"
)

var DnskeyCache = NewDnskeyCache()

func NewDnskeyCache() *DnskeyCacheT {
	return &DnskeyCacheT{
		Map: cmap.New[TrustAnchor](),
	}
}

func (dkc *DnskeyCacheT) Get(zonename string, keyid uint16) *TrustAnchor {
	lookupKey := fmt.Sprintf("%s::%d", zonename, keyid)
	tmp, ok := dkc.Map.Get(lookupKey)
	if !ok {
		return nil
	}
	if tmp.Expiration.Before(time.Now()) {
		dkc.Map.Remove(lookupKey)
		log.Printf("DnskeyCache: Removed expired key %s", lookupKey)
		return nil
	}
	return &tmp
}

func (dkc *DnskeyCacheT) Set(zonename string, keyid uint16, ta *TrustAnchor) {
	lookupKey := fmt.Sprintf("%s::%d", zonename, keyid)
	dkc.Map.Set(lookupKey, *ta)
}

// var RRsetCache = NewRRsetCache()

func NewRRsetCache(lg *log.Logger, verbose, debug bool) *RRsetCacheT {
	return &RRsetCacheT{
		RRsets:    NewCmap[CachedRRset](),
		Servers:   NewCmap[[]string](),               // servers stored as []string{ "1.2.3.4:53", "9.8.7.6:53"}
		ServerMap: NewCmap[map[string]*AuthServer](), // servers stored as map[string][]string{} a la map[addr][]string{"dot", "doq", "do53"}
		Logger:    lg,
		Verbose:   verbose,
		Debug:     debug,
	}
}

func (rrcache *RRsetCacheT) Get(qname string, qtype uint16) *CachedRRset {
	lookupKey := fmt.Sprintf("%s::%d", qname, qtype)
	tmp, ok := rrcache.RRsets.Get(lookupKey)
	if !ok {
		return nil
	}
	if tmp.Expiration.Before(time.Now()) {
		rrcache.RRsets.Remove(lookupKey)
		log.Printf("RRsetCache: Removed expired key %s", lookupKey)
		return nil
	}
	return &tmp
}

func (rrcache *RRsetCacheT) Set(qname string, qtype uint16, rrset *CachedRRset) {
	lookupKey := fmt.Sprintf("%s::%d", qname, qtype)
	rrcache.RRsets.Set(lookupKey, *rrset)
}

// A stub is a static mapping from a zone name to a list of addresses (later probably AuthServers)
func (rrcache *RRsetCacheT) AddStub(zone string, servers []AuthServer) error {
	addrlist := []string{}
	authservers := map[string]*AuthServer{}
	for _, server := range servers {
		for _, addr := range server.Addrs {
			var tmpaddr string
			if !strings.HasSuffix(addr, ":53") {
				tmpaddr = net.JoinHostPort(addr, "53")
			} else {
				tmpaddr = addr
			}
			addrlist = append(addrlist, tmpaddr)
		}
		tmpauthserver := &AuthServer{
			Name:  server.Name,
			Addrs: server.Addrs,
			Alpn:  server.Alpn,
			Src:   "stub",
		}
		if len(server.Alpn) == 0 {
			tmpauthserver.Alpn = []string{"do53"}
		}
		tmpauthserver.PrefTransport = tmpauthserver.Alpn[0]
		authservers[server.Name] = tmpauthserver
	}
	rrcache.Servers.Set(zone, addrlist)
	rrcache.ServerMap.Set(zone, authservers)
	return nil
}

func (rrcache *RRsetCacheT) AddServers(zone string, sm map[string]*AuthServer) error {
	serverMap, ok := rrcache.ServerMap.Get(zone)
	if !ok {
		serverMap = map[string]*AuthServer{}
	}
	for name, server := range sm {
		if _, exist := serverMap[name]; !exist {
			serverMap[name] = server
		} else {
			for _, addr := range server.Addrs {
				if !slices.Contains(serverMap[name].Addrs, addr) {
					serverMap[name].Addrs = append(serverMap[name].Addrs, addr)
				}
			}
			for _, alpn := range server.Alpn {
				if !slices.Contains(serverMap[name].Alpn, alpn) {
					serverMap[name].Alpn = append(serverMap[name].Alpn, alpn)
				}
			}
		}
		serverMap[name].PrefTransport = serverMap[name].Alpn[0]
	}
	rrcache.ServerMap.Set(zone, serverMap)
	return nil
}

func (rrcache *RRsetCacheT) PrimeWithHints(hintsfile string) error {
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

	//	rootData := &OwnerData{
	//		Name:    ".",
	//		RRtypes: NewRRTypeStore(),
	//	}

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
			nsMap[rr.(*dns.NS).Ns] = true
			authMap[rr.(*dns.NS).Ns] = &AuthServer{
				Name:          rr.(*dns.NS).Ns,
				Alpn:          []string{"do53"},
				Src:           "hint",
				PrefTransport: "do53",
			}
			rootns = append(rootns, rr.(*dns.NS).Ns)

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
		rrcache.Set(".", dns.TypeNS, &CachedRRset{
			Name:    ".",
			RRtype:  dns.TypeNS,
			Context: ContextHint,
			RRset: &RRset{
				Name:   ".",
				RRtype: dns.TypeNS,
				Class:  dns.ClassINET,
				RRs:    nsRecords,
				RRSIGs: nil, // No DNSSEC in root hints
			},
			Expiration: time.Now().Add(time.Duration(nsRecords[0].Header().Ttl) * time.Second),
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

		// Create RRset for each type
		for rrtype, records := range typeGroups {
			rrcache.Set(name, rrtype, &CachedRRset{
				Name:    name,
				RRtype:  rrtype,
				Context: ContextHint,
				RRset: &RRset{
					Name:   name,
					Class:  dns.ClassINET,
					RRtype: rrtype,
					RRs:    records,
					RRSIGs: nil, // No DNSSEC in root hints
				},
				Expiration: time.Now().Add(time.Duration(records[0].Header().Ttl) * time.Second),
			})
		}

		// cache.Data[name] = ownerData
	}

	rrcache.ServerMap.Set(".", authMap)
	rrcache.Servers.Set(".", servers)

	rrset, _, _, err := rrcache.IterativeDNSQuery(".", dns.TypeNS, rootns, true) // force re-query bypassing cache
	if err != nil {
		return fmt.Errorf("Error priming RRsetCache with root hints: %v", err)
	}
	if rrset == nil {
		return fmt.Errorf("No NS records found in root hints file %s", hintsfile)
	}

	log.Printf("*** RRsetCache: primed with these roots: %v", rootns)

	rrcache.Primed = true

	return nil
}
