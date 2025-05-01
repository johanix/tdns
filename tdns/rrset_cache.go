/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"log"
	"net"
	"os"
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

var RRsetCache = NewRRsetCache()

func NewRRsetCache() *RRsetCacheT {
	return &RRsetCacheT{
		RRsets:  NewCmap[CachedRRset](),
		Servers: NewCmap[[]string](),
	}
}

func (rsc *RRsetCacheT) Get(qname string, qtype uint16) *CachedRRset {
	lookupKey := fmt.Sprintf("%s::%d", qname, qtype)
	tmp, ok := rsc.RRsets.Get(lookupKey)
	if !ok {
		return nil
	}
	if tmp.Expiration.Before(time.Now()) {
		rsc.RRsets.Remove(lookupKey)
		log.Printf("RRsetCache: Removed expired key %s", lookupKey)
		return nil
	}
	return &tmp
}

func (rsc *RRsetCacheT) Set(qname string, qtype uint16, rrset *CachedRRset) {
	lookupKey := fmt.Sprintf("%s::%d", qname, qtype)
	rsc.RRsets.Set(lookupKey, *rrset)
}

func (rsc *RRsetCacheT) PrimeWithHints(hintsfile string) error {
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
		rsc.Set(".", dns.TypeNS, &CachedRRset{
			QueryResult: ResultPriming,
			RRset: &RRset{
				Name:   ".",
				Class:  dns.ClassINET,
				RRtype: dns.TypeNS,
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
		//		ownerData := &OwnerData{
		//			Name:    name,
		//			RRtypes: NewRRTypeStore(),
		//		}

		// Group records by type (A or AAAA)
		typeGroups := map[uint16][]dns.RR{}
		for _, rr := range rrs {
			rrtype := rr.Header().Rrtype
			typeGroups[rrtype] = append(typeGroups[rrtype], rr)
			switch rr.Header().Rrtype {
			case dns.TypeA:
				servers = append(servers, net.JoinHostPort(rr.(*dns.A).A.String(), "53"))
			case dns.TypeAAAA:
				servers = append(servers, net.JoinHostPort(rr.(*dns.AAAA).AAAA.String(), "53"))
			}
		}

		// Create RRset for each type
		for rrtype, records := range typeGroups {
			rsc.Set(name, rrtype, &CachedRRset{
				QueryResult: ResultPriming,
				RRset: &RRset{
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

	rsc.Servers.Set(".", servers)

	// var keys []string
	// for k, _ := range cache.Data {
	// 	keys = append(keys, k)
	// }
	// log.Printf("Keys: %v", rsc.RRsets.Keys())

	log.Printf("*** RRsetCache: primed with these roots: %v", rootns)

	rsc.Primed = true

	return nil
}
