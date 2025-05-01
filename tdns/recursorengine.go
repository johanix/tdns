/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/miekg/dns"
)

type xxxCacheRRset struct {
	RRset     *RRset
	Validated bool
	Expires   time.Time
}

// There is already an RRsetCache defined in rrset_cache.go. As this is just an
// experiment we don't want to change that.
type xxxRRsetCacheNG struct {
	Data    map[string]*OwnerData
	Zones   map[string]bool
	Servers map[string][]string
}

type RecursorRequest struct {
	Qname      string
	Qtype      uint16
	Qclass     uint16
	ResponseCh chan RecursorResponse
}

type RecursorResponse struct {
	RRset     *RRset
	Validated bool
	Error     bool
	ErrorMsg  string
	Msg       string
}

// The RecursorEngine is a simple caching DNS recursor. It is not a fully fledged, all singing,
// all dancing recursive server. It is just intended to get the job done for the particular cases
// that we need to support.

// var RecursorCache *RRsetCacheNG

func RecursorEngine(conf *Config, stopch chan struct{}) {
	var recursorch = conf.Internal.RecursorCh

	if !viper.GetBool("recursorengine.active") {
		log.Printf("RecursorEngine is NOT active.")
		for rrq := range recursorch {
			log.Printf("RecursorEngine: not active, but got a request: %v", rrq)
			continue // ensure that we keep reading to keep the channel open
		}
	} else {
		log.Printf("RecursorEngine: Starting")
	}

	// 1. Create the cache
	var err error
	// RecursorCache, err = NewRRsetCacheNG(viper.GetString("recursorengine.root-hints"))
	if !RRsetCache.Primed {
		RRsetCache.PrimeWithHints(viper.GetString("recursorengine.root-hints"))
		if err != nil {
			Shutdowner(conf, fmt.Sprintf("RecursorEngine: failed to initialize RecursorCache w/ root hints: %v", err))
		}
	}

	// var DnskeyCache = NewRRsetCache()

	for rrq := range recursorch {
		if Globals.Debug {
			log.Printf("RecursorEngine: received query for %s %s %s", rrq.Qname, dns.ClassToString[rrq.Qclass], dns.TypeToString[rrq.Qtype])
		}
		resp := RecursorResponse{
			Validated: false,
			Msg:       "RecursorEngine: request to look up a RRset",
		}

		// 1. Is the answer in the cache?
		crrset := RRsetCache.Get(rrq.Qname, rrq.Qtype)
		if crrset != nil {
			resp.RRset = crrset.RRset
		} else {
			log.Printf("Recursor: <qname, qtype> tuple <%q, %s> not known, needs to be queried for", rrq.Qname, dns.TypeToString[rrq.Qtype])
			maxiter := 12
		outerLoop:
			for {
				if maxiter <= 0 {
					log.Printf("*** Recursor: max iterations reached. Giving up.")
					break
				} else {
					maxiter--
				}
				bestmatch, servers, err := RRsetCache.FindClosestKnownZone(rrq.Qname)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Error from FindClosestKnownZone: %v", err)
					break
				}
				log.Printf("Recursor: best zone match for qname %q seems to be %q", rrq.Qname, bestmatch)
				ss := servers
				if len(servers) > 4 {
					ss = servers[:3]
					ss = append(ss, "...")
				}
				log.Printf("Recursor: sending query to %d servers: %v", len(servers), ss)
				rrset, rcode, result, err := RRsetCache.AuthDNSQuery(rrq.Qname, rrq.Qtype, servers, log.Default(), true)
				// log.Printf("Recursor: response from AuthDNSQuery: rcode: %d, err: %v", rrset, rcode, err)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Error from AuthDNSQuery: %v", err)
					break
				}
				if rrset != nil {
					log.Printf("Recursor: received response from AuthDNSQuery:")
					for _, rr := range rrset.RRs {
						log.Printf("Recursor: %s", rr.String())
					}
					resp.RRset = rrset
					break
				}
				if rcode == dns.RcodeNameError {
					// this is a negative response, which we need to figure out how to represent
					log.Printf("Recursor: received NXDOMAIN for qname %q, no point in continuing", rrq.Qname)
					resp.Msg = "NXDOMAIN (negative response type 3)"
					break
				}
				switch result {
				case ResultReferral:
					continue // if all is good we will now hit the new referral and get further
				case ResultNoErrNoAns:
					resp.Msg = "negative response type 0"
					break outerLoop
				}
				time.Sleep(1 * time.Second)
			}
		}

		if rrq.ResponseCh != nil {
			rrq.ResponseCh <- resp
		}
	}
}

func (rrcache *RRsetCacheT) FindClosestKnownZone(qname string) (string, []string, error) {
	// Iterate through known zone names and return the longest match.
	var bestmatch string
	var servers []string
	log.Printf("FindClosestKnownZone: checking qname %q against %d zones with data in cache", qname, rrcache.Servers.Count())
	for item := range rrcache.Servers.IterBuffered() {
		z := item.Key
		ss := item.Val
		if strings.HasSuffix(qname, z) && len(z) > len(bestmatch) {
			bestmatch = z
			servers = ss
		}
	}
	return bestmatch, servers, nil
}
