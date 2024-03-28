/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	"fmt"
	"log"
	// "sync"
	"time"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
)

// 1. Query parent servers until we get a child NS RRset back
// 2. Iterate over child NS RRset from parent and identify all in-bailiwick NS
// 3. Query same parent server as returned the NS RRset for the glue for this child NS
// 4. When all parent-side data is collected, compare to the data in the ZoneData struct

// Return insync (bool), adds, removes ([]dns.RR) and error
// func AnalyseZoneDelegation(conf *Config, dp tdns.DelegationPost) (bool, []dns.RR, []dns.RR, error) {
func AnalyseZoneDelegation(conf *Config, dp tdns.DelegationPost) (tdns.DelegationResponse, error) {
	var resp = tdns.DelegationResponse{Time: time.Now()}
	var zd *tdns.ZoneData
	var exist bool

	if zd, exist = tdns.Zones.Get(dp.Zone); !exist {
		msg := fmt.Sprintf("Zone \"%s\" is unknown.", dp.Zone)
		log.Printf(msg)
		return resp, fmt.Errorf(msg)
	}

	err := zd.FetchParentData()
	if err != nil {
		return resp, err
	}

	resp.Zone = zd.ZoneName
	resp.Parent = zd.Parent

	var p_nsrrs []dns.RR
	var pserver string // outside loop to preserve for later re-use

	// 1. Compare NS RRsets between parent and child
	for _, pserver = range zd.ParentServers {
		p_nsrrs, err = tdns.AuthQuery(zd.ZoneName, pserver, dns.TypeNS)
		if err != nil {
			log.Printf("Error from AuthQuery(%s, %s, NS): %v", pserver, zd.ZoneName, err)
			continue
		}

		if len(p_nsrrs) == 0 {
			log.Printf("Empty respone to AuthQuery(%s, %s, NS)", pserver, zd.ZoneName)
			continue
		}

		// We have a response, no need to talk to rest of parent servers
		break
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return resp, err
	}
	differ, adds, removes := tdns.RRsetDiffer(zd.ZoneName, apex.RRtypes[dns.TypeNS].RRs,
		p_nsrrs, dns.TypeNS, zd.Logger)
	resp.InSync = !differ

	if len(adds) > 0 {
		var tmp []dns.NS
		for _, rr := range adds {
			tmp = append(tmp, *rr.(*dns.NS))
		}
		resp.NsAdds = tmp
	}

	if len(removes) > 0 {
		var tmp []dns.NS
		for _, rr := range removes {
			tmp = append(tmp, *rr.(*dns.NS))
		}
		resp.NsRemoves = tmp
	}

	// 2. Compute the in-bailiwick subset of nameservers
	child_inb, _ := tdns.BailiwickNS(zd.ZoneName, apex.RRtypes[dns.TypeNS].RRs)
	// parent_inb, _ := tdns.BailiwickNS(zd.ZoneName, apex.RRtypes[dns.TypeNS].RRs)

	// 3. Compare A and AAAA glue for in child in-bailiwick nameservers
	for _, ns := range child_inb {
		owner, err := zd.GetOwner(ns)
		if err != nil {
			log.Printf("Error from zd.GetOwner(%s): %v", ns, err)
		}
		child_a_glue := owner.RRtypes[dns.TypeA].RRs
		parent_a_glue, err := tdns.AuthQuery(ns, pserver, dns.TypeA)
		if err != nil {
			log.Printf("Error from AuthQuery(%s, %s, A): %v", pserver, child_inb, err)
		}
		differ, adds, removes := tdns.RRsetDiffer(ns, child_a_glue, parent_a_glue,
			dns.TypeA, zd.Logger)
		if differ {
			resp.InSync = false
			if len(adds) > 0 {
				for _, rr := range adds {
					resp.AAdds = append(resp.AAdds, *rr.(*dns.A))
				}
			}

			if len(removes) > 0 {
				for _, rr := range removes {
					resp.ARemoves = append(resp.ARemoves, *rr.(*dns.A))
				}
			}
		}

		child_aaaa_glue := owner.RRtypes[dns.TypeAAAA].RRs
		parent_aaaa_glue, err := tdns.AuthQuery(ns, pserver, dns.TypeAAAA)
		if err != nil {
			log.Printf("Error from AuthQuery(%s, %s, AAAA): %v", pserver, child_inb, err)
		}
		differ, adds, removes = tdns.RRsetDiffer(ns, child_aaaa_glue, parent_aaaa_glue,
			dns.TypeAAAA, zd.Logger)
		if differ {
			resp.InSync = false
			if len(adds) > 0 {
				for _, rr := range adds {
					resp.AAAAAdds = append(resp.AAAAAdds, *rr.(*dns.AAAA))
				}
			}

			if len(removes) > 0 {
				for _, rr := range removes {
					resp.AAAARemoves = append(resp.AAAARemoves, *rr.(*dns.AAAA))
				}
			}
		}
	}
	// 4. If NS RRsets differ, then also compare glue for parent in-bailiwick nameservers

	return resp, nil
}

func SyncZoneDelegation(conf *Config, dp tdns.DelegationPost) (string, error) {

	resp, err := AnalyseZoneDelegation(conf, dp)
	if err != nil {
	   return "", err
	}

	if resp.InSync {
	   return fmt.Sprintf("Zone \"%s\" delegation data in parent \"%s\" is in sync. No action needed.",
	   	  resp.Zone, resp.Parent), nil
	}

	if zd, exist = tdns.Zones.Get(dp.Zone); !exist {
		msg := fmt.Sprintf("Zone \"%s\" is unknown.", dp.Zone)
		log.Printf(msg)
		return resp, fmt.Errorf(msg)
	}

	// 1. Check what DSYNC schemes are supported by parent and preference in request
	// If UPDATE:
	// 2. Create DNS UPDATE msg
	// 3. Fetch the SIG(0) key from the keystore
	// 4. Sign the msg
	// 5. Send the msg
	// 6. Check the response
	// 7. Return result to CLI

	return "foobar", nil
}
