/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"github.com/miekg/dns"
	"log"
	"strings"
)

// Returns [] NS RRs + [] glue RRs
func (zd *ZoneData) FindDelegation(qname string, dnssec_ok bool) (*RRset, *RRset) {
	var child string
	labels := strings.Split(qname, ".")
	for i := 0; i < len(labels)-1; i++ {
		child = strings.Join(labels[i:], ".")
		if child == zd.ZoneName {
			break // no point in checking above current zone name
		}
		if zd.NameExists(child) {
			childrrs, _ := zd.GetOwner(child)
			log.Printf("FindDelegation for qname='%s': there are RRs for '%s'", qname, child)
			if childns, ok := childrrs.RRtypes[dns.TypeNS]; ok {
				//				log.Printf("FindDelegation for qname='%s': there are NS RRs for '%s'", qname, child)
				// Ok, we found a delegation. Do we need any glue?
				glue := zd.FindGlue(childns, dnssec_ok)
				return &childns, glue
			}
		}
	}
	log.Printf("FindZone: no delegation for qname=%s found in %s", qname, zd.ZoneName)
	return nil, nil
}

func (zd *ZoneData) FindGlue(nsrrs RRset, dnssec_ok bool) *RRset {
	zd.Logger.Printf("FindGlue: nsrrs: %v", nsrrs)
	var glue, maybe_glue RRset
	var nsname string
	zone := nsrrs.RRs[0].Header().Name
	for _, rr := range nsrrs.RRs {
		if nsrr, ok := rr.(*dns.NS); ok {
			nsname = nsrr.Ns
			zd.Logger.Printf("FindGlue: zone '%s' has a nameserver '%s'", zone, nsname)
			// nsnidx, exist := zd.OwnerIndex[nsname]
			if !zd.NameExists(nsname) {
				continue // no match for nsname in zd.OwnerIndex (i.e nameserver is out of bailiwick)
			}
			nsnamerrs, _ := zd.GetOwner(nsname)

			if ns_A_rrs, ok := nsnamerrs.RRtypes[dns.TypeA]; ok {
				// Ok, we found an A RR
				maybe_glue.RRs = append(maybe_glue.RRs, ns_A_rrs.RRs...)
				maybe_glue.RRSIGs = append(maybe_glue.RRSIGs, ns_A_rrs.RRSIGs...)
			}
			if ns_AAAA_rrs, ok := nsnamerrs.RRtypes[dns.TypeAAAA]; ok {
				// Ok, we found an AAAA RR
				maybe_glue.RRs = append(maybe_glue.RRs, ns_AAAA_rrs.RRs...)
				maybe_glue.RRSIGs = append(maybe_glue.RRSIGs, ns_AAAA_rrs.RRSIGs...)
			}
		} else {
			log.Printf("FindGlue: in the NS RRset I found this RRSIG: %s", rr.String())
		}
	}

	if len(maybe_glue.RRs) == 0 {
		//		log.Printf("FindGlue: no glue for zone=%s found in %s", zone, zd.ZoneName)
	} else {
		//		log.Printf("FindGlue: found %d glue RRs zone=%s in %s", len(glue.RRs), zone, zd.ZoneName)
		glue = maybe_glue
		if !dnssec_ok {
			glue.RRSIGs = []dns.RR{} // drop any RRSIGs
		}
	}
	return &glue
}
