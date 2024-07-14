/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"strings"

	"github.com/miekg/dns"
)

// XXX: This should be merged with the FetchChildDelegationData() function
// Returns [] NS RRs + [] v4glue RRs + [] v6glue RRs
func (zd *ZoneData) FindDelegation(qname string, dnssec_ok bool) (*ChildDelegationData, *RRset, *RRset) {
	var child string
	labels := strings.Split(qname, ".")
	for i := 0; i < len(labels)-1; i++ {
		child = strings.Join(labels[i:], ".")
		if child == zd.ZoneName {
			break // no point in checking above current zone name
		}
		if zd.NameExists(child) {
			childrrs, _ := zd.GetOwner(child)
			zd.Logger.Printf("FindDelegation for qname='%s': there are RRs for '%s'", qname, child)
			if childns, ok := childrrs.RRtypes[dns.TypeNS]; ok {
				childds := childrrs.RRtypes[dns.TypeDS]
				cdd := ChildDelegationData{
					ChildName: child,
					NS_rrset:  &childns,
					DS_rrset:  &childds,
				}
				// zd.Logger.Printf("FindDelegation for qname='%s': there are NS RRs for '%s'", qname, child)
				// Ok, we found a delegation. Do we need any glue?
				v4glue, v6glue := zd.FindGlue(childns, dnssec_ok)
				return &cdd, v4glue, v6glue
			}
		}
	}
	zd.Logger.Printf("FindZone: no delegation for qname=%s found in %s", qname, zd.ZoneName)
	return nil, nil, nil
}

// Returns two RRsets with A glue and AAAA glue. Each RRset may be nil.
// XXX: This is wrong. The v4 (and v6) glue is not an *RRset, but a []*RRset
func (zd *ZoneData) FindGlue(nsrrs RRset, dnssec_ok bool) (*RRset, *RRset) {
	zd.Logger.Printf("FindGlue: nsrrs: %v", nsrrs)
	var v4glue, v6glue, maybe_4glue, maybe_6glue RRset
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
				maybe_4glue.RRs = append(maybe_4glue.RRs, ns_A_rrs.RRs...)
				maybe_4glue.RRSIGs = append(maybe_4glue.RRSIGs, ns_A_rrs.RRSIGs...)
			}
			if ns_AAAA_rrs, ok := nsnamerrs.RRtypes[dns.TypeAAAA]; ok {
				// Ok, we found an AAAA RR
				maybe_6glue.RRs = append(maybe_6glue.RRs, ns_AAAA_rrs.RRs...)
				maybe_6glue.RRSIGs = append(maybe_6glue.RRSIGs, ns_AAAA_rrs.RRSIGs...)
			}
		} else {
			zd.Logger.Printf("FindGlue: in the NS RRset I found this RRSIG: %s",
				rr.String())
		}
	}

	if len(maybe_4glue.RRs) != 0 {
		// zd.Logger.Printf("FindGlue: found %d glue RRs zone=%s in %s",
		// 			       len(glue.RRs), zone, zd.ZoneName)
		v4glue = maybe_4glue
		if !dnssec_ok {
			v4glue.RRSIGs = []dns.RR{} // drop any RRSIGs
		}
	} else {
		// zd.Logger.Printf("FindGlue: no v4 glue for zone=%s found in %s",
		// 			       zone, zd.ZoneName)
	}
	if len(maybe_6glue.RRs) != 0 {
		// zd.Logger.Printf("FindGlue: found %d v6 glue RRs zone=%s in %s",
		// 			       len(maybe_v6glue.RRs), zone, zd.ZoneName)
		v6glue = maybe_6glue
		if !dnssec_ok {
			v6glue.RRSIGs = []dns.RR{} // drop any RRSIGs
		}
	} else {
		// zd.Logger.Printf("FindGlue: no v6 glue for zone=%s found in %s",
		// 			       zone, zd.ZoneName)
	}
	return &v4glue, &v6glue
}
