/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"strings"

	"github.com/miekg/dns"
	core "github.com/johanix/tdns/tdns/core"
)

// XXX: This should be merged with the FetchChildDelegationData() function
// Returns [] NS RRs + [] v4glue RRs + [] v6glue RRs
func (zd *ZoneData) FindDelegation(qname string, dnssec_ok bool) *ChildDelegationData {
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
			if childns, ok := childrrs.RRtypes.Get(dns.TypeNS); ok {
				childds := childrrs.RRtypes.GetOnlyRRSet(dns.TypeDS)
				cdd := ChildDelegationData{
					ChildName: child,
					NS_rrset:  &childns,
					DS_rrset:  &childds,
				}
				// zd.Logger.Printf("FindDelegation for qname='%s': there are NS RRs for '%s'", qname, child)
				// Ok, we found a delegation. Do we need any glue?
				zd.Logger.Printf("FindDelegation: cdd=%v", cdd)
				v4glue, v6glue, v4glue_rrsigs, v6glue_rrsigs := zd.FindGlueSimple(childns, dnssec_ok)
				cdd.A_glue = v4glue
				cdd.AAAA_glue = v6glue
				cdd.A_glue_rrsigs = v4glue_rrsigs
				cdd.AAAA_glue_rrsigs = v6glue_rrsigs
				zd.Logger.Printf("FindDelegation: v4glue=%v, v6glue=%v", v4glue, v6glue)
				return &cdd
			}
		}
	}
	zd.Logger.Printf("FindZone: no delegation for qname=%s found in %s", qname, zd.ZoneName)
	return nil
}

// Returns two RRsets with A glue and AAAA glue. Each RRset may be nil.
// XXX: This is wrong. The v4 (and v6) glue is not an *RRset, but a []*RRset
func (zd *ZoneData) FindGlue(nsrrs core.RRset, dnssec_ok bool) (*core.RRset, *core.RRset) {
	// zd.Logger.Printf("FindGlue: nsrrs: %v", nsrrs)
	// dump.P(nsrrs)
	var v4glue, v6glue, maybe_4glue, maybe_6glue core.RRset
	var nsname string
	zone := nsrrs.RRs[0].Header().Name
	for _, rr := range nsrrs.RRs {
		if nsrr, ok := rr.(*dns.NS); ok {
			nsname = nsrr.Ns
			if zd.Debug {
				zd.Logger.Printf("FindGlue: zone '%s' has a nameserver '%s'", zone, nsname)
			}
			// nsnidx, exist := zd.OwnerIndex[nsname]
			if !zd.NameExists(nsname) {
				continue // no match for nsname in zd.OwnerIndex (i.e nameserver is out of bailiwick)
			}
			nsnamerrs, _ := zd.GetOwner(nsname)

			if ns_A_rrs, ok := nsnamerrs.RRtypes.Get(dns.TypeA); ok {
				// Ok, we found an A RR
				maybe_4glue.RRs = append(maybe_4glue.RRs, ns_A_rrs.RRs...)
				maybe_4glue.RRSIGs = append(maybe_4glue.RRSIGs, ns_A_rrs.RRSIGs...)
			}
			if ns_AAAA_rrs, ok := nsnamerrs.RRtypes.Get(dns.TypeAAAA); ok {
				// Ok, we found an AAAA RR
				maybe_6glue.RRs = append(maybe_6glue.RRs, ns_AAAA_rrs.RRs...)
				maybe_6glue.RRSIGs = append(maybe_6glue.RRSIGs, ns_AAAA_rrs.RRSIGs...)
			}
		} else {
			if zd.Debug {
				zd.Logger.Printf("FindGlue: in the NS RRset I found this RRSIG: %s", rr.String())
			}
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

func (zd *ZoneData) FindGlueSimple(nsrrs core.RRset, dnssec_ok bool) ([]dns.RR, []dns.RR, []dns.RR, []dns.RR) {
	// zd.Logger.Printf("FindGlue: nsrrs: %v", nsrrs)
	// dump.P(nsrrs)
	var v4glue, v6glue, v4glue_rrsigs, v6glue_rrsigs []dns.RR
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

			if ns_A_rrs, ok := nsnamerrs.RRtypes.Get(dns.TypeA); ok {
				// Ok, we found an A RR
				v4glue = append(v4glue, ns_A_rrs.RRs...)
				v4glue_rrsigs = append(v4glue_rrsigs, ns_A_rrs.RRSIGs...)
			}
			if ns_AAAA_rrs, ok := nsnamerrs.RRtypes.Get(dns.TypeAAAA); ok {
				// Ok, we found an AAAA RR
				v6glue = append(v6glue, ns_AAAA_rrs.RRs...)
				v6glue_rrsigs = append(v6glue_rrsigs, ns_AAAA_rrs.RRSIGs...)
			}
		} else {
			zd.Logger.Printf("FindGlue: in the NS RRset I found this RRSIG: %s", rr.String())
		}
	}

	if !dnssec_ok {
		v4glue_rrsigs = []dns.RR{} // drop any RRSIGs
		v6glue_rrsigs = []dns.RR{} // drop any RRSIGs
	}

	return v4glue, v6glue, v4glue_rrsigs, v6glue_rrsigs
}
