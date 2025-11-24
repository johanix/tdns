/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package core

import (
	"log"

	"github.com/miekg/dns"
)

func RRsetDiffer(zone string, newrrs, oldrrs []dns.RR, rrtype uint16, lg *log.Logger, verbose, debug bool) (bool, []dns.RR, []dns.RR) {
	var match, rrsets_differ bool
	typestr := dns.TypeToString[rrtype]
	adds := []dns.RR{}
	removes := []dns.RR{}

	if debug {
		lg.Printf("*** RRD: Comparing %s RRsets for %s:", typestr, zone)
		lg.Printf("-------- Old set for %s %s:", zone, typestr)
		for _, rr := range oldrrs {
			lg.Printf("%s", rr.String())
		}
		lg.Printf("-------- New set for %s %s:", zone, typestr)
		for _, rr := range newrrs {
			lg.Printf("%s", rr.String())
		}
	}
	// compare oldrrs to newrrs
	for _, orr := range oldrrs {
		if dns.TypeToString[orr.Header().Rrtype] == "RRSIG" {
			continue
		}
		match = false
		for _, nrr := range newrrs {
			if dns.IsDuplicate(orr, nrr) {
				match = true
				break
			}
		}
		// if we get here w/o match then this orr has no equal nrr
		if !match {
			rrsets_differ = true
			removes = append(removes, orr)
		}
	}

	// compare newrrs to oldrrs
	for _, nrr := range newrrs {
		if dns.TypeToString[nrr.Header().Rrtype] == "RRSIG" {
			continue
		}
		match = false
		for _, orr := range oldrrs {
			if dns.IsDuplicate(nrr, orr) {
				match = true
				break
			}
		}
		// if we get here w/o match then this nrr has no equal orr
		if !match {
			rrsets_differ = true
			adds = append(adds, nrr)
		}
	}
	if verbose {
		lg.Printf("*** RRD: RRsetDiffer: Zone %s %s rrsets_differ: %v\n***Adds: %v\n***Removes: %v", zone, typestr, rrsets_differ, adds, removes)
	}
	return rrsets_differ, adds, removes
}

func (rrset *RRset) RemoveRR(rr dns.RR, verbose, debug bool) {
	if debug {
		log.Printf("RemoveRR: Trying to remove '%s' from RRset %s %s", rr.String(), rrset.Name, dns.TypeToString[rr.Header().Rrtype])
	}
	for i, r := range rrset.RRs {
		if debug {
			log.Printf("RemoveRR: Comparing:\n%s\n%s\n", r.String(), rr.String())
		}
		if dns.IsDuplicate(r, rr) {
			rrset.RRs = append(rrset.RRs[:i], rrset.RRs[i+1:]...)
			rrset.RRSIGs = []dns.RR{}
			log.Printf("RemoveRR: *REMOVED* '%s' from RRset %s %s", rr.String(), rrset.Name, dns.TypeToString[rr.Header().Rrtype])
			return
		}
	}
}

func (rrset *RRset) Copy() *RRset {
	new_rrset := RRset{
		Name:   rrset.Name,
		RRs:    []dns.RR{},
		RRSIGs: []dns.RR{},
	}
	new_rrset.RRs = append(new_rrset.RRs, rrset.RRs...)
	new_rrset.RRSIGs = append(new_rrset.RRSIGs, rrset.RRSIGs...)
	return &new_rrset
}

// Add adds a RR to the RRset if it is not already present.
func (rrset *RRset) Add(rr dns.RR) {
	for _, rr2 := range rrset.RRs {
		if dns.IsDuplicate(rr, rr2) {
			// log.Printf("rrset.Add: RR already present: %s", rr.String())
			return
		}
	}
	// log.Printf("rrset.Add: Adding RR: %s to RRset\n%v", rr.String(), rrset.RRs)
	rrset.RRs = append(rrset.RRs, rr)
}

// Delete deletes a RR from the RRset if it is present.
func (rrset *RRset) Delete(rr dns.RR) {
	for i, rr2 := range rrset.RRs {
		if dns.IsDuplicate(rr, rr2) {
			// log.Printf("rrset.Delete: Found RR: %s in RRset\n%v", rr.String(), rrset.RRs)
			rrset.RRs = append(rrset.RRs[:i], rrset.RRs[i+1:]...)
			return
		}
	}
	// log.Printf("rrset.Delete: RR not found: %s", rr.String())
}

func (rrset *RRset) Clone() *RRset {
	if rrset == nil {
		return nil
	}
	
	clone := &RRset{
		Name:   rrset.Name,
		Class:  rrset.Class,
		RRtype: rrset.RRtype,
	}
	for _, rr := range rrset.RRs {
		if rr != nil {
			clone.RRs = append(clone.RRs, dns.Copy(rr))
		}
	}
	for _, sig := range rrset.RRSIGs {
		if sig != nil {
			clone.RRSIGs = append(clone.RRSIGs, dns.Copy(sig))
		}
	}
	return clone
}