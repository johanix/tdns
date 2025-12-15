/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package core

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

// RRsetDiffer compares old and new DNS resource record slices for a given RR type in a zone, ignoring RRSIG records.
// It returns: a boolean that is true if the RRsets differ, a slice of records present in newrrs but not in oldrrs (adds), and a slice of records present in oldrrs but not in newrrs (removes).
// When verbose or debug are true, comparison details are logged to lg.
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

func (rrset *RRset) RRsetDiffer(newrrset *RRset, lg *log.Logger, verbose, debug bool) (bool, []dns.RR, []dns.RR) {
	emptySlice := []dns.RR{}

	// Nil guard: if either RRset is nil, treat as no difference
	if rrset == nil && newrrset == nil {
		return false, emptySlice, emptySlice
	}
	if rrset == nil || newrrset == nil {
		// One is nil, the other is not - they differ
		return true, emptySlice, emptySlice
	}

	// Treat nil .RRs as empty slices
	oldrrs := rrset.RRs
	if oldrrs == nil {
		oldrrs = emptySlice
	}
	newrrs := newrrset.RRs
	if newrrs == nil {
		newrrs = emptySlice
	}

	var match, rrsets_differ bool
	typestr := dns.TypeToString[rrset.RRtype]
	adds := []dns.RR{}
	removes := []dns.RR{}

	if debug {
		lg.Printf("*** RRD: Comparing %s RRsets for %s:", typestr, rrset.Name)
		lg.Printf("-------- Old set for %s %s:", rrset.Name, typestr)
		for _, rr := range oldrrs {
			lg.Printf("%s", rr.String())
		}
		lg.Printf("-------- New set for %s %s:", rrset.Name, typestr)
		for _, rr := range newrrs {
			lg.Printf("%s", rr.String())
		}
	}
	// compare oldrrs to newrrs
	for _, orr := range oldrrs {
		if orr.Header().Rrtype == dns.TypeRRSIG {
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
		if nrr.Header().Rrtype == dns.TypeRRSIG {
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
		lg.Printf("*** RRD: RRsetDiffer: Zone %s %s rrsets_differ: %v\n***Adds: %v\n***Removes: %v", rrset.Name, typestr, rrsets_differ, adds, removes)
	}
	return rrsets_differ, adds, removes
}

// RRSIGsDiffer compares two slices of RRSIGs and returns true if they differ.
// Two RRSIG slices are considered equal if they contain the same RRSIGs (using dns.IsDuplicate for comparison),
// regardless of order. Returns true if the RRSIGs differ, false if they are the same.
func (rrset *RRset) RRSIGsDiffer(newrrset *RRset) bool {
	// Nil guard: if both RRsets are nil, RRSIGs are the same (both empty)
	if rrset == nil && newrrset == nil {
		return false
	}
	// If one is nil and the other is not, check if the non-nil one has any RRSIGs
	if rrset == nil {
		// Old is nil (no RRSIGs), check if new has any
		if newrrset.RRSIGs == nil || len(newrrset.RRSIGs) == 0 {
			return false // Both effectively empty
		}
		return true // New has RRSIGs, old doesn't
	}
	if newrrset == nil {
		// New is nil (no RRSIGs), check if old has any
		if rrset.RRSIGs == nil || len(rrset.RRSIGs) == 0 {
			return false // Both effectively empty
		}
		return true // Old has RRSIGs, new doesn't
	}

	// Both are non-nil, treat nil .RRSIGs as empty slices
	oldRRSIGs := rrset.RRSIGs
	if oldRRSIGs == nil {
		oldRRSIGs = []dns.RR{}
	}
	newRRSIGs := newrrset.RRSIGs
	if newRRSIGs == nil {
		newRRSIGs = []dns.RR{}
	}

	if len(oldRRSIGs) != len(newRRSIGs) {
		return true
	}
	// Compare old RRSIGs to new RRSIGs
	for _, oldSig := range oldRRSIGs {
		found := false
		for _, newSig := range newRRSIGs {
			if dns.IsDuplicate(oldSig, newSig) {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	// Compare new RRSIGs to old RRSIGs (check the other direction)
	for _, newSig := range newRRSIGs {
		found := false
		for _, oldSig := range oldRRSIGs {
			if dns.IsDuplicate(newSig, oldSig) {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
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

func (rrset *RRset) String(maxlen int) (out string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("RRset.String: panic recovered: %v", r)
			if out == "" {
				out = fmt.Sprintf("(RRset.String panic: %v)\n", r)
			}
		}
		if out == "" {
			// Fallback: ensure we always return something
			log.Printf("RRset.String: WARNING - returning empty string, using fallback")
			out = "(RRset.String returned empty string - this should not happen)\n"
		}
	}()

	if rrset == nil {
		return "(nil RRset)\n"
	}

	out = ""
	rrCount := 0
	if rrset.RRs != nil {
		rrCount = len(rrset.RRs)
		for _, rr := range rrset.RRs {
			if rr == nil {
				continue
			}
			rrstr := rr.String() + "\n"
			if maxlen > 4 && len(rrstr) > maxlen {
				rrstr = rrstr[:maxlen-4] + "...\n"
			}
			out += rrstr
		}
	}
	sigCount := 0
	if rrset.RRSIGs != nil {
		sigCount = len(rrset.RRSIGs)
		for _, sig := range rrset.RRSIGs {
			if sig == nil {
				continue
			}
			sigstr := sig.String() + "\n"
			if maxlen > 4 && len(sigstr) > maxlen {
				sigstr = sigstr[:maxlen-4] + "...\n"
			}
			out += sigstr
		}
	}

	if out == "" {
		typeStr := "UNKNOWN"
		if rrset.RRtype > 0 {
			if value, ok := dns.TypeToString[rrset.RRtype]; ok && value != "" {
				typeStr = value
			} else {
				typeStr = fmt.Sprintf("TYPE%d", rrset.RRtype)
			}
		}
		name := rrset.Name
		if name == "" {
			name = "(empty)"
		}
		out = fmt.Sprintf("(empty RRset: name=%q type=%s rrs=%d rrsigs=%d)\n",
			name, typeStr, rrCount, sigCount)
	}

	return out
}
