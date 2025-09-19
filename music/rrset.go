/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package music

// https://www.rfc-editor.org/rfc/rfc2181

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

// Add adds a RR to the RRset if it is not already present.
func (rrset *RRset) Add(rr dns.RR) {
	for _, rr2 := range rrset.RRs {
		if dns.IsDuplicate(rr, rr2) {
			return
		}
	}
	rrset.RRs = append(rrset.RRs, rr)
}

// Delete deletes a RR from the RRset if it is present.
func (rrset *RRset) Delete(rr dns.RR) {
	for i, rr2 := range rrset.RRs {
		if dns.IsDuplicate(rr, rr2) {
			rrset.RRs = append(rrset.RRs[:i], rrset.RRs[i+1:]...)
			return
		}
	}
}

// RRsetEqual compares two RRsets and returns if they are equal or not,
// include the non-matching RRs in a slice per RRset.
func RRsetEqual(rrset1, rrset2 []dns.RR) (bool, []dns.RR, []dns.RR) {
	allEqual := true
	var equal bool
	var rrset1Extra []dns.RR
	var rrset2Extra []dns.RR

	for _, rr1 := range rrset1 {
		equal = false
		for _, rr2 := range rrset2 {
			if dns.IsDuplicate(rr1, rr2) {
				equal = true
				break
			}
		}
		if !equal {
			// have not found rr1 in rrset2
			rrset1Extra = append(rrset1Extra, rr1)
			allEqual = false
		}
	}
	for _, rr2 := range rrset2 {
		equal = false
		for _, rr1 := range rrset1 {
			if dns.IsDuplicate(rr2, rr1) {
				equal = true
				break
			}
		}
		if !equal {
			// have not found rr2 in rrset1
			rrset2Extra = append(rrset2Extra, rr2)
			allEqual = false
		}
	}
	return allEqual, rrset1Extra, rrset2Extra
}

// SignerRRsetEqual compares a RRset across all signers and returns if they are equal or not
func SignerRRsetEqual(zone *Zone, rrType uint16) bool {
	log.Printf("Comparing %s RRset for %s\n", dns.TypeToString[rrType], zone.Name)
	rrSets := make(map[string][]dns.RR)
	var signerNames []string
	matches := true

	// Collect RRset for each signer
	for signerName, signer := range zone.SGroup.SignerMap {
		signerNames = append(signerNames, signerName)
		updater := GetUpdater(signer.Method)
		rrSet, err := updater.FetchRRset(signer, zone.Name, zone.Name, rrType)
		if err != nil {
			log.Printf("SignerCompare: Error from updater.FetchRRset (signer %s): %v", signer.Name, err)
		}
		rrSets[signer.Name] = rrSet
	}

	// Check that the RRsets match between the signers.
	numSigners := len(signerNames)
	if numSigners > 1 {
		for i := numSigners - 1; i > 0; i-- {
			match, rrSet1Extra, rrSet2Extra := RRsetEqual(rrSets[signerNames[0]], rrSets[signerNames[i]])
			if !match {
				matches = false
				if len(rrSet1Extra) > 0 {
					log.Printf("%s: Missing %s: %v\n", signerNames[i], dns.TypeToString[rrType], rrSet1Extra)
				}
				if len(rrSet2Extra) > 0 {
					log.Printf("%s: Missing %s: %v\n", signerNames[0], dns.TypeToString[rrType], rrSet2Extra)
				}
			}

		}
	}
	if !matches {
		_, err := zone.SetStopReason(fmt.Sprintf("%s not synced on signers", dns.TypeToString[rrType]))
		if err != nil {
			log.Printf("Couldn't set stop reason: %s not synced on signers\n", dns.TypeToString[rrType])
		}
	}
	return matches
}
