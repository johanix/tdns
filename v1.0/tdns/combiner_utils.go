/*
 * Copyright (c) 2024-2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"

	"github.com/gookit/goutil/dump"
	core "github.com/johanix/tdns/v1.0/tdns/core"
	"github.com/miekg/dns"
	cmap "github.com/orcaman/concurrent-map/v2"
)

var AllowedLocalRRtypes = map[uint16]bool{
	dns.TypeDNSKEY: true,
	dns.TypeCDS:    true,
	dns.TypeCSYNC:  true,
	dns.TypeNS:     true,
}

// Returns true if the zone data was modified.
func (zd *ZoneData) CombineWithLocalChanges() (bool, error) {
	modified := false
	if zd.CombinerData == nil {
		zd.Logger.Printf("CombineWithLocalChanges: Zone %s: No combiner data to apply", zd.ZoneName)
		return false, nil
	}

	switch zd.ZoneStore {
	case SliceZone:
		// TODO: Implement this
	case XfrZone:
		// TODO: Implement this
	case MapZone:
		// Iterate over all owners in the CombinerData
		for item := range zd.CombinerData.IterBuffered() {
			ownerName := item.Key
			newOwnerData := item.Val

			if ownerName != zd.ZoneName {
				zd.Logger.Printf("CombineWithLocalChanges: Zone %s: LocalChanges outside apex (%s). Ignored", zd.ZoneName, ownerName)
				continue
			}

			// Get or create the owner in the main zone data
			existingOwnerData, exists := zd.Data.Get(ownerName)
			if !exists {
				// If owner doesn't exist in main data, create it
				existingOwnerData = OwnerData{
					Name:    ownerName,
					RRtypes: NewRRTypeStore(),
				}
			}

			// Replace RRsets for all RRtypes that exist in the combiner data
			for _, rrtype := range newOwnerData.RRtypes.Keys() {
				if zd.Debug {
					zd.Logger.Printf("CombineWithLocalChanges: Zone %s: Processing local change to owner %q RRtype %s", zd.ZoneName, ownerName, dns.TypeToString[rrtype])
				}
				if !AllowedLocalRRtypes[rrtype] {
					zd.Logger.Printf("CombineWithLocalChanges: Zone %s: LocalChanges apex RRtype %s is not allowed. Ignored", zd.ZoneName, dns.TypeToString[rrtype])
					continue
				}
				if zd.Debug {
					zd.Logger.Printf("CombineWithLocalChanges: Zone %s: LocalChanges apex RRset %s replaced", zd.ZoneName, dns.TypeToString[rrtype])
				}
				newRRset, _ := newOwnerData.RRtypes.Get(rrtype)
				existingOwnerData.RRtypes.Set(rrtype, newRRset)
				modified = true
			}

			// Update the main zone data with the modified owner data
			zd.Data.Set(ownerName, existingOwnerData)
		}
		return modified, nil
	}

	return false, fmt.Errorf("Not implemented")
}

// AddCombinerData adds or updates local RRsets for the zone.
// The input map keys are owner names and values are slices of RRsets.
func (zd *ZoneData) AddCombinerData(data map[string][]core.RRset) error {
	if zd.CombinerData == nil {
		var m = cmap.New[OwnerData]()
		zd.CombinerData = &m
	}

	dump.P(data)

	for owner, rrsets := range data {
		// Get or create owner data
		ownerData, exists := zd.CombinerData.Get(owner)
		if !exists {
			ownerData = OwnerData{
				Name:    owner,
				RRtypes: NewRRTypeStore(),
			}
		}

		// Add each RRset to the owner's RRtype store
		for _, rrset := range rrsets {
			if len(rrset.RRs) == 0 {
				continue // Skip empty RRsets
			}
			dump.P(rrset)
			rrtype := rrset.RRs[0].Header().Rrtype
			ownerData.RRtypes.Set(rrtype, rrset)
		}

		// Store updated owner data
		zd.CombinerData.Set(owner, ownerData)
	}

	modified, err := zd.CombineWithLocalChanges()
	if err != nil {
		return err
	}
	if modified {
		zd.Logger.Printf("AddCombinerData: Zone %q: Local changes applied immediately", zd.ZoneName)
	}
	return nil
}

// GetCombinerData retrieves all local combiner data for the zone
func (zd *ZoneData) GetCombinerData() (map[string][]core.RRset, error) {
	if zd.CombinerData == nil {
		return nil, fmt.Errorf("no local data exists for zone %s", zd.ZoneName)
	}

	result := make(map[string][]core.RRset)

	// Iterate over all owners in CombinerData
	for item := range zd.CombinerData.IterBuffered() {
		owner := item.Key
		ownerData := item.Val

		// Get all RRsets for this owner
		var rrsets []core.RRset
		for _, rrtype := range ownerData.RRtypes.Keys() {
			if rrset, ok := ownerData.RRtypes.Get(rrtype); ok {
				rrsets = append(rrsets, rrset)
			}
		}

		if len(rrsets) > 0 {
			result[owner] = rrsets
		}
	}

	return result, nil
}

// AddCombinerDataNG adds or updates local RRsets for the zone.
// The input map keys are owner names and values are slices of RR strings.
func (zd *ZoneData) AddCombinerDataNG(data map[string][]string) error {
	if zd.CombinerData == nil {
		var m = cmap.New[OwnerData]()
		zd.CombinerData = &m
	}

	// Convert string RRs to dns.RR objects and group them into RRsets
	rrsetData := make(map[string][]core.RRset)
	for owner, rrStrings := range data {
		var rrs []dns.RR
		for _, rrString := range rrStrings {
			rr, err := dns.NewRR(rrString)
			if err != nil {
				return fmt.Errorf("error parsing RR string %q: %v", rrString, err)
			}
			rrs = append(rrs, rr)
		}

		// Group RRs by type into RRsets
		rrsByType := make(map[uint16][]dns.RR)
		for _, rr := range rrs {
			rrtype := rr.Header().Rrtype
			rrsByType[rrtype] = append(rrsByType[rrtype], rr)
		}

		// Create RRsets
		var rrsets []core.RRset
		for rrtype, typeRRs := range rrsByType {
			rrsets = append(rrsets, core.RRset{
				Name:   owner,
				RRtype: rrtype,
				RRs:    typeRRs,
			})
		}
		rrsetData[owner] = rrsets
	}

	// Use the existing AddCombinerData method to store the data
	return zd.AddCombinerData(rrsetData)
}

// GetCombinerDataNG returns the combiner data in string format suitable for JSON marshaling
func (zd *ZoneData) GetCombinerDataNG() map[string][]RRsetString {
	responseData := make(map[string][]RRsetString)

	if zd.CombinerData == nil {
		return responseData
	}

	for owner, ownerData := range zd.CombinerData.Items() {
		var rrsets []RRsetString
		if ownerData.RRtypes != nil {
			for _, rrtype := range ownerData.RRtypes.Keys() {
				rrset, ok := ownerData.RRtypes.Get(rrtype)
				if !ok {
					continue
				}

				// Convert RRs to strings
				rrStrings := make([]string, len(rrset.RRs))
				for i, rr := range rrset.RRs {
					rrStrings[i] = rr.String()
				}

				// Convert RRSIGs to strings if present
				var rrsigStrings []string
				if len(rrset.RRSIGs) > 0 {
					rrsigStrings = make([]string, len(rrset.RRSIGs))
					for i, rrsig := range rrset.RRSIGs {
						rrsigStrings[i] = rrsig.String()
					}
				}

				rrsets = append(rrsets, RRsetString{
					Name:   rrset.Name,
					RRtype: rrtype,
					RRs:    rrStrings,
					RRSIGs: rrsigStrings,
				})
			}
		}
		responseData[owner] = rrsets
	}

	return responseData
}
