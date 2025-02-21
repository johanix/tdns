/*
*
 */

package tdns

import (
	"fmt"

	"github.com/miekg/dns"
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
	case XfrZone:
		// TODO: Implement this
	}

	return false, fmt.Errorf("Not implemented")
}
