/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	core "github.com/johanix/tdns/v0.x/core"
	"github.com/miekg/dns"
)

// APICatalog handles catalog zone management operations
func APICatalog(app *AppDetails) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var data CatalogPost

		resp := CatalogResponse{
			Time: time.Now(),
		}

		if r.Body == http.NoBody {
			resp.Error = true
			resp.ErrorMsg = "Error: missing request body"
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(resp)
			return
		}

		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error decoding JSON: %v", err)
			log.Printf("APICatalog: JSON decode error: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(resp)
			return
		}

		log.Printf("APICatalog: command=%s catalog=%s zone=%s group=%s",
			data.Command, data.CatalogZone, data.Zone, data.Group)

		switch data.Command {
		case "create":
			err = handleCatalogCreate(data.CatalogZone, &resp)

		case "zone-add":
			err = handleCatalogZoneAdd(data.CatalogZone, data.Zone, &resp)

		case "zone-delete":
			err = handleCatalogZoneDelete(data.CatalogZone, data.Zone, &resp)

		case "zone-list":
			err = handleCatalogZoneList(data.CatalogZone, &resp)

		case "group-add":
			err = handleCatalogGroupAdd(data.CatalogZone, data.Group, &resp)

		case "group-delete":
			err = handleCatalogGroupDelete(data.CatalogZone, data.Group, &resp)

		case "group-list":
			err = handleCatalogGroupList(data.CatalogZone, &resp)

		case "zone-group-add":
			err = handleCatalogZoneGroupAdd(data.CatalogZone, data.Zone, data.Group, &resp)

		case "zone-group-delete":
			err = handleCatalogZoneGroupDelete(data.CatalogZone, data.Zone, data.Group, &resp)

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", data.Command)
			log.Printf("APICatalog: Unknown command: %s", data.Command)
		}

		if err != nil && !resp.Error {
			resp.Error = true
			resp.ErrorMsg = err.Error()
		}

		w.Header().Set("Content-Type", "application/json")
		if resp.Error {
			w.WriteHeader(http.StatusBadRequest)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		json.NewEncoder(w).Encode(resp)
	}
}

func handleCatalogCreate(catalogZoneName string, resp *CatalogResponse) error {
	if catalogZoneName == "" {
		return fmt.Errorf("catalog zone name is required")
	}

	// Ensure zone name is FQDN
	catalogZoneName = dns.Fqdn(catalogZoneName)

	// Check if catalog zone already exists in Zones
	if _, exists := Zones.Get(catalogZoneName); exists {
		return fmt.Errorf("zone %s already exists", catalogZoneName)
	}

	// Create the catalog membership
	_ = GetOrCreateCatalogMembership(catalogZoneName)

	// Use CreateAutoZone to create the catalog zone
	kdb := &KeyDB{} // Empty KeyDB for catalog zones
	zd, err := kdb.CreateAutoZone(catalogZoneName, []string{})
	if err != nil {
		return fmt.Errorf("failed to create catalog zone: %v", err)
	}

	// Mark it as a catalog zone
	zd.Options[OptCatalogZone] = true

	// Add version TXT record: version.{catalog} IN TXT "2" (RFC 9432 requirement)
	versionOwner := fmt.Sprintf("version.%s", catalogZoneName)
	versionTxtStr := fmt.Sprintf("%s 0 IN TXT \"2\"", versionOwner)
	versionTxt, err := dns.NewRR(versionTxtStr)
	if err != nil {
		return fmt.Errorf("failed to create version TXT record: %v", err)
	}

	// Get or create OwnerData for version owner
	ownerData, exists := zd.Data.Get(versionOwner)
	if !exists {
		ownerData = OwnerData{
			Name:    versionOwner,
			RRtypes: NewRRTypeStore(),
		}
	}

	// Create or update TXT RRset
	rrset := core.RRset{
		Name:   versionOwner,
		RRtype: dns.TypeTXT,
		Class:  dns.ClassINET,
		RRs:    []dns.RR{versionTxt},
	}
	ownerData.RRtypes.Set(dns.TypeTXT, rrset)
	zd.Data.Set(versionOwner, ownerData)

	// Register the zone
	Zones.Set(catalogZoneName, zd)

	resp.Msg = fmt.Sprintf("Catalog zone %s created successfully", catalogZoneName)
	log.Printf("CATALOG: Created catalog zone %s", catalogZoneName)
	return nil
}

func handleCatalogZoneAdd(catalogZoneName, zoneName string, resp *CatalogResponse) error {
	if catalogZoneName == "" || zoneName == "" {
		return fmt.Errorf("catalog zone name and member zone name are required")
	}

	catalogZoneName = dns.Fqdn(catalogZoneName)
	zoneName = dns.Fqdn(zoneName)

	cm := GetOrCreateCatalogMembership(catalogZoneName)
	err := cm.AddMemberZone(zoneName)
	if err != nil {
		return err
	}

	// Regenerate catalog zone PTR records
	err = regenerateCatalogZone(catalogZoneName)
	if err != nil {
		return fmt.Errorf("failed to regenerate catalog zone: %v", err)
	}

	resp.Msg = fmt.Sprintf("Zone %s added to catalog %s", zoneName, catalogZoneName)
	return nil
}

func handleCatalogZoneDelete(catalogZoneName, zoneName string, resp *CatalogResponse) error {
	if catalogZoneName == "" || zoneName == "" {
		return fmt.Errorf("catalog zone name and member zone name are required")
	}

	catalogZoneName = dns.Fqdn(catalogZoneName)
	zoneName = dns.Fqdn(zoneName)

	cm := GetOrCreateCatalogMembership(catalogZoneName)
	err := cm.RemoveMemberZone(zoneName)
	if err != nil {
		return err
	}

	// Regenerate catalog zone PTR records
	err = regenerateCatalogZone(catalogZoneName)
	if err != nil {
		return fmt.Errorf("failed to regenerate catalog zone: %v", err)
	}

	resp.Msg = fmt.Sprintf("Zone %s removed from catalog %s", zoneName, catalogZoneName)
	return nil
}

func handleCatalogZoneList(catalogZoneName string, resp *CatalogResponse) error {
	if catalogZoneName == "" {
		return fmt.Errorf("catalog zone name is required")
	}

	catalogZoneName = dns.Fqdn(catalogZoneName)

	cm := GetOrCreateCatalogMembership(catalogZoneName)
	resp.Zones = cm.GetMemberZones()
	return nil
}

func handleCatalogGroupAdd(catalogZoneName, group string, resp *CatalogResponse) error {
	if catalogZoneName == "" || group == "" {
		return fmt.Errorf("catalog zone name and group name are required")
	}

	catalogZoneName = dns.Fqdn(catalogZoneName)

	cm := GetOrCreateCatalogMembership(catalogZoneName)
	err := cm.AddGroup(group)
	if err != nil {
		return err
	}

	resp.Msg = fmt.Sprintf("Group %s added to catalog %s", group, catalogZoneName)
	return nil
}

func handleCatalogGroupDelete(catalogZoneName, group string, resp *CatalogResponse) error {
	if catalogZoneName == "" || group == "" {
		return fmt.Errorf("catalog zone name and group name are required")
	}

	catalogZoneName = dns.Fqdn(catalogZoneName)

	cm := GetOrCreateCatalogMembership(catalogZoneName)
	err := cm.RemoveGroup(group)
	if err != nil {
		return err
	}

	resp.Msg = fmt.Sprintf("Group %s removed from catalog %s", group, catalogZoneName)
	return nil
}

func handleCatalogGroupList(catalogZoneName string, resp *CatalogResponse) error {
	if catalogZoneName == "" {
		return fmt.Errorf("catalog zone name is required")
	}

	catalogZoneName = dns.Fqdn(catalogZoneName)

	cm := GetOrCreateCatalogMembership(catalogZoneName)
	resp.Groups = cm.GetGroups()
	return nil
}

func handleCatalogZoneGroupAdd(catalogZoneName, zoneName, group string, resp *CatalogResponse) error {
	if catalogZoneName == "" || zoneName == "" || group == "" {
		return fmt.Errorf("catalog zone name, member zone name, and group name are required")
	}

	catalogZoneName = dns.Fqdn(catalogZoneName)
	zoneName = dns.Fqdn(zoneName)

	cm := GetOrCreateCatalogMembership(catalogZoneName)
	err := cm.AddZoneGroup(zoneName, group)
	if err != nil {
		return err
	}

	// Regenerate catalog zone PTR records
	err = regenerateCatalogZone(catalogZoneName)
	if err != nil {
		return fmt.Errorf("failed to regenerate catalog zone: %v", err)
	}

	resp.Msg = fmt.Sprintf("Group %s added to zone %s in catalog %s", group, zoneName, catalogZoneName)
	return nil
}

func handleCatalogZoneGroupDelete(catalogZoneName, zoneName, group string, resp *CatalogResponse) error {
	if catalogZoneName == "" || zoneName == "" || group == "" {
		return fmt.Errorf("catalog zone name, member zone name, and group name are required")
	}

	catalogZoneName = dns.Fqdn(catalogZoneName)
	zoneName = dns.Fqdn(zoneName)

	cm := GetOrCreateCatalogMembership(catalogZoneName)
	err := cm.RemoveZoneGroup(zoneName, group)
	if err != nil {
		return err
	}

	// Regenerate catalog zone PTR records
	err = regenerateCatalogZone(catalogZoneName)
	if err != nil {
		return fmt.Errorf("failed to regenerate catalog zone: %v", err)
	}

	resp.Msg = fmt.Sprintf("Group %s removed from zone %s in catalog %s", group, zoneName, catalogZoneName)
	return nil
}

// regenerateCatalogZone rebuilds the catalog zone PTR records from membership data
func regenerateCatalogZone(catalogZoneName string) error {
	zd, exists := Zones.Get(catalogZoneName)
	if !exists {
		return fmt.Errorf("catalog zone %s not found", catalogZoneName)
	}

	cm := GetOrCreateCatalogMembership(catalogZoneName)

	// Remove all existing zone records (*.zones.{catalog} and group.*.zones.{catalog})
	zoneSuffix := fmt.Sprintf(".zones.%s", catalogZoneName)
	for owner := range zd.Data.IterBuffered() {
		if strings.HasSuffix(owner.Key, zoneSuffix) {
			zd.Data.Remove(owner.Key)
		}
	}

	// Generate PTR and TXT records for each member zone
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	for _, member := range cm.MemberZones {
		ownerName := fmt.Sprintf("%s.zones.%s", member.Hash, catalogZoneName)

		// PTR record: zone name
		ptrStr := fmt.Sprintf("%s 0 IN PTR %s", ownerName, member.ZoneName)
		ptr, err := dns.NewRR(ptrStr)
		if err != nil {
			log.Printf("Error creating PTR for zone %s: %v", member.ZoneName, err)
			continue
		}

		// Create RRset for PTR record
		ptrRRset := core.RRset{
			Name:   ownerName,
			RRtype: dns.TypePTR,
			Class:  dns.ClassINET,
			RRs:    []dns.RR{ptr},
		}

		// Get or create OwnerData for this owner
		ownerData, exists := zd.Data.Get(ownerName)
		if !exists {
			ownerData = OwnerData{
				Name:    ownerName,
				RRtypes: NewRRTypeStore(),
			}
		}

		// Add the PTR RRset to the owner
		ownerData.RRtypes.Set(dns.TypePTR, ptrRRset)
		zd.Data.Set(ownerName, ownerData)

		// TXT record for groups: group.{uniqueid}.zones.{catalog} with all groups
		if len(member.Groups) > 0 {
			groupOwnerName := fmt.Sprintf("group.%s.zones.%s", member.Hash, catalogZoneName)

			// Create TXT record with all groups as strings
			// Format: "group1" "group2" "group3" ...
			txtStrings := make([]string, len(member.Groups))
			for i, grp := range member.Groups {
				txtStrings[i] = grp
			}

			// Create TXT RR with all group strings
			txtRR := &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   groupOwnerName,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				Txt: txtStrings,
			}

			// Create RRset for TXT record
			txtRRset := core.RRset{
				Name:   groupOwnerName,
				RRtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				RRs:    []dns.RR{txtRR},
			}

			// Get or create OwnerData for group owner
			groupOwnerData, exists := zd.Data.Get(groupOwnerName)
			if !exists {
				groupOwnerData = OwnerData{
					Name:    groupOwnerName,
					RRtypes: NewRRTypeStore(),
				}
			}

			// Add the TXT RRset to the group owner
			groupOwnerData.RRtypes.Set(dns.TypeTXT, txtRRset)
			zd.Data.Set(groupOwnerName, groupOwnerData)
		}
	}

	// Bump SOA serial
	_, err := zd.BumpSerial()
	if err != nil {
		log.Printf("Error bumping SOA serial for catalog %s: %v", catalogZoneName, err)
	}

	// Notify downstreams
	zd.NotifyDownstreams()

	log.Printf("CATALOG: Regenerated catalog zone %s with %d member zones", catalogZoneName, len(cm.MemberZones))
	return nil
}
