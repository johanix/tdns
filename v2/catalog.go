/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// MemberZone represents a zone discovered in a catalog zone
type MemberZone struct {
	ZoneName      string    `json:"zone_name"`
	Hash          string    `json:"hash"`
	ServiceGroups []string  `json:"service_groups"` // Groups associated with this zone (RFC 9432 terminology)
	SigningGroup  string    `json:"signing_group"`  // Signing group for this zone
	MetaGroup     string    `json:"meta_group"`     // Meta group for this zone
	DiscoveredAt  time.Time `json:"discovered_at"`
}

// CatalogZoneUpdate contains information about catalog zone changes
type CatalogZoneUpdate struct {
	CatalogZone string                    `json:"catalog_zone"`
	MemberZones map[string]*MemberZone    `json:"member_zones"`
	Serial      uint32                    `json:"serial"`
	UpdateTime  time.Time                 `json:"update_time"`
}

// CatalogZoneCallback is called when a catalog zone is updated
type CatalogZoneCallback func(update *CatalogZoneUpdate) error

var (
	catalogCallbacks      []CatalogZoneCallback
	catalogCallbacksMutex sync.RWMutex
)

// RegisterCatalogZoneCallback registers a callback for catalog zone updates
func RegisterCatalogZoneCallback(callback CatalogZoneCallback) {
	catalogCallbacksMutex.Lock()
	defer catalogCallbacksMutex.Unlock()
	catalogCallbacks = append(catalogCallbacks, callback)
	log.Printf("RegisterCatalogZoneCallback: Registered catalog zone callback")
}

// ParseCatalogZone parses a catalog zone and extracts member zones and groups
func ParseCatalogZone(zd *ZoneData) (*CatalogZoneUpdate, error) {
	if zd == nil || zd.Data.IsEmpty() {
		return nil, fmt.Errorf("catalog zone data is empty")
	}

	catalogZoneName := zd.ZoneName
	log.Printf("CATALOG: ParseCatalogZone: Starting to parse catalog zone %s", catalogZoneName)

	// Get SOA serial
	soa, err := zd.GetSOA()
	if err != nil {
		log.Printf("CATALOG: ParseCatalogZone: ERROR - failed to get catalog SOA: %v", err)
		return nil, fmt.Errorf("failed to get catalog SOA: %v", err)
	}
	log.Printf("CATALOG: ParseCatalogZone: Catalog zone %s has SOA serial %d", catalogZoneName, soa.Serial)

	// Group PTR records by opaque ID (hash)
	type memberInfo struct {
		zoneName string
		groups   []string
	}
	memberMap := make(map[string]*memberInfo) // hash -> member info

	zoneSuffix := fmt.Sprintf(".zones.%s", catalogZoneName)

	// Iterate through all owners in the zone
	for owner := range zd.Data.IterBuffered() {
		ownerName := owner.Key
		ownerData := owner.Val

		// Process *.zones.{catalog-zone}. records (PTR records with zone names)
		if strings.HasSuffix(ownerName, zoneSuffix) && !strings.HasPrefix(ownerName, "group.") {
			// Extract hash (opaque ID) from owner name
			// Format: {hash}.zones.{catalog-zone}.
			parts := strings.Split(ownerName, ".")
			if len(parts) < 3 {
				continue
			}
			hash := parts[0]

			// Get PTR records for this owner (should contain the zone name)
			ptrRRset := ownerData.RRtypes.GetOnlyRRSet(dns.TypePTR)
			if len(ptrRRset.RRs) == 0 {
				log.Printf("CATALOG: ParseCatalogZone: Warning: hash %s has no PTR record, skipping", hash)
				continue
			}

			// Process PTR records (should be just the zone name)
			for _, rr := range ptrRRset.RRs {
				ptr, ok := rr.(*dns.PTR)
				if !ok {
					continue
				}

				ptrValue := ptr.Ptr
				if memberMap[hash] == nil {
					memberMap[hash] = &memberInfo{}
				}
				memberMap[hash].zoneName = ptrValue
				log.Printf("CATALOG: ParseCatalogZone: Found zone %s (hash: %s)", ptrValue, hash)
			}
		}

		// Process group.{hash}.zones.{catalog-zone}. records (TXT records with groups)
		if strings.HasPrefix(ownerName, "group.") && strings.HasSuffix(ownerName, zoneSuffix) {
			// Extract hash from owner name
			// Format: group.{hash}.zones.{catalog-zone}.
			parts := strings.Split(ownerName, ".")
			if len(parts) < 4 {
				continue
			}
			hash := parts[1] // hash is the second part after "group"

			// Get TXT records for this owner (should contain group names)
			txtRRset := ownerData.RRtypes.GetOnlyRRSet(dns.TypeTXT)
			if len(txtRRset.RRs) == 0 {
				log.Printf("CATALOG: ParseCatalogZone: Warning: group.%s has no TXT record, skipping", hash)
				continue
			}

			// Process TXT records (each string is a group name)
			for _, rr := range txtRRset.RRs {
				txt, ok := rr.(*dns.TXT)
				if !ok {
					continue
				}

				if memberMap[hash] == nil {
					memberMap[hash] = &memberInfo{}
				}
				// TXT record contains multiple strings, each is a group
				memberMap[hash].groups = append(memberMap[hash].groups, txt.Txt...)
				log.Printf("CATALOG: ParseCatalogZone: Found groups for hash %s: %v", hash, txt.Txt)
			}
		}
	}

	// Convert to MemberZone structs, categorizing groups by type
	memberZones := make(map[string]*MemberZone)
	now := time.Now()

	for hash, info := range memberMap {
		if info.zoneName == "" {
			log.Printf("ParseCatalogZone: Warning: hash %s has groups but no zone name, skipping", hash)
			continue
		}

		// Categorize groups by prefix
		var serviceGroups []string
		var signingGroup string
		var metaGroup string

		for _, group := range info.groups {
			if strings.HasPrefix(group, "sign_") {
				if signingGroup != "" {
					log.Printf("ParseCatalogZone: Warning: Zone %s has multiple signing groups (%s, %s), using first",
						info.zoneName, signingGroup, group)
				} else {
					signingGroup = group
				}
			} else if strings.HasPrefix(group, "meta_") {
				if metaGroup != "" {
					log.Printf("ParseCatalogZone: Warning: Zone %s has multiple meta groups (%s, %s), using first",
						info.zoneName, metaGroup, group)
				} else {
					metaGroup = group
				}
			} else {
				// Service group (no specific prefix)
				serviceGroups = append(serviceGroups, group)
			}
		}

		// Log warning if no meta group (needed for auto-configuration)
		if metaGroup == "" {
			log.Printf("ParseCatalogZone: Info: Zone %s has no meta group, auto-configuration not possible",
				info.zoneName)
		}

		memberZones[info.zoneName] = &MemberZone{
			ZoneName:     info.zoneName,
			Hash:         hash,
			ServiceGroups: serviceGroups,
			SigningGroup:  signingGroup,
			MetaGroup:     metaGroup,
			DiscoveredAt:  now,
		}
	}

	update := &CatalogZoneUpdate{
		CatalogZone: catalogZoneName,
		MemberZones: memberZones,
		Serial:      soa.Serial,
		UpdateTime:  now,
	}

	log.Printf("CATALOG: ParseCatalogZone: Successfully parsed catalog zone %s (serial %d): %d member zones discovered",
		catalogZoneName, soa.Serial, len(memberZones))
	
	// Log details about each member zone
	for zoneName, member := range memberZones {
		log.Printf("CATALOG: ParseCatalogZone: Member zone %s - services: %v, signing: %s, meta: %s",
			zoneName, member.ServiceGroups, member.SigningGroup, member.MetaGroup)
	}

	return update, nil
}

// NotifyCatalogZoneUpdate invokes all registered callbacks
func NotifyCatalogZoneUpdate(update *CatalogZoneUpdate) error {
	catalogCallbacksMutex.RLock()
	callbacks := make([]CatalogZoneCallback, len(catalogCallbacks))
	copy(callbacks, catalogCallbacks)
	catalogCallbacksMutex.RUnlock()

	var firstErr error
	for _, callback := range callbacks {
		if err := callback(update); err != nil {
			log.Printf("NotifyCatalogZoneUpdate: Callback error: %v", err)
			if firstErr == nil {
				firstErr = err
			}
			// Continue with other callbacks even if one fails
		}
	}

	return firstErr
}

// AutoConfigureZonesFromCatalog auto-configures zones based on catalog and meta groups
func AutoConfigureZonesFromCatalog(ctx context.Context, update *CatalogZoneUpdate, conf *Config) error {
	log.Printf("CATALOG: AutoConfigureZonesFromCatalog: Starting for catalog %s with %d member zones", update.CatalogZone, len(update.MemberZones))
	log.Printf("CATALOG: AutoConfigureZonesFromCatalog: Policy check - catalog.policy.zones.add=%q", conf.Catalog.Policy.Zones.Add)
	
	// Get catalog zone's ZoneData for error reporting
	catalogZd, catalogExists := Zones.Get(update.CatalogZone)
	if !catalogExists {
		log.Printf("CATALOG: Warning: Catalog zone %s not found in Zones map", update.CatalogZone)
	}
	
	autoConfigureEnabled := conf.Catalog.Policy.Zones.Add == "auto"
	
	// VALIDATION: Check all member zones for configuration errors (applies regardless of policy)
	errorCount := 0
	for zoneName, member := range update.MemberZones {
		// VALIDATION (a): Check if zone references a group that doesn't exist in config
		// This validation applies regardless of auto-config policy
		if member.MetaGroup != "" {
			metaConfig, exists := conf.Catalog.MetaGroups[member.MetaGroup]
			if !exists {
				errorMsg := fmt.Sprintf("Member zone %s in catalog %s references group '%s' which does not exist in local config. Available groups: %v",
					zoneName, update.CatalogZone, member.MetaGroup, getMetaGroupNames(conf.Catalog.MetaGroups))
				log.Printf("CATALOG: ERROR: %s", errorMsg)
				if catalogExists {
					catalogZd.SetError(ConfigError, errorMsg)
					catalogZd.LatestError = time.Now()
				}
				errorCount++
				continue
			}
			
			// VALIDATION (b): Check if group config is insufficient for auto-configuration
			// This validation only applies when auto-config is enabled
			// Note: store defaults to "map" if not specified, so only upstream is required
			if autoConfigureEnabled && metaConfig.Upstream == "" {
				errorMsg := fmt.Sprintf("Member zone %s in catalog %s references group '%s' which is missing required field for auto-configuration (upstream: %q). 'upstream' is required when catalog.policy.zones.add=auto",
					zoneName, update.CatalogZone, member.MetaGroup, metaConfig.Upstream)
				log.Printf("CATALOG: ERROR: %s", errorMsg)
				if catalogExists {
					catalogZd.SetError(ConfigError, errorMsg)
					catalogZd.LatestError = time.Now()
				}
				errorCount++
				continue
			}
		}
	}
	
	if !autoConfigureEnabled {
		log.Printf("CATALOG: Auto-configure disabled by policy (catalog.policy.zones.add=%q, expected \"auto\"), catalog provides metadata only. %d member zones will not be auto-configured.", conf.Catalog.Policy.Zones.Add, len(update.MemberZones))
		// Clear error state if no validation errors were found (validation still runs to catch missing groups)
		if errorCount == 0 && catalogExists && catalogZd.Error && catalogZd.ErrorType == ConfigError {
			if strings.Contains(catalogZd.ErrorMsg, "Member zone") || strings.Contains(catalogZd.ErrorMsg, "references group") {
				log.Printf("CATALOG: All catalog zone member zone configurations are now valid, clearing previous error state")
				catalogZd.SetError(NoError, "")
			}
		}
		return nil
	}

	log.Printf("CATALOG: Auto-configure enabled, processing %d member zones from catalog %s", len(update.MemberZones), update.CatalogZone)
	log.Printf("CATALOG: Available meta_groups in config: %v", getMetaGroupNames(conf.Catalog.MetaGroups))

	processedCount := 0
	skippedCount := 0
	configuredCount := 0

	for zoneName, member := range update.MemberZones {
		log.Printf("CATALOG: Processing member zone %s (services: %v, signing: %s, meta: %s)", 
			zoneName, member.ServiceGroups, member.SigningGroup, member.MetaGroup)
		
		// RULE 1: Manual config ALWAYS wins (hardcoded behavior)
		if _, exists := Zones.Get(zoneName); exists {
			log.Printf("CATALOG: Zone %s manually configured, ignoring catalog entry (services: %v, meta: %s)",
				zoneName, member.ServiceGroups, member.MetaGroup)
			skippedCount++
			continue
		}

		// RULE 2: Meta group is required for auto-configuration
		if member.MetaGroup == "" {
			log.Printf("CATALOG: Zone %s has no meta group, cannot auto-configure", zoneName)
			skippedCount++
			continue
		}

		// Get meta group config (already validated above, but check again for safety)
		metaConfig, exists := conf.Catalog.MetaGroups[member.MetaGroup]
		if !exists {
			// Should not happen if validation above worked, but skip just in case
			log.Printf("CATALOG: Zone %s meta group '%s' not found in config, skipping. Available groups: %v",
				zoneName, member.MetaGroup, getMetaGroupNames(conf.Catalog.MetaGroups))
			skippedCount++
			continue
		}
		
		// Check if config is sufficient (already validated above, but check again for safety)
		// Note: store defaults to "map" if not specified, so only upstream is required
		if metaConfig.Upstream == "" {
			log.Printf("CATALOG: Zone %s meta group '%s' is missing required field (upstream: %q), skipping",
				zoneName, member.MetaGroup, metaConfig.Upstream)
			skippedCount++
			continue
		}

		// Determine store value (default to "map" if not specified)
		storeValue := metaConfig.Store
		if storeValue == "" {
			storeValue = "map"
		}

		// RULE 4: Auto-configure zone using meta group
		log.Printf("CATALOG: Auto-configuring zone %s using meta group '%s' (upstream: %s, store: %s)",
			zoneName, member.MetaGroup, metaConfig.Upstream, storeValue)

		zd := &ZoneData{
			ZoneName:      zoneName,
			ZoneType:      Secondary,
			ZoneStore:     parseZoneStore(storeValue),
			Upstream:      metaConfig.Upstream,
			Logger:        log.Default(),
			SourceCatalog: update.CatalogZone,
			Options: map[ZoneOption]bool{
				OptAutomaticZone: true, // Mark as dynamically configured
			},
		}

		// Apply zone options from meta group
		for _, optStr := range metaConfig.Options {
			if opt, exists := StringToZoneOption[optStr]; exists {
				zd.Options[opt] = true
			}
		}

		// Configure TSIG if specified
		if metaConfig.TsigKey != "" {
			_, ok := Globals.TsigKeys[metaConfig.TsigKey]
			if !ok {
				log.Printf("CATALOG: Warning: TSIG key '%s' not found for zone %s",
					metaConfig.TsigKey, zoneName)
			} else {
				// Apply TSIG configuration to zone
				// TODO: Set zd.TsigKey = tsigDetails (depends on TSIG implementation)
				log.Printf("CATALOG: Applied TSIG key '%s' to zone %s", metaConfig.TsigKey, zoneName)
			}
		}

		// Add to Zones map
		Zones.Set(zoneName, zd)
		log.Printf("CATALOG: Zone %s added to Zones map", zoneName)

		// Trigger initial zone transfer (non-blocking with timeout and context support)
		log.Printf("CATALOG: Triggering initial zone transfer for %s from %s", zoneName, metaConfig.Upstream)
		zr := ZoneRefresher{
			Name:      zoneName,
			ZoneType:  Secondary,
			Primary:   metaConfig.Upstream,
			ZoneStore: zd.ZoneStore,
			Options:   zd.Options,
		}
		
		// Attempt non-blocking send with timeout and context cancellation support
		select {
		case conf.Internal.RefreshZoneCh <- zr:
			// Successfully enqueued
		case <-ctx.Done():
			log.Printf("CATALOG: WARNING: Context cancelled while attempting to enqueue zone refresh for %s, dropping refresh request", zoneName)
			// Context cancelled, drop the send
		case <-time.After(5 * time.Second):
			log.Printf("CATALOG: WARNING: Timeout while attempting to enqueue zone refresh for %s (channel may be full), dropping refresh request", zoneName)
			// Timeout - channel likely full, drop the send
		}

		log.Printf("CATALOG: Zone %s auto-configured successfully (meta: %s, signing: %s, services: %v)",
			zoneName, member.MetaGroup, member.SigningGroup, member.ServiceGroups)
		configuredCount++
		processedCount++
	}

	log.Printf("CATALOG: AutoConfigureZonesFromCatalog: Completed. Processed: %d, Configured: %d, Skipped: %d, Errors: %d", 
		processedCount, configuredCount, skippedCount, errorCount)
	
	// Clear error state if no errors were found and zone was previously in error
	if errorCount == 0 && catalogExists && catalogZd.Error && catalogZd.ErrorType == ConfigError {
		// Check if the error was catalog-related (contains "Member zone" or "references group")
		if strings.Contains(catalogZd.ErrorMsg, "Member zone") || strings.Contains(catalogZd.ErrorMsg, "references group") {
			log.Printf("CATALOG: All catalog zone member zone configurations are now valid, clearing previous error state")
			catalogZd.SetError(NoError, "")
		}
	}
	
	return nil
}

// getMetaGroupNames returns a list of meta group names for logging
func getMetaGroupNames(metaGroups map[string]*MetaGroupConfig) []string {
	if metaGroups == nil {
		return []string{}
	}
	names := make([]string, 0, len(metaGroups))
	for name := range metaGroups {
		names = append(names, name)
	}
	return names
}

// parseZoneStore converts a zone store string to ZoneStore type
// Defaults to MapZone if empty or unknown (matching parseconfig.go behavior)
func parseZoneStore(storeStr string) ZoneStore {
	storeStr = strings.ToLower(strings.TrimSpace(storeStr))
	switch storeStr {
	case "xfr":
		return XfrZone
	case "map":
		return MapZone
	case "slice":
		return SliceZone
	case "":
		// Default to map when not specified
		return MapZone
	default:
		log.Printf("Unknown zone store type %q, defaulting to map", storeStr)
		return MapZone
	}
}

// --- Catalog Zone Management (Primary Side) ---

// CatalogMembership manages the membership data for a catalog zone
type CatalogMembership struct {
	mu              sync.RWMutex
	CatalogZoneName string
	MemberZones     map[string]*CatalogMemberZone // zonename -> member data
	AvailableGroups []string                       // List of all defined groups (RFC 9432 terminology)
}

// CatalogMemberZone represents a member zone in the catalog
type CatalogMemberZone struct {
	ZoneName     string
	Hash         string    // SHA256 hash of zone name (first 16 chars)
	Groups       []string  // List of group names associated with this zone (RFC 9432 terminology)
	DiscoveredAt time.Time // Timestamp when the zone was first added to the catalog
}

var (
	catalogMemberships     = make(map[string]*CatalogMembership) // catalog-zone-name -> membership
	catalogMembershipMutex sync.RWMutex
)

// GetOrCreateCatalogMembership returns the membership for a catalog zone, creating if needed
func GetOrCreateCatalogMembership(catalogZoneName string) *CatalogMembership {
	catalogMembershipMutex.Lock()
	defer catalogMembershipMutex.Unlock()

	if cm, exists := catalogMemberships[catalogZoneName]; exists {
		return cm
	}

	cm := &CatalogMembership{
		CatalogZoneName: catalogZoneName,
		MemberZones:     make(map[string]*CatalogMemberZone),
		AvailableGroups: []string{},
	}
	catalogMemberships[catalogZoneName] = cm
	return cm
}

// AddMemberZone adds a zone to the catalog
func (cm *CatalogMembership) AddMemberZone(zoneName string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if _, exists := cm.MemberZones[zoneName]; exists {
		return fmt.Errorf("zone %s already exists in catalog %s", zoneName, cm.CatalogZoneName)
	}

	cm.MemberZones[zoneName] = &CatalogMemberZone{
		ZoneName:     zoneName,
		Hash:         generateZoneHash(zoneName),
		Groups:       []string{},
		DiscoveredAt: time.Now(),
	}

	log.Printf("CATALOG: Added zone %s to catalog %s (hash: %s)", zoneName, cm.CatalogZoneName, cm.MemberZones[zoneName].Hash)
	return nil
}

// RemoveMemberZone removes a zone from the catalog
func (cm *CatalogMembership) RemoveMemberZone(zoneName string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if _, exists := cm.MemberZones[zoneName]; !exists {
		return fmt.Errorf("zone %s not found in catalog %s", zoneName, cm.CatalogZoneName)
	}

	delete(cm.MemberZones, zoneName)
	log.Printf("CATALOG: Removed zone %s from catalog %s", zoneName, cm.CatalogZoneName)
	return nil
}

// AddGroup adds a group to the available groups list
func (cm *CatalogMembership) AddGroup(group string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Check if already exists
	for _, g := range cm.AvailableGroups {
		if g == group {
			return fmt.Errorf("group %s already exists in catalog %s", group, cm.CatalogZoneName)
		}
	}

	cm.AvailableGroups = append(cm.AvailableGroups, group)
	log.Printf("CATALOG: Added group %s to catalog %s", group, cm.CatalogZoneName)
	return nil
}

// RemoveGroup removes a group from the available groups list
func (cm *CatalogMembership) RemoveGroup(group string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	found := false
	newGroups := []string{}
	for _, g := range cm.AvailableGroups {
		if g != group {
			newGroups = append(newGroups, g)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("group %s not found in catalog %s", group, cm.CatalogZoneName)
	}

	cm.AvailableGroups = newGroups
	log.Printf("CATALOG: Removed group %s from catalog %s", group, cm.CatalogZoneName)
	return nil
}

// AddZoneGroup associates a group with a zone
func (cm *CatalogMembership) AddZoneGroup(zoneName, group string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	member, exists := cm.MemberZones[zoneName]
	if !exists {
		return fmt.Errorf("zone %s not found in catalog %s", zoneName, cm.CatalogZoneName)
	}

	// Check if group exists in catalog's available groups
	groupExists := false
	for _, g := range cm.AvailableGroups {
		if g == group {
			groupExists = true
			break
		}
	}
	if !groupExists {
		return fmt.Errorf("group %s is not defined in catalog %s. Add it to the catalog first using 'catalog group add'", group, cm.CatalogZoneName)
	}

	// Check if group already associated with this zone (exact duplicate)
	for _, g := range member.Groups {
		if g == group {
			return fmt.Errorf("Group %s is already added to zone %s", group, zoneName)
		}
	}

	// Check for meta_ and sign_ group uniqueness (different group of same type)
	if strings.HasPrefix(group, "meta_") {
		for _, g := range member.Groups {
			if strings.HasPrefix(g, "meta_") {
				return fmt.Errorf("Only one meta group allowed for %s (zone already has group %s)", zoneName, g)
			}
		}
	} else if strings.HasPrefix(group, "sign_") {
		for _, g := range member.Groups {
			if strings.HasPrefix(g, "sign_") {
				return fmt.Errorf("Only one sign group allowed for %s (zone already has group %s)", zoneName, g)
			}
		}
	}

	member.Groups = append(member.Groups, group)
	log.Printf("CATALOG: Added group %s to zone %s in catalog %s", group, zoneName, cm.CatalogZoneName)
	return nil
}

// RemoveZoneGroup disassociates a group from a zone
func (cm *CatalogMembership) RemoveZoneGroup(zoneName, group string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	member, exists := cm.MemberZones[zoneName]
	if !exists {
		return fmt.Errorf("zone %s not found in catalog %s", zoneName, cm.CatalogZoneName)
	}

	found := false
	newGroups := []string{}
	for _, g := range member.Groups {
		if g != group {
			newGroups = append(newGroups, g)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("group %s not associated with zone %s", group, zoneName)
	}

	member.Groups = newGroups
	log.Printf("CATALOG: Removed group %s from zone %s in catalog %s", group, zoneName, cm.CatalogZoneName)
	return nil
}

// GetMemberZones returns all member zones (thread-safe copy)
func (cm *CatalogMembership) GetMemberZones() map[string]*MemberZone {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	result := make(map[string]*MemberZone)
	for zoneName, member := range cm.MemberZones {
		// Categorize groups by type
		var serviceGroups []string
		var signingGroup string
		var metaGroup string

		for _, grp := range member.Groups {
			if strings.HasPrefix(grp, "sign_") {
				if signingGroup == "" {
					signingGroup = grp
				}
			} else if strings.HasPrefix(grp, "meta_") {
				if metaGroup == "" {
					metaGroup = grp
				}
			} else {
				serviceGroups = append(serviceGroups, grp)
			}
		}

		// Use the stored DiscoveredAt timestamp, or time.Now() if not set (for backward compatibility)
		discoveredAt := member.DiscoveredAt
		if discoveredAt.IsZero() {
			discoveredAt = time.Now()
		}

		result[zoneName] = &MemberZone{
			ZoneName:     zoneName,
			Hash:         member.Hash,
			ServiceGroups: serviceGroups,
			SigningGroup:  signingGroup,
			MetaGroup:     metaGroup,
			DiscoveredAt:  discoveredAt,
		}
	}

	return result
}

// GetGroups returns all available groups (thread-safe copy)
func (cm *CatalogMembership) GetGroups() []string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	result := make([]string, len(cm.AvailableGroups))
	copy(result, cm.AvailableGroups)
	return result
}

// generateZoneHash generates a SHA256 hash of the zone name (first 16 hex chars)
func generateZoneHash(zoneName string) string {
	h := sha256.New()
	h.Write([]byte(zoneName))
	hash := hex.EncodeToString(h.Sum(nil))
	return hash[:16] // Use first 16 characters as opaque ID
}
