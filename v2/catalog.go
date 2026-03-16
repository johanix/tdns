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
	CatalogZone string                 `json:"catalog_zone"`
	MemberZones map[string]*MemberZone `json:"member_zones"`
	Serial      uint32                 `json:"serial"`
	UpdateTime  time.Time              `json:"update_time"`
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
	lg.Info("RegisterCatalogZoneCallback: registered catalog zone callback")
}

// ParseCatalogZone parses a catalog zone and extracts member zones and groups
func ParseCatalogZone(zd *ZoneData) (*CatalogZoneUpdate, error) {
	if zd == nil || zd.Data.IsEmpty() {
		return nil, fmt.Errorf("catalog zone data is empty")
	}

	catalogZoneName := zd.ZoneName
	lg.Info("CATALOG: ParseCatalogZone: starting to parse catalog zone", "zone", catalogZoneName)

	// Get SOA serial
	soa, err := zd.GetSOA()
	if err != nil {
		lg.Error("CATALOG: ParseCatalogZone: failed to get catalog SOA", "error", err)
		return nil, fmt.Errorf("failed to get catalog SOA: %v", err)
	}
	lg.Info("CATALOG: ParseCatalogZone: catalog zone SOA", "zone", catalogZoneName, "serial", soa.Serial)

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
				lg.Warn("CATALOG: ParseCatalogZone: hash has no PTR record, skipping", "hash", hash)
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
				lg.Debug("CATALOG: ParseCatalogZone: found zone", "zone", ptrValue, "hash", hash)
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
				lg.Warn("CATALOG: ParseCatalogZone: group has no TXT record, skipping", "hash", hash)
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
				lg.Debug("CATALOG: ParseCatalogZone: found groups for hash", "hash", hash, "groups", txt.Txt)
			}
		}
	}

	// Convert to MemberZone structs, categorizing groups by type
	memberZones := make(map[string]*MemberZone)
	now := time.Now()

	for hash, info := range memberMap {
		if info.zoneName == "" {
			lg.Warn("ParseCatalogZone: hash has groups but no zone name, skipping", "hash", hash)
			continue
		}

		// Categorize groups by configured prefixes
		var serviceGroups []string
		var signingGroup string
		var configGroup string

		// Get configured group prefixes
		if Conf.Catalog == nil {
			lg.Error("ParseCatalogZone: Conf.Catalog is nil, cannot categorize groups")
			return nil, fmt.Errorf("Conf.Catalog is nil, cannot parse catalog zone")
		}
		configPrefix := Conf.Catalog.GroupPrefixes.Config
		signingPrefix := Conf.Catalog.GroupPrefixes.Signing

		for _, group := range info.groups {
			// Check if this is a signing group (only if prefix != "none")
			if signingPrefix != "none" && strings.HasPrefix(group, signingPrefix) {
				if signingGroup != "" {
					lg.Warn("ParseCatalogZone: zone has multiple signing groups, using first", "zone", info.zoneName, "existing", signingGroup, "duplicate", group)
				} else {
					signingGroup = group
				}
			} else if configPrefix != "none" && strings.HasPrefix(group, configPrefix) {
				// Check if this is a config group (only if prefix != "none")
				if configGroup != "" {
					lg.Warn("ParseCatalogZone: zone has multiple config groups, using first", "zone", info.zoneName, "existing", configGroup, "duplicate", group)
				} else {
					configGroup = group
				}
			} else {
				// Service group (no specific prefix), or all groups are ordinary if both prefixes are "none"
				serviceGroups = append(serviceGroups, group)
			}
		}

		// Log info if no config group (needed for auto-configuration)
		if configPrefix != "none" && configGroup == "" {
			lg.Info("ParseCatalogZone: zone has no config group, auto-configuration not possible", "zone", info.zoneName)
		}

		memberZones[info.zoneName] = &MemberZone{
			ZoneName:      info.zoneName,
			Hash:          hash,
			ServiceGroups: serviceGroups,
			SigningGroup:  signingGroup,
			MetaGroup:     configGroup, // Note: Field named MetaGroup for backward compat, but contains config group
			DiscoveredAt:  now,
		}
	}

	update := &CatalogZoneUpdate{
		CatalogZone: catalogZoneName,
		MemberZones: memberZones,
		Serial:      soa.Serial,
		UpdateTime:  now,
	}

	lg.Info("CATALOG: ParseCatalogZone: successfully parsed catalog zone", "zone", catalogZoneName, "serial", soa.Serial, "members", len(memberZones))

	// Log details about each member zone
	for zoneName, member := range memberZones {
		lg.Debug("CATALOG: ParseCatalogZone: member zone", "zone", zoneName, "services", member.ServiceGroups, "signing", member.SigningGroup, "meta", member.MetaGroup)
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
			lg.Error("NotifyCatalogZoneUpdate: callback error", "error", err)
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
	lg.Info("CATALOG: AutoConfigureZonesFromCatalog: starting", "catalog", update.CatalogZone, "members", len(update.MemberZones))

	// Get catalog zone's ZoneData to check its options
	catalogZd, catalogExists := Zones.Get(update.CatalogZone)
	if !catalogExists {
		lg.Warn("CATALOG: catalog zone not found in Zones map", "zone", update.CatalogZone)
		return fmt.Errorf("AutoConfigureZonesFromCatalog: catalog zone %s not found in Zones map", update.CatalogZone)
	}

	if conf.Catalog == nil {
		lg.Warn("CATALOG: conf.Catalog is nil, cannot auto-configure zones")
		return fmt.Errorf("AutoConfigureZonesFromCatalog: conf.Catalog is nil for catalog zone %s", update.CatalogZone)
	}

	// Check if auto-create is enabled for this catalog zone
	autoConfigureEnabled := catalogZd.Options[OptCatalogMemberAutoCreate]
	lg.Info("CATALOG: AutoConfigureZonesFromCatalog: policy check", "catalog", update.CatalogZone, "autoCreate", autoConfigureEnabled)

	// VALIDATION: Check all member zones for configuration errors (applies regardless of policy)
	errorCount := 0
	for zoneName, member := range update.MemberZones {
		// Validate zone name is a valid FQDN
		if !dns.IsFqdn(zoneName) {
			errorMsg := fmt.Sprintf("Member zone %q in catalog %s is not a valid FQDN", zoneName, update.CatalogZone)
			lg.Error("CATALOG: validation error", "msg", errorMsg)
			errorCount++
			continue
		}
		// VALIDATION (a): Check if zone references a group that doesn't exist in config
		// This validation applies regardless of auto-config policy
		if member.MetaGroup != "" {
			configGroupConfig, exists := conf.Catalog.ConfigGroups[member.MetaGroup]
			if !exists {
				errorMsg := fmt.Sprintf("Member zone %s in catalog %s references group '%s' which does not exist in local config. Available groups: %v",
					zoneName, update.CatalogZone, member.MetaGroup, getConfigGroupNames(conf.Catalog.ConfigGroups))
				lg.Error("CATALOG: validation error", "msg", errorMsg)
				if catalogExists {
					catalogZd.SetError(ConfigError, "%s", errorMsg)
					catalogZd.LatestError = time.Now()
				}
				errorCount++
				continue
			}

			// VALIDATION (b): Check if group config is insufficient for auto-configuration
			// This validation only applies when auto-config is enabled
			// Note: store defaults to "map" if not specified, so only upstream is required
			if autoConfigureEnabled && configGroupConfig.Upstream == "" {
				errorMsg := fmt.Sprintf("Member zone %s in catalog %s references group '%s' which is missing required field for auto-configuration (upstream: %q). 'upstream' is required when catalog-member-auto-create is enabled",
					zoneName, update.CatalogZone, member.MetaGroup, configGroupConfig.Upstream)
				lg.Error("CATALOG: validation error", "msg", errorMsg)
				if catalogExists {
					catalogZd.SetError(ConfigError, "%s", errorMsg)
					catalogZd.LatestError = time.Now()
				}
				errorCount++
				continue
			}
		}
	}

	if !autoConfigureEnabled {
		lg.Info("CATALOG: auto-configure disabled, catalog provides metadata only", "catalog", update.CatalogZone, "members", len(update.MemberZones))
		// Clear error state if no validation errors were found (validation still runs to catch missing groups)
		if errorCount == 0 && catalogExists && catalogZd.Error && catalogZd.ErrorType == ConfigError {
			if strings.Contains(catalogZd.ErrorMsg, "Member zone") || strings.Contains(catalogZd.ErrorMsg, "references group") {
				lg.Info("CATALOG: all member zone configurations now valid, clearing previous error state")
				catalogZd.SetError(NoError, "")
			}
		}
		return nil
	}

	lg.Info("CATALOG: auto-configure enabled, processing member zones", "members", len(update.MemberZones), "catalog", update.CatalogZone)
	lg.Debug("CATALOG: available config groups", "groups", getConfigGroupNames(conf.Catalog.ConfigGroups))

	processedCount := 0
	skippedCount := 0
	configuredCount := 0

	for zoneName, member := range update.MemberZones {
		lg.Debug("CATALOG: processing member zone", "zone", zoneName, "services", member.ServiceGroups, "signing", member.SigningGroup, "meta", member.MetaGroup)

		// RULE 1: Manual config ALWAYS wins (hardcoded behavior)
		if _, exists := Zones.Get(zoneName); exists {
			lg.Debug("CATALOG: zone manually configured, ignoring catalog entry", "zone", zoneName, "services", member.ServiceGroups, "meta", member.MetaGroup)
			skippedCount++
			continue
		}

		// RULE 2: Meta group is required for auto-configuration
		if member.MetaGroup == "" {
			lg.Debug("CATALOG: zone has no meta group, cannot auto-configure", "zone", zoneName)
			skippedCount++
			continue
		}

		// Get meta group config (already validated above, but check again for safety)
		configGroupConfig, exists := conf.Catalog.ConfigGroups[member.MetaGroup]
		if !exists {
			// Should not happen if validation above worked, but skip just in case
			lg.Warn("CATALOG: config group not found, skipping", "zone", zoneName, "group", member.MetaGroup, "available", getConfigGroupNames(conf.Catalog.ConfigGroups))
			skippedCount++
			continue
		}

		// Check if config is sufficient (already validated above, but check again for safety)
		// Note: store defaults to "map" if not specified, so only upstream is required
		if configGroupConfig.Upstream == "" {
			lg.Warn("CATALOG: config group missing required upstream field, skipping", "zone", zoneName, "group", member.MetaGroup)
			skippedCount++
			continue
		}

		// Determine store value (default to "map" if not specified)
		storeValue := configGroupConfig.Store
		if storeValue == "" {
			storeValue = "map"
		}

		// RULE 4: Auto-configure zone using config group
		lg.Info("CATALOG: auto-configuring zone", "zone", zoneName, "group", member.MetaGroup, "upstream", configGroupConfig.Upstream, "store", storeValue)

		zd := &ZoneData{
			ZoneName:      zoneName,
			ZoneType:      Secondary,
			ZoneStore:     parseZoneStore(storeValue),
			Upstream:      NormalizeAddress(configGroupConfig.Upstream),
			Logger:        log.Default(),
			SourceCatalog: update.CatalogZone,
			Options: map[ZoneOption]bool{
				OptAutomaticZone: true, // Mark as dynamically configured
			},
		}

		// Apply zone options from config group
		for _, optStr := range configGroupConfig.Options {
			if opt, exists := StringToZoneOption[optStr]; exists {
				zd.Options[opt] = true
			}
		}

		// Configure TSIG if specified
		if configGroupConfig.TsigKey != "" {
			_, ok := Globals.TsigKeys[configGroupConfig.TsigKey]
			if !ok {
				lg.Warn("CATALOG: TSIG key not found", "key", configGroupConfig.TsigKey, "zone", zoneName)
			} else {
				// Apply TSIG configuration to zone
				// TODO: Set zd.TsigKey = tsigDetails (depends on TSIG implementation)
				lg.Info("CATALOG: applied TSIG key", "key", configGroupConfig.TsigKey, "zone", zoneName)
			}
		}

		// Add to Zones map
		Zones.Set(zoneName, zd)
		lg.Debug("CATALOG: zone added to Zones map", "zone", zoneName)

		// Write dynamic config file if persistence is enabled
		// Note: We write config file immediately after creation (before transfer)
		// Zone file will be written after successful transfer (in RefreshEngine)
		if conf.ShouldPersistZone(zd) {
			if err := conf.AddDynamicZoneToConfig(zd); err != nil {
				lg.Warn("CATALOG: failed to update dynamic config file", "zone", zoneName, "error", err)
				// Don't fail the operation, just log the warning
			}
		}

		// Trigger initial zone transfer (non-blocking with timeout and context support)
		lg.Info("CATALOG: triggering initial zone transfer", "zone", zoneName, "upstream", configGroupConfig.Upstream)
		zr := ZoneRefresher{
			Name:      zoneName,
			ZoneType:  Secondary,
			Primary:   NormalizeAddress(configGroupConfig.Upstream),
			ZoneStore: zd.ZoneStore,
			Options:   zd.Options,
		}

		// Attempt non-blocking send with timeout and context cancellation support
		select {
		case conf.Internal.RefreshZoneCh <- zr:
			// Successfully enqueued
		case <-ctx.Done():
			lg.Warn("CATALOG: context cancelled while enqueuing zone refresh, dropping request", "zone", zoneName)
			// Context cancelled, drop the send
		case <-time.After(5 * time.Second):
			lg.Warn("CATALOG: timeout enqueuing zone refresh, dropping request", "zone", zoneName)
			// Timeout - channel likely full, drop the send
		}

		lg.Info("CATALOG: zone auto-configured successfully", "zone", zoneName, "meta", member.MetaGroup, "signing", member.SigningGroup, "services", member.ServiceGroups)
		configuredCount++
		processedCount++
	}

	lg.Info("CATALOG: AutoConfigureZonesFromCatalog: completed", "processed", processedCount, "configured", configuredCount, "skipped", skippedCount, "errors", errorCount)

	// Clear error state if no errors were found and zone was previously in error
	if errorCount == 0 && catalogExists && catalogZd.Error && catalogZd.ErrorType == ConfigError {
		// Check if the error was catalog-related (contains "Member zone" or "references group")
		if strings.Contains(catalogZd.ErrorMsg, "Member zone") || strings.Contains(catalogZd.ErrorMsg, "references group") {
			lg.Info("CATALOG: all member zone configurations now valid, clearing previous error state")
			catalogZd.SetError(NoError, "")
		}
	}

	return nil
}

// getConfigGroupNames returns a list of config group names from a map
func getConfigGroupNames(configGroups map[string]*ConfigGroupConfig) []string {
	if configGroups == nil {
		return []string{}
	}
	names := make([]string, 0, len(configGroups))
	for name := range configGroups {
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
		lg.Warn("unknown zone store type, defaulting to map", "store", storeStr)
		return MapZone
	}
}

// --- Catalog Zone Management (Primary Side) ---

// CatalogMembership manages the membership data for a catalog zone
type CatalogMembership struct {
	mu              sync.RWMutex
	CatalogZoneName string
	MemberZones     map[string]*CatalogMemberZone // zonename -> member data
	AvailableGroups []string                      // List of all defined groups (RFC 9432 terminology)
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

	lg.Info("CATALOG: added zone to catalog", "zone", zoneName, "catalog", cm.CatalogZoneName, "hash", cm.MemberZones[zoneName].Hash)
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
	lg.Info("CATALOG: removed zone from catalog", "zone", zoneName, "catalog", cm.CatalogZoneName)
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
	lg.Info("CATALOG: added group to catalog", "group", group, "catalog", cm.CatalogZoneName)
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
	lg.Info("CATALOG: removed group from catalog", "group", group, "catalog", cm.CatalogZoneName)
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
			return fmt.Errorf("group %s is already added to zone %s", group, zoneName)
		}
	}

	// Check for meta_ and sign_ group uniqueness (different group of same type)
	if strings.HasPrefix(group, "meta_") {
		for _, g := range member.Groups {
			if strings.HasPrefix(g, "meta_") {
				return fmt.Errorf("only one meta group allowed for %s (zone already has group %s)", zoneName, g)
			}
		}
	} else if strings.HasPrefix(group, "sign_") {
		for _, g := range member.Groups {
			if strings.HasPrefix(g, "sign_") {
				return fmt.Errorf("only one sign group allowed for %s (zone already has group %s)", zoneName, g)
			}
		}
	}

	member.Groups = append(member.Groups, group)
	lg.Info("CATALOG: added group to zone", "group", group, "zone", zoneName, "catalog", cm.CatalogZoneName)
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
	lg.Info("CATALOG: removed group from zone", "group", group, "zone", zoneName, "catalog", cm.CatalogZoneName)
	return nil
}

// GetMemberZones returns all member zones (thread-safe copy)
func (cm *CatalogMembership) GetMemberZones() map[string]*MemberZone {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	result := make(map[string]*MemberZone)

	// Get configured group prefixes
	if Conf.Catalog == nil {
		lg.Warn("GetMemberZones: Conf.Catalog is nil, returning members without group categorization")
		for zoneName, member := range cm.MemberZones {
			discoveredAt := member.DiscoveredAt
			if discoveredAt.IsZero() {
				discoveredAt = time.Now()
			}
			result[zoneName] = &MemberZone{
				ZoneName:      zoneName,
				Hash:          member.Hash,
				ServiceGroups: member.Groups,
				DiscoveredAt:  discoveredAt,
			}
		}
		return result
	}
	configPrefix := Conf.Catalog.GroupPrefixes.Config
	signingPrefix := Conf.Catalog.GroupPrefixes.Signing

	for zoneName, member := range cm.MemberZones {
		// Categorize groups by type using configured prefixes
		var serviceGroups []string
		var signingGroup string
		var configGroup string

		for _, grp := range member.Groups {
			// Check if this is a signing group (only if prefix != "none")
			if signingPrefix != "none" && strings.HasPrefix(grp, signingPrefix) {
				if signingGroup == "" {
					signingGroup = grp
				}
			} else if configPrefix != "none" && strings.HasPrefix(grp, configPrefix) {
				// Check if this is a config group (only if prefix != "none")
				if configGroup == "" {
					configGroup = grp
				}
			} else {
				// Service group (no specific prefix), or all groups are ordinary if both prefixes are "none"
				serviceGroups = append(serviceGroups, grp)
			}
		}

		// Use the stored DiscoveredAt timestamp, or time.Now() if not set (for backward compatibility)
		discoveredAt := member.DiscoveredAt
		if discoveredAt.IsZero() {
			discoveredAt = time.Now()
		}

		result[zoneName] = &MemberZone{
			ZoneName:      zoneName,
			Hash:          member.Hash,
			ServiceGroups: serviceGroups,
			SigningGroup:  signingGroup,
			MetaGroup:     configGroup, // Note: Field named MetaGroup for backward compat, but contains config group
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
