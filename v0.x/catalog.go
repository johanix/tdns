/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
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
	ZoneName          string    `json:"zone_name"`
	Hash              string    `json:"hash"`
	ServiceComponents []string  `json:"service_components"`
	SigningComponent  string    `json:"signing_component"`
	MetaComponent     string    `json:"meta_component"`
	DiscoveredAt      time.Time `json:"discovered_at"`
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

		// Process group.{hash}.zones.{catalog-zone}. records (TXT records with components)
		if strings.HasPrefix(ownerName, "group.") && strings.HasSuffix(ownerName, zoneSuffix) {
			// Extract hash from owner name
			// Format: group.{hash}.zones.{catalog-zone}.
			parts := strings.Split(ownerName, ".")
			if len(parts) < 4 {
				continue
			}
			hash := parts[1] // hash is the second part after "group"

			// Get TXT records for this owner (should contain component names)
			txtRRset := ownerData.RRtypes.GetOnlyRRSet(dns.TypeTXT)
			if len(txtRRset.RRs) == 0 {
				log.Printf("CATALOG: ParseCatalogZone: Warning: group.%s has no TXT record, skipping", hash)
				continue
			}

			// Process TXT records (each string is a component name)
			for _, rr := range txtRRset.RRs {
				txt, ok := rr.(*dns.TXT)
				if !ok {
					continue
				}

				if memberMap[hash] == nil {
					memberMap[hash] = &memberInfo{}
				}
				// TXT record contains multiple strings, each is a component
				memberMap[hash].groups = append(memberMap[hash].groups, txt.Txt...)
				log.Printf("CATALOG: ParseCatalogZone: Found components for hash %s: %v", hash, txt.Txt)
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
		var serviceComponents []string
		var signingComponent string
		var metaComponent string

		for _, group := range info.groups {
			if strings.HasPrefix(group, "sign_") {
				if signingComponent != "" {
					log.Printf("ParseCatalogZone: Warning: Zone %s has multiple signing components (%s, %s), using first",
						info.zoneName, signingComponent, group)
				} else {
					signingComponent = group
				}
			} else if strings.HasPrefix(group, "meta_") {
				if metaComponent != "" {
					log.Printf("ParseCatalogZone: Warning: Zone %s has multiple meta components (%s, %s), using first",
						info.zoneName, metaComponent, group)
				} else {
					metaComponent = group
				}
			} else {
				// Service component (no specific prefix)
				serviceComponents = append(serviceComponents, group)
			}
		}

		// Log warning if no meta component (needed for auto-configuration)
		if metaComponent == "" {
			log.Printf("ParseCatalogZone: Info: Zone %s has no meta component, auto-configuration not possible",
				info.zoneName)
		}

		memberZones[info.zoneName] = &MemberZone{
			ZoneName:          info.zoneName,
			Hash:              hash,
			ServiceComponents: serviceComponents,
			SigningComponent:  signingComponent,
			MetaComponent:     metaComponent,
			DiscoveredAt:      now,
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
			zoneName, member.ServiceComponents, member.SigningComponent, member.MetaComponent)
	}

	return update, nil
}

// NotifyCatalogZoneUpdate invokes all registered callbacks
func NotifyCatalogZoneUpdate(update *CatalogZoneUpdate) error {
	catalogCallbacksMutex.RLock()
	callbacks := make([]CatalogZoneCallback, len(catalogCallbacks))
	copy(callbacks, catalogCallbacks)
	catalogCallbacksMutex.RUnlock()

	for _, callback := range callbacks {
		if err := callback(update); err != nil {
			log.Printf("NotifyCatalogZoneUpdate: Callback error: %v", err)
			// Continue with other callbacks even if one fails
		}
	}

	return nil
}

// AutoConfigureZonesFromCatalog auto-configures zones based on catalog and meta components
func AutoConfigureZonesFromCatalog(update *CatalogZoneUpdate, conf *Config) error {
	log.Printf("CATALOG: AutoConfigureZonesFromCatalog: Starting for catalog %s with %d member zones", update.CatalogZone, len(update.MemberZones))
	log.Printf("CATALOG: AutoConfigureZonesFromCatalog: Policy check - catalog.policy.zones.add=%q", conf.Catalog.Policy.Zones.Add)
	
	if conf.Catalog.Policy.Zones.Add != "auto" {
		log.Printf("CATALOG: Auto-configure disabled by policy (catalog.policy.zones.add=%q, expected \"auto\"), catalog provides metadata only. %d member zones will not be auto-configured.", conf.Catalog.Policy.Zones.Add, len(update.MemberZones))
		return nil
	}

	log.Printf("CATALOG: Auto-configure enabled, processing %d member zones from catalog %s", len(update.MemberZones), update.CatalogZone)
	log.Printf("CATALOG: Available meta_components in config: %v", getMetaComponentNames(conf.Catalog.MetaComponents))

	processedCount := 0
	skippedCount := 0
	configuredCount := 0

	for zoneName, member := range update.MemberZones {
		log.Printf("CATALOG: Processing member zone %s (services: %v, signing: %s, meta: %s)", 
			zoneName, member.ServiceComponents, member.SigningComponent, member.MetaComponent)
		
		// RULE 1: Manual config ALWAYS wins (hardcoded behavior)
		if _, exists := Zones.Get(zoneName); exists {
			log.Printf("CATALOG: Zone %s manually configured, ignoring catalog entry (services: %v, meta: %s)",
				zoneName, member.ServiceComponents, member.MetaComponent)
			skippedCount++
			continue
		}

		// RULE 2: Meta component is required for auto-configuration
		if member.MetaComponent == "" {
			log.Printf("CATALOG: Zone %s has no meta component, cannot auto-configure", zoneName)
			skippedCount++
			continue
		}

		// RULE 3: Find meta component config
		metaConfig, exists := conf.Catalog.MetaComponents[member.MetaComponent]
		if !exists {
			log.Printf("CATALOG: Zone %s meta component '%s' not found in config, cannot auto-configure. Available components: %v",
				zoneName, member.MetaComponent, getMetaComponentNames(conf.Catalog.MetaComponents))
			skippedCount++
			continue
		}

		// RULE 4: Auto-configure zone using meta component
		log.Printf("CATALOG: Auto-configuring zone %s using meta component '%s' (upstream: %s, store: %s)",
			zoneName, member.MetaComponent, metaConfig.Upstream, metaConfig.Store)

		zd := &ZoneData{
			ZoneName:      zoneName,
			ZoneType:      Secondary,
			ZoneStore:     parseZoneStore(metaConfig.Store),
			Upstream:      metaConfig.Upstream,
			Logger:        log.Default(),
			SourceCatalog: update.CatalogZone,
			Options: map[ZoneOption]bool{
				OptAutomaticZone: true, // Mark as dynamically configured
			},
		}

		// Apply zone options from meta component
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

		// Trigger initial zone transfer
		log.Printf("CATALOG: Triggering initial zone transfer for %s from %s", zoneName, metaConfig.Upstream)
		conf.Internal.RefreshZoneCh <- ZoneRefresher{
			Name:      zoneName,
			ZoneType:  Secondary,
			Primary:   metaConfig.Upstream,
			ZoneStore: zd.ZoneStore,
			Options:   zd.Options,
		}

		log.Printf("CATALOG: Zone %s auto-configured successfully (meta: %s, signing: %s, services: %v)",
			zoneName, member.MetaComponent, member.SigningComponent, member.ServiceComponents)
		configuredCount++
		processedCount++
	}

	log.Printf("CATALOG: AutoConfigureZonesFromCatalog: Completed. Processed: %d, Configured: %d, Skipped: %d", 
		processedCount, configuredCount, skippedCount)
	return nil
}

// getMetaComponentNames returns a list of meta component names for logging
func getMetaComponentNames(metaComponents map[string]*MetaComponentConfig) []string {
	if metaComponents == nil {
		return []string{}
	}
	names := make([]string, 0, len(metaComponents))
	for name := range metaComponents {
		names = append(names, name)
	}
	return names
}

// parseZoneStore converts a zone store string to ZoneStore type
func parseZoneStore(storeStr string) ZoneStore {
	switch strings.ToLower(storeStr) {
	case "xfr":
		return XfrZone
	case "map":
		return MapZone
	case "slice":
		return SliceZone
	default:
		log.Printf("Unknown zone store type %q, defaulting to xfr", storeStr)
		return XfrZone
	}
}

// --- Catalog Zone Management (Primary Side) ---

// CatalogMembership manages the membership data for a catalog zone
type CatalogMembership struct {
	mu               sync.RWMutex
	CatalogZoneName  string
	MemberZones      map[string]*CatalogMemberZone // zonename -> member data
	AvailableComponents []string                   // List of all defined components
}

// CatalogMemberZone represents a member zone in the catalog
type CatalogMemberZone struct {
	ZoneName   string
	Hash       string   // SHA256 hash of zone name (first 16 chars)
	Components []string // List of component names associated with this zone
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
		CatalogZoneName:     catalogZoneName,
		MemberZones:         make(map[string]*CatalogMemberZone),
		AvailableComponents: []string{},
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
		ZoneName:   zoneName,
		Hash:       generateZoneHash(zoneName),
		Components: []string{},
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

// AddComponent adds a component to the available components list
func (cm *CatalogMembership) AddComponent(component string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Check if already exists
	for _, c := range cm.AvailableComponents {
		if c == component {
			return fmt.Errorf("component %s already exists in catalog %s", component, cm.CatalogZoneName)
		}
	}

	cm.AvailableComponents = append(cm.AvailableComponents, component)
	log.Printf("CATALOG: Added component %s to catalog %s", component, cm.CatalogZoneName)
	return nil
}

// RemoveComponent removes a component from the available components list
func (cm *CatalogMembership) RemoveComponent(component string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	found := false
	newComponents := []string{}
	for _, c := range cm.AvailableComponents {
		if c != component {
			newComponents = append(newComponents, c)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("component %s not found in catalog %s", component, cm.CatalogZoneName)
	}

	cm.AvailableComponents = newComponents
	log.Printf("CATALOG: Removed component %s from catalog %s", component, cm.CatalogZoneName)
	return nil
}

// AddZoneComponent associates a component with a zone
func (cm *CatalogMembership) AddZoneComponent(zoneName, component string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	member, exists := cm.MemberZones[zoneName]
	if !exists {
		return fmt.Errorf("zone %s not found in catalog %s", zoneName, cm.CatalogZoneName)
	}

	// Check if component exists in catalog's available components
	componentExists := false
	for _, c := range cm.AvailableComponents {
		if c == component {
			componentExists = true
			break
		}
	}
	if !componentExists {
		return fmt.Errorf("component %s is not defined in catalog %s. Add it to the catalog first using 'catalog component add'", component, cm.CatalogZoneName)
	}

	// Check if component already associated with this zone (exact duplicate)
	for _, c := range member.Components {
		if c == component {
			return fmt.Errorf("Component %s is already added to zone %s", component, zoneName)
		}
	}

	// Check for meta_ and sign_ component uniqueness (different component of same type)
	if strings.HasPrefix(component, "meta_") {
		for _, c := range member.Components {
			if strings.HasPrefix(c, "meta_") {
				return fmt.Errorf("Only one meta component allowed for %s (zone already has component %s)", zoneName, c)
			}
		}
	} else if strings.HasPrefix(component, "sign_") {
		for _, c := range member.Components {
			if strings.HasPrefix(c, "sign_") {
				return fmt.Errorf("Only one sign component allowed for %s (zone already has component %s)", zoneName, c)
			}
		}
	}

	member.Components = append(member.Components, component)
	log.Printf("CATALOG: Added component %s to zone %s in catalog %s", component, zoneName, cm.CatalogZoneName)
	return nil
}

// RemoveZoneComponent disassociates a component from a zone
func (cm *CatalogMembership) RemoveZoneComponent(zoneName, component string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	member, exists := cm.MemberZones[zoneName]
	if !exists {
		return fmt.Errorf("zone %s not found in catalog %s", zoneName, cm.CatalogZoneName)
	}

	found := false
	newComponents := []string{}
	for _, c := range member.Components {
		if c != component {
			newComponents = append(newComponents, c)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("component %s not associated with zone %s", component, zoneName)
	}

	member.Components = newComponents
	log.Printf("CATALOG: Removed component %s from zone %s in catalog %s", component, zoneName, cm.CatalogZoneName)
	return nil
}

// GetMemberZones returns all member zones (thread-safe copy)
func (cm *CatalogMembership) GetMemberZones() map[string]*MemberZone {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	result := make(map[string]*MemberZone)
	for zoneName, member := range cm.MemberZones {
		// Categorize components by type
		var serviceComponents []string
		var signingComponent string
		var metaComponent string

		for _, comp := range member.Components {
			if strings.HasPrefix(comp, "sign_") {
				if signingComponent == "" {
					signingComponent = comp
				}
			} else if strings.HasPrefix(comp, "meta_") {
				if metaComponent == "" {
					metaComponent = comp
				}
			} else {
				serviceComponents = append(serviceComponents, comp)
			}
		}

		result[zoneName] = &MemberZone{
			ZoneName:          zoneName,
			Hash:              member.Hash,
			ServiceComponents: serviceComponents,
			SigningComponent:  signingComponent,
			MetaComponent:     metaComponent,
			DiscoveredAt:      time.Now(),
		}
	}

	return result
}

// GetComponents returns all available components (thread-safe copy)
func (cm *CatalogMembership) GetComponents() []string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	result := make([]string, len(cm.AvailableComponents))
	copy(result, cm.AvailableComponents)
	return result
}

// generateZoneHash generates a SHA256 hash of the zone name (first 16 hex chars)
func generateZoneHash(zoneName string) string {
	h := sha256.New()
	h.Write([]byte(zoneName))
	hash := hex.EncodeToString(h.Sum(nil))
	return hash[:16] // Use first 16 characters as opaque ID
}
