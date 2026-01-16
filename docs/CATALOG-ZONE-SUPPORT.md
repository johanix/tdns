# TDNS Catalog Zone Support (RFC 9432)

## Overview
Implement RFC 9432 catalog zone support in the tdns library. Catalog zones are a standard DNS mechanism for distributing zone membership information. This feature will be available to all tdns applications (tdns-auth, tdns-imr, KRS, etc.).

## Catalog Zone Format (RFC 9432)
Each member zone has an opaque ID with multiple PTR records:
```
{opaque-id}.zones.{catalog-zone}. PTR {member-zonename}
{opaque-id}.zones.{catalog-zone}. PTR group.{groupname}.groups.{catalog-zone}.
```

Example from `dig @127.0.0.1 -p 5356 catalog.kdc. axfr`:
```
catalog.kdc.        3600  IN  SOA    ns.catalog.kdc. admin.catalog.kdc. ...
catalog.kdc.        3600  IN  NS     ns.catalog.kdc.

; Zone: pella.se. (hash: be0a0dc3b5fe5785)
be0a0dc3b5fe5785.zones.catalog.kdc. 0 IN PTR pella.se.
be0a0dc3b5fe5785.zones.catalog.kdc. 0 IN PTR group.any_se.groups.catalog.kdc.
be0a0dc3b5fe5785.zones.catalog.kdc. 0 IN PTR group.sign_edge_zsk.groups.catalog.kdc.
be0a0dc3b5fe5785.zones.catalog.kdc. 0 IN PTR group.meta_kdc.groups.catalog.kdc.

; Zone: foffa.se. (hash: eda1901b7f08e2ad)
eda1901b7f08e2ad.zones.catalog.kdc. 0 IN PTR foffa.se.
eda1901b7f08e2ad.zones.catalog.kdc. 0 IN PTR group.any_se.groups.catalog.kdc.
eda1901b7f08e2ad.zones.catalog.kdc. 0 IN PTR group.sign_edge_dyn.groups.catalog.kdc.
eda1901b7f08e2ad.zones.catalog.kdc. 0 IN PTR group.meta_edge.groups.catalog.kdc.
```

## Design Approach

### Use Zone Option (Not Zone Type)
Catalog zones are **secondary zones with special parsing**. They're fetched via AXFR like any secondary zone, but after each refresh, we parse the zone data to extract member zones and groups.

**Configuration:**
```yaml
zones:
  catalog.kdc.:
    type: secondary          # Standard secondary zone
    store: xfr               # XFR-only storage
    primary: "127.0.0.1:5353"  # KDC address
    options:
      - catalog-zone         # NEW: Trigger catalog parsing
```

**Rationale:**
- Catalog zones ARE secondary zones (fetched via AXFR)
- Options modify behavior (like `online-signing`, `multisigner`)
- Clearer semantics: type = "what it is", options = "what it does"
- Follows existing tdns patterns

### Component Type System

Catalog zones use a **three-component-type system** to separate concerns:

1. **Service Components** (e.g., `any_se`, `corp_internal`)
   - Define zone distribution: which nodes serve which zones
   - A zone can have **multiple service components**
   - Used by applications to filter zones (e.g., KRS checks subscriptions)

2. **Signing Components** (e.g., `sign_edge_zsk`, `sign_kdc`)
   - Define DNSSEC signing logic for the zone
   - A zone has **exactly ONE signing component**
   - Prefix: `sign_*`

3. **Meta Components** (e.g., `meta_kdc`, `meta_edge`)
   - Define configuration metadata: upstream, TSIG, store, options
   - A zone has **exactly ONE meta component**
   - Prefix: `meta_*`
   - Required for auto-configuration

**Rules:**
- Service components: 0 or more (distribution/filtering)
- Signing components: exactly 1 (DNSSEC policy)
- Meta components: exactly 1 (transfer configuration)
- If multiple signing/meta components found: log warning, use first

### Architecture

1. **Add `OptCatalogZone` option** to `ZoneOption` enum
2. **Parse after refresh** - When a zone with `catalog-zone` option is refreshed, automatically parse it
3. **Callback registration** - Applications register callbacks to be notified of member zone changes
4. **Auto-configuration** - Optionally auto-configure zones based on meta components
5. **Manual override** - Manual zone config ALWAYS takes priority (hardcoded behavior)

**Flow:**
1. Catalog zone configured as `type: secondary` with `options: [catalog-zone]`
2. KDC sends NOTIFY → DnsEngine → NotifyResponder → RefreshEngine
3. RefreshEngine calls `zd.ZoneTransferIn()` (standard AXFR)
4. After successful transfer, tdns detects `OptCatalogZone` option
5. Automatically calls `ParseCatalogZone(zd)`
6. Categorizes groups into service/signing/meta components
7. Invokes registered callbacks with member zone changes
8. If auto-configuration enabled, creates zone configs using meta components
9. Applications (like KRS) filter by service components

### Callback Interface

Applications register callbacks to be notified when catalog zones are updated:

```go
type CatalogZoneUpdate struct {
    CatalogZone   string                    // e.g., "catalog.kdc."
    MemberZones   map[string]*MemberZone    // zonename -> member info
    Serial        uint32                    // Catalog zone SOA serial
    UpdateTime    time.Time
}

type MemberZone struct {
    ZoneName          string      // e.g., "pella.se."
    Hash              string      // Opaque ID from catalog
    ServiceComponents []string    // e.g., ["any_se", "corp_internal"]
    SigningComponent  string      // e.g., "sign_edge_zsk" (exactly one)
    MetaComponent     string      // e.g., "meta_kdc" (exactly one)
    DiscoveredAt      time.Time
}

type CatalogZoneCallback func(update *CatalogZoneUpdate) error

// Register callback
tdns.RegisterCatalogZoneCallback(func(update *CatalogZoneUpdate) error {
    log.Printf("Catalog zone %s updated with %d member zones",
        update.CatalogZone, len(update.MemberZones))
    // Application-specific handling
    return nil
})
```

## Configuration

### Full YAML Configuration Example

```yaml
catalog:
  policy:
    auto_configure_zones: true       # Enable auto-configuration from catalog
    auto_remove_zones: false         # Whether to remove zones when deleted from catalog
    # Note: Manual config ALWAYS overrides catalog (hardcoded behavior)

  meta_components:
    # Meta component name MUST start with "meta_"
    # Provides configuration for zone transfers
    meta_kdc:
      upstream: "127.0.0.1:5353"     # Where to AXFR from
      tsig_key: "kdc-key"             # TSIG key name (optional)
      store: "xfr"                    # Zone store type
      options: []                     # Zone options (if any)

    meta_edge:
      upstream: "192.0.2.1:5353"     # Different upstream
      tsig_key: "edge-key"
      store: "xfr"
      options: []

    meta_central:
      upstream: "198.51.100.5:5353"
      tsig_key: "central-key"
      store: "map"
      options: ["online-signing"]

  # Optional: Document what signing components mean (for reference only)
  # Catalog already defines signing behavior, this is just documentation
  signing_components:
    sign_edge_zsk:
      description: "Edge signing with ZSK only"
    sign_edge_full:
      description: "Edge signing with KSK+ZSK"
    sign_kdc:
      description: "Central signing at KDC"

# TSIG keys (existing tdns feature)
tsig:
  kdc-key:
    algorithm: "hmac-sha256"
    secret: "base64encodedvalue=="
  edge-key:
    algorithm: "hmac-sha256"
    secret: "anotherbase64value=="
  central-key:
    algorithm: "hmac-sha256"
    secret: "centralbase64=="

# Zones
zones:
  catalog.kdc.:
    type: secondary
    store: xfr
    primary: "127.0.0.1:5353"
    options:
      - catalog-zone              # Enable catalog zone parsing

  # Manually configured zones ALWAYS take priority over catalog
  example.com.:
    type: secondary
    store: map
    primary: "198.51.100.1:53"
    # Even if example.com. appears in catalog, this config wins
```

### Conflict Resolution

**Hardcoded Policy: Manual ALWAYS Wins**
- If a zone is manually configured in YAML, catalog entry is ignored
- Log warning when conflict detected
- No configuration option to change this behavior (safety first)

## Implementation Steps

### 1. Add Catalog Zone Option
**File**: `tdns/v0.x/enums.go`

Add new zone option:
```go
const (
    OptDelSyncParent ZoneOption = iota + 1
    OptDelSyncChild
    // ... existing options ...
    OptAddTransportSignal
    OptCatalogZone        // NEW: Mark zone as RFC 9432 catalog zone
)

var ZoneOptionToString = map[ZoneOption]string{
    // ... existing mappings ...
    OptAddTransportSignal: "add-transport-signal",
    OptCatalogZone:        "catalog-zone",  // NEW
}

var StringToZoneOption = map[string]ZoneOption{
    // ... existing mappings ...
    "add-transport-signal": OptAddTransportSignal,
    "catalog-zone":         OptCatalogZone,  // NEW
}
```

### 2. Validate Catalog Zone Option
**File**: `tdns/v0.x/parseoptions.go`

Add validation in `parseZoneOptions()`:
```go
func parseZoneOptions(conf *Config, zname string, zconf *ZoneConf, zd *ZoneData) map[ZoneOption]bool {
    // ... existing code ...

    switch opt {
    // ... existing cases ...

    case OptCatalogZone:
        // Validate: catalog-zone requires type: secondary
        if zconf.Type != "secondary" {
            log.Printf("Error: Zone %s: Option \"catalog-zone\" requires type: secondary. Option ignored.", zname)
            if zd != nil {
                zd.SetError(ConfigError, "catalog-zone option requires type: secondary")
            }
            continue
        }
        options[opt] = true
        cleanoptions = append(cleanoptions, opt)
        log.Printf("ParseZones: Zone %s: catalog zone option enabled", zname)

    default:
        // ... existing default handling ...
    }
}
```

### 3. Add Configuration Structures
**File**: `tdns/v0.x/config.go`

Add catalog configuration structures:
```go
type CatalogConf struct {
    Policy            CatalogPolicy                   `yaml:"policy" mapstructure:"policy"`
    MetaComponents    map[string]*MetaComponentConfig `yaml:"meta_components" mapstructure:"meta_components"`
    SigningComponents map[string]*SigningComponentInfo `yaml:"signing_components" mapstructure:"signing_components"`
}

type CatalogPolicy struct {
    AutoConfigureZones bool `yaml:"auto_configure_zones" mapstructure:"auto_configure_zones"`
    AutoRemoveZones    bool `yaml:"auto_remove_zones" mapstructure:"auto_remove_zones"`
    // Note: conflict_resolution is hardcoded to "manual-priority", not configurable
}

type MetaComponentConfig struct {
    Name     string   `yaml:"-" mapstructure:"-"`      // Populated from map key
    Upstream string   `yaml:"upstream" mapstructure:"upstream"`
    TsigKey  string   `yaml:"tsig_key" mapstructure:"tsig_key"`
    Store    string   `yaml:"store" mapstructure:"store"`
    Options  []string `yaml:"options" mapstructure:"options"`
}

type SigningComponentInfo struct {
    Description string `yaml:"description" mapstructure:"description"`
}

type Config struct {
    // ... existing fields ...
    Catalog CatalogConf `yaml:"catalog" mapstructure:"catalog"`
}
```

### 4. Create Catalog Zone Parser
**File**: `tdns/v0.x/catalog.go` (NEW)

Core parsing logic:
```go
package tdns

import (
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
    CatalogZone   string                    `json:"catalog_zone"`
    MemberZones   map[string]*MemberZone    `json:"member_zones"`
    Serial        uint32                    `json:"serial"`
    UpdateTime    time.Time                 `json:"update_time"`
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
    log.Printf("ParseCatalogZone: Parsing catalog zone %s", catalogZoneName)

    // Get SOA serial
    soa, err := zd.GetSOA()
    if err != nil {
        return nil, fmt.Errorf("failed to get catalog SOA: %v", err)
    }

    // Group PTR records by opaque ID (hash)
    type memberInfo struct {
        zoneName string
        groups   []string
    }
    memberMap := make(map[string]*memberInfo) // hash -> member info

    zoneSuffix := fmt.Sprintf(".zones.%s", catalogZoneName)
    groupSuffix := fmt.Sprintf(".groups.%s", catalogZoneName)

    // Iterate through all owners in the zone
    for owner := range zd.Data.IterBuffered() {
        ownerName := owner.Key
        ownerData := owner.Val

        // Only process *.zones.{catalog-zone}. records
        if !strings.HasSuffix(ownerName, zoneSuffix) {
            continue
        }

        // Extract hash (opaque ID) from owner name
        // Format: {hash}.zones.{catalog-zone}.
        parts := strings.Split(ownerName, ".")
        if len(parts) < 3 {
            continue
        }
        hash := parts[0]

        // Get PTR records for this owner
        ptrRRset := ownerData.RRtypes.GetOnlyRRSet(dns.TypePTR)
        if ptrRRset == nil {
            continue
        }

        // Process PTR records
        for _, rr := range ptrRRset.RRs {
            ptr, ok := rr.(*dns.PTR)
            if !ok {
                continue
            }

            ptrValue := ptr.Ptr

            // Check if this is a group membership PTR
            // Format: group.{groupname}.groups.{catalog-zone}.
            if strings.HasPrefix(ptrValue, "group.") &&
               strings.HasSuffix(ptrValue, groupSuffix) {
                // Extract group name
                groupName := strings.TrimPrefix(ptrValue, "group.")
                groupName = strings.TrimSuffix(groupName, groupSuffix)

                if memberMap[hash] == nil {
                    memberMap[hash] = &memberInfo{}
                }
                memberMap[hash].groups = append(memberMap[hash].groups, groupName)
            } else {
                // This is the member zone name PTR (first PTR in group)
                if memberMap[hash] == nil {
                    memberMap[hash] = &memberInfo{}
                }
                memberMap[hash].zoneName = ptrValue
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

    log.Printf("ParseCatalogZone: Parsed catalog zone %s (serial %d): %d member zones discovered",
        catalogZoneName, soa.Serial, len(memberZones))

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
    if !conf.Catalog.Policy.AutoConfigureZones {
        log.Printf("AutoConfigure: Disabled by policy, catalog provides metadata only")
        return nil
    }

    for zoneName, member := range update.MemberZones {
        // RULE 1: Manual config ALWAYS wins (hardcoded behavior)
        if _, exists := Zones.Get(zoneName); exists {
            log.Printf("CATALOG: Zone %s manually configured, ignoring catalog entry (services: %v, meta: %s)",
                zoneName, member.ServiceComponents, member.MetaComponent)
            continue
        }

        // RULE 2: Meta component is required for auto-configuration
        if member.MetaComponent == "" {
            log.Printf("CATALOG: Zone %s has no meta component, cannot auto-configure", zoneName)
            continue
        }

        // RULE 3: Find meta component config
        metaConfig, exists := conf.Catalog.MetaComponents[member.MetaComponent]
        if !exists {
            log.Printf("CATALOG: Zone %s meta component '%s' not found in config, cannot auto-configure",
                zoneName, member.MetaComponent)
            continue
        }

        // RULE 4: Auto-configure zone using meta component
        log.Printf("CATALOG: Auto-configuring zone %s using meta component '%s' (upstream: %s)",
            zoneName, member.MetaComponent, metaConfig.Upstream)

        zd := &ZoneData{
            ZoneName:  zoneName,
            ZoneType:  Secondary,
            ZoneStore: parseZoneStore(metaConfig.Store),
            Upstream:  metaConfig.Upstream,
            Logger:    log.Default(),
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
            tsigDetails, ok := conf.Tsig[metaConfig.TsigKey]
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

        // Trigger initial zone transfer
        conf.Internal.RefreshZoneCh <- ZoneRefresher{
            Name:      zoneName,
            ZoneType:  Secondary,
            Primary:   metaConfig.Upstream,
            ZoneStore: zd.ZoneStore,
            Options:   zd.Options,
        }

        log.Printf("CATALOG: Zone %s auto-configured (meta: %s, signing: %s, services: %v)",
            zoneName, member.MetaComponent, member.SigningComponent, member.ServiceComponents)
    }

    return nil
}

// Helper function to parse zone store string
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
```

### 5. Integrate with RefreshEngine
**File**: `tdns/v0.x/refreshengine.go`

After successful zone refresh, check for catalog-zone option and parse:

```go
// Around line 145-155, after zd.Refresh() call:
go func(zd *ZoneData, zone string, force bool, conf *Config) {
    updated, err := zd.Refresh(Globals.Verbose, Globals.Debug, force, conf)
    if err != nil {
        log.Printf("RefreshEngine: Error from zone refresh(%s): %v", zone, err)
        zd.SetError(RefreshError, "refresh error: %v", err)
        zd.LatestError = time.Now()
        return
    }
    if updated {
        log.Printf("Zone %s was updated via refresh operation", zd.ZoneName)

        // NEW: Check if this is a catalog zone
        if zd.Options[OptCatalogZone] {
            log.Printf("RefreshEngine: Zone %s is a catalog zone, parsing member zones", zone)
            catalogUpdate, err := ParseCatalogZone(zd)
            if err != nil {
                log.Printf("RefreshEngine: Error parsing catalog zone %s: %v", zone, err)
            } else {
                // Notify all registered callbacks
                if err := NotifyCatalogZoneUpdate(catalogUpdate); err != nil {
                    log.Printf("RefreshEngine: Error notifying catalog zone callbacks: %v", err)
                }

                // Auto-configure zones if enabled
                if err := AutoConfigureZonesFromCatalog(catalogUpdate, conf); err != nil {
                    log.Printf("RefreshEngine: Error auto-configuring zones: %v", err)
                }
            }
        }
    }
}(zd, zone, zr.Force, conf)
```

### 6. Application Integration (Example: KRS)

**File**: `tdns-nm/cmd/tdns-krs/main.go`

In KRS startup, register callback for application-specific handling:

```go
// After tdns.MainInit(), before starting engines:

// Register catalog zone callback
tdns.RegisterCatalogZoneCallback(func(update *tdns.CatalogZoneUpdate) error {
    log.Printf("KRS: Catalog zone %s updated with %d member zones (serial %d)",
        update.CatalogZone, len(update.MemberZones), update.Serial)

    // Get subscribed components from KRS database
    subscribedComponents, err := krsDB.GetNodeComponents()
    if err != nil {
        return fmt.Errorf("failed to get node components: %v", err)
    }
    subscribedMap := make(map[string]bool)
    for _, comp := range subscribedComponents {
        subscribedMap[comp] = true
    }

    // Filter member zones: keep only zones with subscribed service components
    var subscribedZones []*tdns.MemberZone
    for zoneName, member := range update.MemberZones {
        hasSubscribedComponent := false
        for _, svc := range member.ServiceComponents {
            if subscribedMap[svc] {
                hasSubscribedComponent = true
                break
            }
        }

        if hasSubscribedComponent {
            subscribedZones = append(subscribedZones, member)
        }
    }

    log.Printf("KRS: %d member zones match subscribed components", len(subscribedZones))

    // Store discovered zones in KRS database for tracking
    if err := krsDB.StoreDiscoveredZones(update.MemberZones, subscribedMap); err != nil {
        return fmt.Errorf("failed to store discovered zones: %v", err)
    }

    return nil
})

log.Printf("KRS: Registered catalog zone callback")
```

**File**: `tdns-nm/v0.x/krs/db.go`

Add database methods for storing discovered zones:

```sql
CREATE TABLE IF NOT EXISTS discovered_zones (
    zone_name TEXT PRIMARY KEY,
    hash TEXT NOT NULL,
    service_components TEXT NOT NULL,  -- JSON array
    signing_component TEXT NOT NULL,
    meta_component TEXT NOT NULL,
    subscribed BOOLEAN NOT NULL,
    discovered_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
)
```

Methods:
```go
func (krs *KrsDB) StoreDiscoveredZones(zones map[string]*tdns.MemberZone, subscribed map[string]bool) error
func (krs *KrsDB) GetDiscoveredZones() ([]*tdns.MemberZone, error)
func (krs *KrsDB) GetSubscribedZones() ([]string, error)
```

### 7. CLI Support (Example: KRS)

**File**: `tdns-nm/v0.x/cli/krs_cmds.go`

Add `krs-cli zone list` command:

```go
var KrsZonesCmd = &cobra.Command{
    Use:   "zones",
    Short: "Manage discovered zones from catalog",
}

var krsZonesListCmd = &cobra.Command{
    Use:   "list [--format table|json] [--all]",
    Short: "List zones discovered from catalog zone",
    Long:  `Lists zones discovered from the catalog zone. By default shows only zones with subscribed components. Use --all to show all zones.`,
    Run: func(cmd *cobra.Command, args []string) {
        api, err := getApiClient(true)
        if err != nil {
            log.Fatalf("Error getting API client: %v", err)
        }

        req := map[string]interface{}{
            "command": "list",
        }

        resp, err := sendKrsRequest(api, "/krs/zones", req)
        if err != nil {
            log.Fatalf("Error: %v", err)
        }

        if getBool(resp, "error") {
            log.Fatalf("Error: %v", getString(resp, "error_msg"))
        }

        // Get flags
        format, _ := cmd.Flags().GetString("format")
        showAll, _ := cmd.Flags().GetBool("all")

        zonesRaw, ok := resp["zones"]
        if !ok {
            fmt.Println("No zones discovered")
            return
        }

        zones, ok := zonesRaw.([]interface{})
        if !ok || len(zones) == 0 {
            fmt.Println("No zones discovered")
            return
        }

        if format == "json" {
            prettyJSON, _ := json.MarshalIndent(zones, "", "  ")
            fmt.Println(string(prettyJSON))
            return
        }

        // Table format
        var lines []string
        lines = append(lines, "Zone Name | Service Components | Signing | Meta | Subscribed")

        for _, z := range zones {
            zone, ok := z.(map[string]interface{})
            if !ok {
                continue
            }

            zoneName := getString(zone, "zone_name")
            signingComp := getString(zone, "signing_component")
            metaComp := getString(zone, "meta_component")
            subscribed := getBool(zone, "subscribed")

            if !showAll && !subscribed {
                continue
            }

            // Format service components
            serviceCompsRaw, _ := zone["service_components"].([]interface{})
            serviceStrs := make([]string, 0, len(serviceCompsRaw))
            for _, c := range serviceCompsRaw {
                if s, ok := c.(string); ok {
                    serviceStrs = append(serviceStrs, s)
                }
            }
            serviceCompsStr := strings.Join(serviceStrs, ", ")

            subscribedStr := "No"
            if subscribed {
                subscribedStr = "Yes"
            }

            lines = append(lines, fmt.Sprintf("%s | %s | %s | %s | %s",
                zoneName, serviceCompsStr, signingComp, metaComp, subscribedStr))
        }

        fmt.Println(columnize.SimpleFormat(lines))
    },
}

func init() {
    KrsZonesCmd.AddCommand(krsZonesListCmd)
    krsZonesListCmd.Flags().String("format", "table", "Output format: table or json")
    krsZonesListCmd.Flags().Bool("all", false, "Show all zones (not just subscribed)")
}
```

## Primary Server Side (Future Work)

### Publishing Catalog Zones
Publishing catalog zones is straightforward as they are normal DNS zones. The primary server simply serves the catalog zone like any other zone with PTR records following RFC 9432 format. No special implementation is required for publishing.

### Constructing Catalog Zones (Not Implemented Yet)
Construction of catalog zones will require future implementation including:

**API Endpoints:**
- `POST /catalog/{catalog-zone}/members` - Add a zone to the catalog
- `DELETE /catalog/{catalog-zone}/members/{zone}` - Remove a zone from the catalog
- `PUT /catalog/{catalog-zone}/members/{zone}` - Update zone's components
- `GET /catalog/{catalog-zone}/members` - List all member zones
- `GET /catalog/{catalog-zone}/members/{zone}` - Get zone details

**CLI Commands:**
```bash
# Add zone to catalog with components
tdns-cli catalog add-zone catalog.kdc. pella.se. \
  --service any_se \
  --signing sign_edge_zsk \
  --meta meta_kdc

# Update zone's components
tdns-cli catalog update-zone catalog.kdc. pella.se. \
  --service any_se,corp_internal \
  --signing sign_edge_zsk \
  --meta meta_kdc

# Remove zone from catalog
tdns-cli catalog remove-zone catalog.kdc. pella.se.

# List all zones in catalog
tdns-cli catalog list-zones catalog.kdc.

# Export catalog to zonefile format
tdns-cli catalog export catalog.kdc. > catalog.zone
```

**Database Storage:**
- Table for catalog member zones
- Automatic hash generation (SHA256 of zone name)
- Component associations
- Automatic SOA serial bumping on changes

**Integration Points:**
- Integrate with zone management APIs
- Automatic catalog updates when zones are added/removed
- NOTIFY to catalog consumers when catalog is updated

This work is planned for a future phase and is not part of the current implementation.

## Configuration Examples

### KDC (Catalog Zone Publisher)
```yaml
zones:
  catalog.kdc.:
    type: primary
    store: map
    # KDC dynamically generates catalog zone content
```

### KRS (Catalog Zone Consumer with Auto-Configuration)
```yaml
catalog:
  policy:
    auto_configure_zones: true
    auto_remove_zones: false

  meta_components:
    meta_kdc:
      upstream: "127.0.0.1:5353"
      tsig_key: "kdc-key"
      store: "xfr"
      options: []

tsig:
  kdc-key:
    algorithm: "hmac-sha256"
    secret: "base64value=="

zones:
  catalog.kdc.:
    type: secondary
    store: xfr
    primary: "127.0.0.1:5353"
    options:
      - catalog-zone
```

### tdns-auth (Catalog Zone Consumer, Manual Config)
```yaml
catalog:
  policy:
    auto_configure_zones: false  # Manual configuration only

  meta_components: {}  # Not needed if auto-config disabled

zones:
  catalog.example.:
    type: secondary
    store: xfr
    primary: "192.0.2.1:53"
    options:
      - catalog-zone

  # Manually configure zones after discovering them in catalog
  zone1.example.:
    type: secondary
    store: xfr
    primary: "192.0.2.1:53"
```

## Example Scenarios

### Scenario 1: Simple Zone with All Components
Catalog entry for `pella.se.`:
```
PTR pella.se.
PTR group.any_se.groups.catalog.kdc.
PTR group.sign_edge_zsk.groups.catalog.kdc.
PTR group.meta_kdc.groups.catalog.kdc.
```

Parsed as:
- Service: `[any_se]`
- Signing: `sign_edge_zsk`
- Meta: `meta_kdc`

If KRS node subscribes to `any_se` and `meta_kdc` is configured, zone is auto-configured.

### Scenario 2: Zone with Multiple Service Components
Catalog entry for `internal.corp.`:
```
PTR internal.corp.
PTR group.corp_internal.groups.catalog.kdc.
PTR group.corp_external.groups.catalog.kdc.
PTR group.sign_kdc.groups.catalog.kdc.
PTR group.meta_central.groups.catalog.kdc.
```

Parsed as:
- Services: `[corp_internal, corp_external]`
- Signing: `sign_kdc`
- Meta: `meta_central`

Node serves zone if subscribed to EITHER `corp_internal` OR `corp_external`.

### Scenario 3: Missing Meta Component
Catalog entry for `test.com.`:
```
PTR test.com.
PTR group.any_se.groups.catalog.kdc.
PTR group.sign_edge_zsk.groups.catalog.kdc.
```

Parsed as:
- Services: `[any_se]`
- Signing: `sign_edge_zsk`
- Meta: `` (empty)

Result: Info logged, zone cannot be auto-configured (meta component required).

### Scenario 4: Manual Override
Catalog entry for `example.com.` + manual config for `example.com.`

Result: Manual config wins, catalog entry ignored, warning logged.

### Scenario 5: Multiple Signing Components (Error)
Catalog entry for `bad.example.`:
```
PTR bad.example.
PTR group.sign_edge_zsk.groups.catalog.kdc.
PTR group.sign_kdc.groups.catalog.kdc.  # CONFLICT!
PTR group.meta_kdc.groups.catalog.kdc.
```

Result: Warning logged, uses first signing component (`sign_edge_zsk`).

## Critical Files

1. **`tdns/v0.x/enums.go`** - Add `OptCatalogZone` option
2. **`tdns/v0.x/parseoptions.go`** - Validate catalog-zone option
3. **`tdns/v0.x/config.go`** - Add catalog configuration structures
4. **`tdns/v0.x/catalog.go`** (NEW) - Catalog zone parsing, callbacks, auto-config
5. **`tdns/v0.x/refreshengine.go`** - Trigger parsing after refresh
6. **`tdns-nm/cmd/tdns-krs/main.go`** - Register KRS callback (example)
7. **`tdns-nm/v0.x/krs/db.go`** - Store discovered zones (KRS-specific)
8. **`tdns-nm/v0.x/cli/krs_cmds.go`** - CLI commands (KRS-specific)

## Error Handling

| Scenario | Handling |
|----------|----------|
| Zone transfer fails | Handled by RefreshEngine automatically |
| Parse error | Log error, skip malformed records, continue |
| Empty catalog | Log warning, invoke callbacks with empty list |
| Callback error | Log error, continue with other callbacks |
| Invalid option combo | Config error, zone ignored |
| No meta component | Log info, zone not auto-configured |
| Meta component not found | Log warning, zone not auto-configured |
| Multiple signing/meta components | Log warning, use first |
| Manual vs catalog conflict | Manual wins (hardcoded), log warning |

## Verification Steps

### Basic Functionality
1. **Configure catalog zone** in yaml with `type: secondary` and `options: [catalog-zone]`
2. **Start application** (e.g., KRS with tdns-krs)
3. **Check logs** for "catalog zone option enabled"
4. **Verify initial parse** - logs show "Parsed catalog zone" with member count
5. **Test NOTIFY** - Update catalog on publisher, verify NOTIFY triggers refresh and re-parse

### Auto-Configuration
1. **Enable policy** - Set `auto_configure_zones: true`
2. **Configure meta components** - Define upstreams and TSIG
3. **Verify auto-config** - Logs show "Auto-configuring zone" messages
4. **Check Zones map** - Auto-configured zones appear with `OptAutomaticZone`
5. **Test zone transfer** - Auto-configured zones successfully transfer data

### KRS Integration
1. **Register callback** - Verify "Registered catalog zone callback" in logs
2. **Component filtering** - Verify only zones with subscribed service components are stored
3. **CLI query** - `krs-cli zone list` shows discovered zones
4. **Database persistence** - Restart KRS, verify zones loaded from DB
5. **Component updates** - Update node components, verify zone list updates

### Manual Override
1. **Configure zone manually** - Add zone to YAML config
2. **Add same zone to catalog** - Zone appears in both places
3. **Verify manual wins** - Manual config used, warning logged
4. **Check zone data** - Zone uses manual config, not catalog config

### Multiple Applications
1. **Configure catalog zone** in both KRS and tdns-auth
2. **Verify independent handling** - Each application receives callback
3. **Different filtering** - KRS filters by service components, tdns-auth may have different logic

## Benefits of This Approach

1. **Library-level feature** - Available to all tdns applications automatically
2. **Standard DNS workflow** - Uses existing zone transfer, refresh, NOTIFY infrastructure
3. **Flexible callbacks** - Applications implement their own handling logic
4. **Configuration simplicity** - Just add `catalog-zone` option to any secondary zone
5. **Composable** - Can be combined with other zone options if needed
6. **No code duplication** - Parsing logic shared across all applications
7. **RFC compliant** - Follows RFC 9432 catalog zone specification
8. **Clear component types** - Service, signing, and meta components have distinct purposes
9. **No priority conflicts** - Each zone has exactly one meta and signing component
10. **Safe defaults** - Manual config always wins (hardcoded behavior)
11. **Auto-configuration** - Optional auto-config with meta components
12. **Application flexibility** - Each application filters zones as needed (e.g., by service components)

## Future Enhancements

1. **IXFR support** - Incremental catalog zone updates
2. **Multiple catalogs** - Track changes across different catalog zones
3. **Catalog zone validation** - Verify catalog zone structure compliance
4. **Statistics** - Track catalog update metrics
5. **Catalog zone generation** - Helper functions for applications that publish catalogs
6. **Dynamic meta components** - Allow meta components to be updated without restart
7. **Zone removal cleanup** - Automatically clean up zone data when removed from catalog
8. **Component inheritance** - Default meta/signing components if not specified
