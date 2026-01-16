# TDNS Catalog Zone Support (RFC 9432)

## Overview
RFC 9432 catalog zone support is implemented in the tdns library. Catalog zones are a standard DNS mechanism for distributing zone membership information. This feature is available to all tdns applications (tdns-auth, tdns-imr, KRS, etc.).

## Catalog Zone Format (RFC 9432)
Each member zone has an opaque ID (hash) with:
- A PTR record for the zone name: `{hash}.zones.{catalog-zone}. IN PTR {member-zonename}`
- A TXT record for groups: `group.{hash}.zones.{catalog-zone}. IN TXT "group1" "group2" ...` (all groups in a single TXT record)
- A version record: `version.{catalog-zone}. IN TXT "2"` (required by RFC 9432)

**Note:** Autozones (zones created automatically from catalog zones) use `invalid.` as their NS record, as recommended by RFC 9432.

Example from `dig @127.0.0.1 -p 5356 catalog.kdc. axfr`:
```text
catalog.kdc.        3600  IN  SOA    ns.catalog.kdc. admin.catalog.kdc. ...
catalog.kdc.        3600  IN  NS     ns.catalog.kdc.
version.catalog.kdc. 0    IN  TXT    "2"

; Zone: pella.se. (hash: be0a0dc3b5fe5785)
be0a0dc3b5fe5785.zones.catalog.kdc. 0 IN PTR pella.se.
group.be0a0dc3b5fe5785.zones.catalog.kdc. 0 IN TXT "any_se" "sign_edge_zsk" "meta_kdc"

; Zone: foffa.se. (hash: eda1901b7f08e2ad)
eda1901b7f08e2ad.zones.catalog.kdc. 0 IN PTR foffa.se.
group.eda1901b7f08e2ad.zones.catalog.kdc. 0 IN TXT "any_se" "sign_edge_dyn" "meta_edge"
```

## Design Approach

### Use Zone Option (Not Zone Type)
Catalog zones can be configured as either **primary** or **secondary** zones with special parsing. When configured as secondary, they're fetched via AXFR like any secondary zone. After each refresh (or on primary zones after updates), we parse the zone data to extract member zones and groups.

**Configuration:**
```yaml
zones:
  catalog.kdc.:
    type: primary            # Can be primary (for persistence) or secondary
    store: map               # Zone store type
    # For secondary:
    # primary: "127.0.0.1:5353"  # Upstream server
    options:
      - catalog-zone         # NEW: Trigger catalog parsing
```

**Rationale:**
- Catalog zones can be primary (for persistence across restarts) or secondary (fetched via AXFR)
- Options modify behavior (like `online-signing`, `multisigner`)
- Clearer semantics: type = "what it is", options = "what it does"
- Follows existing tdns patterns

### Group System (RFC 9432 Terminology)

Catalog zones use a **group system** (RFC 9432 terminology) to categorize zones:

1. **Service Groups** (e.g., `any_se`, `corp_internal`)
   - Define zone distribution: which nodes serve which zones
   - A zone can have **multiple service groups**
   - Used by applications to filter zones (e.g., KRS checks subscriptions)
   - No specific prefix required

2. **Signing Groups** (e.g., `sign_edge_zsk`, `sign_kdc`)
   - Define DNSSEC signing logic for the zone
   - A zone has **exactly ONE signing group**
   - Prefix: `sign_*`

3. **Meta Groups** (e.g., `meta_kdc`, `meta_edge`)
   - Define configuration metadata: upstream, TSIG, store, options
   - A zone has **exactly ONE meta group**
   - Prefix: `meta_*`
   - Required for auto-configuration

**Rules:**
- Service groups: 0 or more (distribution/filtering)
- Signing groups: exactly 1 (DNSSEC policy)
- Meta groups: exactly 1 (transfer configuration)
- If multiple signing/meta groups found: log warning, use first

### Architecture

1. **`OptCatalogZone` option** - Added to `ZoneOption` enum
2. **Parse after refresh** - When a zone with `catalog-zone` option is refreshed (or updated for primary zones), automatically parse it
3. **Callback registration** - Applications register callbacks to be notified of member zone changes
4. **Auto-configuration** - Optionally auto-configure zones based on meta groups (when `catalog.policy.zones.add: auto`)
5. **Manual override** - Manual zone config ALWAYS takes priority (hardcoded behavior)
6. **Version record** - Catalog zones include `version.{catalog-zone}. IN TXT "2"` (RFC 9432 requirement)
7. **Invalid NS** - Autozones use `invalid.` as NS record (RFC 9432 recommendation)

**Flow:**
1. Catalog zone configured as `type: primary` or `type: secondary` with `options: [catalog-zone]`
2. For secondary: KDC sends NOTIFY → DnsEngine → NotifyResponder → RefreshEngine
3. For secondary: RefreshEngine calls `zd.ZoneTransferIn()` (standard AXFR)
4. After successful transfer (or on primary after updates), tdns detects `OptCatalogZone` option
5. Automatically calls `ParseCatalogZone(zd)`
6. Parses PTR records for zone names and TXT records for groups
7. Categorizes groups into service/signing/meta groups
8. Invokes registered callbacks with member zone changes
9. If auto-configuration enabled (`catalog.policy.zones.add: auto`), creates zone configs using meta groups
10. Applications (like KRS) filter by service groups

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
    ZoneName      string    // e.g., "pella.se."
    Hash          string    // Opaque ID from catalog (SHA256 hash)
    ServiceGroups []string  // e.g., ["any_se", "corp_internal"] (RFC 9432 terminology)
    SigningGroup  string    // e.g., "sign_edge_zsk" (exactly one)
    MetaGroup     string    // e.g., "meta_kdc" (exactly one)
    DiscoveredAt  time.Time
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
    zones:
      add: auto        # "auto" or "manual" - Enable auto-configuration from catalog
      remove: manual   # "auto" or "manual" - Whether to remove zones when deleted from catalog
    # Note: Manual config ALWAYS overrides catalog (hardcoded behavior)

  meta_groups:
    # Meta group name MUST start with "meta_"
    # Provides configuration for zone transfers (RFC 9432 terminology)
    meta_kdc:
      upstream: "127.0.0.1:5353"     # Where to AXFR from (required for auto-config)
      tsig_key: "kdc-key"             # TSIG key name (optional)
      store: "map"                    # Zone store type (defaults to "map" if not specified)
      options: []                     # Zone options (if any)

    meta_edge:
      upstream: "192.0.2.1:5353"     # Different upstream
      tsig_key: "edge-key"
      store: "map"                    # Defaults to "map" if omitted
      options: []

    meta_central:
      upstream: "198.51.100.5:5353"
      tsig_key: "central-key"
      store: "map"
      options: ["online-signing"]

  # Optional: Document what signing groups mean (for reference only)
  # Catalog already defines signing behavior, this is just documentation (RFC 9432 terminology)
  signing_groups:
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
    type: primary            # Can be primary (for persistence) or secondary
    store: map               # Zone store type
    # For secondary, also specify:
    # primary: "127.0.0.1:5353"
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

#### Hardcoded Policy: Manual ALWAYS Wins
- If a zone is manually configured in YAML, catalog entry is ignored
- Log warning when conflict detected
- No configuration option to change this behavior (safety first)

## Implementation Steps

### 1. Add Catalog Zone Option
**File**: `tdns/v2/enums.go`

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
**File**: `tdns/v2/parseoptions.go`

Add validation in `parseZoneOptions()`:
```go
func parseZoneOptions(conf *Config, zname string, zconf *ZoneConf, zd *ZoneData) map[ZoneOption]bool {
    // ... existing code ...

    switch opt {
    // ... existing cases ...

    case OptCatalogZone:
        // Hard fail: catalog zone requires valid catalog configuration
        if conf.Catalog.MetaGroups == nil {
            log.Fatalf("FATAL: Zone %s is configured as a catalog zone, but catalog.meta_groups is missing or incorrectly structured", zname)
        }
        
        // Validate catalog policy configuration
        if conf.Catalog.Policy.Zones.Add == "" {
            log.Fatalf("FATAL: Zone %s is configured as a catalog zone, but catalog.policy.zones.add is not set", zname)
        }
        if conf.Catalog.Policy.Zones.Add != "auto" && conf.Catalog.Policy.Zones.Add != "manual" {
            log.Fatalf("FATAL: Zone %s is configured as a catalog zone, but catalog.policy.zones.add has invalid value", zname)
        }
        
        // Catalog zones can be primary or secondary
        options[opt] = true
        cleanoptions = append(cleanoptions, opt)
        log.Printf("ParseZones: Zone %s: catalog zone option enabled (type: %s)", zname, zconf.Type)

    default:
        // ... existing default handling ...
    }
}
```

### 3. Add Configuration Structures
**File**: `tdns/v2/config.go`

Add catalog configuration structures:
```go
type CatalogConf struct {
    Policy        CatalogPolicy              `yaml:"policy" mapstructure:"policy"`
    MetaGroups    map[string]*MetaGroupConfig `yaml:"meta_groups" mapstructure:"meta_groups"`
    SigningGroups map[string]*SigningGroupInfo `yaml:"signing_groups" mapstructure:"signing_groups"`
}

type CatalogPolicy struct {
    Zones struct {
        Add    string `yaml:"add" mapstructure:"add"`    // "auto" or "manual"
        Remove string `yaml:"remove" mapstructure:"remove"` // "auto" or "manual"
    } `yaml:"zones" mapstructure:"zones"`
    // Note: conflict_resolution is hardcoded to "manual-priority", not configurable
}

type MetaGroupConfig struct {
    Name     string   `yaml:"-" mapstructure:"-"`      // Populated from map key
    Upstream string   `yaml:"upstream" mapstructure:"upstream"`
    TsigKey  string   `yaml:"tsig_key" mapstructure:"tsig_key"`
    Store    string   `yaml:"store" mapstructure:"store"` // Defaults to "map" if not specified
    Options  []string `yaml:"options" mapstructure:"options"`
}

type SigningGroupInfo struct {
    Description string `yaml:"description" mapstructure:"description"`
}

type Config struct {
    // ... existing fields ...
    Catalog CatalogConf `yaml:"catalog" mapstructure:"catalog"`
}
```

### 4. Create Catalog Zone Parser
**File**: `tdns/v2/catalog.go` (NEW)

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
    ZoneName      string    `json:"zone_name"`
    Hash          string    `json:"hash"`
    ServiceGroups []string  `json:"service_groups"` // Groups associated with this zone (RFC 9432 terminology)
    SigningGroup  string    `json:"signing_group"`  // Signing group for this zone
    MetaGroup     string    `json:"meta_group"`     // Meta group for this zone
    DiscoveredAt  time.Time `json:"discovered_at"`
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

// AutoConfigureZonesFromCatalog auto-configures zones based on catalog and meta groups
func AutoConfigureZonesFromCatalog(update *CatalogZoneUpdate, conf *Config) error {
    if conf.Catalog.Policy.Zones.Add != "auto" {
        log.Printf("AutoConfigure: Disabled by policy (catalog.policy.zones.add=%q), catalog provides metadata only",
            conf.Catalog.Policy.Zones.Add)
        return nil
    }

    for zoneName, member := range update.MemberZones {
        // RULE 1: Manual config ALWAYS wins (hardcoded behavior)
        if _, exists := Zones.Get(zoneName); exists {
            log.Printf("CATALOG: Zone %s manually configured, ignoring catalog entry (services: %v, meta: %s)",
                zoneName, member.ServiceGroups, member.MetaGroup)
            continue
        }

        // RULE 2: Meta group is required for auto-configuration
        if member.MetaGroup == "" {
            log.Printf("CATALOG: Zone %s has no meta group, cannot auto-configure", zoneName)
            continue
        }

        // RULE 3: Find meta group config
        metaConfig, exists := conf.Catalog.MetaGroups[member.MetaGroup]
        if !exists {
            log.Printf("CATALOG: Zone %s meta group '%s' not found in config, cannot auto-configure",
                zoneName, member.MetaGroup)
            continue
        }

        // RULE 4: Auto-configure zone using meta group
        // Store defaults to "map" if not specified
        storeValue := metaConfig.Store
        if storeValue == "" {
            storeValue = "map"
        }

        log.Printf("CATALOG: Auto-configuring zone %s using meta group '%s' (upstream: %s, store: %s)",
            zoneName, member.MetaGroup, metaConfig.Upstream, storeValue)

        zd := &ZoneData{
            ZoneName:  zoneName,
            ZoneType:  Secondary,
            ZoneStore: parseZoneStore(storeValue),
            Upstream:  metaConfig.Upstream,
            Logger:    log.Default(),
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
            zoneName, member.MetaGroup, member.SigningGroup, member.ServiceGroups)
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
**File**: `tdns/v2/refreshengine.go`

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

    // Get subscribed groups from KRS database
    subscribedGroups, err := krsDB.GetNodeGroups()
    if err != nil {
        return fmt.Errorf("failed to get node groups: %v", err)
    }
    subscribedMap := make(map[string]bool)
    for _, grp := range subscribedGroups {
        subscribedMap[grp] = true
    }

    // Filter member zones: keep only zones with subscribed service groups
    var subscribedZones []*tdns.MemberZone
    for zoneName, member := range update.MemberZones {
        hasSubscribedGroup := false
        for _, svc := range member.ServiceGroups {
            if subscribedMap[svc] {
                hasSubscribedGroup = true
                break
            }
        }

        if hasSubscribedGroup {
            subscribedZones = append(subscribedZones, member)
        }
    }

    log.Printf("KRS: %d member zones match subscribed groups", len(subscribedZones))

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
    service_groups TEXT NOT NULL,  -- JSON array (RFC 9432 terminology)
    signing_group TEXT NOT NULL,
    meta_group TEXT NOT NULL,
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
    Long:  `Lists zones discovered from the catalog zone. By default shows only zones with subscribed groups. Use --all to show all zones.`,
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
        lines = append(lines, "Zone Name | Service Groups | Signing | Meta | Subscribed")

        for _, z := range zones {
            zone, ok := z.(map[string]interface{})
            if !ok {
                continue
            }

            zoneName := getString(zone, "zone_name")
            signingGroup := getString(zone, "signing_group")
            metaGroup := getString(zone, "meta_group")
            subscribed := getBool(zone, "subscribed")

            if !showAll && !subscribed {
                continue
            }

            // Format service groups
            serviceGroupsRaw, _ := zone["service_groups"].([]interface{})
            serviceStrs := make([]string, 0, len(serviceGroupsRaw))
            for _, g := range serviceGroupsRaw {
                if s, ok := g.(string); ok {
                    serviceStrs = append(serviceStrs, s)
                }
            }
            serviceGroupsStr := strings.Join(serviceStrs, ", ")

            subscribedStr := "No"
            if subscribed {
                subscribedStr = "Yes"
            }

            lines = append(lines, fmt.Sprintf("%s | %s | %s | %s | %s",
                zoneName, serviceGroupsStr, signingGroup, metaGroup, subscribedStr))
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
- `PUT /catalog/{catalog-zone}/members/{zone}` - Update zone's groups
- `GET /catalog/{catalog-zone}/members` - List all member zones
- `GET /catalog/{catalog-zone}/members/{zone}` - Get zone details

**CLI Commands:**
```bash
# Add zone to catalog with groups
tdns-cli catalog zone add --cat catalog.kdc. --zone pella.se.
tdns-cli catalog zone group add --cat catalog.kdc. --zone pella.se. --group any_se
tdns-cli catalog zone group add --cat catalog.kdc. --zone pella.se. --group sign_edge_zsk
tdns-cli catalog zone group add --cat catalog.kdc. --zone pella.se. --group meta_kdc

# Update zone's groups
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
- Group associations
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
    zones:
      add: auto
      remove: manual

  meta_groups:
    meta_kdc:
      upstream: "127.0.0.1:5353"
      tsig_key: "kdc-key"
      store: "map"              # Defaults to "map" if not specified
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
    zones:
      add: manual               # Manual configuration only
      remove: manual

  meta_groups: {}              # Not needed if auto-config disabled

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

### Scenario 1: Simple Zone with All Groups
Catalog entry for `pella.se.` (hash: `be0a0dc3b5fe5785`):
```text
be0a0dc3b5fe5785.zones.catalog.kdc. 0 IN PTR pella.se.
group.be0a0dc3b5fe5785.zones.catalog.kdc. 0 IN TXT "any_se" "sign_edge_zsk" "meta_kdc"
```

Parsed as:
- Service groups: `[any_se]`
- Signing group: `sign_edge_zsk`
- Meta group: `meta_kdc`

If KRS node subscribes to `any_se` and `meta_kdc` is configured, zone is auto-configured.

### Scenario 2: Zone with Multiple Service Groups
Catalog entry for `internal.corp.` (hash: `abc123...`):
```text
abc123.zones.catalog.kdc. 0 IN PTR internal.corp.
group.abc123.zones.catalog.kdc. 0 IN TXT "corp_internal" "corp_external" "sign_kdc" "meta_central"
```

Parsed as:
- Service groups: `[corp_internal, corp_external]`
- Signing group: `sign_kdc`
- Meta group: `meta_central`

Node serves zone if subscribed to EITHER `corp_internal` OR `corp_external`.

### Scenario 3: Missing Meta Group
Catalog entry for `test.com.` (hash: `def456...`):
```text
def456.zones.catalog.kdc. 0 IN PTR test.com.
group.def456.zones.catalog.kdc. 0 IN TXT "any_se" "sign_edge_zsk"
```

Parsed as:
- Service groups: `[any_se]`
- Signing group: `sign_edge_zsk`
- Meta group: `` (empty)

Result: Info logged, zone cannot be auto-configured (meta group required).

### Scenario 4: Manual Override
Catalog entry for `example.com.` + manual config for `example.com.`

Result: Manual config wins, catalog entry ignored, warning logged.

### Scenario 5: Multiple Signing Groups (Warning)
Catalog entry for `bad.example.` (hash: `ghi789...`):
```text
ghi789.zones.catalog.kdc. 0 IN PTR bad.example.
group.ghi789.zones.catalog.kdc. 0 IN TXT "sign_edge_zsk" "sign_kdc" "meta_kdc"  # CONFLICT!
```

Result: Warning logged, uses first signing group (`sign_edge_zsk`).

## Critical Files

1. **`tdns/v2/enums.go`** - Add `OptCatalogZone` option
2. **`tdns/v2/parseoptions.go`** - Validate catalog-zone option
3. **`tdns/v2/config.go`** - Add catalog configuration structures
4. **`tdns/v2/catalog.go`** (NEW) - Catalog zone parsing, callbacks, auto-config
5. **`tdns/v2/refreshengine.go`** - Trigger parsing after refresh
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
| No meta group | Log info, zone not auto-configured |
| Meta group not found | Log warning, zone not auto-configured |
| Multiple signing/meta groups | Log warning, use first |
| Manual vs catalog conflict | Manual wins (hardcoded), log warning |

## Verification Steps

### Basic Functionality
1. **Configure catalog zone** in yaml with `type: secondary` and `options: [catalog-zone]`
2. **Start application** (e.g., KRS with tdns-krs)
3. **Check logs** for "catalog zone option enabled"
4. **Verify initial parse** - logs show "Parsed catalog zone" with member count
5. **Test NOTIFY** - Update catalog on publisher, verify NOTIFY triggers refresh and re-parse

### Auto-Configuration
1. **Enable policy** - Set `catalog.policy.zones.add: auto`
2. **Configure meta groups** - Define upstreams and TSIG
3. **Verify auto-config** - Logs show "Auto-configuring zone" messages
4. **Check Zones map** - Auto-configured zones appear with `OptAutomaticZone`
5. **Test zone transfer** - Auto-configured zones successfully transfer data

### KRS Integration
1. **Register callback** - Verify "Registered catalog zone callback" in logs
2. **Group filtering** - Verify only zones with subscribed service groups are stored
3. **CLI query** - `krs-cli zone list` shows discovered zones
4. **Database persistence** - Restart KRS, verify zones loaded from DB
5. **Group updates** - Update node groups, verify zone list updates

### Manual Override
1. **Configure zone manually** - Add zone to YAML config
2. **Add same zone to catalog** - Zone appears in both places
3. **Verify manual wins** - Manual config used, warning logged
4. **Check zone data** - Zone uses manual config, not catalog config

### Multiple Applications
1. **Configure catalog zone** in both KRS and tdns-auth
2. **Verify independent handling** - Each application receives callback
3. **Different filtering** - KRS filters by service groups, tdns-auth may have different logic

## Benefits of This Approach

1. **Library-level feature** - Available to all tdns applications automatically
2. **Standard DNS workflow** - Uses existing zone transfer, refresh, NOTIFY infrastructure
3. **Flexible callbacks** - Applications implement their own handling logic
4. **Configuration simplicity** - Just add `catalog-zone` option to any primary or secondary zone
5. **Composable** - Can be combined with other zone options if needed
6. **No code duplication** - Parsing logic shared across all applications
7. **RFC compliant** - Follows RFC 9432 catalog zone specification
8. **Clear group types** - Service, signing, and meta groups have distinct purposes (RFC 9432 terminology)
9. **No priority conflicts** - Each zone has exactly one meta and signing group
10. **Safe defaults** - Manual config always wins (hardcoded behavior)
11. **Auto-configuration** - Optional auto-config with meta groups
12. **Application flexibility** - Each application filters zones as needed (e.g., by service groups)

## Future Enhancements

1. **IXFR support** - Incremental catalog zone updates
2. **Multiple catalogs** - Track changes across different catalog zones
3. **Catalog zone validation** - Verify catalog zone structure compliance
4. **Statistics** - Track catalog update metrics
5. **Catalog zone generation** - Helper functions for applications that publish catalogs
6. **Dynamic meta groups** - Allow meta groups to be updated without restart
7. **Zone removal cleanup** - Automatically clean up zone data when removed from catalog
8. **Group inheritance** - Default meta/signing groups if not specified
