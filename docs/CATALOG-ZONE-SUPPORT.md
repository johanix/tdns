# TDNS Catalog Zone Support (RFC 9432)

**Last Updated:** 2026-01-21

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
group.be0a0dc3b5fe5785.zones.catalog.kdc. 0 IN TXT "any_se" "sign_edge_zsk" "config_kdc"

; Zone: foffa.se. (hash: eda1901b7f08e2ad)
eda1901b7f08e2ad.zones.catalog.kdc. 0 IN PTR foffa.se.
group.eda1901b7f08e2ad.zones.catalog.kdc. 0 IN TXT "any_se" "sign_edge_dyn" "config_edge"
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

3. **Config Groups** (e.g., `config_kdc`, `config_edge`)
   - Define configuration metadata: upstream, TSIG, store, options
   - A zone has **exactly ONE config group**
   - Prefix: configurable (default: `config`)
   - Required for auto-configuration

**Rules:**
- Service groups: 0 or more (distribution/filtering)
- Signing groups: exactly 1 (DNSSEC policy)
- Config groups: exactly 1 (transfer configuration)
- If multiple signing/config groups found: log warning, use first

### Architecture

1. **`OptCatalogZone` option** - Added to `ZoneOption` enum
2. **Parse after refresh** - When a zone with `catalog-zone` option is refreshed (or updated for primary zones), automatically parse it
3. **Callback registration** - Applications register callbacks to be notified of member zone changes
4. **Auto-configuration** - Optionally auto-configure zones based on config groups (per-catalog-zone option: `catalog-member-auto-create`)
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
7. Categorizes groups into service/signing/config groups based on configured prefixes
8. Invokes registered callbacks with member zone changes
9. If auto-configuration enabled (zone option `catalog-member-auto-create`), creates zone configs using config groups
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
    ConfigGroup   string    // e.g., "config_kdc" (exactly one)
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
  # Group prefixes define how to categorize groups in catalog zones
  # These are REQUIRED if you have config_groups defined
  group_prefixes:
    config: "config"   # Groups starting with this prefix are config groups
    signing: "sign"    # Groups starting with this prefix are signing groups
    # Use "none" to explicitly disable a group type
    # Service groups have no prefix (any group not matching config/signing)

  # Config groups provide configuration for auto-configured member zones
  config_groups:
    # Config group names should match the configured prefix (e.g., "config_kdc")
    config_kdc:
      upstream: "127.0.0.1:5353"     # Where to AXFR from (required for auto-config)
      tsig_key: "kdc-key"             # TSIG key name (optional)
      store: "map"                    # Zone store type (defaults to "map" if not specified)
      options: []                     # Zone options (if any)

    config_edge:
      upstream: "192.0.2.1:5353"     # Different upstream
      tsig_key: "edge-key"
      store: "map"                    # Defaults to "map" if omitted
      options: []

    config_central:
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
            log.Fatalf("FATAL: Zone %s is configured as a catalog zone, but catalog.config_groups is missing or incorrectly structured", zname)
        }
        
        // Validate catalog configuration
        // (Policy is now per-zone via catalog-member-auto-create/auto-delete options)
        // Check for required group_prefixes and config_groups
        if len(conf.Catalog.ConfigGroups) > 0 && conf.Catalog.GroupPrefixes.Config == "" {
            log.Fatalf("FATAL: Zone %s is configured as a catalog zone, but catalog.group_prefixes is not set", zname)
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
    GroupPrefixes GroupPrefixesConf            `yaml:"group_prefixes" mapstructure:"group_prefixes"`
    ConfigGroups  map[string]*ConfigGroupConfig `yaml:"config_groups" mapstructure:"config_groups"`
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
    ConfigGroup   string    `json:"config_group"`   // Config group for this zone
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
            } else if strings.HasPrefix(group, conf.Catalog.GroupPrefixes.Config) {
                if configGroup != "" {
                    log.Printf("ParseCatalogZone: Warning: Zone %s has multiple config groups (%s, %s), using first",
                        info.zoneName, configGroup, group)
                } else {
                    configGroup = group
                }
            } else {
                // Service group (no specific prefix)
                serviceGroups = append(serviceGroups, group)
            }
        }

        // Log warning if no config group (needed for auto-configuration)
        if configGroup == "" {
            log.Printf("ParseCatalogZone: Info: Zone %s has no config group, auto-configuration not possible",
                info.zoneName)
        }

        memberZones[info.zoneName] = &MemberZone{
            ZoneName:      info.zoneName,
            Hash:          hash,
            ServiceGroups: serviceGroups,
            SigningGroup:  signingGroup,
            ConfigGroup:   configGroup,
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

// AutoConfigureZonesFromCatalog auto-configures zones based on catalog and config groups
func AutoConfigureZonesFromCatalog(update *CatalogZoneUpdate, conf *Config, catalogZd *ZoneData) error {
    // Check if auto-create is enabled for this specific catalog zone
    if !catalogZd.Options[OptCatalogMemberAutoCreate] {
        log.Printf("AutoConfigure: Disabled for catalog %s (catalog-member-auto-create not set), catalog provides metadata only",
            catalogZd.ZoneName)
        return nil
    }

    for zoneName, member := range update.MemberZones {
        // RULE 1: Manual config ALWAYS wins (hardcoded behavior)
        if _, exists := Zones.Get(zoneName); exists {
            log.Printf("CATALOG: Zone %s manually configured, ignoring catalog entry (services: %v, meta: %s)",
                zoneName, member.ServiceGroups, member.MetaGroup)
            continue
        }

        // RULE 2: Config group is required for auto-configuration
        if member.ConfigGroup == "" {
            log.Printf("CATALOG: Zone %s has no config group, cannot auto-configure", zoneName)
            continue
        }

        // RULE 3: Find config group config
        configGroupConfig, exists := conf.Catalog.ConfigGroups[member.ConfigGroup]
        if !exists {
            log.Printf("CATALOG: Zone %s config group '%s' not found in config, cannot auto-configure",
                zoneName, member.ConfigGroup)
            continue
        }

        // RULE 4: Auto-configure zone using config group
        // Store defaults to "map" if not specified
        storeValue := configGroupConfig.Store
        if storeValue == "" {
            storeValue = "map"
        }

        log.Printf("CATALOG: Auto-configuring zone %s using config group '%s' (upstream: %s, store: %s)",
            zoneName, member.ConfigGroup, configGroupConfig.Upstream, storeValue)

        zd := &ZoneData{
            ZoneName:  zoneName,
            ZoneType:  Secondary,
            ZoneStore: parseZoneStore(storeValue),
            Upstream:  configGroupConfig.Upstream,
            Logger:    log.Default(),
            Options: map[ZoneOption]bool{
                OptAutomaticZone: true, // Mark as dynamically configured
            },
        }

        // Apply zone options from config group
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
    config_group TEXT NOT NULL,
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
            configGroup := getString(zone, "config_group")
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

### Notify Addresses Management

**Requirement:** Support for adding, removing, and listing notify addresses for catalog zones. Since catalog zones are dynamically created via the API, we need API and CLI support for managing notify addresses.

**Scope:** This feature applies **only to catalog zones** (primary catalog zone publishers). Notify addresses for member zones (secondary zones created from catalog) are managed via config groups and are out of scope for this feature.

**Implementation:**

#### API Endpoints
Add new commands to catalog zone API (e.g., `APICatalog` in `tdns/v2/apihandler_catalog.go`):
- `notify-add`: Add a notify address to a catalog zone
- `notify-remove`: Remove a notify address from a catalog zone
- `notify-list`: List all notify addresses for a catalog zone

**API Request Format:**
```json
{
  "command": "notify-add",
  "catalog": "catalog.example.com.",
  "address": "192.0.2.1:53"
}
```

**Implementation Details:**
- Store notify addresses in `zd.Downstreams` field (`ZoneData.Downstreams`)
- Validate address format (IP:port)
- Ensure addresses are unique (no duplicates)
- Update zone immediately (no regeneration needed)
- Use existing `tdns` notify mechanism (`zd.Downstreams`)
- Persist notify addresses (see Persistence section below)

#### CLI Commands
Add to `tdns-cli`:
- `tdns-cli catalog notify add --cat <catalog> --addr <IP:port>`
- `tdns-cli catalog notify remove --cat <catalog> --addr <IP:port>`
- `tdns-cli catalog notify list --cat <catalog>`

**Example:**
```bash
# Add notify address to catalog zone
tdns-cli catalog notify add --cat catalog.kdc. --addr 192.0.2.1:53

# List notify addresses
tdns-cli catalog notify list --cat catalog.kdc.

# Remove notify address
tdns-cli catalog notify remove --cat catalog.kdc. --addr 192.0.2.1:53
```

### Persistence

**Requirement:** Catalog zones and dynamically configured zones need to be persisted to disk for recovery across restarts. This includes:
1. Writing zone files to disk
2. Generating YAML config for dynamically configured zones
3. Loading zones from disk on startup

**Configuration:**

Add new configuration sections to `tdns` config (e.g., `tdns-auth.yaml`):
```yaml
catalog:
  # Group type prefixes (REQUIRED - defines which groups have special semantics)
  # These prefixes identify group types in catalog zones and trigger special behavior
  # Use "none" to disable a group type (no special semantics, all groups are ordinary)
  group_prefixes:
    config:  "config"     # Prefix for config/transfer groups (e.g., "configKdc")
    signing: "sign"       # Prefix for signing groups (e.g., "signEdge")
  
  # Config groups define zone transfer settings for auto-configuration
  # Only ONE config group allowed per zone (enforced if prefix != "none")
  config_groups:
    kdc:                  # Full group name in catalog: "configkdc"
      upstream: "127.0.0.1:5353"
      store: map          # Optional, defaults to "map"
      options: []
    
    edge:                 # Full group name in catalog: "configedge"
      upstream: "192.0.2.1:5353"
      store: map
      options: []
  
  # Signing groups (documentation only, not used for auto-configuration)
  # Only ONE signing group allowed per zone (enforced if prefix != "none")
  signing_groups:
    edge_zsk:             # Full group name in catalog: "signedge_zsk"
      description: "Edge signing with ZSK only"
    kdc:                  # Full group name in catalog: "signkdc"
      description: "Central signing at KDC"

dynamiczones:
  configfile: /var/lib/tdns/dynamic-zones.yaml  # Absolute path to dynamic config file
  zonedirectory: /var/lib/tdns/zones            # Absolute path to zone file directory
  
  catalog_zones:
    allowed: true          # Whether catalog zones are allowed
    storage: persistent    # "memory" or "persistent"
  
  catalog_members:
    allowed: true          # Whether catalog member zones are allowed
    storage: persistent    # "memory" or "persistent"
    add: auto              # "auto" or "manual" - Enable auto-configuration from catalog
    remove: manual         # "auto" or "manual" - Whether to remove zones when deleted from catalog
  
  dynamic:
    allowed: false         # Whether direct API-created zones are allowed (future feature)
    storage: memory        # "memory" or "persistent"
```

**Field Descriptions:**

**Catalog Configuration:**
- `group_prefixes`: **REQUIRED** - Defines which group types have special semantics
  - `config`: Prefix for config/transfer groups (used for auto-configuration)
    - Groups starting with this prefix are **config groups**
    - Only ONE config group allowed per zone
    - Used to determine zone transfer settings (upstream, store, options)
    - Set to `"none"` to disable config groups (no auto-configuration)
  - `signing`: Prefix for signing groups (documentation only)
    - Groups starting with this prefix are **signing groups**
    - Only ONE signing group allowed per zone
    - Currently used for documentation only, may trigger signing automation in future
    - Set to `"none"` to disable signing groups (all groups are ordinary)
  - **Note:** Operator controls separator by including it in prefix (e.g., `"config_"` vs `"config"`)
  - **Validation:** Prefixes must contain valid DNS label characters, cannot start/end with hyphen
  - **Interoperability:** Different implementations can use different prefixes to identify their special groups
- `config_groups`: Config group definitions (used when auto-configuring zones from catalog)
  - Key is the group name suffix (full name in catalog = `{prefix}{name}`)
  - `upstream`: Where to AXFR member zones from (required)
  - `store`: Zone store type - `xfr`, `map`, or `slice` (optional, defaults to `map`)
  - `options`: Zone options array (optional)
- `signing_groups`: Signing group definitions (documentation only)
  - Key is the group name suffix (full name in catalog = `{prefix}{name}`)
  - `description`: Human-readable description of signing policy

**Dynamic Zones Configuration:**
- `configfile`: Absolute path to YAML file where dynamic zone configs are stored
  - Server must have write access to this file
  - File format matches existing zone config format
  - Server may create file if it doesn't exist
  - File should be included in main config via `include:` statement (see below)
  - If `configfile` is set but not included, log a warning (not a hard fail)
- `zonedirectory`: Absolute path to directory where zone files are written
  - Server must have write access to this directory
  - Server may create directory if it doesn't exist
  - Zone files use standard zone file format
- `catalog_zones`: Configuration for catalog zones (primary catalog zone publishers)
  - `allowed`: Whether catalog zones are allowed (default: `true`)
  - `storage`: `memory` or `persistent` (default: `memory`)
- `catalog_members`: Configuration for catalog member zones (secondary zones from catalog)
  - `allowed`: Whether catalog member zones are allowed (default: `true`)
  - `storage`: `memory` or `persistent` (default: `memory`)
  - `add`: `auto` or `manual` - Enable auto-configuration from catalog
  - `remove`: `auto` or `manual` - Whether to remove zones when deleted from catalog
- `dynamic`: Configuration for direct API-created zones (future feature)
  - `allowed`: Whether direct API-created zones are allowed (default: `false`)
  - `storage`: `memory` or `persistent` (default: `memory`)

**Backward Compatibility:**
- Old `catalog.policy.zones.add/remove` settings are migrated to `dynamiczones.catalog_members.add/remove`
- Old `meta_groups` name is migrated to `config_groups` with deprecation warning
- Hardcoded `"meta_"` and `"sign_"` prefixes are replaced with configurable `group_prefixes`

**Include Statement:**
The dynamic config file should be included in the main config file:
```yaml
# Main config file (tdns-auth.yaml)
include:
  - /etc/tdns/dynamic-zones.yaml

dynamiczones:
  configfile: /etc/tdns/dynamic-zones.yaml
  zonedirectory: /var/lib/tdns/zones
  catalog_zones:
    allowed: true
    storage: persistent
  catalog_members:
    allowed: true
    storage: persistent
    add: auto
    remove: manual
```

If `dynamiczones.configfile` is specified but the file is not included via `include:`, log a warning (not a hard fail) that the dynamic zones will not be loaded on startup.

#### Zone File Persistence

**For Catalog Zones (Primary):**
- When `storage: persistent`:
  - After catalog zone generation/update, write zone file to `{zonedirectory}/{catalog-zone-name}.zone`
  - Use `zd.WriteZoneFile()` or equivalent to write zone data
  - Include all records (SOA, version TXT, PTR, group TXT records)
  - Update zone file whenever catalog zone is regenerated

**For Member Zones (Secondary, from catalog):**
- When `dynamiczones.catalog_members.storage: persistent`:
  - **Only write zone file after successful inbound zone transfer** (when zone data is available)
  - Do NOT write zone file immediately after auto-configuration (before first transfer)
  - Update zone file on subsequent successful transfers
  - Include all zone data (RRs, RRSIGs if signed)

#### Dynamic Config File Generation

**Format:**
The dynamic config file should follow the same format as the main zone config file:
```yaml
zones:
  - name: catalog.example.com.
    zonefile: /var/lib/tdns/zones/catalog.example.com.zone
    type: primary
    store: map
    options: [catalog-zone]
    notify: [ "192.0.2.1:53", "192.0.2.2:53" ]
    # ... other fields as needed

  - name: example.com.
    zonefile: /var/lib/tdns/zones/example.com.zone
    type: secondary
    store: map
    primary: 192.0.2.10:53
    options: [automatic-zone]
    source_catalog: catalog.example.com.
    # ... other fields as needed
```

**Implementation:**
- Generate config entry when zone is created/configured
- Update config entry when zone properties change (e.g., notify addresses)
- Remove config entry when zone is deleted
- Use atomic writes (write to temp file, then rename) to avoid corruption
- Load dynamic config separately from main config at startup

#### Loading on Startup

**For Catalog Zones:**
1. Check if catalog zone exists in `tdns.Zones`
2. If not and `storage: persistent`:
   - Check if zone file exists in `zonedirectory`
   - If exists, load zone from file using `zd.ReadZoneFile()`
   - Load notify addresses from dynamic config file
   - Register with `tdns.Zones`
   - Mark as catalog zone (`OptCatalogZone`)

**For Member Zones (Secondary):**
1. On startup, load dynamic config file
2. For each zone in dynamic config:
   - Check if zone file exists
   - If exists, load zone from file
   - Register with `tdns.Zones`
   - If `type: secondary` and `primary` is set, trigger zone transfer
   - Restore `SourceCatalog` field

**Load Order:**
1. Load main config file (static zones)
2. Load dynamic config file (dynamic zones)
3. Initialize catalog zones (if configured)
4. Process catalog zones to auto-configure member zones

#### File Management

**Zone Files:**
- Write zone files atomically (write to temp, then rename)
- Use standard zone file format
- Include all zone data (RRs, RRSIGs if signed)

**Config File:**
- Use YAML format matching main config
- Write atomically (write to temp, then rename)
- Include all zone metadata (type, store, options, notify, etc.)
- Track `SourceCatalog` for member zones
- **Add clear warning comment at top of file:**
  ```yaml
  # WARNING: This file is automatically maintained by tdns.
  # Manual edits may be overwritten without warning when the server is running.
  # Edits made while the server is stopped will be accepted, but may be overwritten
  # on the next server operation that modifies this file.
  
  zones:
    # ... zone configs ...
  ```

**Error Handling:**
- If zone file is corrupted on startup:
  - Create the zone in memory (so it appears in zone listings)
  - Skip loading the zone file content
  - Set persistent error on zone using `zd.SetError(ConfigError, "failed to load zone file: <details>")`
  - Log error with details about the parse error
  - Zone will appear in API listings with error state, allowing operator to diagnose issue
- If config file is corrupted, log error and start with empty dynamic config
- If directory doesn't exist, create it with appropriate permissions
- If file write fails, log error but continue operation (zone remains in memory)

#### Integration Points

**In `tdns/v2/apihandler_catalog.go:regenerateCatalogZone()`:**
- After successful regeneration, if `storage: persistent`:
  - Write zone file to `zonedirectory`
  - Update/add entry in dynamic config file

**In `tdns/v2/catalog.go:AutoConfigureZonesFromCatalog()`:**
- After successful zone creation, if `storage: persistent`:
  - Write zone file to `zonedirectory` (after first transfer)
  - Add entry to dynamic config file

**In `tdns/v2/main_initfuncs.go:MainInit()`:**
- After loading main config:
  - Check if `dynamiczones.configfile` is set
  - If set, check if file is included via `include:` statement
  - If not included, log warning (not hard fail)
  - If included and `dynamiczones.catalog_zones.storage: persistent` or `dynamiczones.catalog_members.storage: persistent`:
    - Load dynamic config file
    - Load zone files for dynamic zones (with error handling for corrupted files)

#### Configuration Validation

- Validate that `configfile` path is absolute
- Validate that `zonedirectory` path is absolute
- Validate that paths exist or can be created
- Validate file/directory permissions (read/write access)
- Check if `configfile` is included via `include:` statement
  - If not included, log warning (not hard fail)
  - Dynamic zones will not be loaded on startup if not included
- If validation fails, log error and fall back to `memory` mode for that zone type
- Validate that `catalog_members.add` and `catalog_members.remove` are either `auto` or `manual`

#### Migration Considerations

- Existing catalog zones in memory will be lost on restart until persistence is enabled
- After enabling persistence, existing zones should be saved manually (via API) or regenerated
- Dynamic config file can be manually edited while server is stopped (edits will be accepted)
- Dynamic config file may be overwritten when server is running (warning comment in file)
- Zone files can be manually edited (server will overwrite on next update)
- **Breaking change:** Global `catalog.policy.zones.add/remove` settings are replaced with per-catalog-zone options `catalog-member-auto-create` and `catalog-member-auto-delete`
  - This allows different policies for different catalog zones
  - Old global settings in `dynamiczones.catalog_members.add/remove` are deprecated
  - Use zone options for finer-grained control

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
# Add zone to catalog (atomically with all groups)
tdns-cli catalog zone add --cat catalog.kdc. --zone pella.se. --groups any_se,sign_edge_zsk,config_kdc

# Or add zone first, then add groups individually
tdns-cli catalog zone add --cat catalog.kdc. --zone pella.se.
tdns-cli catalog zone group add --cat catalog.kdc. --zone pella.se. --group any_se
tdns-cli catalog zone group add --cat catalog.kdc. --zone pella.se. --group sign_edge_zsk
tdns-cli catalog zone group add --cat catalog.kdc. --zone pella.se. --group config_kdc

# Remove a group from a zone
tdns-cli catalog zone group delete --cat catalog.kdc. --zone pella.se. --group any_se

# Remove zone from catalog
tdns-cli catalog zone delete --cat catalog.kdc. --zone pella.se.

# List all zones in catalog
tdns-cli catalog zone list --cat catalog.kdc.

# Delete entire catalog zone
tdns-cli catalog delete --cat catalog.kdc.
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
  group_prefixes:
    config: "config"
    signing: "sign"
  
  config_groups:
    config_kdc:
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
    store: map
    primary: "127.0.0.1:5353"
    options:
      - catalog-zone
      - catalog-member-auto-create    # Enable auto-configuration
      - catalog-member-auto-delete    # Auto-delete when removed from catalog
```

### tdns-auth (Catalog Zone Consumer, Manual Config)
```yaml
catalog:
  group_prefixes:
    config: "config"
    signing: "sign"
  
  config_groups: {}            # Not needed if auto-config disabled

zones:
  catalog.example.:
    type: secondary
    store: map
    primary: "192.0.2.1:53"
    options:
      - catalog-zone
      # NOTE: No catalog-member-auto-create/delete options - manual config only

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
group.be0a0dc3b5fe5785.zones.catalog.kdc. 0 IN TXT "any_se" "sign_edge_zsk" "config_kdc"
```

Parsed as:
- Service groups: `[any_se]`
- Signing group: `sign_edge_zsk`
- Config group: `config_kdc`

If KRS node subscribes to `any_se` and `config_kdc` is configured, zone is auto-configured.

### Scenario 2: Zone with Multiple Service Groups
Catalog entry for `internal.corp.` (hash: `abc123...`):
```text
abc123.zones.catalog.kdc. 0 IN PTR internal.corp.
group.abc123.zones.catalog.kdc. 0 IN TXT "corp_internal" "corp_external" "sign_kdc" "config_central"
```

Parsed as:
- Service groups: `[corp_internal, corp_external]`
- Signing group: `sign_kdc`
- Config group: `config_central`

Node serves zone if subscribed to EITHER `corp_internal` OR `corp_external`.

### Scenario 3: Missing Config Group
Catalog entry for `test.com.` (hash: `def456...`):
```text
def456.zones.catalog.kdc. 0 IN PTR test.com.
group.def456.zones.catalog.kdc. 0 IN TXT "any_se" "sign_edge_zsk"
```

Parsed as:
- Service groups: `[any_se]`
- Signing group: `sign_edge_zsk`
- Config group: `` (empty)

Result: Info logged, zone cannot be auto-configured (config group required).

### Scenario 4: Manual Override
Catalog entry for `example.com.` + manual config for `example.com.`

Result: Manual config wins, catalog entry ignored, warning logged.

### Scenario 5: Multiple Signing Groups (Warning)
Catalog entry for `bad.example.` (hash: `ghi789...`):
```text
ghi789.zones.catalog.kdc. 0 IN PTR bad.example.
group.ghi789.zones.catalog.kdc. 0 IN TXT "sign_edge_zsk" "sign_kdc" "config_kdc"  # CONFLICT!
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
| No config group | Log info, zone not auto-configured |
| Config group not found | Log warning, zone not auto-configured |
| Multiple signing/config groups | Log warning, use first |
| Manual vs catalog conflict | Manual wins (hardcoded), log warning |

## Verification Steps

### Basic Functionality
1. **Configure catalog zone** in yaml with `type: secondary` and `options: [catalog-zone]`
2. **Start application** (e.g., KRS with tdns-krs)
3. **Check logs** for "catalog zone option enabled"
4. **Verify initial parse** - logs show "Parsed catalog zone" with member count
5. **Test NOTIFY** - Update catalog on publisher, verify NOTIFY triggers refresh and re-parse

### Auto-Configuration
1. **Enable per-zone** - Add `catalog-member-auto-create` option to catalog zone
2. **Configure config groups** - Define upstreams and TSIG in `catalog.config_groups`
3. **Configure group prefixes** - Set `catalog.group_prefixes.config` and `.signing`
4. **Verify auto-config** - Logs show "Auto-configuring zone" messages
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
8. **Clear group types** - Service, signing, and config groups have distinct purposes (RFC 9432 terminology)
9. **No priority conflicts** - Each zone has exactly one config and signing group
10. **Safe defaults** - Manual config always wins (hardcoded behavior)
11. **Auto-configuration** - Optional auto-config with config groups (per-catalog-zone option)
12. **Application flexibility** - Each application filters zones as needed (e.g., by service groups)

## Future Enhancements

1. **Notify addresses management** - API and CLI support for managing notify addresses on catalog zones (see Notify Addresses Management section)
2. **Persistence** - Zone file and config file persistence for catalog zones and dynamically configured zones (see Persistence section)
3. **IXFR support** - Incremental catalog zone updates
4. **Multiple catalogs** - Track changes across different catalog zones
5. **Catalog zone validation** - Verify catalog zone structure compliance
6. **Statistics** - Track catalog update metrics
7. **Catalog zone generation** - Helper functions for applications that publish catalogs
8. **Dynamic config groups** - Allow config groups to be updated without restart
9. **Zone removal cleanup** - Automatically clean up zone data when removed from catalog
10. **Group inheritance** - Default meta/signing groups if not specified
