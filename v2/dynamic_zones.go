/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Dynamic zone persistence support for catalog zones and catalog member zones
 */

package tdns

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"

	core "github.com/johanix/tdns/v2/core"
)

// WriteDynamicZoneFile writes a zone file to the dynamic zones directory using atomic writes
// Returns the full path to the written file, or an error
func (zd *ZoneData) WriteDynamicZoneFile(zoneDirectory string) (string, error) {
	if zoneDirectory == "" {
		return "", fmt.Errorf("zone directory is required")
	}

	// Ensure zone directory exists
	if err := os.MkdirAll(zoneDirectory, 0755); err != nil {
		return "", fmt.Errorf("failed to create zone directory %s: %v", zoneDirectory, err)
	}

	// Generate zone file name: {zonedirectory}/{zone-name}.zone
	// Remove trailing dot from zone name for filename
	zoneFileName := fmt.Sprintf("%s.zone", strings.TrimSuffix(zd.ZoneName, "."))
	zoneFilePath := filepath.Join(zoneDirectory, zoneFileName)

	// Create temp file in the same directory for atomic write
	tempFile, err := os.CreateTemp(zoneDirectory, fmt.Sprintf(".%s.tmp", zoneFileName))
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %v", err)
	}
	tempFilePath := tempFile.Name()

	// Write zone data to temp file
	err = zd.WriteZoneToFile(tempFile)
	if err != nil {
		tempFile.Close()
		os.Remove(tempFilePath) // Clean up temp file on error
		return "", fmt.Errorf("failed to write zone data to temp file: %v", err)
	}

	// Close temp file before rename (WriteZoneToFile flushes but doesn't close)
	if err := tempFile.Close(); err != nil {
		os.Remove(tempFilePath)
		return "", fmt.Errorf("failed to close temp file: %v", err)
	}

	// Atomic rename: temp file -> final file
	if err := os.Rename(tempFilePath, zoneFilePath); err != nil {
		os.Remove(tempFilePath) // Clean up temp file on error
		return "", fmt.Errorf("failed to rename temp file to final file: %v", err)
	}

	lg.Info("wrote zone file", "zone", zd.ZoneName, "path", zoneFilePath)
	return zoneFilePath, nil
}

// LoadDynamicZoneFile loads a zone from a file in the dynamic zones directory
// Returns true if zone was updated, the serial number, and any error
// If the file is corrupted, creates the zone but sets an error state
func (zd *ZoneData) LoadDynamicZoneFile(zoneDirectory string) (bool, uint32, error) {
	if zoneDirectory == "" {
		return false, 0, fmt.Errorf("zone directory is required")
	}

	// Generate zone file name (same logic as WriteDynamicZoneFile)
	zoneFileName := fmt.Sprintf("%s.zone", strings.TrimSuffix(zd.ZoneName, "."))
	zoneFilePath := filepath.Join(zoneDirectory, zoneFileName)

	// Check if file exists
	if _, err := os.Stat(zoneFilePath); os.IsNotExist(err) {
		return false, 0, fmt.Errorf("zone file does not exist: %s", zoneFilePath)
	}

	// Try to read the zone file
	updated, serial, err := zd.ReadZoneFile(zoneFilePath, false)
	if err != nil {
		// File is corrupted - create zone but set error state
		lg.Error("failed to load zone file", "zone", zd.ZoneName, "path", zoneFilePath, "err", err)

		// Ensure zone exists in Zones map (create if needed)
		if _, exists := Zones.Get(zd.ZoneName); !exists {
			Zones.Set(zd.ZoneName, zd)
		}

		// Set persistent error state
		zd.SetError(ConfigError, "Failed to load zone file: %v", err)

		return false, 0, fmt.Errorf("zone file corrupted: %v", err)
	}

	// Successful load clears ConfigError specifically. Other categories
	// (rollover-policy, refresh, etc.) are independent and survive.
	zd.ClearError(ConfigError)

	lg.Info("loaded zone file", "zone", zd.ZoneName, "path", zoneFilePath, "serial", serial)
	return updated, serial, nil
}

// GetDynamicZoneFilePath returns the expected file path for a dynamic zone file
// This is useful for checking if a file exists before attempting to load it
func GetDynamicZoneFilePath(zoneName, zoneDirectory string) string {
	zoneFileName := fmt.Sprintf("%s.zone", strings.TrimSuffix(zoneName, "."))
	return filepath.Join(zoneDirectory, zoneFileName)
}

// ShouldPersistZone checks if a zone should be persisted based on configuration
// Returns true if the zone should be written to disk
func (conf *Config) ShouldPersistZone(zd *ZoneData) bool {
	// Check if dynamiczones is configured
	if conf.DynamicZones.ZoneDirectory == "" {
		return false
	}

	// Check zone type and storage setting
	if zd.Options[OptCatalogZone] {
		// Catalog zone
		return conf.DynamicZones.CatalogZones.Storage == "persistent" && conf.DynamicZones.CatalogZones.Allowed
	}

	if zd.Options[OptAutomaticZone] {
		// Catalog member zone (auto-configured)
		return conf.DynamicZones.CatalogMembers.Storage == "persistent" && conf.DynamicZones.CatalogMembers.Allowed
	}

	if zd.Options[OptApiManagedZone] {
		// API-managed zone (zone add/delete/modify)
		return conf.DynamicZones.Dynamic.Storage == "persistent" && conf.DynamicZones.Dynamic.Allowed
	}

	return false
}

// LoadDynamicZoneFiles loads dynamic zones from the dynamic config file on startup
// This should be called after ParseZones() but before engines start
// It loads zones that were persisted in previous runs
func (conf *Config) LoadDynamicZoneFiles(ctx context.Context) error {
	if conf.DynamicZones.ConfigFile == "" {
		return nil // No config file configured, nothing to load
	}

	// Check if config file exists
	if _, err := os.Stat(conf.DynamicZones.ConfigFile); os.IsNotExist(err) {
		lg.Debug("dynamic config file does not exist, skipping", "path", conf.DynamicZones.ConfigFile)
		return nil
	}

	lg.Info("loading dynamic zones from config file", "path", conf.DynamicZones.ConfigFile)

	// Load dynamic config file
	zoneConfs, err := conf.loadDynamicConfigFile()
	if err != nil {
		// Error already logged in loadDynamicConfigFile
		return nil // Start with empty config rather than failing
	}

	loadedCount := 0
	skippedCount := 0

	for _, zconf := range zoneConfs {
		zoneName := zconf.Name

		// Check if zone already exists (from main config or already loaded)
		if _, exists := Zones.Get(zoneName); exists {
			lg.Debug("zone already exists, skipping dynamic config entry", "zone", zoneName)
			skippedCount++
			continue
		}

		// Parse zone type
		var zoneType ZoneType
		switch strings.ToLower(zconf.Type) {
		case "primary":
			zoneType = Primary
		case "secondary":
			zoneType = Secondary
		default:
			lg.Warn("invalid zone type, skipping", "zone", zoneName, "type", zconf.Type)
			skippedCount++
			continue
		}

		// Parse zone store
		var zoneStore ZoneStore
		switch strings.ToLower(zconf.Store) {
		case "map":
			zoneStore = MapZone
		case "slice":
			zoneStore = SliceZone
		case "xfr":
			zoneStore = XfrZone
		default:
			lg.Warn("invalid zone store, defaulting to map", "zone", zoneName, "store", zconf.Store)
			zoneStore = MapZone
		}

		// Parse options
		options := make(map[ZoneOption]bool)
		for _, optStr := range zconf.OptionsStrs {
			if opt, ok := StringToZoneOption[optStr]; ok {
				options[opt] = true
			}
		}
		// Re-derive the internal markers from their persisted fields — they are
		// not serialized as options (B5a). Without this, a reloaded managed zone
		// loses its marker on restart and degrades to looking static (the latent
		// catalog bug this fix also closes).
		if zconf.SourceCatalog != "" {
			options[OptAutomaticZone] = true
		}
		if zconf.ApiManaged {
			options[OptApiManagedZone] = true
		}

		// Log what we're loading
		if options[OptCatalogZone] {
			lg.Debug("enqueuing catalog zone for refresh", "zone", zoneName, "type", zconf.Type)
		} else if options[OptAutomaticZone] {
			lg.Debug("enqueuing auto-configured zone for refresh", "zone", zoneName, "type", zconf.Type, "catalog", zconf.SourceCatalog)
		} else {
			lg.Debug("enqueuing zone for refresh", "zone", zoneName, "type", zconf.Type)
		}

		// Re-resolve the persisted as-written primaries (hostnames -> addresses)
		// on every load. Zero resolved is logged and still enqueued so the zone
		// is created and visible (it surfaces a refresh error rather than
		// silently vanishing); partial is logged and served from the rest.
		res := resolvePrimaries(ctx, conf.Internal.ImrEngine, zconf.Primaries)
		if zoneType == Secondary && len(res.Resolved) == 0 {
			lg.Error("dynamic zone: no primary resolved to an address (enqueuing anyway, will surface as refresh error)", "zone", zoneName, "unresolved", res.Unresolved)
		} else if len(res.Unresolved) > 0 || len(res.KeyCollisions) > 0 {
			lg.Warn("dynamic zone: some primaries unavailable, serving from the rest", "zone", zoneName, "unresolved", res.Unresolved, "key_collisions", res.KeyCollisions, "serving", len(res.Resolved))
		}

		// Create ZoneRefresher and enqueue to RefreshEngine (same as ParseZones does)
		zr := ZoneRefresher{
			Name:          zoneName,
			Force:         true, // Force refresh on startup to load from disk
			ZoneType:      zoneType,
			PrimariesConf: clonePeerConfs(zconf.Primaries),
			Primaries:     res.Resolved,
			ZoneStore:     zoneStore,
			Notify:        zconf.Notify,
			Zonefile:      zconf.Zonefile,
			Options:       options,
		}

		// Attempt non-blocking send (same pattern as ParseZones)
		select {
		case conf.Internal.RefreshZoneCh <- zr:
			loadedCount++
			lg.Debug("enqueued zone for refresh", "zone", zoneName)
		case <-ctx.Done():
			lg.Warn("context cancelled while enqueueing zone", "zone", zoneName)
			return ctx.Err()
		case <-time.After(5 * time.Second):
			lg.Debug("timeout enqueueing zone to RefreshEngine", "zone", zoneName)
			skippedCount++
		}
	}

	lg.Info("dynamic zone loading complete", "loaded", loadedCount, "skipped", skippedCount)
	return nil
}

// DynamicConfigFile represents the structure of the dynamic zones config file
type DynamicConfigFile struct {
	Zones []ZoneConf `yaml:"zones"`
}

var (
	// dynamicConfigMutex protects concurrent access to the dynamic config file
	// Used by both loadDynamicConfigFile() and writeDynamicConfigFile() to prevent
	// race conditions and ensure consistency between read/write operations
	dynamicConfigMutex sync.Mutex
)

// zoneDataToZoneConf converts a ZoneData to ZoneConf for serialization
func zoneDataToZoneConf(zd *ZoneData, zoneDirectory string) ZoneConf {
	// Generate zone file path
	zoneFileName := fmt.Sprintf("%s.zone", strings.TrimSuffix(zd.ZoneName, "."))
	zoneFilePath := filepath.Join(zoneDirectory, zoneFileName)

	// Convert options to strings
	optionsStrs := make([]string, 0)
	for opt, enabled := range zd.Options {
		if enabled {
			if optStr, ok := ZoneOptionToString[opt]; ok {
				// Skip internal options that shouldn't be in config.
				// OptAutomaticZone is re-derived on reload from SourceCatalog;
				// OptApiManagedZone is re-derived from the ApiManaged bool — both
				// are internal markers, not config options.
				if opt != OptDirty && opt != OptFrozen && opt != OptAutomaticZone && opt != OptApiManagedZone {
					optionsStrs = append(optionsStrs, optStr)
				}
			}
		}
	}
	sort.Strings(optionsStrs) // Sort for consistent output

	// Determine store string
	storeStr := ZoneStoreToString[zd.ZoneStore]
	if storeStr == "" {
		storeStr = "map" // Default
	}

	// Determine type string
	typeStr := ZoneTypeToString[zd.ZoneType]
	if typeStr == "" {
		typeStr = "secondary" // Default
	}

	zconf := ZoneConf{
		Name:          zd.ZoneName,
		Zonefile:      zoneFilePath,
		Type:          typeStr,
		Store:         storeStr,
		Primaries:     clonePeerConfs(zd.PrimariesConf),
		Notify:        zd.Notify,
		OptionsStrs:   optionsStrs,
		SourceCatalog: zd.SourceCatalog,
		ApiManaged:    zd.Options[OptApiManagedZone],
		// Note: We don't serialize Frozen, Dirty, Error, ErrorType, ErrorMsg, RefreshCount
		// as these are runtime state, not configuration
	}

	return zconf
}

// loadDynamicConfigFile loads the dynamic config file and returns the zone configs
// Thread-safe: protected by dynamicConfigMutex to prevent races with writeDynamicConfigFile
func (conf *Config) loadDynamicConfigFile() ([]ZoneConf, error) {
	if conf.DynamicZones.ConfigFile == "" {
		return nil, fmt.Errorf("dynamic config file path not configured")
	}

	// Acquire lock to prevent concurrent read/write operations
	// While atomic renames protect against partial reads, this ensures
	// consistency with write operations and prevents TOCTOU issues
	dynamicConfigMutex.Lock()
	defer dynamicConfigMutex.Unlock()

	// Check if file exists
	if _, err := os.Stat(conf.DynamicZones.ConfigFile); os.IsNotExist(err) {
		lg.Debug("dynamic config file does not exist, starting with empty config", "path", conf.DynamicZones.ConfigFile)
		return []ZoneConf{}, nil
	}

	// Read file
	data, err := os.ReadFile(conf.DynamicZones.ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read dynamic config file %s: %v", conf.DynamicZones.ConfigFile, err)
	}

	// Try to parse YAML
	var configFile DynamicConfigFile
	if err := yaml.Unmarshal(data, &configFile); err != nil {
		// File is corrupted - log error and return empty config
		lg.Error("failed to parse dynamic config file, starting with empty config", "path", conf.DynamicZones.ConfigFile, "err", err)
		return []ZoneConf{}, nil
	}

	lg.Info("loaded zones from dynamic config file", "count", len(configFile.Zones), "path", conf.DynamicZones.ConfigFile)
	return configFile.Zones, nil
}

// writeDynamicConfigFile writes the dynamic config file with atomic writes
func (conf *Config) writeDynamicConfigFile(zones []ZoneConf) error {
	if conf.DynamicZones.ConfigFile == "" {
		return fmt.Errorf("dynamic config file path not configured")
	}

	dynamicConfigMutex.Lock()
	defer dynamicConfigMutex.Unlock()

	// Create config file structure
	configFile := DynamicConfigFile{
		Zones: zones,
	}

	// Marshal to YAML
	data, err := yaml.Marshal(&configFile)
	if err != nil {
		return fmt.Errorf("failed to marshal dynamic config: %v", err)
	}

	// Add warning comment at the top
	warningComment := `# WARNING: This file is automatically maintained by tdns.
# Manual edits may be overwritten without warning when the server is running.
# Edits made while the server is stopped will be accepted, but may be overwritten
# on the next server operation that modifies this file.

`
	finalData := []byte(warningComment)
	finalData = append(finalData, data...)

	// Create temp file in same directory for atomic write
	configDir := filepath.Dir(conf.DynamicZones.ConfigFile)
	configFileName := filepath.Base(conf.DynamicZones.ConfigFile)
	tempFile, err := os.CreateTemp(configDir, fmt.Sprintf(".%s.tmp", configFileName))
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	tempFilePath := tempFile.Name()

	// Write data to temp file
	_, err = tempFile.Write(finalData)
	if err != nil {
		tempFile.Close()
		os.Remove(tempFilePath)
		return fmt.Errorf("failed to write temp file: %v", err)
	}

	// Close temp file before rename
	if err := tempFile.Close(); err != nil {
		os.Remove(tempFilePath)
		return fmt.Errorf("failed to close temp file: %v", err)
	}

	// Atomic rename: temp file -> final file
	if err := os.Rename(tempFilePath, conf.DynamicZones.ConfigFile); err != nil {
		os.Remove(tempFilePath)
		return fmt.Errorf("failed to rename temp file to final file: %v", err)
	}

	lg.Info("wrote dynamic config file", "path", conf.DynamicZones.ConfigFile, "zones", len(zones))
	return nil
}

// getDynamicZonesFromZonesMap collects all dynamic zones from the Zones map
func (conf *Config) getDynamicZonesFromZonesMap() []ZoneConf {
	var dynamicZones []ZoneConf

	for zoneName := range Zones.IterBuffered() {
		zd := zoneName.Val
		if zd == nil {
			continue
		}

		// Check if this zone should be persisted
		if !conf.ShouldPersistZone(zd) {
			continue
		}

		// Convert to ZoneConf
		zconf := zoneDataToZoneConf(zd, conf.DynamicZones.ZoneDirectory)
		dynamicZones = append(dynamicZones, zconf)
	}

	// Sort by zone name for consistent output
	sort.Slice(dynamicZones, func(i, j int) bool {
		return dynamicZones[i].Name < dynamicZones[j].Name
	})

	return dynamicZones
}

// WriteDynamicConfigFile writes the current dynamic zones to the config file
// This should be called whenever a dynamic zone is created, updated, or deleted
func (conf *Config) WriteDynamicConfigFile() error {
	if conf.DynamicZones.ConfigFile == "" {
		return nil // No config file configured, nothing to write
	}

	// Collect all dynamic zones
	dynamicZones := conf.getDynamicZonesFromZonesMap()

	// Write to file
	return conf.writeDynamicConfigFile(dynamicZones)
}

// AddDynamicZoneToConfig adds or updates a zone in the dynamic config file
func (conf *Config) AddDynamicZoneToConfig(zd *ZoneData) error {
	if conf.DynamicZones.ConfigFile == "" {
		return nil // No config file configured, nothing to do
	}

	if !conf.ShouldPersistZone(zd) {
		return nil // Zone should not be persisted
	}

	// Simply rewrite the entire file (simpler than trying to update individual entries)
	return conf.WriteDynamicConfigFile()
}

// RemoveDynamicZoneFromConfig removes a zone from the dynamic config file
func (conf *Config) RemoveDynamicZoneFromConfig(zoneName string) error {
	if conf.DynamicZones.ConfigFile == "" {
		return nil // No config file configured, nothing to do
	}

	// Simply rewrite the entire file (simpler than trying to remove individual entries)
	return conf.WriteDynamicConfigFile()
}

// CheckDynamicConfigFileIncluded checks if the dynamic config file is included in the main config
// Returns true if included, false otherwise (logs warning if not included)
func (conf *Config) CheckDynamicConfigFileIncluded(includedFiles []string) bool {
	if conf.DynamicZones.ConfigFile == "" {
		return true // No config file configured, nothing to check
	}

	configFileAbs := filepath.Clean(conf.DynamicZones.ConfigFile)

	// Check if the config file is in the included files list
	for _, includedFile := range includedFiles {
		includedFileAbs := filepath.Clean(includedFile)
		if configFileAbs == includedFileAbs {
			return true
		}
	}

	// Not included - log warning
	lg.Warn("dynamic config file not included via 'include:' in main config, dynamic zones will not be loaded on startup", "path", conf.DynamicZones.ConfigFile)
	return false
}

// DynamicZoneInput carries the parameters for the shared add/modify cores. There
// is no Store field: dynamic zones are always MapZone (enforced in the cores).
type DynamicZoneInput struct {
	Name      string
	Type      ZoneType
	Primaries []PeerConf
	Options   map[ZoneOption]bool
}

// ProvisionDynamicZone is the shared *add* core, called by both the catalog
// auto-configure path and the new zone-add API/CLI. It registers + persists +
// enqueues a refresh, then returns immediately — it does NOT wait for the AXFR
// (the caller polls ZoneConf.Provisioning for state). fromAPI gates the
// dynamiczones.dynamic.allowed check and the OptApiManagedZone marker: the
// catalog path has its own members config and is not API-managed.
func (conf *Config) ProvisionDynamicZone(ctx context.Context, in DynamicZoneInput, fromAPI bool) (string, error) {
	name := dns.Fqdn(in.Name)

	// API/CLI callers are gated by dynamiczones.dynamic.allowed (defaults false).
	// The catalog path is gated by its own members config, not this.
	if fromAPI && !conf.DynamicZones.Dynamic.Allowed {
		return "", fmt.Errorf("dynamic zone provisioning via API is not allowed (set dynamiczones.dynamic.allowed: true)")
	}

	// API/CLI v1 is secondary-only (primary + notify peers are static/catalog
	// config until a later extension).
	if fromAPI && in.Type != Secondary {
		return "", fmt.Errorf("zone add supports secondary zones only (got %s)", ZoneTypeToString[in.Type])
	}

	if _, err := dns.IsDomainName(name); !err {
		return "", fmt.Errorf("invalid zone name %q", in.Name)
	}
	if _, exists := Zones.Get(name); exists {
		return "", fmt.Errorf("zone %s already exists", name)
	}

	// Validate the primary's key. Improvement-1 phase: NOKEY is the only
	// resolvable key name (any other is an unknown-key error until the keys:
	// block lands).
	if in.Type == Secondary {
		if len(in.Primaries) == 0 || in.Primaries[0].Addr == "" {
			return "", fmt.Errorf("secondary zone %s requires a primary address", name)
		}
		for _, p := range in.Primaries {
			if p.Key != NOKEY {
				return "", fmt.Errorf("unknown primary key %q (only NOKEY is valid until TSIG keys are configured)", p.Key)
			}
		}
	}

	options := in.Options
	if options == nil {
		options = map[ZoneOption]bool{}
	}
	if fromAPI {
		options[OptApiManagedZone] = true
	}

	// Resolve hostname primaries to addresses via the IMR at add time (not only
	// on the next restart). Zero resolved on a secondary -> reject the add.
	res := resolvePrimaries(ctx, conf.Internal.ImrEngine, in.Primaries)
	if in.Type == Secondary && len(res.Resolved) == 0 {
		return "", fmt.Errorf("zone %s: no primary resolved to an address (unresolved: %v)", name, res.Unresolved)
	}
	primariesConf := clonePeerConfs(in.Primaries)
	upstreams := res.Resolved

	// Store is always map for dynamic zones — single chokepoint for the map-only
	// rule (also covers the catalog re-point).
	zd := &ZoneData{
		ZoneName:      name,
		ZoneType:      in.Type,
		ZoneStore:     MapZone,
		PrimariesConf: primariesConf,
		Upstreams:     upstreams,
		Logger:        log.Default(),
		Options:       options,
		Status:        ZoneStatusPending,
		Data:          core.NewCmap[OwnerData](),
		KeyDB:         conf.Internal.KeyDB,
	}

	// Register, then persist; roll back the live registration if persist fails
	// (never leave a live-but-unpersisted zone that vanishes on restart).
	Zones.Set(name, zd)
	if err := conf.AddDynamicZoneToConfig(zd); err != nil {
		Zones.Remove(name)
		return "", fmt.Errorf("failed to persist dynamic zone %s: %w", name, err)
	}

	// Partial resolution: the zone is served from the addresses that resolved,
	// with a visibility-only ConfigWarning naming the rest.
	if len(res.Unresolved) > 0 || len(res.KeyCollisions) > 0 {
		served := len(in.Primaries) - len(res.Unresolved)
		zd.SetError(ConfigWarning, "serving from %d of %d primaries (unresolved: %v, key-collisions: %v)", served, len(in.Primaries), res.Unresolved, res.KeyCollisions)
	}

	// Enqueue the initial transfer — fire-and-forget (no Wait, no Response). If
	// enqueue fails (channel full / context cancelled), the zone is registered
	// and persisted but no refresh is scheduled — it would be stuck in pending
	// with no AXFR. Surface that rather than reporting success; the zone is
	// reachable via list-dynamic and the operator can retry modify/delete.
	zr := ZoneRefresher{
		Name:          name,
		ZoneType:      in.Type,
		PrimariesConf: primariesConf,
		Primaries:     upstreams,
		ZoneStore:     MapZone,
		Options:       options,
	}
	if err := conf.enqueueRefresh(ctx, zr); err != nil {
		return "", fmt.Errorf("zone %s registered but failed to schedule initial transfer: %w", name, err)
	}

	return fmt.Sprintf("zone %s provisioning; poll list-dynamic for state", name), nil
}

// enqueueRefresh sends a ZoneRefresher to the refresh engine, returning an error
// if the send cannot complete (context cancelled or the channel stays full past
// the timeout) instead of silently dropping the request.
func (conf *Config) enqueueRefresh(ctx context.Context, zr ZoneRefresher) error {
	select {
	case conf.Internal.RefreshZoneCh <- zr:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("context cancelled while enqueuing refresh for %s: %w", zr.Name, ctx.Err())
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout enqueuing refresh for %s (refresh channel full)", zr.Name)
	}
}

// RemoveDynamicZone is the shared *delete* core. It refuses to delete a static
// or catalog-managed zone (guard on OptApiManagedZone), bumps the zone's
// generation counter so any in-flight refresh self-aborts at its pre-persist
// guard (B5b), removes it from the live map and the persisted config, and
// best-effort removes the persisted zone file.
func (conf *Config) RemoveDynamicZone(name string) (string, error) {
	name = dns.Fqdn(name)
	zd, exists := Zones.Get(name)
	if !exists {
		return "", fmt.Errorf("zone %s not found", name)
	}
	if !zd.Options[OptApiManagedZone] {
		return "", fmt.Errorf("zone %s is not API-managed and cannot be deleted here", name)
	}

	Zones.Remove(name)
	// Bump generation AFTER removing from the map so any refresh goroutine that
	// snapshotted the old generation fails the pre-persist guard (B5b) and does
	// not resurrect the files we are about to remove.
	zd.generation.Add(1)

	// Persist the removal. RemoveDynamicZoneFromConfig rewrites the whole file
	// from the live Zones map, so it MUST run after Zones.Remove (otherwise the
	// zone would be re-written back in). If the rewrite fails, surface it: the
	// zone is gone from memory but the stale config entry would resurrect it on
	// restart — that's a failed delete, not a success.
	if err := conf.RemoveDynamicZoneFromConfig(name); err != nil {
		return "", fmt.Errorf("zone %s removed from memory but failed to update dynamic config (will reappear on restart): %w", name, err)
	}
	// Best-effort remove the persisted zone file.
	if conf.DynamicZones.ZoneDirectory != "" {
		zoneFilePath := filepath.Join(conf.DynamicZones.ZoneDirectory, name+"zone")
		if err := os.Remove(zoneFilePath); err != nil && !os.IsNotExist(err) {
			lg.Warn("RemoveDynamicZone: failed to remove zone file", "zone", name, "path", zoneFilePath, "error", err)
		}
	}

	return fmt.Sprintf("zone %s deleted", name), nil
}

// ModifyDynamicZone is the shared *modify* core. Implemented as
// stale-old + build-new + replace (NOT in-place mutation) so the modify/refresh
// data race is gone by construction: the refresh reads the old zd.Upstreams
// without a lock, so the changed params live on a fresh ZoneData and the old one
// is only ever read by its now-doomed refresh. Scope: primary addr/key and
// options; store is fixed at map; rename is out of scope (= delete+add).
func (conf *Config) ModifyDynamicZone(ctx context.Context, in DynamicZoneInput) (string, error) {
	name := dns.Fqdn(in.Name)
	oldZd, exists := Zones.Get(name)
	if !exists {
		return "", fmt.Errorf("zone %s not found", name)
	}
	if !oldZd.Options[OptApiManagedZone] {
		return "", fmt.Errorf("zone %s is not API-managed and cannot be modified here", name)
	}
	for _, p := range in.Primaries {
		if p.Key != "" && p.Key != NOKEY {
			return "", fmt.Errorf("unknown primary key %q (only NOKEY is valid until TSIG keys are configured)", p.Key)
		}
	}

	// Resolve any new primaries up front, before mutating state, so a
	// zero-resolution modify is rejected cleanly with no side effects. When no
	// new primaries are supplied, carry the old as-written + resolved forward.
	primariesConf := oldZd.PrimariesConf
	upstreams := oldZd.Upstreams
	var modRes PrimaryResolveResult
	if len(in.Primaries) > 0 {
		modRes = resolvePrimaries(ctx, conf.Internal.ImrEngine, in.Primaries)
		if len(modRes.Resolved) == 0 {
			return "", fmt.Errorf("zone %s: no primary resolved to an address (unresolved: %v)", name, modRes.Unresolved)
		}
		primariesConf = clonePeerConfs(in.Primaries)
		upstreams = modRes.Resolved
	}

	// (1) Bump the old generation so any in-flight refresh on the captured
	// pointer self-aborts at its pre-persist guard (B5b).
	oldZd.generation.Add(1)

	// (2) Build a fresh ZoneData carrying the changed params; (3) replace.
	options := in.Options
	if options == nil {
		options = oldZd.Options
	} else {
		options[OptApiManagedZone] = true
	}
	newZd := &ZoneData{
		ZoneName:      name,
		ZoneType:      oldZd.ZoneType,
		ZoneStore:     MapZone,
		PrimariesConf: primariesConf,
		Upstreams:     upstreams,
		Logger:        log.Default(),
		Options:       options,
		Status:        ZoneStatusPending,
		Data:          core.NewCmap[OwnerData](),
		KeyDB:         conf.Internal.KeyDB,
	}
	Zones.Set(name, newZd)

	// (4) Overwrite the persisted entry. AddDynamicZoneToConfig rewrites the
	// whole file from the live Zones map, so it MUST run after Zones.Set (so the
	// rewrite includes the new params). On failure, surface it — the live zone
	// now has the new params but they would be lost on restart.
	if err := conf.AddDynamicZoneToConfig(newZd); err != nil {
		return "", fmt.Errorf("zone %s modified in memory but failed to persist (change will be lost on restart): %w", name, err)
	}
	// Partial resolution of the new primaries: served from what resolved, with
	// a visibility-only ConfigWarning naming the rest.
	if len(modRes.Unresolved) > 0 || len(modRes.KeyCollisions) > 0 {
		served := len(in.Primaries) - len(modRes.Unresolved)
		newZd.SetError(ConfigWarning, "serving from %d of %d primaries (unresolved: %v, key-collisions: %v)", served, len(in.Primaries), modRes.Unresolved, modRes.KeyCollisions)
	}
	// (5) Force a re-pull from the new upstream.
	zr := ZoneRefresher{
		Name:          name,
		ZoneType:      newZd.ZoneType,
		PrimariesConf: primariesConf,
		Primaries:     upstreams,
		ZoneStore:     MapZone,
		Options:       options,
		Force:         true,
	}
	if err := conf.enqueueRefresh(ctx, zr); err != nil {
		return "", fmt.Errorf("zone %s modified but failed to schedule refresh: %w", name, err)
	}

	return fmt.Sprintf("zone %s modified; poll list-dynamic for state", name), nil
}
