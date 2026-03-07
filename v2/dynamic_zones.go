/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Dynamic zone persistence support for catalog zones and catalog member zones
 */

package tdns

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
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
		zd.SetError(ConfigError, fmt.Sprintf("Failed to load zone file: %v", err))

		return false, 0, fmt.Errorf("zone file corrupted: %v", err)
	}

	// Clear any previous error state on successful load
	zd.SetError(NoError, "")

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

	// Future: check for other dynamic zone types
	// For now, only catalog zones and catalog members are supported

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

		// Log what we're loading
		if options[OptCatalogZone] {
			lg.Debug("enqueuing catalog zone for refresh", "zone", zoneName, "type", zconf.Type)
		} else if options[OptAutomaticZone] {
			lg.Debug("enqueuing auto-configured zone for refresh", "zone", zoneName, "type", zconf.Type, "catalog", zconf.SourceCatalog)
		} else {
			lg.Debug("enqueuing zone for refresh", "zone", zoneName, "type", zconf.Type)
		}

		// Create ZoneRefresher and enqueue to RefreshEngine (same as ParseZones does)
		zr := ZoneRefresher{
			Name:      zoneName,
			Force:     true, // Force refresh on startup to load from disk
			ZoneType:  zoneType,
			Primary:   zconf.Primary,
			ZoneStore: zoneStore,
			Notify:    zconf.Downstreams,
			Zonefile:  zconf.Zonefile,
			Options:   options,
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
				// Skip internal options that shouldn't be in config
				// OptAutomaticZone is an internal marker (via SourceCatalog field), not a config option
				if opt != OptDirty && opt != OptFrozen && opt != OptAutomaticZone {
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

	// Get primary/upstream
	primary := zd.Upstream
	if primary == "" && zd.ZoneType == Secondary {
		// Try to get from parent or other sources if available
		primary = zd.Parent
	}

	zconf := ZoneConf{
		Name:          zd.ZoneName,
		Zonefile:      zoneFilePath,
		Type:          typeStr,
		Store:         storeStr,
		Primary:       primary,
		Notify:        zd.Downstreams, // Notify addresses are stored in Downstreams
		Downstreams:   zd.Downstreams,
		OptionsStrs:   optionsStrs,
		SourceCatalog: zd.SourceCatalog,
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
