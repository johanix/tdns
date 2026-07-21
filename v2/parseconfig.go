/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	// "flag"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var lgConfig = Logger("config")

// Add near the top of the file with other vars
var Templates = make(map[string]ZoneConf)

// OrderedConfig preserves the order of configuration entries
type ConfigEntry struct {
	Key   string
	Value interface{}
}

// processConfigFile reads and processes a YAML config file and any included files.
// IMPORTANT: All includes must be specified as a single array at the top level of the config:
//
//	include:
//	  - file1.yaml
//	  - file2.yaml
//
//	# Rest of configuration...
//	stuff1: value1
//	stuff2: value2
//
// The older style of multiple separate 'include' statements throughout the file
// is not supported.
// Returns the processed config map and a list of all included file paths (absolute).
func processConfigFile(file string, baseDir string, depth int) (map[string]interface{}, []string, error) {
	if depth > 10 {
		return nil, nil, errors.New("maximum include depth exceeded (10 levels)")
	}

	// Read the file
	lgConfig.Debug("reading config file", "file", file)
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading file %s: %v", file, err)
	}

	// Parse YAML directly into a map
	var config map[string]interface{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		// On parse error, show context around the reported line to help diagnose
		// (e.g. tabs, wrong indentation, stray colons). Both log it (server-side
		// detail) AND fold it into the returned error so callers over RPC see it.
		errStr := err.Error()
		var lineNum int
		if idx := strings.Index(errStr, "line "); idx >= 0 {
			rest := errStr[idx+5:]
			end := 0
			for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
				end++
			}
			if end > 0 {
				fmt.Sscanf(rest[:end], "%d", &lineNum)
			}
		}
		var contextBuf strings.Builder
		if lineNum > 0 {
			lines := strings.Split(string(data), "\n")
			start := lineNum - 4
			if start < 0 {
				start = 0
			}
			end := lineNum + 2
			if end > len(lines) {
				end = len(lines)
			}
			lgConfig.Error("YAML parse error", "line", lineNum, "contextStart", start+1, "contextEnd", end)
			for i := start; i < end; i++ {
				line := lines[i]
				marker := "  "
				if i == lineNum-1 {
					marker = "> "
				}
				// Reveal tabs and other problematic chars for the failing line
				if i == lineNum-1 {
					reveal := strings.ReplaceAll(line, "\t", "\\t")
					reveal = strings.ReplaceAll(reveal, "\r", "\\r")
					if reveal != line {
						lgConfig.Error("context line", "num", i+1, "line", line, "raw", reveal)
						fmt.Fprintf(&contextBuf, "  %s%4d: %s\n", marker, i+1, reveal)
						continue
					}
					lgConfig.Error("context line", "num", i+1, "line", line)
				} else {
					lgConfig.Error("context line", "num", i+1, "line", line)
				}
				fmt.Fprintf(&contextBuf, "  %s%4d: %s\n", marker, i+1, line)
			}
		}
		lgConfig.Debug("error unmarshalling YAML to struct", "file", file)
		if Globals.Debug {
			fmt.Printf("Config that we failed to unmarshal:\n%s\n", string(data))
		}
		if contextBuf.Len() > 0 {
			return nil, nil, fmt.Errorf("error parsing YAML in %s: %v\n%s(tabs shown as \\t; '>' marks the reported line — actual mistake often on a previous line)", file, err, contextBuf.String())
		}
		return nil, nil, fmt.Errorf("error parsing YAML in %s: %v", file, err)
	}

	// Track included files
	includedFiles := make([]string, 0)

	// Handle includes if present
	if includes, ok := config["include"].([]interface{}); ok {
		delete(config, "include")
		for _, inc := range includes {
			if includeFile, ok := inc.(string); ok {
				var fullPath string
				if filepath.IsAbs(includeFile) {
					// If the included file path is absolute, use it as is
					fullPath = includeFile
				} else {
					// If the included file path is relative, join it with the base directory
					fullPath = filepath.Join(baseDir, includeFile)
				}
				fullPath = filepath.Clean(fullPath)
				includedFiles = append(includedFiles, fullPath)

				included, subIncluded, err := processConfigFile(fullPath, filepath.Dir(fullPath), depth+1)
				if err != nil {
					return nil, nil, err
				}

				// Merge included config
				for k, v := range included {
					if existing, exists := config[k]; exists {
						// If both are maps, merge them
						if existingMap, ok1 := existing.(map[string]interface{}); ok1 {
							if newMap, ok2 := v.(map[string]interface{}); ok2 {
								for k2, v2 := range newMap {
									existingMap[k2] = v2
								}
								continue
							}
						}
					}
					// Otherwise just override
					config[k] = v
				}

				// Add sub-included files to our list
				includedFiles = append(includedFiles, subIncluded...)
			}
		}
	}

	return config, includedFiles, nil
}

// deprecatedConfigKey describes a config key (or key fragment) that the
// code no longer reads, together with operator-facing migration advice.
// `match` is tested against each unused config key path reported by
// mapstructure (dotted, e.g. "dnssec.policies[fastroll].KSK.sigvalidity"):
//   - exact: the unused path equals match (use for top-level keys)
//   - else: match is treated as a substring (use ".suffix" forms to catch
//     a renamed leaf wherever it appears, e.g. ".sigvalidity")
type deprecatedConfigKey struct {
	match  string
	exact  bool
	advice string
	key    string // populated per-occurrence by classifyUnusedConfigKeys (the actual offending path)
}

// deprecatedConfigKeys is the registry of config keys removed or moved by
// past restructures. When the operator's config still uses one, the loader
// emits a specific migration error instead of a generic "unknown key"
// warning — turning a silent, system-wide breakage (e.g. every signed zone
// losing its policy) into a one-line "here is what to change."
//
// TEMPLATE — adding a new entry as the config evolves:
//   - Removed/renamed a TOP-LEVEL key (foo: → bar.foo:)? Add
//     {match: "foo", exact: true, advice: "`foo:` moved to `bar.foo:` (restructure YYYY-MM-DD)"}.
//   - Renamed/moved a LEAF that can appear under many parents
//     (x: → y: under each policy)? Add
//     {match: ".oldleaf", advice: "`oldleaf` moved to ...; see <doc>"}.
//     A non-exact entry is matched against the END of the unused path, so it
//     fires on the leaf itself and not on a valid block of the same name that
//     merely happens to contain a typo'd child.
//
// Keep advice concrete: name the new location and, ideally, the change date
// or doc so an operator can find the migration.
var deprecatedConfigKeys = []deprecatedConfigKey{
	// Config restructure 2026-06-16 (per-role KSK/ZSK algorithms + nesting):
	// the DNSSEC config moved under a single top-level `dnssec:` block.
	{match: "dnssecpolicies", exact: true,
		advice: "`dnssecpolicies:` moved under `dnssec:` as `dnssec.policies:` (restructure 2026-06-16)"},
	{match: "kasp", exact: true,
		advice: "`kasp:` moved under `dnssec:` as `dnssec.kasp:` (restructure 2026-06-16)"},
	{match: "large_algorithms", exact: true,
		advice: "`large_algorithms:` moved under `dnssec:` as `dnssec.large_algorithms:` (restructure 2026-06-16)"},
	{match: "split_algorithms", exact: true,
		advice: "`split_algorithms:` moved under `dnssec:` as `dnssec.split_algorithms:` (restructure 2026-06-16)"},
	// sigvalidity reshape: was a per-key scalar (ksk/zsk/csk: sigvalidity: X);
	// is now a policy-level subtree `sigvalidity: { default, dnskey, ds }`
	// with `default` required.
	{match: ".sigvalidity",
		advice: "per-key `sigvalidity:` is now a policy-level subtree `sigvalidity: { default, dnskey, ds }` (default required)"},
	{match: ".sig-validity",
		advice: "`sig-validity:` is spelled `sigvalidity:` and is a policy-level subtree `{ default, dnskey, ds }` (default required), not a key under ksk:/zsk:"},
	// Zone-level leaves whose misspelling silently disables the feature: an
	// unrecognized dnssec_policy/dnssec-policy leaves the zone with no policy,
	// which then rejects online-signing/inline-signing at validation.
	{match: ".dnssec_policy",
		advice: "zone key is `dnssecpolicy:` (one word, no underscore); `dnssec_policy:` is ignored, leaving the zone unsigned"},
	{match: ".dnssec-policy",
		advice: "zone key is `dnssecpolicy:` (one word, no hyphen); `dnssec-policy:` is ignored, leaving the zone unsigned"},
	{match: ".multi_signer",
		advice: "zone key is `multisigner:` (one word, no underscore); `multi_signer:` is ignored"},
}

// classifyUnusedConfigKeys splits mapstructure's unused-key list into keys
// that match a known deprecated shape (with migration advice) and keys that
// are merely unrecognized (likely typos). Case-insensitive on the path;
// mapstructure reports field paths in the Go struct's case (e.g. ".KSK.").
func classifyUnusedConfigKeys(unused []string) (deprecated []deprecatedConfigKey, unknown []string) {
	for _, key := range unused {
		lk := strings.ToLower(key)
		var hit *deprecatedConfigKey
		for i := range deprecatedConfigKeys {
			d := &deprecatedConfigKeys[i]
			ml := strings.ToLower(d.match)
			// A non-exact entry names a deprecated LEAF (".oldleaf") that may sit
			// under many parents, so it must match the END of the path. Matching
			// anywhere in the path would also fire on a valid parent block: a typo
			// inside the (valid) `sigvalidity:` subtree reports as
			// "dnssec.policies[p].SigValidity.defualt", which contains
			// ".sigvalidity" but is a misspelled `default`, not a deprecated key.
			if (d.exact && lk == ml) || (!d.exact && strings.HasSuffix(lk, ml)) {
				hit = d
				break
			}
		}
		if hit != nil {
			// Carry the actual key in a per-occurrence copy so the log line
			// names the offending path, not just the pattern.
			deprecated = append(deprecated, deprecatedConfigKey{key: key, advice: hit.advice})
		} else {
			unknown = append(unknown, key)
		}
	}
	return deprecated, unknown
}

func (conf *Config) ParseConfig(reload bool) error {
	lgConfig.Debug("entering ParseConfig")

	cfgfile := conf.Internal.CfgFile
	if cfgfile == "" {
		lgConfig.Warn("no config file specified, proceed at own risk")
		return nil
	}

	// Process the config file and all includes
	configMap, includedFiles, err := processConfigFile(cfgfile, filepath.Dir(cfgfile), 0)
	if err != nil {
		return fmt.Errorf("error processing config: %v", err)
	}

	// Configure mapstructure decoder to respect yaml tags. The decode hook
	// converts a bare-string primary:/notify: entry (the pre-migration shape)
	// into a PeerConf legacy marker instead of failing the whole-file decode —
	// per-zone validation then quarantines just that zone to ERROR. A custom
	// yaml.Unmarshaler does NOT work here: config decodes yaml -> map ->
	// mapstructure, and mapstructure ignores the yaml.Unmarshaler interface.
	var md mapstructure.Metadata
	decoderConfig := &mapstructure.DecoderConfig{
		TagName: "yaml",
		Result:  conf,
		// Replace, don't merge. Result is the long-lived conf, reused across
		// reloads, and ParseZones writes template-expanded options/policy back
		// into conf.Zones[i] (*zconf = updated). Without ZeroFields, a reload
		// merges the new zones list into the stale slice, so a zone whose YAML
		// omits a field silently inherits a former slot-neighbour's value —
		// e.g. a plain secondary gaining online-signing + a dnssecpolicy. It
		// also drops Templates/Policies deleted from the config. Absent keys are
		// still skipped, so runtime state in conf.Internal is untouched.
		ZeroFields: true,
		Metadata:   &md,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			stringToPeerConfHook(),
			stringToAclEntryHook(),
		),
	}
	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return fmt.Errorf("error creating decoder: %v", err)
	}

	// Set default for apiserver.usetls (default: true) before decoding
	// Check if usetls was explicitly set in the config by checking the raw map
	if apiserverMap, ok := configMap["apiserver"].(map[string]interface{}); ok {
		if _, explicitlySet := apiserverMap["usetls"]; !explicitlySet {
			// usetls was not explicitly set, set default to true in the map
			apiserverMap["usetls"] = true
		}
	}

	// Decode the entire config at once. A bare-string primary:/notify: entry no
	// longer aborts the decode — stringToPeerConfHook turns it into a PeerConf
	// legacy marker that per-zone validation quarantines (see DecoderConfig above).
	if err := decoder.Decode(configMap); err != nil {
		return fmt.Errorf("error decoding config: %v", err)
	}

	// Server-wide error registry: create once, preserve across reloads (so
	// boot-scoped Transport errors survive a reload). parseconfig owns the
	// Config/CertMissing check (clear-then-reassert on every load).
	if conf.Internal.ServerErrors == nil {
		conf.Internal.ServerErrors = NewServerErrorRegistry()
	}
	conf.validateDnsEngineCerts()

	if len(md.Unused) > 0 {
		// Split the unused keys into two buckets: keys that match a known
		// DEPRECATED/RENAMED config shape (the config lags the code — emit
		// a specific migration message), and genuinely unrecognized keys
		// (likely typos — the generic warning). A deprecated key carries a
		// real risk (e.g. a moved DNSSEC policy block silently disables
		// signing for every zone), so it gets a loud, actionable line of
		// its own rather than being buried in the generic list.
		deprecated, unknown := classifyUnusedConfigKeys(md.Unused)
		for _, d := range deprecated {
			lgConfig.Error("deprecated config key (config lags the code) — "+d.advice,
				"key", d.key)
		}
		if len(unknown) > 0 {
			lgConfig.Warn("unknown config keys ignored (possible misspellings)", "keys", unknown)
		}
	}

	// Parse the entire dnssec: block (large_algorithms, split_algorithms,
	// kasp, and the named policies) into conf.Internal.*. The zone-reload
	// paths call this same helper so reloading zones also refreshes the
	// policy definitions they depend on. ParseZones (later) validates zone
	// dnssec_policy references against the resolved map.
	if err := conf.parseDnssecConfig(); err != nil {
		return err
	}

	// Normalize service.transport.type (default: none)
	if conf.Service.Transport.Type == "" {
		conf.Service.Transport.Type = "none"
	} else {
		ts := strings.ToLower(conf.Service.Transport.Type)
		switch ts {
		case "svcb", "tsync", "none":
			conf.Service.Transport.Type = ts
		default:
			lgConfig.Warn("unknown service.transport.type, defaulting to none", "type", conf.Service.Transport.Type)
			conf.Service.Transport.Type = "none"
		}
	}

	lgConfig.Debug("templates defined", "count", len(conf.Templates))

	if err := conf.buildTemplateMap(); err != nil {
		return err
	}

	// log.Printf("*** ParseConfig: 1")
	// Set up viper with the same config for compatibility
	processedConfig, err := yaml.Marshal(configMap)
	if err != nil {
		return fmt.Errorf("error marshaling processed config: %v", err)
	}

	viper.SetConfigType("yaml")
	if err := viper.ReadConfig(strings.NewReader(string(processedConfig))); err != nil {
		return fmt.Errorf("error reading processed config: %v", err)
	}

	// Populate ConfigGroupConfig.Name from map keys after parsing CatalogConf
	if conf.Catalog != nil {
		if conf.Catalog.ConfigGroups != nil {
			for name, configGroup := range conf.Catalog.ConfigGroups {
				if configGroup != nil {
					configGroup.Name = name
				}
			}
		}
		// Also populate MetaGroups (deprecated) if present
		if conf.Catalog.MetaGroups != nil {
			for name, metaGroup := range conf.Catalog.MetaGroups {
				if metaGroup != nil {
					metaGroup.Name = name
				}
			}
		}
	}

	// Set default values for DynamicZonesConf if not configured
	conf.setDynamicZonesDefaults()

	// Handle backward compatibility migrations
	conf.migrateCatalogPolicyToDynamicZones()
	conf.migrateMetaGroupsToConfigGroups()

	// Validate group prefixes (required if config_groups or signing_groups are defined)
	if err := conf.validateGroupPrefixes(); err != nil {
		return err
	}

	// Validate dynamiczones configuration (check if configfile is included)
	conf.validateDynamicZonesConfig(includedFiles)

	if Globals.App.Type == AppTypeImr {
		conf.parseImrOptions()
	}

	switch Globals.App.Type {
	case AppTypeAuth, AppTypeAgent:
		conf.ParseAuthOptions()
	}

	// KDC and KRS configuration parsing has been moved to tdns-nm
	// See kdc.ParseKdcConfigFromFile() and krs.ParseKrsConfigFromFile()

	// On first start: build the KeyDB. On reload: keep the existing
	// KeyDB but re-apply outbound_soa_serial so a config edit takes
	// effect without a full restart.
	switch Globals.App.Type {
	case AppTypeAuth, AppTypeAgent:
		if !reload {
			err = conf.InitializeKeyDB()
			if err != nil {
				return err
			}
		} else if conf.Internal.KeyDB != nil {
			// Refresh the live KeyDB's options from the freshly-parsed config so
			// a reloaded option (e.g. minimal-responses) takes effect without a
			// restart. The KeyDB is built once at startup and reused across
			// reloads, but the query responder reads them — without this, reload
			// updated only conf.DnsEngine.Options (the presentation) while the
			// responder kept the stale startup map. SetOptions swaps the map
			// atomically, so the per-query lock-free readers are race-free.
			conf.Internal.KeyDB.SetOptions(conf.DnsEngine.Options)
			if err := applyOutboundSoaSerial(conf.Internal.KeyDB, conf.DnsEngine.OutboundSoaSerial); err != nil {
				return err
			}
		}
	}

	err = ValidateConfig(nil, conf.Internal.CfgFile) // will terminate on error
	if err != nil {
		return err
	}

	if Globals.App.Type == AppTypeAuth && len(conf.Service.Identities) > 0 {
		var transports []string
		for _, t := range conf.DnsEngine.Transports {
			t = strings.ToLower(t)
			switch t {
			case "do53", "dot", "doh", "doq":
				transports = append(transports, t)
			default:
				lgConfig.Error("unknown transport", "transport", t)
			}
		}
		// Add do53 if not already present
		if !slices.Contains(transports, "do53") {
			transports = append(transports, "do53")
		}

		transports = slices.Compact(transports)
		if len(transports) > 0 {
			alpn := []dns.SVCBKeyValue{
				&dns.SVCBAlpn{Alpn: transports},
			}
			Globals.ServerSVCB = &dns.SVCB{
				Priority: 1,
				Target:   dns.Fqdn(conf.Service.Identities[0]),
				Value:    alpn,
			}
		}
	}

	if hook := conf.Internal.PostParseConfigHook; hook != nil {
		if err := hook(conf, configMap); err != nil {
			return fmt.Errorf("PostParseConfigHook: %w", err)
		}
	}

	return nil
}

// KDC and KRS configuration parsing has been moved to tdns-nm
// See kdc.ParseKdcConfigFromFile() and krs.ParseKrsConfigFromFile()

func (conf *Config) InitializeKeyDB() error {
	// dbFile := viper.GetString("db.file")
	dbFile := strings.TrimSpace(conf.Db.File)
	// Hard fail if database file is unset (before filepath.Clean which would turn "" into ".")
	if dbFile == "" {
		return fmt.Errorf("db.file is required but not set (must be specified in config)")
	}
	// Ensure the database file path is within allowed boundaries
	dbFile = filepath.Clean(dbFile)
	if dbFile == "." {
		return fmt.Errorf("db.file is unset (got '.' from empty path); must specify a valid database file path")
	}
	if strings.Contains(dbFile, "..") {
		return errors.New("invalid database file path: must not contain directory traversal")
	}
	// M42: Check for symlinks in database path
	if info, err := os.Lstat(dbFile); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("database file path %q is a symlink (not allowed)", dbFile)
	}
	// Create DB file and parent directory if missing (auto-initialize on first run).
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		lgConfig.Info("TDNS DB file does not exist, creating", "file", dbFile)
		dir := filepath.Dir(dbFile)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("ParseConfig: failed to create DB directory %s: %v", dir, err)
		}
		if err := os.WriteFile(dbFile, nil, 0664); err != nil {
			return fmt.Errorf("ParseConfig: failed to create TDNS DB file %s: %v", dbFile, err)
		}
	}
	kdb, err := NewKeyDB(dbFile, false, conf.DnsEngine.Options)
	if err != nil {
		return fmt.Errorf("error from NewKeyDB: %v", err)
	}
	conf.Internal.KeyDB = kdb

	if err := applyOutboundSoaSerial(kdb, conf.DnsEngine.OutboundSoaSerial); err != nil {
		return err
	}

	return nil
}

// applyOutboundSoaSerial resolves the configured outbound_soa_serial mode
// onto the KeyDB and ensures the persist-mode table exists. Called from
// InitializeKeyDB on first start AND from the reload path in ParseConfig
// so a config edit that flips dnsengine.outbound_soa_serial takes effect
// without a full restart.
func applyOutboundSoaSerial(kdb *KeyDB, raw string) error {
	// Default to "keep" when unset. Validation (oneof=keep|unixtime|persist)
	// is enforced by the struct tag at config-validate time.
	mode := strings.TrimSpace(strings.ToLower(raw))
	if mode == "" {
		mode = OutboundSoaSerialKeep
	}
	kdb.OutboundSoaSerial = mode

	if mode == OutboundSoaSerialPersist {
		schema := DefaultTables["OutgoingSerials"]
		if _, err := kdb.DB.Exec(schema); err != nil {
			return fmt.Errorf("failed to create OutgoingSerials table: %w", err)
		}
	}
	return nil
}

// func ParseZones(zones map[string]tdns.ZoneConf, zrch chan tdns.ZoneRefresher) error {
//
// Returns (allZones, brokenZones, err). allZones lists zones whose
// config parsed cleanly and were queued for refresh. brokenZones lists
// zones whose config had a fatal error; these are still registered in
// the Zones map with the error attached so they remain visible to the
// zone-list API and survive reload-diffs, but are not sent to the
// RefreshEngine.
func (conf *Config) ParseZones(ctx context.Context, reload bool) ([]string, []string, error) {
	if len(conf.Zones) == 0 {
		lgConfig.Info("no authoritative zones defined")
		return nil, nil, nil
	}

	lgConfig.Debug("parsing authoritative zones", "count", len(conf.Zones))
	var all_zones []string
	var broken_zones []string

	// Process each zone configuration
	for i := range conf.Zones {
		zconf := &conf.Zones[i]
		zname := dns.Fqdn(zconf.Name)
		zconf.Name = zname

		// Get-or-create the registry entry up front so SetError calls
		// during validation attach to the actual zone object, not a
		// throwaway stack value. On reload, clear any prior error so a
		// previously-broken zone can become healthy without restart.
		zd, exists := Zones.Get(zname)
		if !exists {
			zd = &ZoneData{
				ZoneName:      zname,
				Logger:        log.Default(),
				FirstZoneLoad: true,
			}
			Zones.Set(zname, zd)
		}
		zd.Zonefile = zconf.Zonefile
		if zd.Error {
			zd.SetError(NoError, "")
		}

		// M46: Validate zone name length (DNS max is 255 octets)
		if len(zname) > 255 {
			lgConfig.Error("zone name too long, ignoring", "zone", zname)
			zd.SetError(ConfigError, "zone name too long: %q", zname)
			broken_zones = append(broken_zones, zname)
			continue
		}

		if strings.Contains(zconf.Name, "..") || strings.Contains(zconf.Name, "//") {
			lgConfig.Error("zone name contains invalid characters, ignoring", "zone", zconf.Name)
			zd.SetError(ConfigError, "zone name contains invalid characters: %q", zconf.Name)
			broken_zones = append(broken_zones, zname)
			continue
		}

		// Handle template expansion if specified
		if zconf.Template != "" {
			if tmpl, exist := Templates[zconf.Template]; exist {
				updated, err := ExpandTemplate(*zconf, &tmpl, Globals.App.Type)
				if err != nil {
					lgConfig.Error("template expansion failed, zone in error state", "zone", zname, "template", zconf.Template, "err", err)
					zd.SetError(ConfigError, "template expansion error: %q: %v", zconf.Template, err)
					broken_zones = append(broken_zones, zname)
					continue
				}
				*zconf = updated
			} else {
				lgConfig.Error("zone refers to undefined template, zone in error state", "zone", zname, "template", zconf.Template)
				zd.SetError(ConfigError, "template %q does not exist", zconf.Template)
				broken_zones = append(broken_zones, zname)
				continue
			}
		}

		zonestore := parseZoneStore(zconf.Store)

		var zonetype ZoneType
		// resolvedPrimaries holds the addr:port tuples for a secondary zone's
		// upstreams, resolved (hostnames -> addresses) at parse time. nil for
		// primary zones. Carried to the ZoneRefresher build below.
		var resolvedPrimaries []PeerConf

		switch strings.ToLower(zconf.Type) {
		case "primary":
			zonetype = Primary
			_ = append([]string{}, zname) // primary_zones was unused
		case "secondary":
			zonetype = Secondary
			if len(zconf.Primaries) == 0 {
				lgConfig.Error("secondary zone has no primary configured, zone in error state", "zone", zname)
				zd.SetError(ConfigError, "secondary zone but has no primary (upstream) configured")
				broken_zones = append(broken_zones, zname)
				continue
			}
			secondaryOK := true
			for i := range zconf.Primaries {
				p := &zconf.Primaries[i]
				if p.Legacy != "" {
					lgConfig.Error("secondary zone uses legacy bare-string primary, zone in error state", "zone", zname, "primary", p.Legacy)
					zd.SetError(ConfigError, "primary now requires {addr, key} (got bare string %q)", p.Legacy)
					secondaryOK = false
					break
				}
				if p.Addr == "" {
					lgConfig.Error("secondary zone primary has no address, zone in error state", "zone", zname)
					zd.SetError(ConfigError, "secondary zone but has no primary (upstream) configured")
					secondaryOK = false
					break
				}
				if p.Key == "" {
					lgConfig.Error("secondary zone primary has no key, zone in error state", "zone", zname)
					zd.SetError(ConfigError, "primary requires an explicit key (use key: NOKEY for no TSIG)")
					secondaryOK = false
					break
				}
				if !conf.tsigKeyDefined(p.Key) {
					lgConfig.Error("secondary zone primary references unknown key, zone in error state", "zone", zname, "key", p.Key)
					zd.SetError(ConfigError, "unknown primary key %q (define it in keys.tsig or keystore tsig, or use NOKEY for no TSIG)", p.Key)
					secondaryOK = false
					break
				}
				origPrimary := p.Addr
				p.Addr = NormalizeAddress(p.Addr)
				if origPrimary != p.Addr {
					lgConfig.Warn("primary has no port specified, using default :53", "zone", zname, "primary", origPrimary)
				}
			}
			if !secondaryOK {
				broken_zones = append(broken_zones, zname)
				continue
			}

			// Resolve the as-written primaries to addr:port tuples (hostnames
			// -> addresses via the IMR), re-resolved on every parse/reload.
			// Zero resolved -> ConfigError (quarantine); partial -> ConfigWarning
			// (serve from the rest). A prior parse's ConfigWarning was already
			// cleared by the SetError(NoError) reset at the top of the loop.
			res := resolvePrimaries(ctx, conf.Internal.ImrEngine, zconf.Primaries)
			if len(res.Resolved) == 0 {
				// D1: an unresolved hostname primary at parse time is NOT fatal.
				// The zone is created and the refresh engine re-resolves on every
				// cycle, so a transient failure (or an IMR not yet up at boot)
				// self-heals instead of permanently quarantining the zone. It
				// serves nothing until a primary resolves, surfacing as a refresh
				// error rather than a config quarantine.
				lgConfig.Warn("secondary zone: no primary resolved yet, will retry at refresh", "zone", zname, "unresolved", res.Unresolved)
				zd.SetError(ConfigWarning, "no primary resolved yet (unresolved: %v); retrying at refresh", res.Unresolved)
			} else if len(res.Unresolved) > 0 || len(res.KeyCollisions) > 0 {
				// Count resolved addresses actually usable for transfer — not
				// entries-minus-unresolved, which over-counts when a key
				// collision drops an otherwise-resolved address.
				served := len(res.Resolved)
				lgConfig.Warn("secondary zone: some primaries unavailable, serving from the rest", "zone", zname, "unresolved", res.Unresolved, "key_collisions", res.KeyCollisions, "resolved_upstreams", served, "configured_primaries", len(zconf.Primaries))
				zd.SetError(ConfigWarning, "serving from %d resolved upstream(s) of %d configured primaries (unresolved: %v, key-collisions: %v)", served, len(zconf.Primaries), res.Unresolved, res.KeyCollisions)
			}
			resolvedPrimaries = res.Resolved

		default:
			lgConfig.Error("unknown zone type, zone in error state", "zone", zname, "type", zconf.Type)
			zd.SetError(ConfigError, "unknown zone type: %s", zconf.Type)
			broken_zones = append(broken_zones, zname)
			continue
		}

		// Legacy bare-string notify: entries (the decode hook recorded each as a
		// Legacy marker) quarantine the zone, mirroring the primary check —
		// otherwise an empty-Addr PeerConf silently drops that notify target.
		legacyNotify := false
		for _, n := range zconf.Notify {
			if n.Legacy != "" {
				lgConfig.Error("zone uses legacy bare-string notify entry, zone in error state", "zone", zname, "notify", n.Legacy)
				zd.SetError(ConfigError, "notify now requires {addr, key} (got bare string %q)", n.Legacy)
				legacyNotify = true
				break
			}
		}
		if legacyNotify {
			broken_zones = append(broken_zones, zname)
			continue
		}

		// allow-notify: / downstreams: ACL validation — every ip-spec must parse
		// and every key must be NOKEY, BLOCKED, or a defined keys.tsig name.
		// A bad ACL quarantines just this zone (same rule as the primary check).
		if err := ValidateACL(zconf.AllowNotify, conf.tsigKeyDefined); err != nil {
			lgConfig.Error("zone allow-notify ACL invalid, zone in error state", "zone", zname, "err", err)
			zd.SetError(ConfigError, "allow-notify: %v", err)
			broken_zones = append(broken_zones, zname)
			continue
		}
		if err := ValidateACL(zconf.Downstreams, conf.tsigKeyDefined); err != nil {
			lgConfig.Error("zone downstreams ACL invalid, zone in error state", "zone", zname, "err", err)
			zd.SetError(ConfigError, "downstreams: %v", err)
			broken_zones = append(broken_zones, zname)
			continue
		}

		publishCadence, err := parsePublishCadence(zconf.PublishCadence)
		if err != nil {
			lgConfig.Error("zone publish-cadence invalid, zone in error state", "zone", zname, "err", err)
			zd.SetError(ConfigError, "publish-cadence: %v", err)
			broken_zones = append(broken_zones, zname)
			continue
		}

		lgConfig.Debug("checking DNSSEC policy", "zone", zname)
		// dump.P(zconf)

		if zconf.DnssecPolicy == "none" {
			lgConfig.Info("DNSSEC policy is none, zone will not be signed", "zone", zname)
			zconf.DnssecPolicy = ""
		}
		if zconf.DnssecPolicy != "" {
			polName := zconf.DnssecPolicy
			usable, errMsg := resolveZonePolicyRef(polName, conf.Internal.DnssecPolicies)
			if errMsg != "" {
				lgConfig.Error("zone DNSSEC policy unusable, zone will not be signed", "zone", zname, "policy", polName, "err", errMsg)
				zconf.DnssecPolicy = ""
				zd.SetError(DnssecError, "%s", errMsg)
			} else if usable {
				lgConfig.Info("DNSSEC policy accepted", "zone", zname, "policy", polName)
			}
		}

		options := parseZoneOptions(conf, zname, zconf, zd)
		var outopts []string
		for o, val := range options {
			if val {
				outopts = append(outopts, ZoneOptionToString[o])
			}
		}
		lgConfig.Debug("zone outgoing options", "zone", zname, "options", outopts)

		lgConfig.Info("zone configuration", "zone", zname, "type", zconf.Type, "store", zconf.Store, "primaries", zconf.Primaries, "notify", zconf.Notify, "zonefile", zconf.Zonefile)

		lgConfig.Debug("zone incoming update policy", "zone", zname, "policy", fmt.Sprintf("%+v", zconf.UpdatePolicy))

		switch zconf.UpdatePolicy.Child.Type {
		case "selfsub", "self":
			// all ok, we know these
		case "none", "":
			// these are also ok, but imply that no updates are allowed
			options[OptAllowChildUpdates] = false
		default:
			lgConfig.Error("zone has unknown child update policy type, zone in error state", "zone", zname, "type", zconf.UpdatePolicy.Child.Type)
			zd.SetError(ConfigError, "unknown child update policy type: %s", zconf.UpdatePolicy.Child.Type)
			broken_zones = append(broken_zones, zname)
			continue
		}

		// A zone that accepts child updates MUST have a delegation backend.
		// Without one, the write path mutates in-memory zone data while the
		// scanner read path queries the (nil) backend, so diff computation
		// always sees "empty current state" and child updates accumulate
		// without ever being removed. Refuse to start such a zone rather
		// than letting it silently misbehave.
		if options[OptAllowChildUpdates] && zconf.DelegationBackend == "" {
			lgConfig.Error("zone has 'allow-child-updates' but no 'delegationbackend' configured, zone in error state", "zone", zname)
			zd.SetError(ConfigError, "allow-child-updates requires delegationbackend to be configured (e.g. 'delegationbackend: direct')")
			broken_zones = append(broken_zones, zname)
			continue
		}

		switch zconf.UpdatePolicy.Zone.Type {
		case "selfsub", "self":
			// all ok, we know these
		case "none", "":
			// these are also ok, but imply that no updates are allowed
			options[OptAllowUpdates] = false
		default:
			lgConfig.Error("zone has unknown update policy type, zone in error state", "zone", zname, "type", zconf.UpdatePolicy.Zone.Type)
			zd.SetError(ConfigError, "unknown update policy type: %s", zconf.UpdatePolicy.Zone.Type)
			broken_zones = append(broken_zones, zname)
			continue
		}

		// log.Printf("*** ParseZones: 2")
		var rrt uint16
		var exist bool
		childrrtypes := map[uint16]bool{}
		for _, rrtype := range zconf.UpdatePolicy.Child.RRtypes {
			rrtype = strings.ToUpper(rrtype)
			if rrt, exist = dns.StringToType[rrtype]; exist {
				childrrtypes[rrt] = true
			}
		}

		// log.Printf("*** ParseZones: 3")
		zonerrtypes := map[uint16]bool{}
		for _, rrtype := range zconf.UpdatePolicy.Zone.RRtypes {
			rrtype = strings.ToUpper(rrtype)
			if rrt, exist = dns.StringToType[rrtype]; exist {
				zonerrtypes[rrt] = true
			}
		}

		// log.Printf("*** ParseZones: 4")
		childTTL := zconf.UpdatePolicy.Child.TTL
		if childTTL == 0 {
			childTTL = 120
		}
		zoneTTL := zconf.UpdatePolicy.Zone.TTL
		if zoneTTL == 0 {
			zoneTTL = 120
		}
		policy := UpdatePolicy{
			Child: UpdatePolicyDetail{
				Type:         zconf.UpdatePolicy.Child.Type,
				RRtypes:      childrrtypes,
				KeyBootstrap: zconf.UpdatePolicy.Child.KeyBootstrap,
				KeyUpload:    zconf.UpdatePolicy.Child.KeyUpload,
				TTL:          childTTL,
			},
			Zone: UpdatePolicyDetail{
				Type:    zconf.UpdatePolicy.Zone.Type,
				RRtypes: zonerrtypes,
				TTL:     zoneTTL,
			},
		}

		if Globals.App.Type == AppTypeAgent && zconf.Type == "primary" {
			// tdns-agent doesn't serve primary zones. MP roles are
			// hosted by tdns-mp (tdns-mpagent etc.), not by standalone
			// tdns-agent. A primary zone in a tdns-agent config is a
			// configuration error.
			lgConfig.Error("tdns-agent does not support primary zones, zone in error state", "zone", zname)
			zd.SetError(ConfigError, "tdns-agent does not support primary zones; use tdns-mpagent for multi-provider roles")
			broken_zones = append(broken_zones, zname)
			continue
		}

		// log.Printf("*** ParseZones: 5. Refreshch: %v", conf.Internal.RefreshZoneCh)

		// Validate this zone's configuration
		var zones = make(map[string]interface{}, 1)
		zones["zone:"+zname] = zconf
		if errmsg, err := ValidateBySection(conf, zones, "foobar"); err != nil {
			lgConfig.Error("zone validation failed, zone in error state", "zone", zname, "detail", errmsg)
			zd.SetError(ConfigError, "config validation: %v", err)
			broken_zones = append(broken_zones, zname)
			continue
		}

		all_zones = append(all_zones, zname)

		// The registry entry (zd) was created up front; rebind to zdp
		// here for the remaining post-parse setup that uses zdp.
		zdp := zd

		// Apply static options via copy-on-write to avoid racing with
		// concurrent readers of zdp.Options / zdp.MP.MPdata.Options.
		// Build from fresh parsed options only; on reload this clears
		// options that were removed from the config file.
		newOpts := make(map[ZoneOption]bool, len(options))
		for opt, val := range options {
			newOpts[opt] = val
		}

		zdp.mu.Lock()
		zdp.Options = newOpts
		zdp.publishCadence = publishCadence
		zdp.mu.Unlock()

		invokeOptionHandlers(zname, options)

		// Wire the delegation backend synchronously on every parse pass
		// (initial load + reload). Backend constructors don't touch zone
		// data, so this works before FirstZoneLoad has completed.
		// Config validation above guarantees that OptAllowChildUpdates
		// implies a non-empty zconf.DelegationBackend.
		if options[OptAllowChildUpdates] {
			kdb := conf.Internal.KeyDB
			if kdb == nil {
				lgConfig.Error("KeyDB unavailable, cannot wire delegation backend", "zone", zname)
				zd.SetError(ConfigError, "KeyDB unavailable")
				broken_zones = append(broken_zones, zname)
				continue
			}
			backend, err := LookupDelegationBackend(zconf.DelegationBackend, kdb, zdp)
			if err != nil {
				lgConfig.Error("failed to create delegation backend, zone in error state", "zone", zname, "backend", zconf.DelegationBackend, "error", err)
				zd.SetError(ConfigError, "delegationbackend %q: %v", zconf.DelegationBackend, err)
				broken_zones = append(broken_zones, zname)
				continue
			}
			zdp.mu.Lock()
			zdp.DelegationBackend = backend
			zdp.mu.Unlock()
			lgConfig.Info("delegation backend wired", "zone", zname, "backend", backend.Name())
		} else {
			// Reload may have cleared OptAllowChildUpdates; drop any
			// previously-wired backend so the live state matches config.
			zdp.mu.Lock()
			zdp.DelegationBackend = nil
			zdp.mu.Unlock()
		}

		lgConfig.Info("evaluating zone option flags", "zone", zname,
			"online-signing", options[OptOnlineSigning],
			"inline-signing", options[OptInlineSigning],
			"multi-provider", options[OptMultiProvider],
			"firstLoad", zdp.FirstZoneLoad,
			"apptype", AppTypeToString[Globals.App.Type])

		// Condition checks are evaluated on every parse pass (initial +
		// reload) so config-reload picks up flag changes. The setup
		// functions need the zone to be loaded; on initial load we defer
		// via OnFirstLoad, on reload (zone already loaded) we call them
		// directly. The setup functions are idempotent.

		// Signing setup: zones with explicit signing options in config.
		//
		// First load: sign once the zone data is available (deferred via
		// OnFirstLoad). Reload: we deliberately do NOT sign synchronously here.
		// A synchronous SignZone on the reload branch ran under confMu (held
		// across ParseZones by ReloadZoneConfig), serializing every signed
		// zone's signing behind the global config lock (Finding 4). It was also
		// redundant: the config-bearing forced refresh queued for every zone at
		// the end of this loop already re-signs off-lock in the RefreshEngine —
		// triggerResign() when the policy rebinds (see applyReloadedPolicyLocked
		// in refreshengine.go) and the post-refresh SetupZoneSigning when the
		// zone data changed. Both run in the refresh path, not under confMu.
		if options[OptOnlineSigning] || options[OptInlineSigning] {
			if zdp.FirstZoneLoad {
				zdp.OnFirstLoad = append(zdp.OnFirstLoad, func(zd *ZoneData) {
					if err := zd.SetupZoneSigning(conf.Internal.ResignQ); err != nil {
						lgConfig.Error("SetupZoneSigning failed in OnFirstLoad", "zone", zd.ZoneName, "error", err)
					}
				})
			}
		}

		// Sig-validity floor: config-load check on every parse pass so
		// policy/kasp edits on reload refresh DnssecError/Warning state.
		if options[OptOnlineSigning] || options[OptInlineSigning] {
			if zdp.DnssecPolicy != nil {
				UpdateSigValidityFloor(zdp, zdp.DnssecPolicy, conf.KaspPropagationDelay(), 0, false, conf.IsLargeAlgorithm, false)
			}
		}

		// Rollover policy validation: requires loaded zone data. Only
		// registered on first load; the ObserveParentDSTTL goroutine it
		// spawns is long-running and re-spawning on reload would leak.
		// (See follow-up: make rollover setup reload-safe.)
		if zdp.FirstZoneLoad {
			zdp.OnFirstLoad = append(zdp.OnFirstLoad, func(zd *ZoneData) {
				if zd.DnssecPolicy == nil || zd.DnssecPolicy.Rollover.Method == RolloverMethodNone {
					return
				}
				EvaluateRolloverPolicyInvariants(zd, zd.DnssecPolicy)
				// Use the ParseZones ctx so the parent-DS observation
				// goroutine cancels on daemon shutdown.
				go ObserveParentDSTTL(ctx, zd, zd.DnssecPolicy)
			})
		}

		// Delegation sync setup: DSYNC publication (parent) or
		// delegation sync monitoring (child), or proxy forwarding for a
		// DSYNC-unaware primary (agent secondary).
		if options[OptDelSyncParent] || options[OptDelSyncChild] || options[OptDelSyncProxy] {
			capturedOpts := options
			setupSync := func(zd *ZoneData) {
				// Skip if the MP HSYNCPARAM callback already set up delegation sync for this zone.
				if zd.Options[OptDelSyncChild] && !capturedOpts[OptDelSyncChild] {
					return
				}
				if zd.Options[OptDelSyncParent] && !capturedOpts[OptDelSyncParent] {
					return
				}
				delegationSyncQ := conf.Internal.DelegationSyncQ
				if delegationSyncQ == nil {
					lgConfig.Error("DelegationSyncQ not available", "zone", zd.ZoneName)
					return
				}
				if err := zd.SetupZoneSync(delegationSyncQ); err != nil {
					lgConfig.Error("SetupZoneSync failed", "zone", zd.ZoneName, "error", err)
				}
			}
			if zdp.FirstZoneLoad {
				zdp.OnFirstLoad = append(zdp.OnFirstLoad, setupSync)
			} else {
				setupSync(zdp)
			}
		}

		// delegation-sync-proxy: register the post-transfer change-detection
		// hook so an agent secondary forwards NOTIFY(CDS/CSYNC) to the parent
		// when a relevant RRset changes in an incoming transfer. The hook is an
		// OnZonePreRefresh callback (it needs both old and new zone data to
		// diff) that records what changed in zd.ProxyRefreshAnalysis; the
		// matching OnZonePostRefresh callback acts on it (P-3). Mirrors the
		// tdns-mp MPPreRefresh/PostRefresh pattern (tdns-mp/v2/config.go), for
		// the non-MP agent path.
		// Register only on first load: on reload zdp is the existing registry
		// entry and its OnZone*Refresh slices already carry these hooks, so
		// appending again would accumulate duplicates (same convention as the
		// OnFirstLoad-guarded setupSync block above).
		if options[OptDelSyncProxy] && zdp.FirstZoneLoad {
			delegationSyncQ := conf.Internal.DelegationSyncQ
			zdp.OnZonePreRefresh = append(zdp.OnZonePreRefresh,
				func(zd, new_zd *ZoneData) {
					zd.ProxyDelegationPreRefresh(new_zd)
				})
			zdp.OnZonePostRefresh = append(zdp.OnZonePostRefresh,
				func(zd *ZoneData) {
					zd.ProxyDelegationPostRefresh(delegationSyncQ)
				})
		}

		// Note: DelegationBackend wiring is done synchronously above,
		// outside the FirstZoneLoad guard, so config-reload picks up
		// changes to the 'delegationbackend' key.

		// Republish-at-signal-names consumer (RFC 9615 at-NS bootstrap):
		// every tdns-auth SECONDARY watches incoming transfers for an apex
		// HSYNCPARAM pubkey/pubcds flag and republishes the customer's apex
		// KEY / CDS(+CDNSKEY) under the _sig0key/_dsboot signal names owned
		// by each NS, into whichever local primary zone the signal name
		// falls in. Always-on, no option gate (see signal_republish.go).
		// Registered only on first load (the OnZonePostRefresh slice would
		// otherwise accumulate duplicate callbacks across reloads).
		if Globals.App.Type == AppTypeAuth && zonetype == Secondary && zdp.FirstZoneLoad {
			zdp.OnZonePostRefresh = append(zdp.OnZonePostRefresh, func(zd *ZoneData) {
				zd.RepublishAtSignalNames()
			})
		}

		// Leader election OnFirstLoad is registered in StartAgent() (not here)
		// because LeaderElectionManager doesn't exist until StartAgent runs.
		// MP zone KEY publication is registered in tdns-mp's StartAgent.

		// Non-zone-serving app types skip zone refresh. Everything
		// else (Auth, Agent, downstream MP/NM/ES roles) queues each
		// parsed zone for refresh.
		switch Globals.App.Type {
		case AppTypeImr, AppTypeCli, AppTypeReporter, AppTypeScanner, AppTypeKdc, AppTypeKrs, AppTypeEdgeSigner:
			// skip — these app types don't serve zones
		default:
			if conf.Internal.RefreshZoneCh == nil {
				lgConfig.Error("refresh channel is not configured, zones will not be refreshed, terminating")
				return nil, nil, errors.New("parseZones: error: refresh channel is not configured, zones will not be refreshed, terminating")
			}
			zr := ZoneRefresher{
				Name:          zname,
				Force:         true,     // force refresh, ignoring SOA serial, when reloading from file
				ZoneType:      zonetype, // primary | secondary
				PrimariesConf: clonePeerConfs(zconf.Primaries),
				Primaries:     resolvedPrimaries,
				ZoneStore:     zonestore,
				Notify:        zconf.Notify,
				AllowNotify:   zconf.AllowNotify,
				Downstreams:   zconf.Downstreams,
				ConfigUpdate:  true, // config-bearing: lets reload clear removed ACLs
				Zonefile:      zconf.Zonefile,
				Options:       options,
				UpdatePolicy:  policy,
				DnssecPolicy:  zconf.DnssecPolicy,
			}
			select {
			case conf.Internal.RefreshZoneCh <- zr:
			case <-ctx.Done():
				return all_zones, broken_zones, ctx.Err()
			}
		}
	}

	lgConfig.Info("zones parsed and refreshing", "count", len(all_zones), "zones", all_zones, "broken", broken_zones, "queued", len(conf.Internal.RefreshZoneCh))

	lgConfig.Debug("ParseZones complete")
	return all_zones, broken_zones, nil
}

// ExpandTemplate applies template tmpl's settings to zone zconf. Every config
// field the template SETS is copied to the zone UNLESS the zone already set it
// (the zone always wins), so new ZoneConf config fields are propagated
// automatically without editing this function. Three fields need bespoke
// handling and are excluded from the generic copy: Zonefile (%-substituted with
// the zone name), OptionsStrs (unioned, not gap-filled) and DnssecPolicy (gated
// off for agents). Name and Template are never copied from a template. Runtime/
// display fields (Error, Frozen, RefreshCount, Provisioning, …) are never set in
// a template config, so the zero-value check skips them naturally.
func ExpandTemplate(zconf ZoneConf, tmpl *ZoneConf, appMode AppType) (ZoneConf, error) {
	// --- bespoke fields (cannot be a plain gap-fill copy) ---

	// Zonefile: the template carries a pattern that is %-substituted with the
	// zone name, not copied verbatim.
	if zconf.Zonefile == "" && tmpl.Zonefile != "" {
		if strings.ContainsAny(zconf.Name, "%") {
			return zconf, fmt.Errorf("zone name %q contains format specifiers", zconf.Name)
		}
		expanded := filepath.Clean(fmt.Sprintf(tmpl.Zonefile, zconf.Name))
		if strings.Contains(expanded, "..") {
			return zconf, fmt.Errorf("expanded zonefile path %q contains directory traversal", expanded)
		}
		zconf.Zonefile = expanded
	}

	// OptionsStrs: union (append template options the zone lacks), not gap-fill.
	for _, option := range tmpl.OptionsStrs {
		if !slices.Contains(zconf.OptionsStrs, option) {
			zconf.OptionsStrs = append(zconf.OptionsStrs, option)
		}
	}

	// DnssecPolicy: gap-fill, but agents do not sign so it is gated off there.
	if appMode != AppTypeAgent && zconf.DnssecPolicy == "" && tmpl.DnssecPolicy != "" {
		zconf.DnssecPolicy = tmpl.DnssecPolicy
	}

	// --- generic gap-fill for every other config field (zone wins) ---
	// Shallow (deep=false): zones have no nested config block that wants a
	// recursive merge — UpdatePolicy is copied whole if the zone left it unset.
	// A template config never sets runtime/display fields, so IsZero skips them.
	bespoke := map[string]bool{
		"Name": true, "Template": true, // never copied from a template
		"Zonefile": true, "OptionsStrs": true, "DnssecPolicy": true, // handled above
	}
	gapFillStruct(reflect.ValueOf(&zconf).Elem(), reflect.ValueOf(tmpl).Elem(), bespoke, false)
	return zconf, nil
}

// gapFillStruct fills fields of dst that are still at their zero value from the
// matching field of src; dst always wins. dst and src must be addressable
// structs of the same type. skip names top-level fields that are never copied.
//
// When deep is false a struct-typed field is treated as a single value (copied
// whole only if dst's is entirely zero). When deep is true a struct-typed field
// is merged recursively, so dst can set part of a nested block and inherit the
// rest from src. Slices are cloned so dst never aliases src's backing array.
//
// Caveat (both modes): a leaf counts as "set" iff it is non-zero, so dst cannot
// override an src value back to the zero value ("" / 0 / false / nil) — that
// reads as unset and src fills it.
func gapFillStruct(dst, src reflect.Value, skip map[string]bool, deep bool) {
	for i := 0; i < dst.NumField(); i++ {
		if skip[dst.Type().Field(i).Name] {
			continue
		}
		df, sf := dst.Field(i), src.Field(i)
		if !df.CanSet() {
			continue
		}
		if deep && df.Kind() == reflect.Struct {
			gapFillStruct(df, sf, nil, deep) // skip set applies only at the top level
			continue
		}
		if !df.IsZero() || sf.IsZero() {
			continue // dst already set it, or src has nothing to give
		}
		if df.Kind() == reflect.Slice {
			c := reflect.MakeSlice(df.Type(), sf.Len(), sf.Len())
			reflect.Copy(c, sf)
			df.Set(c)
		} else {
			df.Set(sf)
		}
	}
}

// ExpandPolicyTemplate fills the gaps in a DNSSEC policy from a named template
// (the policy's own values win). Unlike zone templates it deep-merges: a policy
// that sets only some fields of a nested block (ksk, zsk, rollover, ttls,
// sigvalidity, clamping, ...) inherits the remaining fields of that block from
// the template, rather than overriding the whole block.
func ExpandPolicyTemplate(pconf DnssecPolicyConf, tmpl *DnssecPolicyConf) DnssecPolicyConf {
	skip := map[string]bool{"Name": true, "Template": true}
	gapFillStruct(reflect.ValueOf(&pconf).Elem(), reflect.ValueOf(tmpl).Elem(), skip, true)
	return pconf
}

// resolveDnssecPolicyTemplate applies a policy's `template:` reference (if any)
// by deep-merging the named template into dp (the policy's own values win).
// Returns the possibly-expanded policy, or an error if the referenced template
// is unknown. Shared by the runtime config parse and the standalone
// `policy validate --file` path so the two cannot drift.
func resolveDnssecPolicyTemplate(dp DnssecPolicyConf, templates map[string]DnssecPolicyConf) (DnssecPolicyConf, error) {
	if dp.Template == "" {
		return dp, nil
	}
	tmpl, ok := templates[dp.Template]
	if !ok {
		return dp, fmt.Errorf("references unknown dnssec template %q", dp.Template)
	}
	return ExpandPolicyTemplate(dp, &tmpl), nil
}

// buildTemplateMap rebuilds the global Templates map from conf.Templates.
// Called from ParseConfig() and reloadTemplatesFromFile().
func (conf *Config) buildTemplateMap() error {
	if Globals.App.Type == AppTypeReporter || Globals.App.Type == AppTypeImr {
		return nil
	}

	// Build template map
	Templates = make(map[string]ZoneConf) // Clear existing entries on reload
	for _, tmpl := range conf.Templates {
		if tmpl.Name == "" {
			return fmt.Errorf("template missing required 'name' field")
		}
		if _, exists := Templates[tmpl.Name]; exists {
			return fmt.Errorf("duplicate template name: %s", tmpl.Name)
		}
		Templates[tmpl.Name] = tmpl
	}

	// Handle template expansion if specified
	// Robust expansion with cycle detection
	var done = make(map[string]bool)
	for _, t := range conf.Templates {
		if _, ok := Templates[t.Name]; !ok {
			continue
		}
		_, _ = expandTemplateChain(t.Name, []string{}, make(map[string]bool), done, Globals.App.Type)
	}

	lgConfig.Debug("buildTemplateMap complete", "count", len(Templates))
	return nil
}

// reloadTemplatesFromFile re-reads the config file and rebuilds the Templates map.
// Used by ReloadZoneConfig() to pick up template changes without a full config reload.
func (conf *Config) reloadTemplatesFromFile() error {
	cfgfile := conf.Internal.CfgFile
	if cfgfile == "" {
		return nil
	}

	configMap, _, err := processConfigFile(cfgfile, filepath.Dir(cfgfile), 0)
	if err != nil {
		return fmt.Errorf("error processing config: %v", err)
	}

	// Decode only the templates from the config
	// Note: TagName:"yaml" means mapstructure reads yaml struct tags
	var partial struct {
		Templates []ZoneConf `yaml:"templates"`
	}
	decoderConfig := &mapstructure.DecoderConfig{
		TagName: "yaml",
		Result:  &partial,
	}
	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return fmt.Errorf("error creating decoder: %v", err)
	}
	if err := decoder.Decode(configMap); err != nil {
		return fmt.Errorf("error decoding templates: %v", err)
	}

	conf.Templates = partial.Templates
	return conf.buildTemplateMap()
}

// reloadDnssecFromFile re-reads the config file, decodes just the dnssec:
// block into conf.Dnssec, and re-parses it into conf.Internal.*. Used by the
// zone-reload paths so an edited policy (or other dnssec setting) is picked up
// without a full config reload — parseDnssecConfig alone would re-parse the
// already-decoded (startup) conf.Dnssec, missing the operator's edits. Mirrors
// reloadTemplatesFromFile.
func (conf *Config) reloadDnssecFromFile() error {
	cfgfile := conf.Internal.CfgFile
	if cfgfile == "" {
		// No config file (e.g. embedded use) — just re-parse what we have.
		return conf.parseDnssecConfig()
	}

	configMap, _, err := processConfigFile(cfgfile, filepath.Dir(cfgfile), 0)
	if err != nil {
		return fmt.Errorf("error processing config: %v", err)
	}

	var partial struct {
		Dnssec DnssecConf `yaml:"dnssec"`
	}
	decoderConfig := &mapstructure.DecoderConfig{
		TagName: "yaml",
		Result:  &partial,
	}
	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return fmt.Errorf("error creating decoder: %v", err)
	}
	if err := decoder.Decode(configMap); err != nil {
		return fmt.Errorf("error decoding dnssec config: %v", err)
	}

	conf.Dnssec = partial.Dnssec
	return conf.parseDnssecConfig()
}

// reloadZonesFromFile re-reads the config file(s), decodes just the zones: block,
// and replaces conf.Zones. Used by the zone-reload path (ReloadZoneConfig) so a
// config-file edit to the ZONE set — an added or removed zone, or a changed
// dnssecpolicy/primaries/ACLs/options/zonefile — is picked up by a single
// `reload-zones`, not only policy-definition edits. Without this, ParseZones
// iterates the stale startup conf.Zones (the longstanding "must get the zones
// config file from outside" gap in ReloadZoneConfig), so zone edits needed a
// restart. Uses the SAME decode hooks + ZeroFields as the full ParseConfig so a
// legacy bare-string primary:/notify: entry decodes to a PeerConf legacy marker
// (quarantined per-zone) instead of failing the whole decode, and so a zone whose
// YAML omits a field does not inherit a stale slot-neighbour's value.
func (conf *Config) reloadZonesFromFile() error {
	cfgfile := conf.Internal.CfgFile
	if cfgfile == "" {
		// No config file (e.g. embedded use) — keep the in-memory zone set.
		return nil
	}

	configMap, _, err := processConfigFile(cfgfile, filepath.Dir(cfgfile), 0)
	if err != nil {
		return fmt.Errorf("error processing config: %v", err)
	}

	var partial struct {
		Zones []ZoneConf `yaml:"zones"`
	}
	decoderConfig := &mapstructure.DecoderConfig{
		TagName:    "yaml",
		Result:     &partial,
		ZeroFields: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			stringToPeerConfHook(),
			stringToAclEntryHook(),
		),
	}
	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return fmt.Errorf("error creating decoder: %v", err)
	}
	if err := decoder.Decode(configMap); err != nil {
		return fmt.Errorf("error decoding zones config: %v", err)
	}

	conf.Zones = partial.Zones
	return nil
}

// reloadTsigKeysFromFile re-reads the config file and decodes just the keys:
// block into conf.Keys. Used by reload-tsig without a full config reload.
func (conf *Config) reloadTsigKeysFromFile() error {
	cfgfile := conf.Internal.CfgFile
	if cfgfile == "" {
		return nil
	}

	configMap, _, err := processConfigFile(cfgfile, filepath.Dir(cfgfile), 0)
	if err != nil {
		return fmt.Errorf("error processing config: %v", err)
	}

	var partial struct {
		Keys KeyConf `yaml:"keys"`
	}
	decoderConfig := &mapstructure.DecoderConfig{
		TagName: "yaml",
		Result:  &partial,
	}
	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return fmt.Errorf("error creating decoder: %v", err)
	}
	if err := decoder.Decode(configMap); err != nil {
		return fmt.Errorf("error decoding keys config: %v", err)
	}

	conf.Keys = partial.Keys
	return nil
}

// expandTemplateChain expands a template by following its parent chain (via the Template field)
// using DFS with cycle detection. It updates the global Templates map with the fully expanded
// template on success. If a cycle is detected, all templates in the cycle are removed from the
// Templates map and an error is returned. Missing parent references also remove the referring
// template.
func expandTemplateChain(name string, stack []string, onStack map[string]bool, done map[string]bool, appMode AppType) (ZoneConf, error) {
	if done[name] {
		return Templates[name], nil
	}
	t, exists := Templates[name]
	if !exists {
		return ZoneConf{}, fmt.Errorf("expandTemplateChain: template %q not found", name)
	}

	if onStack[name] {
		// Cycle detected: find cycle in stack
		var cycle []string
		for i := range stack {
			if stack[i] == name {
				cycle = append([]string{}, stack[i:]...)
				break
			}
		}
		cycle = append(cycle, name)
		lgConfig.Error("template cycle detected", "cycle", strings.Join(cycle, " -> "))
		for _, n := range cycle {
			delete(Templates, n)
		}
		return ZoneConf{}, fmt.Errorf("template cycle: %s", strings.Join(cycle, " -> "))
	}

	onStack[name] = true
	stack = append(stack, name)

	if t.Template != "" && t.Template != name {
		parent, exists := Templates[t.Template]
		if !exists {
			lgConfig.Warn("template refers to non-existing template, ignored", "template", t.Name, "parent", t.Template)
			delete(Templates, t.Name)
			onStack[name] = false
			return ZoneConf{}, fmt.Errorf("missing parent template %q for %q", t.Template, t.Name)
		}
		// Recurse to expand parent first
		expandedParent, err := expandTemplateChain(parent.Name, stack, onStack, done, appMode)
		if err != nil {
			onStack[name] = false
			return ZoneConf{}, err
		}
		// Apply parent's fields into child
		expandedChild, err := ExpandTemplate(t, &expandedParent, appMode)
		if err != nil {
			lgConfig.Error("error expanding template from parent", "template", t.Name, "parent", t.Template, "err", err)
			delete(Templates, t.Name)
			onStack[name] = false
			return ZoneConf{}, err
		}
		t = expandedChild
	} else if t.Template == name {
		// Self-cycle
		lgConfig.Error("self-referential template cycle, removing", "template", name)
		delete(Templates, name)
		onStack[name] = false
		return ZoneConf{}, fmt.Errorf("self-referential template %q", name)
	}

	// Mark done and store expanded result
	done[name] = true
	onStack[name] = false
	Templates[name] = t
	return t, nil
}

// parseDnssecConfig resolves the entire dnssec: block (large_algorithms,
// split_algorithms, kasp, and the named policies) from conf.Dnssec into the
// derived conf.Internal.* structures. Called from ParseConfig at startup, and
// from the zone-reload paths so that reloading zones also refreshes the policy
// definitions they depend on (closing the "reload policies before zones" gap).
//
// Rebuilds conf.Internal.DnssecPolicies from scratch every call: on reload,
// removed or rejected policies must not survive from the previous parse. A
// policy that fails to parse is kept in the map with its Error field set
// (visible to the operator; zones referencing it are quarantined), rather than
// dropped — the server still starts.
func (conf *Config) parseDnssecConfig() error {
	if err := validateKaspPropagationDelay(conf.Dnssec.Kasp.PropagationDelay); err != nil {
		return err
	}
	largeAlgs, err := buildLargeAlgorithmSet(conf.Dnssec.LargeAlgorithms)
	if err != nil {
		return err
	}
	conf.Internal.LargeAlgorithms = largeAlgs
	conf.Internal.SplitAlgorithms = buildSplitAlgorithmSet(conf.Dnssec.SplitAlgorithms)
	mode, err := resolveCompletenessMode(conf.Dnssec.Completeness)
	if err != nil {
		return err
	}
	conf.Internal.Completeness = mode

	conf.Internal.DnssecPolicies = make(map[string]DnssecPolicy)
	for name, dp := range conf.Dnssec.Policies {
		dpLocal := dp
		// markBroken records a rejected policy in the map (Name + Error) so it
		// stays visible to the operator and zones referencing it can be
		// quarantined with a reason. The server still starts.
		markBroken := func(reason string) {
			lgConfig.Error("DNSSEC policy rejected, unusable", "policy", name, "err", reason)
			conf.Internal.DnssecPolicies[name] = DnssecPolicy{Name: name, Error: reason}
		}
		// A policy may inherit the gaps in its definition from a named template
		// (deep merge; the policy's own values win). An unknown template name
		// quarantines just this policy and keeps the server running.
		expanded, terr := resolveDnssecPolicyTemplate(dpLocal, conf.Dnssec.Templates)
		if terr != nil {
			markBroken(terr.Error())
			continue
		}
		dpLocal = expanded
		alg, kskAlg, zskAlg, err := resolvePolicyRoleAlgorithms(name, &dpLocal)
		if err != nil {
			markBroken(err.Error())
			continue
		}
		if err := validateSplitAlgorithm(name, kskAlg, zskAlg, conf.Internal.SplitAlgorithms); err != nil {
			markBroken(err.Error())
			continue
		}
		if err := validateRoleCapabilities(name, kskAlg, zskAlg); err != nil {
			markBroken(err.Error())
			continue
		}
		kskLT, err := GenKeyLifetime(dpLocal.KSK.Lifetime)
		if err != nil {
			markBroken(fmt.Sprintf("ksk.lifetime: %v", err))
			continue
		}
		zskLT, err := GenKeyLifetime(dpLocal.ZSK.Lifetime)
		if err != nil {
			markBroken(fmt.Sprintf("zsk.lifetime: %v", err))
			continue
		}
		cskLT, err := GenKeyLifetime(dpLocal.CSK.Lifetime)
		if err != nil {
			markBroken(fmt.Sprintf("csk.lifetime: %v", err))
			continue
		}
		tmp := DnssecPolicy{
			Name:         name,
			Algorithm:    alg,
			KSKAlgorithm: kskAlg,
			ZSKAlgorithm: zskAlg,
			KSK:          kskLT,
			ZSK:          zskLT,
			CSK:          cskLT,
		}
		if err := FinishDnssecPolicy(name, &dpLocal, &tmp); err != nil {
			markBroken(err.Error())
			continue
		}
		conf.Internal.DnssecPolicies[name] = tmp
	}
	// If no "default" policy in config, use built-in default (e.g. for agent autozone).
	// An explicit dnssec.policies.default in YAML overrides this. A broken
	// "default" stays broken (it is in the map with Error set, so "exists" is
	// true): we surface the operator's error rather than silently substituting
	// the builtin. Zones referencing it are quarantined with the reason.
	if _, exists := conf.Internal.DnssecPolicies["default"]; !exists {
		conf.Internal.DnssecPolicies["default"] = BuiltinDefaultDnssecPolicy()
	}
	return nil
}

// resolveZonePolicyRef decides whether a zone's named DNSSEC policy is usable.
// It returns (usable, errMsg): usable is true only for a healthy policy;
// errMsg is a quarantine reason (empty when usable). The three cases are kept
// distinct so the operator can tell a typo (policy does not exist) from a
// genuinely broken policy (defined but rejected at parse).
func resolveZonePolicyRef(polName string, policies map[string]DnssecPolicy) (usable bool, errMsg string) {
	pol, exist := policies[polName]
	switch {
	case !exist:
		return false, fmt.Sprintf("DNSSEC policy %q does not exist", polName)
	case pol.Error != "":
		return false, fmt.Sprintf("configured DNSSEC policy %q is broken: %s", polName, pol.Error)
	default:
		return true, ""
	}
}

// builtinDefaultDnssecPolicy returns the built-in "default" DNSSEC policy used when
// no dnssec.policies.default is defined in config (e.g. for agent autozone). An explicit
// dnssec.policies.default in YAML overrides this. No automatic key rollovers.
func BuiltinDefaultDnssecPolicy() DnssecPolicy {
	const day = 24 * time.Hour
	kskLT, err := GenKeyLifetime("forever")
	if err != nil {
		panic(err)
	}
	zskLT, err := GenKeyLifetime("forever")
	if err != nil {
		panic(err)
	}
	cskLT, err := GenKeyLifetime("none")
	if err != nil {
		panic(err)
	}
	return DnssecPolicy{
		Name:         "default",
		Algorithm:    dns.ED25519,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		Mode:         DnssecPolicyModeKSKZSK,
		KSK:          kskLT,
		ZSK:          zskLT,
		CSK:          cskLT,
		SigValidity: PolicySigValidity{
			Default: uint32((14 * day).Seconds()),
			DNSKEY:  uint32((30 * day).Seconds()),
			DS:      uint32((14 * day).Seconds()),
		},
	}
}

func GenKeyLifetime(lifetime string) (KeyLifetime, error) {
	var lifetime_secs time.Duration
	var err error

	switch lifetime {
	case "forever":
		lifetime_secs = time.Duration(10000) * time.Hour

	case "", "none":
		lifetime_secs = time.Duration(0)

	default:
		lifetime_secs, err = parseExtendedDuration(lifetime)
		if err != nil {
			return KeyLifetime{}, fmt.Errorf("invalid key lifetime %q: %w", lifetime, err)
		}
	}
	return KeyLifetime{
		Lifetime: uint32(lifetime_secs.Seconds()),
	}, nil
}

// NormalizeAddress ensures an address has a port number.
// If the address doesn't have a port, ":53" is appended.
// This allows users to specify addresses as either "IP" or "IP:port" in config.
// Returns empty string if input is empty.
func NormalizeAddress(addr string) string {
	if addr == "" {
		return ""
	}

	// Try to split host and port
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		// If SplitHostPort fails, it means no port is present
		// Add default DNS port :53
		return net.JoinHostPort(addr, "53")
	}
	// Address already has a port, use as-is
	return addr
}

// stringToPeerConfHook returns a mapstructure decode hook that converts a
// bare-string value (the legacy primary:/notify: shape) into a PeerConf carrying
// a Legacy marker, instead of letting mapstructure fail the whole-file decode on
// the string->struct type mismatch. mapstructure applies the hook element-wise
// for []PeerConf, so a bare-string entry inside a notify: list is handled too.
// Per-zone validation later sees a non-empty Legacy and quarantines that zone.
func stringToPeerConfHook() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		if from.Kind() != reflect.String || to != reflect.TypeOf(PeerConf{}) {
			return data, nil
		}
		return PeerConf{Legacy: data.(string)}, nil
	}
}

// stringToAclEntryHook is the AclEntry analogue of stringToPeerConfHook: it turns
// a legacy bare-string allow-notify:/downstreams: value into an AclEntry carrying
// a Legacy marker (applied element-wise across the []AclEntry list), so a
// pre-{prefix,key} list quarantines just that zone (ValidateACL rejects the
// marker) instead of failing the whole-file decode on the string->struct
// mismatch.
func stringToAclEntryHook() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		if from.Kind() != reflect.String || to != reflect.TypeOf(AclEntry{}) {
			return data, nil
		}
		return AclEntry{Legacy: data.(string)}, nil
	}
}

// NormalizeAddresses ensures all addresses have a port number.
// If an address doesn't have a port, ":53" is appended.
// This allows users to specify addresses as either "IP" or "IP:port" in config.
func NormalizeAddresses(addresses []string) []string {
	if len(addresses) == 0 {
		return addresses
	}

	normalized := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		normalized = append(normalized, NormalizeAddress(addr))
	}
	return normalized
}

// normalizePeerAddrs returns a copy of peers with each .Addr run through
// NormalizeAddress (ensuring a port). The Key and Legacy fields are preserved.
func normalizePeerAddrs(peers []PeerConf) []PeerConf {
	if len(peers) == 0 {
		return peers
	}
	normalized := make([]PeerConf, 0, len(peers))
	for _, p := range peers {
		p.Addr = NormalizeAddress(p.Addr)
		normalized = append(normalized, p)
	}
	return normalized
}

// peerAddrs extracts the .Addr value from each PeerConf into a []string.
func peerAddrs(peers []PeerConf) []string {
	if len(peers) == 0 {
		return nil
	}
	addrs := make([]string, 0, len(peers))
	for _, p := range peers {
		addrs = append(addrs, p.Addr)
	}
	return addrs
}

// setDynamicZonesDefaults sets default values for DynamicZonesConf if not configured
func (conf *Config) setDynamicZonesDefaults() {
	// Default: catalog zones allowed, memory storage
	if conf.DynamicZones.CatalogZones.Storage == "" {
		conf.DynamicZones.CatalogZones.Storage = "memory"
	}
	if !conf.DynamicZones.CatalogZones.Allowed {
		// Default to true if not explicitly set (zero value is false, but we want true as default)
		// Check if it was explicitly set by checking if any dynamiczones config exists
		// For now, default to true
		conf.DynamicZones.CatalogZones.Allowed = true
	}

	// Default: catalog members allowed, memory storage, manual add/remove
	if conf.DynamicZones.CatalogMembers.Storage == "" {
		conf.DynamicZones.CatalogMembers.Storage = "memory"
	}
	if !conf.DynamicZones.CatalogMembers.Allowed {
		// Default to true if not explicitly set
		conf.DynamicZones.CatalogMembers.Allowed = true
	}
	if conf.DynamicZones.CatalogMembers.Add == "" {
		conf.DynamicZones.CatalogMembers.Add = "manual"
	}
	if conf.DynamicZones.CatalogMembers.Remove == "" {
		conf.DynamicZones.CatalogMembers.Remove = "manual"
	}

	// Default: dynamic zones not allowed, memory storage
	if conf.DynamicZones.Dynamic.Storage == "" {
		conf.DynamicZones.Dynamic.Storage = "memory"
	}
	// Dynamic zones default to not allowed (false is correct default)
}

// migrateCatalogPolicyToDynamicZones handles backward compatibility by migrating
// catalog.policy.zones.add/remove to dynamiczones.catalog_members.add/remove
func (conf *Config) migrateCatalogPolicyToDynamicZones() {
	if conf.Catalog == nil {
		return
	}
	// If catalog.policy.zones.add is set but dynamiczones.catalog_members.add is not,
	// migrate the value
	if conf.Catalog.Policy.Zones.Add != "" && conf.DynamicZones.CatalogMembers.Add == "" {
		conf.DynamicZones.CatalogMembers.Add = conf.Catalog.Policy.Zones.Add
		lgConfig.Warn("catalog.policy.zones.add is deprecated, use dynamiczones.catalog_members.add instead", "migratedValue", conf.Catalog.Policy.Zones.Add)
	}

	// If catalog.policy.zones.remove is set but dynamiczones.catalog_members.remove is not,
	// migrate the value
	if conf.Catalog.Policy.Zones.Remove != "" && conf.DynamicZones.CatalogMembers.Remove == "" {
		conf.DynamicZones.CatalogMembers.Remove = conf.Catalog.Policy.Zones.Remove
		lgConfig.Warn("catalog.policy.zones.remove is deprecated, use dynamiczones.catalog_members.remove instead", "migratedValue", conf.Catalog.Policy.Zones.Remove)
	}
}

// migrateMetaGroupsToConfigGroups handles backward compatibility by migrating
// catalog.meta_groups to catalog.config_groups
func (conf *Config) migrateMetaGroupsToConfigGroups() {
	if conf.Catalog == nil {
		return
	}
	// If meta_groups is set but config_groups is empty, migrate
	if len(conf.Catalog.MetaGroups) > 0 && len(conf.Catalog.ConfigGroups) == 0 {
		conf.Catalog.ConfigGroups = conf.Catalog.MetaGroups
		lgConfig.Warn("catalog.meta_groups is deprecated, use catalog.config_groups instead", "migratedGroups", len(conf.Catalog.MetaGroups))
		// Clear meta_groups after migration
		conf.Catalog.MetaGroups = nil
	}
}

// validateDynamicZonesConfig validates dynamiczones configuration
// Checks if configfile is included in the include list (warns if not)
func (conf *Config) validateDynamicZonesConfig(includedFiles []string) {
	if conf.DynamicZones.ConfigFile == "" {
		return // No dynamic config file configured, nothing to validate
	}

	// Check if configfile path is absolute
	if !filepath.IsAbs(conf.DynamicZones.ConfigFile) {
		lgConfig.Warn("dynamiczones.configfile must be an absolute path", "path", conf.DynamicZones.ConfigFile)
		return
	}

	// Check if zone directory path is absolute
	if conf.DynamicZones.ZoneDirectory != "" && !filepath.IsAbs(conf.DynamicZones.ZoneDirectory) {
		lgConfig.Warn("dynamiczones.zonedirectory must be an absolute path", "path", conf.DynamicZones.ZoneDirectory)
	}

	// Check if the configfile is in the include list
	conf.CheckDynamicConfigFileIncluded(includedFiles)
}

// validateGroupPrefixes validates catalog.group_prefixes configuration
func (conf *Config) validateGroupPrefixes() error {
	if conf.Catalog == nil {
		return nil
	}
	// Check if config_groups or signing_groups are defined
	hasConfigGroups := len(conf.Catalog.ConfigGroups) > 0
	hasSigningGroups := len(conf.Catalog.SigningGroups) > 0

	if !hasConfigGroups && !hasSigningGroups {
		// No groups defined, no need to validate prefixes
		return nil
	}

	// If groups are defined, group_prefixes is REQUIRED
	if conf.Catalog.GroupPrefixes.Config == "" || conf.Catalog.GroupPrefixes.Signing == "" {
		return fmt.Errorf("catalog.group_prefixes is REQUIRED when catalog.config_groups or catalog.signing_groups are configured.\n" +
			"Please add:\n" +
			"  catalog:\n" +
			"    group_prefixes:\n" +
			"      config: \"config\"    # or \"config_\" or \"none\"\n" +
			"      signing: \"sign\"     # or \"sign_\" or \"none\"")
	}

	// Validate config prefix
	if conf.Catalog.GroupPrefixes.Config != "none" {
		if err := validateGroupPrefix(conf.Catalog.GroupPrefixes.Config, "config"); err != nil {
			return fmt.Errorf("invalid catalog.group_prefixes.config: %w", err)
		}
	}

	// Validate signing prefix
	if conf.Catalog.GroupPrefixes.Signing != "none" {
		if err := validateGroupPrefix(conf.Catalog.GroupPrefixes.Signing, "signing"); err != nil {
			return fmt.Errorf("invalid catalog.group_prefixes.signing: %w", err)
		}
	}

	// Check for prefix conflicts (if both are not "none")
	if conf.Catalog.GroupPrefixes.Config != "none" && conf.Catalog.GroupPrefixes.Signing != "none" {
		// Check for exact equality
		if conf.Catalog.GroupPrefixes.Config == conf.Catalog.GroupPrefixes.Signing {
			return fmt.Errorf("catalog.group_prefixes.config and catalog.group_prefixes.signing must be different (both are: %q)", conf.Catalog.GroupPrefixes.Config)
		}

		// Check for substring/prefix conflicts to prevent misclassification
		// e.g., "config" and "config_" would cause issues as one is a prefix of the other
		if strings.HasPrefix(conf.Catalog.GroupPrefixes.Config, conf.Catalog.GroupPrefixes.Signing) {
			return fmt.Errorf("catalog.group_prefixes.config (%q) cannot start with catalog.group_prefixes.signing (%q) - this would cause misclassification in group detection",
				conf.Catalog.GroupPrefixes.Config, conf.Catalog.GroupPrefixes.Signing)
		}
		if strings.HasPrefix(conf.Catalog.GroupPrefixes.Signing, conf.Catalog.GroupPrefixes.Config) {
			return fmt.Errorf("catalog.group_prefixes.signing (%q) cannot start with catalog.group_prefixes.config (%q) - this would cause misclassification in group detection",
				conf.Catalog.GroupPrefixes.Signing, conf.Catalog.GroupPrefixes.Config)
		}
	}

	return nil
}

// validateGroupPrefix validates a single group prefix value
func validateGroupPrefix(prefix string, prefixType string) error {
	// Check length (must leave room for group name in DNS label - max 63 chars)
	if len(prefix) > 50 {
		return fmt.Errorf("%s prefix too long (%d chars), max 50 chars to leave room for group names", prefixType, len(prefix))
	}

	// Check for valid DNS label characters
	// Valid: letters, digits, hyphens (but not at start/end)
	for i, ch := range prefix {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_') {
			return fmt.Errorf("%s prefix contains invalid character at position %d: %q (only letters, digits, hyphens, and underscores allowed)", prefixType, i, ch)
		}
	}

	// Check prefix doesn't start or end with hyphen
	if len(prefix) > 0 && (prefix[0] == '-' || prefix[len(prefix)-1] == '-') {
		return fmt.Errorf("%s prefix cannot start or end with hyphen", prefixType)
	}

	return nil
}
