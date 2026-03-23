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
	"slices"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
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
		// (e.g. tabs, wrong indentation, stray colons)
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
				// Reveal tabs and other problematic chars for the failing line
				if i == lineNum-1 {
					reveal := strings.ReplaceAll(line, "\t", "\\t")
					reveal = strings.ReplaceAll(reveal, "\r", "\\r")
					if reveal != line {
						lgConfig.Error("context line", "num", i+1, "line", line, "raw", reveal)
					} else {
						lgConfig.Error("context line", "num", i+1, "line", line)
					}
				} else {
					lgConfig.Error("context line", "num", i+1, "line", line)
				}
			}
		}
		lgConfig.Debug("error unmarshalling YAML to struct", "file", file)
		if Globals.Debug {
			fmt.Printf("Config that we failed to unmarshal:\n%s\n", string(data))
		}
		return nil, nil, fmt.Errorf("error parsing YAML: %v", err)
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

	// Configure mapstructure decoder to respect yaml tags
	var md mapstructure.Metadata
	decoderConfig := &mapstructure.DecoderConfig{
		TagName:  "yaml",
		Result:   conf,
		Metadata: &md,
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

	// Decode the entire config at once
	if err := decoder.Decode(configMap); err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "'Primary'") && strings.Contains(errMsg, "[]interface") {
			return fmt.Errorf("error decoding config: %v\nHint: 'primary' must be a single address string (e.g., primary: \"10.4.0.4:8055\"), not a YAML list", err)
		}
		return fmt.Errorf("error decoding config: %v", err)
	}

	if len(md.Unused) > 0 {
		lgConfig.Warn("unknown config keys ignored (possible misspellings)", "keys", md.Unused)
	}

	// Normalize all identity fields (domain names) from config to FQDN form.
	// Config files may omit trailing dots; wire protocol always uses FQDN.
	conf.normalizeConfigIdentities()

	// Validate multi-provider.role matches the application type
	if conf.MultiProvider != nil {
		expectedRole := map[AppType]string{
			AppTypeAuth:     "signer",
			AppTypeCombiner: "combiner",
			AppTypeAgent:    "agent",
		}
		if expected, ok := expectedRole[Globals.App.Type]; ok {
			if conf.MultiProvider.Role != expected {
				return fmt.Errorf("multi-provider.role=%q does not match app type %s (expected %q)",
					conf.MultiProvider.Role, Globals.App.Name, expected)
			}
		}
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

	// Initialize DnssecPolicies if needed
	switch Globals.App.Type {
	case AppTypeAuth, AppTypeAgent:
		if conf.Internal.DnssecPolicies == nil {
			conf.Internal.DnssecPolicies = make(map[string]DnssecPolicy)
		}

		for name, dp := range conf.DnssecPolicies {
			tmp := DnssecPolicy{
				Name:      name,
				Algorithm: dns.StringToAlgorithm[strings.ToUpper(dp.Algorithm)],
				KSK:       GenKeyLifetime(dp.KSK.Lifetime, dp.KSK.SigValidity),
				ZSK:       GenKeyLifetime(dp.ZSK.Lifetime, dp.ZSK.SigValidity),
				CSK:       GenKeyLifetime(dp.CSK.Lifetime, dp.CSK.SigValidity),
			}
			if tmp.Algorithm == 0 {
				lgConfig.Error("DNSSEC policy has unknown algorithm, ignored", "policy", name, "algorithm", dp.Algorithm)
				continue
			}
			conf.Internal.DnssecPolicies[name] = tmp
		}

		// If no "default" policy in config, use built-in default (e.g. for agent autozone).
		// An explicit dnssecpolicies.default in YAML overrides this.
		if _, exists := conf.Internal.DnssecPolicies["default"]; !exists {
			conf.Internal.DnssecPolicies["default"] = builtinDefaultDnssecPolicy()
		}
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
	case AppTypeAuth, AppTypeAgent, AppTypeCombiner:
		conf.parseAuthOptions()
	}

	conf.parseMultiProviderOptions()

	// KDC and KRS configuration parsing has been moved to tdns-nm
	// See kdc.ParseKdcConfigFromFile() and krs.ParseKrsConfigFromFile()

	// XXX: Hmm. Should not initialize KeyDB on reload?
	switch Globals.App.Type {
	case AppTypeAuth, AppTypeAgent, AppTypeCombiner:
		if !reload { // || kdb == nil {
			err = conf.InitializeKeyDB()
			if err != nil {
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
	switch Globals.App.Type {
	case AppTypeAuth, AppTypeAgent, AppTypeCombiner, AppTypeScanner:

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

		// Ensure OutgoingSerials table exists for persist-outbound-serial option
		if kdb.Options[AuthOptPersistOutboundSerial] != "" {
			schema := HsyncTables["OutgoingSerials"]
			if _, err := kdb.DB.Exec(schema); err != nil {
				return fmt.Errorf("failed to create OutgoingSerials table: %w", err)
			}
		}

	default:
		// do nothing for tdns-imr, tdns-cli
	}
	return nil
}

// func ParseZones(zones map[string]tdns.ZoneConf, zrch chan tdns.ZoneRefresher) error {
func (conf *Config) ParseZones(ctx context.Context, reload bool) ([]string, error) {
	if len(conf.Zones) == 0 {
		lgConfig.Info("no authoritative zones defined")
		return nil, nil
	}

	lgConfig.Debug("parsing authoritative zones", "count", len(conf.Zones))
	var all_zones []string

	// Process each zone configuration
	for i := range conf.Zones {
		zconf := &conf.Zones[i]
		zname := dns.Fqdn(zconf.Name)
		zconf.Name = zname

		zd := ZoneData{
			ZoneName: zname,
			Zonefile: zconf.Zonefile,
		}

		// M46: Validate zone name length (DNS max is 255 octets)
		if len(zname) > 255 {
			lgConfig.Error("zone name too long, ignoring", "zone", zname)
			zd.SetError(ConfigError, "zone name too long: %q", zname)
			continue
		}

		if strings.Contains(zconf.Name, "..") || strings.Contains(zconf.Name, "//") {
			lgConfig.Error("zone name contains invalid characters, ignoring", "zone", zconf.Name)
			zd.SetError(ConfigError, "zone name contains invalid characters: %q", zconf.Name)
			continue
		}

		// Handle template expansion if specified
		if zconf.Template != "" {
			if tmpl, exist := Templates[zconf.Template]; exist {
				updated, err := ExpandTemplate(*zconf, &tmpl, Globals.App.Type)
				if err != nil {
					fmt.Printf("Error expanding template %s for zone %s. Aborting.\n", zconf.Template, zname)
					// return nil, err
					zd.SetError(ConfigError, "template expansion error: %q: %v", zconf.Template, err)
					continue
				}
				*zconf = updated
				//fmt.Printf("Success expanding template %s for zone %s.\n", zconf.Template, zname)
			} else {
				zd.SetError(ConfigError, "template %q does not exist", zconf.Template)
				fmt.Printf("Zone %q refers to the non-existing template %q. Ignored.\n", zname, zconf.Template)
				continue
			}
		}

		zconf.Store = strings.ToLower(zconf.Store)
		// fmt.Printf("Zone %s uses \"%s\" storage\n", zconf.Name, zconf.Store)
		var zonestore ZoneStore
		switch zconf.Store {
		case "xfr":
			zonestore = XfrZone
		case "map":
			zonestore = MapZone
		case "slice":
			zonestore = SliceZone
		default:
			lgConfig.Warn("unknown zone store type, using map store", "zone", zname, "store", zconf.Store)
			zonestore = MapZone
		}

		var zonetype ZoneType

		switch strings.ToLower(zconf.Type) {
		case "primary":
			zonetype = Primary
			_ = append([]string{}, zname) // primary_zones was unused
		case "secondary":
			zonetype = Secondary
			if zconf.Primary == "" {
				lgConfig.Error("secondary zone has no primary configured, ignored", "zone", zname)
				zd.SetError(ConfigError, "secondary zone but has no primary (upstream) configured")
				continue
			}

			// Normalize primary address to include port if not specified
			origPrimary := zconf.Primary
			zconf.Primary = NormalizeAddress(zconf.Primary)
			if origPrimary != zconf.Primary {
				lgConfig.Warn("primary has no port specified, using default :53", "zone", zname, "primary", origPrimary)
			}

		default:
			lgConfig.Error("unknown zone type, ignored", "zone", zname, "type", zconf.Type)
			zd.SetError(ConfigError, "unknown zone type: %s", zconf.Type)
			continue
		}

		lgConfig.Debug("checking DNSSEC policy", "zone", zname)
		// dump.P(zconf)

		if zconf.DnssecPolicy == "none" {
			lgConfig.Info("DNSSEC policy is none, zone will not be signed", "zone", zname)
			zconf.DnssecPolicy = ""
		}
		if zconf.DnssecPolicy != "" {
			_, exist := conf.Internal.DnssecPolicies[zconf.DnssecPolicy]
			if !exist {
				lgConfig.Error("zone refers to non-existing DNSSEC policy, will not be signed", "zone", zname, "policy", zconf.DnssecPolicy)
				zconf.DnssecPolicy = ""
				zd.SetError(DnssecError, "DNSSEC policy %q does not exist", zconf.DnssecPolicy)
			}
			lgConfig.Info("DNSSEC policy accepted", "zone", zname, "policy", zconf.DnssecPolicy)
		}

		options := parseZoneOptions(conf, zname, zconf, &zd)
		var outopts []string
		for o, val := range options {
			if val {
				outopts = append(outopts, ZoneOptionToString[o])
			}
		}
		lgConfig.Debug("zone outgoing options", "zone", zname, "options", outopts)

		lgConfig.Info("zone configuration", "zone", zname, "type", zconf.Type, "store", zconf.Store, "primary", zconf.Primary, "notify", zconf.Notify, "zonefile", zconf.Zonefile)

		lgConfig.Debug("zone incoming update policy", "zone", zname, "policy", fmt.Sprintf("%+v", zconf.UpdatePolicy))

		switch zconf.UpdatePolicy.Child.Type {
		case "selfsub", "self":
			// all ok, we know these
		case "none", "":
			// these are also ok, but imply that no updates are allowed
			options[OptAllowChildUpdates] = false
		default:
			lgConfig.Error("zone has unknown child update policy type, ignored", "zone", zname, "type", zconf.UpdatePolicy.Child.Type)
			zd.SetError(ConfigError, "unknown child update policy type: %s", zconf.UpdatePolicy.Child.Type)
			continue
		}

		// log.Printf("*** ParseZones: 1")

		switch zconf.UpdatePolicy.Zone.Type {
		case "selfsub", "self":
			// all ok, we know these
		case "none", "":
			// these are also ok, but imply that no updates are allowed
			options[OptAllowUpdates] = false
		default:
			lgConfig.Error("zone has unknown update policy type, ignored", "zone", zname, "type", zconf.UpdatePolicy.Zone.Type)
			zd.SetError(ConfigError, "unknown update policy type: %s", zconf.UpdatePolicy.Zone.Type)
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
			if conf.MultiProvider == nil {
				zd.SetError(ConfigError, "agent has primary zone %q but multi-provider config is missing", zname)
				continue
			}
			// Agent only supports primary zone if it matches its identity
			if zname != conf.MultiProvider.Identity {
				zd.SetError(AgentError, "primary zone does not match agent identity (%q)", conf.MultiProvider.Identity)
				continue
			} else {
				// For agent's own zone, ensure required options are set
				options[OptAllowUpdates] = true
				options[OptOnlineSigning] = true
			}
		}

		// log.Printf("*** ParseZones: 5. Refreshch: %v", conf.Internal.RefreshZoneCh)

		// Validate this zone's configuration
		var zones = make(map[string]interface{}, 1)
		zones["zone:"+zname] = zconf
		if errmsg, err := ValidateBySection(conf, zones, "foobar"); err != nil {
			lgConfig.Error("zone validation failed", "zone", zname, "detail", errmsg)
			zd.SetError(ConfigError, "config validation: %v", err)
			continue
		}

		all_zones = append(all_zones, zname)

		// Get existing zd or create a minimal stub.
		// On SIGHUP reload, zones already exist — reuse them.
		zdp, exists := Zones.Get(zname)
		if !exists {
			zdp = &ZoneData{
				ZoneName:      zname,
				Logger:        log.Default(),
				FirstZoneLoad: true,
			}
			Zones.Set(zname, zdp)
		}

		// Apply static options via copy-on-write to avoid racing with
		// concurrent readers of zdp.Options / zdp.MP.MPdata.Options.
		// Build from fresh parsed options only; on reload this clears
		// options that were removed from the config file.
		newOpts := make(map[ZoneOption]bool, len(options))
		for opt, val := range options {
			newOpts[opt] = val
		}

		var newMPdata *MPdata
		if options[OptMultiProvider] {
			zdp.EnsureMP()
			if zdp.MP.MPdata != nil {
				// Copy existing MPdata, build fresh MP Options map
				cp := *zdp.MP.MPdata
				newMPdata = &cp
				newMPdata.Options = map[ZoneOption]bool{OptMultiProvider: true}
			} else {
				newMPdata = &MPdata{
					Options: map[ZoneOption]bool{OptMultiProvider: true},
				}
			}
		}

		zdp.mu.Lock()
		zdp.Options = newOpts
		if newMPdata != nil {
			zdp.EnsureMP()
			zdp.MP.MPdata = newMPdata
		} else if !options[OptMultiProvider] && zdp.MP != nil {
			zdp.MP.MPdata = nil
		}
		zdp.mu.Unlock()

		invokeOptionHandlers(zname, options)

		if zdp.FirstZoneLoad {
			lgConfig.Info("considering OnFirstLoad callbacks", "zone", zname,
				"online-signing", options[OptOnlineSigning],
				"inline-signing", options[OptInlineSigning],
				"multi-provider", options[OptMultiProvider],
				"apptype", AppTypeToString[Globals.App.Type])

			// Signing callback: zones with explicit signing options in config
			if options[OptOnlineSigning] || options[OptInlineSigning] {
				zdp.OnFirstLoad = append(zdp.OnFirstLoad, func(zd *ZoneData) {
					if err := zd.SetupZoneSigning(conf.Internal.ResignQ); err != nil {
						lgConfig.Error("SetupZoneSigning failed in OnFirstLoad", "zone", zd.ZoneName, "error", err)
					}
				})
			}

			// Multi-provider post-load callback: for auth servers serving MP zones.
			// By this point, FetchFromUpstream has examined the HSYNC RRset and
			// may have set OptInlineSigning dynamically. Only sign if it did.
			// Future: other MP-specific post-load setup goes here.
			if options[OptMultiProvider] && Globals.App.Type == AppTypeAuth {
				zdp.OnFirstLoad = append(zdp.OnFirstLoad, func(zd *ZoneData) {
					if zd.Options[OptInlineSigning] {
						if err := zd.SetupZoneSigning(conf.Internal.ResignQ); err != nil {
							lgConfig.Error("SetupZoneSigning failed in MP OnFirstLoad", "zone", zd.ZoneName, "error", err)
						}
					}
				})
			}

			// MP delegation sync callback: for MP zones, check HSYNCPARAM for
			// parentsync=agent. If set, enable delegation sync and call SetupZoneSync.
			// Only if our identity is listed in the zone's HSYNC3 records.
			if options[OptMultiProvider] {
				delegationSyncQ := conf.Internal.DelegationSyncQ
				zdp.OnFirstLoad = append(zdp.OnFirstLoad, func(zd *ZoneData) {
					if zd.Options[OptDelSyncChild] {
						return // already set via static config, handled by callback below
					}
					// Verify that our identity is listed in HSYNC3 before setting any options.
					matched, _, _ := zd.matchHsyncProvider(ourHsyncIdentities())
					if !matched {
						return
					}
					apex, err := zd.GetOwner(zd.ZoneName)
					if err != nil || apex == nil {
						return
					}
					hsyncparamRRset, exists := apex.RRtypes.Get(core.TypeHSYNCPARAM)
					if !exists || len(hsyncparamRRset.RRs) == 0 {
						return
					}
					if prr, ok := hsyncparamRRset.RRs[0].(*dns.PrivateRR); ok {
						if hsyncparam, ok := prr.Data.(*core.HSYNCPARAM); ok {
							if hsyncparam.GetParentSync() == core.HsyncParentSyncAgent {
								lgConfig.Info("HSYNCPARAM parentsync=agent, enabling delegation sync",
									"zone", zd.ZoneName)
								zd.Options[OptDelSyncChild] = true
								if err := zd.SetupZoneSync(delegationSyncQ); err != nil {
									lgConfig.Error("SetupZoneSync failed in MP OnFirstLoad",
										"zone", zd.ZoneName, "error", err)
								}
							}
						}
					}
				})
			}

			// Delegation sync callback: set up DSYNC publication (parent) or
			// delegation sync monitoring (child) after zone is loaded.
			if options[OptDelSyncParent] || options[OptDelSyncChild] {
				zdp.OnFirstLoad = append(zdp.OnFirstLoad, func(zd *ZoneData) {
					// Skip if the MP HSYNCPARAM callback already set up delegation sync for this zone.
					if zd.Options[OptDelSyncChild] && !options[OptDelSyncChild] {
						return
					}
					if zd.Options[OptDelSyncParent] && !options[OptDelSyncParent] {
						return
					}
					delegationSyncQ := conf.Internal.DelegationSyncQ
					if delegationSyncQ == nil {
						lgConfig.Error("DelegationSyncQ not available in OnFirstLoad", "zone", zd.ZoneName)
						return
					}
					if err := zd.SetupZoneSync(delegationSyncQ); err != nil {
						lgConfig.Error("SetupZoneSync failed in OnFirstLoad", "zone", zd.ZoneName, "error", err)
					}
				})
			}

			// Parent delegation backend: initialize on parent zones that accept child updates.
			if options[OptDelSyncParent] && options[OptAllowChildUpdates] && zconf.DelegationBackend != "" {
				backendName := zconf.DelegationBackend
				kdb := conf.Internal.KeyDB
				zdp.OnFirstLoad = append(zdp.OnFirstLoad, func(zd *ZoneData) {
					if kdb == nil {
						return
					}
					backend, err := LookupDelegationBackend(backendName, kdb, zd)
					if err != nil {
						lgConfig.Error("failed to create delegation backend", "zone", zd.ZoneName, "backend", backendName, "error", err)
						return
					}
					zd.DelegationBackend = backend
					lgConfig.Info("delegation backend initialized", "zone", zd.ZoneName, "backend", backend.Name())
				})
			}

			// Leader election OnFirstLoad is registered in StartAgent() (not here)
			// because LeaderElectionManager doesn't exist until StartAgent runs.

			// MP zone KEY publication: send SIG(0) KEY to combiner as REPLACE operation.
			// For MP zones, the combiner manages the zone apex, so the agent cannot
			// publish the KEY locally — it must send it to the combiner.
			if options[OptMultiProvider] {
				zdp.OnFirstLoad = append(zdp.OnFirstLoad, func(zd *ZoneData) {
					tm := conf.Internal.TransportManager
					kdb := conf.Internal.KeyDB
					if tm == nil || kdb == nil || !zd.Options[OptDelSyncChild] {
						return
					}
					targetName := DsyncUpdateTargetName(zd.ZoneName)
					if targetName == "" {
						targetName = zd.ZoneName
					}
					sak, err := kdb.GetSig0Keys(targetName, Sig0StateActive)
					if err != nil || len(sak.Keys) == 0 {
						lgConfig.Debug("MP KEY publication: no active SIG(0) key", "zone", zd.ZoneName)
						return
					}
					keyRR := &sak.Keys[0].KeyRR
					zu := &ZoneUpdate{
						Zone: ZoneName(zd.ZoneName),
						Operations: []core.RROperation{{
							Operation: "replace",
							RRtype:    "KEY",
							Records:   []string{keyRR.String()},
						}},
						Publish: &core.PublishInstruction{
							KEYRRs:    []string{keyRR.String()},
							Locations: []string{"at-apex", "at-ns"},
						},
					}
					distID, err := tm.EnqueueForCombiner(ZoneName(zd.ZoneName), zu, "")
					if err != nil {
						lgConfig.Error("MP KEY publication: failed to send KEY to combiner", "zone", zd.ZoneName, "err", err)
					} else {
						lgConfig.Info("MP KEY publication: KEY + PublishInstruction sent to combiner", "zone", zd.ZoneName, "distID", distID)
					}
				})
			}
		}

		switch Globals.App.Type {
		case AppTypeAuth, AppTypeAgent, AppTypeCombiner:
			if conf.Internal.RefreshZoneCh == nil {
				lgConfig.Error("refresh channel is not configured, zones will not be refreshed, terminating")
				return nil, errors.New("parseZones: error: refresh channel is not configured, zones will not be refreshed, terminating")
			}
			zr := ZoneRefresher{
				Name:         zname,
				Force:        true,     // force refresh, ignoring SOA serial, when reloading from file
				ZoneType:     zonetype, // primary | secondary
				Primary:      zconf.Primary,
				ZoneStore:    zonestore,
				Notify:       zconf.Notify,
				Zonefile:     zconf.Zonefile,
				Options:      options,
				UpdatePolicy: policy,
				DnssecPolicy: zconf.DnssecPolicy,
			}
			conf.Internal.RefreshZoneCh <- zr
		}
	}

	lgConfig.Info("zones parsed and refreshing", "count", len(all_zones), "zones", all_zones, "queued", len(conf.Internal.RefreshZoneCh))

	lgConfig.Debug("ParseZones complete")
	return all_zones, nil
}

func ExpandTemplate(zconf ZoneConf, tmpl *ZoneConf, appMode AppType) (ZoneConf, error) {

	// for each field in tmpl, check whether it contains any data
	// and if so, then let that data overwrite the same field in zconf

	if tmpl.Type != "" {
		zconf.Type = tmpl.Type
	}
	if tmpl.Store != "" {
		// fmt.Printf("ExpandTemplate: zone %s now uses the \"%s\" storage alternative.\n", zconf.Name, tmpl.Store)
		zconf.Store = tmpl.Store
	}
	if tmpl.Primary != "" {
		zconf.Primary = tmpl.Primary
	}
	if len(tmpl.Zonefile) > 0 {
		// H26: Validate zone name doesn't contain format specifiers
		if strings.ContainsAny(zconf.Name, "%") {
			return zconf, fmt.Errorf("zone name %q contains format specifiers", zconf.Name)
		}
		expanded := filepath.Clean(fmt.Sprintf(tmpl.Zonefile, zconf.Name))
		if strings.Contains(expanded, "..") {
			return zconf, fmt.Errorf("expanded zonefile path %q contains directory traversal", expanded)
		}
		zconf.Zonefile = expanded
	}
	if len(tmpl.Notify) > 0 {
		zconf.Notify = tmpl.Notify
	}

	// template options are appended to existing zone options
	if len(tmpl.OptionsStrs) > 0 {
		for _, option := range tmpl.OptionsStrs {
			if !slices.Contains(zconf.OptionsStrs, option) {
				zconf.OptionsStrs = append(zconf.OptionsStrs, option)
			}
		}
	}
	if (tmpl.UpdatePolicy.Child.Type != "" && len(tmpl.UpdatePolicy.Child.RRtypes) > 0) ||
		(tmpl.UpdatePolicy.Zone.Type != "" && len(tmpl.UpdatePolicy.Zone.RRtypes) > 0) {
		zconf.UpdatePolicy = tmpl.UpdatePolicy
	}

	// tdns-agent does not have DNSSEC policies, so we ignore them
	if appMode != AppTypeAgent && tmpl.DnssecPolicy != "" {
		zconf.DnssecPolicy = tmpl.DnssecPolicy
	}

	zconf.MultiSigner = tmpl.MultiSigner

	return zconf, nil
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

// builtinDefaultDnssecPolicy returns the built-in "default" DNSSEC policy used when
// no dnssecpolicies.default is defined in config (e.g. for agent autozone). An explicit
// dnssecpolicies.default in YAML overrides this. No automatic key rollovers.
func builtinDefaultDnssecPolicy() DnssecPolicy {
	return DnssecPolicy{
		Name:      "default",
		Algorithm: dns.ED25519,
		KSK:       GenKeyLifetime("forever", "168h"),
		ZSK:       GenKeyLifetime("forever", "2h"),
		CSK:       GenKeyLifetime("none", "168h"),
	}
}

func GenKeyLifetime(lifetime, sigvalidity string) KeyLifetime {
	var lifetime_secs, sigvalidity_secs time.Duration
	var err error

	switch lifetime {
	case "forever":
		lifetime_secs = time.Duration(10000) * time.Hour

	case "none":
		lifetime_secs = time.Duration(0)

	default:
		lifetime_secs, err = time.ParseDuration(lifetime)
		if err != nil {
			Fatal("error from ParseDuration", "err", err)
		}
	}

	sigvalidity_secs, err = time.ParseDuration(sigvalidity)
	if err != nil {
		Fatal("error from ParseDuration", "err", err)
	}
	return KeyLifetime{
		Lifetime:    uint32(lifetime_secs.Seconds()),
		SigValidity: uint32(sigvalidity_secs.Seconds()),
	}
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

// normalizeConfigIdentities applies dns.Fqdn() to all identity fields (domain names)
// in the parsed config. This ensures trailing dots are present regardless of whether
// the YAML config included them.
func (conf *Config) normalizeConfigIdentities() {
	// Agent identity and peers
	if conf.MultiProvider != nil {
		if conf.MultiProvider.Identity != "" {
			conf.MultiProvider.Identity = dns.Fqdn(conf.MultiProvider.Identity)
		}
		if conf.MultiProvider.Dns.ControlZone != "" {
			conf.MultiProvider.Dns.ControlZone = dns.Fqdn(conf.MultiProvider.Dns.ControlZone)
		}
		if conf.MultiProvider.Combiner != nil && conf.MultiProvider.Combiner.Identity != "" {
			conf.MultiProvider.Combiner.Identity = dns.Fqdn(conf.MultiProvider.Combiner.Identity)
		}
		if conf.MultiProvider.Signer != nil && conf.MultiProvider.Signer.Identity != "" {
			conf.MultiProvider.Signer.Identity = dns.Fqdn(conf.MultiProvider.Signer.Identity)
		}
		for i, p := range conf.MultiProvider.AuthorizedPeers {
			conf.MultiProvider.AuthorizedPeers[i] = dns.Fqdn(p)
		}
		for _, peer := range conf.MultiProvider.Peers {
			if peer != nil && peer.Identity != "" {
				peer.Identity = dns.Fqdn(peer.Identity)
			}
		}
	}

	// Multi-provider agent peers and combiner-specific normalization
	if conf.MultiProvider != nil {
		for _, agent := range conf.MultiProvider.Agents {
			if agent != nil && agent.Identity != "" {
				agent.Identity = dns.Fqdn(agent.Identity)
			}
		}
		if conf.MultiProvider.Role == "combiner" {
			for i, ns := range conf.MultiProvider.ProtectedNamespaces {
				conf.MultiProvider.ProtectedNamespaces[i] = dns.Fqdn(ns)
			}
			for i := range conf.MultiProvider.ProviderZones {
				conf.MultiProvider.ProviderZones[i].Zone = dns.Fqdn(conf.MultiProvider.ProviderZones[i].Zone)
				RegisterProviderZoneRRtypes(conf.MultiProvider.ProviderZones[i])
			}
		}
	}
}
