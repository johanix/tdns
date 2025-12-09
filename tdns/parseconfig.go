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

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

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
func processConfigFile(file string, baseDir string, depth int) (map[string]interface{}, error) {
	if depth > 10 {
		return nil, errors.New("maximum include depth exceeded (10 levels)")
	}

	// Read the file
	if Globals.Debug {
		log.Printf("processConfigFile: Reading %q", file)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %v", file, err)
	}

	// Parse YAML directly into a map
	var config map[string]interface{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		if Globals.Debug {
			log.Printf("processConfigFile: error unmarshalling YAML from %q to struct", file)
		}
		return nil, fmt.Errorf("error parsing YAML: %v", err)
	}

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

				included, err := processConfigFile(fullPath, filepath.Dir(fullPath), depth+1)
				if err != nil {
					return nil, err
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
			}
		}
	}

	return config, nil
}

func (conf *Config) ParseConfig(reload bool) error {
	if Globals.Debug {
		log.Printf("Enter ParseConfig")
	}

	cfgfile := conf.Internal.CfgFile
	if cfgfile == "" {
		log.Printf("No config file specified. Proceed at own risk.")
		return nil
	}

	// Process the config file and all includes
	configMap, err := processConfigFile(cfgfile, filepath.Dir(cfgfile), 0)
	if err != nil {
		return fmt.Errorf("error processing config: %v", err)
	}

	// Configure mapstructure decoder to respect yaml tags
	decoderConfig := &mapstructure.DecoderConfig{
		TagName: "yaml",
		Result:  conf,
	}
	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return fmt.Errorf("error creating decoder: %v", err)
	}

	if Globals.Debug {
		// log.Printf("Before decoding configuration")
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
		return fmt.Errorf("error decoding config: %v", err)
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
			log.Printf("ParseConfig: unknown service.transport.type=%q; defaulting to 'none'", conf.Service.Transport.Type)
			conf.Service.Transport.Type = "none"
		}
	}

	if Globals.Debug {
		tmp := fmt.Sprintf("Templates: %d templates defined: ", len(conf.Templates))
		for _, tmpl := range conf.Templates {
			tmp += fmt.Sprintf(" %s", tmpl.Name)
		}
		log.Printf(tmp)
	}

	if Globals.App.Type != AppTypeReporter && Globals.App.Type != AppTypeImr {
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

		if Globals.Debug {
			tmp := fmt.Sprintf("Templates (again): %d templates defined: ", len(Templates))
			for _, tmpl := range Templates {
				tmp += fmt.Sprintf(" %s", tmpl.Name)
			}
			log.Printf(tmp)
		}
	}

	// log.Printf("*** ParseConfig: 1")
	// Set up viper with the same config for compatibility
	processedConfig, err := yaml.Marshal(configMap)
	if err != nil {
		return fmt.Errorf("error marshaling processed config: %v", err)
	}

	if Globals.Debug {
		// log.Printf("*** ParseConfig: 2")
		// log.Printf("Processed config YAML:\n%s", string(processedConfig))
	}

	viper.SetConfigType("yaml")
	if err := viper.ReadConfig(strings.NewReader(string(processedConfig))); err != nil {
		return fmt.Errorf("error reading processed config: %v", err)
	}

	// Initialize DnssecPolicies if needed
	switch Globals.App.Type {
	case AppTypeServer, AppTypeAgent:
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
				log.Printf("Error: DnssecPolicy %s has unknown algorithm: %s. Policy ignored.", name, dp.Algorithm)
				continue
			}
			conf.Internal.DnssecPolicies[name] = tmp
		}

		if _, exists := conf.Internal.DnssecPolicies["default"]; !exists {
			return errors.New("ParseConfig: DnssecPolicy 'default' not defined. Default policy is required")
		}
	}

	if Globals.App.Type == AppTypeImr {
		conf.parseImrOptions()
	}

	// XXX: Hmm. Should not initialize KeyDB on reload?
	switch Globals.App.Type {
	case AppTypeServer, AppTypeAgent, AppTypeCombiner:
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

	if Globals.App.Type == AppTypeServer && len(conf.Service.Identities) > 0 {
		var transports []string
		for _, t := range conf.DnsEngine.Transports {
			t = strings.ToLower(t)
			switch t {
			case "do53", "dot", "doh", "doq":
				transports = append(transports, t)
			default:
				log.Printf("Error: Unknown transport: %s", t)
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

	if Globals.Debug {
		// dump.P(conf.Agent)
		// log.Printf("** ParseConfig: exit")
	}
	return nil
}

func (conf *Config) InitializeKeyDB() error {
	// dbFile := viper.GetString("db.file")
	dbFile := conf.Db.File
	// Ensure the database file path is within allowed boundaries
	dbFile = filepath.Clean(dbFile)
	if strings.Contains(dbFile, "..") {
		return errors.New("invalid database file path: must not contain directory traversal")
	}
	if dbFile == "" {
		return fmt.Errorf("invalid database file: '%s'", dbFile)
	}
	switch Globals.App.Type {
	case AppTypeServer, AppTypeAgent, AppTypeCombiner, AppTypeScanner:

		// Verify that we have a MUSIC DB file.
		fmt.Printf("Verifying existence of TDNS DB file: %s\n", dbFile)
		if _, err := os.Stat(dbFile); os.IsNotExist(err) {
			log.Printf("ParseConfig: TDNS DB file '%s' does not exist.", dbFile)
			log.Printf("Please initialize TDNS DB using 'tdns-cli|sidecar-cli db init -f %s'.", dbFile)
			return errors.New("ParseConfig: TDNS DB file does not exist")
		}
		kdb, err := NewKeyDB(dbFile, false)
		if err != nil {
			return fmt.Errorf("Error from NewKeyDB: %v", err)
		}
		conf.Internal.KeyDB = kdb

	default:
		// do nothing for tdns-imr, tdns-cli
	}
	return nil
}

// func ParseZones(zones map[string]tdns.ZoneConf, zrch chan tdns.ZoneRefresher) error {
func (conf *Config) ParseZones(ctx context.Context, reload bool) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(conf.Zones) == 0 {
		log.Printf("ParseZones: no authoritative zones defined.")
		return nil, nil
	}

	if Globals.Debug {
		log.Printf("ParseZones: %d authoritative zones defined. Parsing...", len(conf.Zones))
	}
	var all_zones []string
	var primary_zones []string

	// Process each zone configuration
	for i := range conf.Zones {
		zconf := &conf.Zones[i]
		zname := dns.Fqdn(zconf.Name)
		zconf.Name = zname

		zd := ZoneData{
			ZoneName: zname,
			Zonefile: zconf.Zonefile,
		}

		if strings.Contains(zconf.Name, "..") || strings.Contains(zconf.Name, "//") {
			log.Printf("ParseZones: Zone %s contains invalid characters. Ignoring.", zconf.Name)
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
			log.Printf("Zone %s: Unknown zone store type: %q. Using map store.", zname, zconf.Store)
			zonestore = MapZone
		}

		var zonetype ZoneType

		switch strings.ToLower(zconf.Type) {
		case "primary":
			zonetype = Primary
			primary_zones = append(primary_zones, zname)
		case "secondary":
			zonetype = Secondary
			if zconf.Primary == "" {
				log.Printf("Error: Zone %q is a secondary zone but has no primary (upstream) configured. Zone ignored.", zname)
				zd.SetError(ConfigError, "secondary zone but has no primary (upstream) configured")
				continue
			}

			// Check if primary has port specified
			_, _, err := net.SplitHostPort(zconf.Primary)
			if err != nil {
				log.Printf("Warning: Zone %q: primary %q has no port specified, using default port :53", zname, zconf.Primary)
				zconf.Primary = net.JoinHostPort(zconf.Primary, "53")
			}

		default:
			log.Printf("Error: Zone %s: Unknown zone type: \"%s\". Zone ignored.", zname, zconf.Type)
			zd.SetError(ConfigError, "unknown zone type: %s", zconf.Type)
			continue
		}

		log.Printf("ParseZones: zone %s: checking DNSSEC policy", zname)
		// dump.P(zconf)

		if zconf.DnssecPolicy == "none" {
			log.Printf("ParseZones: Zone %s: DNSSEC policy is \"none\". Zone will not be signed.", zname)
			zconf.DnssecPolicy = ""
		}
		if zconf.DnssecPolicy != "" {
			_, exist := conf.DnssecPolicies[zconf.DnssecPolicy]
			if !exist {
				log.Printf("Error: Zone %s refers to non-existing DNSSEC policy %s. Zone will not be signed.", zname, zconf.DnssecPolicy)
				zconf.DnssecPolicy = ""
				zd.SetError(DnssecError, "DNSSEC policy %q does not exist", zconf.DnssecPolicy)
			}
			log.Printf("ParseZones: zone %s: DNSSEC policy %q accepted", zname, zconf.DnssecPolicy)
		}

		options := parseZoneOptions(conf, zname, zconf, &zd)
		var outopts []string
		for o, val := range options {
			if val {
				outopts = append(outopts, ZoneOptionToString[o])
			}
		}
		log.Printf("ParseZones: zone %s outgoing options: %+v", zname, outopts)

		log.Printf("ParseZones: zone %s: type: %s, store: %s, primary: %s, notify: %v, zonefile: %s",
			zname, zconf.Type, zconf.Store, zconf.Primary, zconf.Notify, zconf.Zonefile)

		log.Printf("ParseZones: zone %s incoming update policy: %+v", zname, zconf.UpdatePolicy)

		switch zconf.UpdatePolicy.Child.Type {
		case "selfsub", "self":
			// all ok, we know these
		case "none", "":
			// these are also ok, but imply that no updates are allowed
			options[OptAllowChildUpdates] = false
		default:
			log.Printf("ParseZones: Error: zone %s has an unknown child update policy type: \"%s\". Zone ignored.", zname, zconf.UpdatePolicy.Child.Type)
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
			log.Printf("ParseZones: Error: zone %s has an unknown update policy type: \"%s\". Zone ignored.", zname, zconf.UpdatePolicy.Zone.Type)
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
		policy := UpdatePolicy{
			Child: UpdatePolicyDetail{
				Type:         zconf.UpdatePolicy.Child.Type,
				RRtypes:      childrrtypes,
				KeyBootstrap: zconf.UpdatePolicy.Child.KeyBootstrap,
				KeyUpload:    zconf.UpdatePolicy.Child.KeyUpload,
			},
			Zone: UpdatePolicyDetail{
				Type:    zconf.UpdatePolicy.Zone.Type,
				RRtypes: zonerrtypes,
			},
		}

		if Globals.App.Type == AppTypeAgent && zconf.Type == "primary" {
			// Agent only supports primary zone if it matches its identity
			if zname != conf.Agent.Identity {
				zd.SetError(AgentError, "primary zone does not match agent identity (%q)", conf.Agent.Identity)
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
			log.Printf("Error validating zone %s:\n%s", zname, errmsg)
			zd.SetError(ConfigError, "config validation: %v", err)
			continue
		}

		all_zones = append(all_zones, zname)

		switch Globals.App.Type {
		case AppTypeServer, AppTypeAgent, AppTypeCombiner:
			// If validation passed, enqueue refresh. Avoid blocking ParseZones on a bounded channel:
			// try a non-blocking send; if it would block, send from a goroutine.
			if conf.Internal.RefreshZoneCh == nil {
				log.Printf("ParseZones: Error: refresh channel is not configured. Zones will not be refreshed. Terminating.", zname)
				return nil, errors.New("ParseZones: Error: refresh channel is not configured. Zones will not be refreshed. Terminating.")
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
			select {
			case conf.Internal.RefreshZoneCh <- zr:
				// enqueued immediately
			default:
				go func(z ZoneRefresher) {
					select {
					case conf.Internal.RefreshZoneCh <- z:
					case <-ctx.Done():
					}
				}(zr)
			}
		}
	}

	// ValidateZones(conf, ZonesCfgFile) // will terminate on error
	log.Printf("ParseZones: %d zones parsed and are now refreshing: %v (queued for refresh: %d zones)",
		len(all_zones), all_zones, len(conf.Internal.RefreshZoneCh))

	if Globals.Debug {
		log.Print("ParseZones: exit")
	}
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
		// XXX: We should do some sanity checking of the filename here.
		zconf.Zonefile = filepath.Clean(fmt.Sprintf(tmpl.Zonefile, zconf.Name))
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
		log.Printf("Template cycle detected: %s", strings.Join(cycle, " -> "))
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
			log.Printf("Template %q refers to non-existing template %q. Ignored.", t.Name, t.Template)
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
			log.Printf("Error expanding template %q from parent %q: %v", t.Name, t.Template, err)
			delete(Templates, t.Name)
			onStack[name] = false
			return ZoneConf{}, err
		}
		t = expandedChild
	} else if t.Template == name {
		// Self-cycle
		log.Printf("Template %q: self-referential cycle. Removing.", name)
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
			log.Fatalf("Error from ParseDuration: %v", err)
		}
	}

	sigvalidity_secs, err = time.ParseDuration(sigvalidity)
	if err != nil {
		log.Fatalf("Error from ParseDuration: %v", err)
	}
	return KeyLifetime{
		Lifetime:    uint32(lifetime_secs.Seconds()),
		SigValidity: uint32(sigvalidity_secs.Seconds()),
	}
}
