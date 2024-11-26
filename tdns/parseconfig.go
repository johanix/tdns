/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	// "flag"
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
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type Zconfig struct {
	Templates map[string]TemplateConf
	Zones     map[string]ZoneConf
}

// type TAtmp map[string]TmpAnchor

// type TmpAnchor struct {
// 	Name   string
// 	Dnskey string
// }

// type Sig0tmp map[string]TmpSig0Key

// type TmpSig0Key struct {
// 	Name string
// 	Key  string
// }

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

func ParseConfig(conf *Config, reload bool) error {
	if Globals.Debug {
		log.Printf("Enter ParseConfig")
	}
	cfgfile := conf.Internal.CfgFile
	if cfgfile == "" {
		cfgfile = DefaultCfgFile
	}
	viper.SetConfigFile(cfgfile)

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	} else {
		log.Fatalf("Could not load config %s: Error: %v", cfgfile, err)
	}

	viper.WriteConfigAs("/tmp/tdnsd.parsed.yaml")
	Globals.IMR = viper.GetString("resolver.address")
	if Globals.IMR == "" {
		log.Fatalf("Error: IMR undefined.")
	} else {
		log.Printf("*** Using resolver: %s", Globals.IMR)
	}

	err := viper.Unmarshal(&conf)
	if err != nil {
		log.Fatalf("Error unmarshalling config into struct: %v", err)
	}

	if conf.AppMode == "server" || conf.AppMode == "sidecar" {
		// dump.P(conf.DnssecPolicies)
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
				// if this is a reload, we ignore the policy from the config, i.e. we keep the old one
				continue
			}
			conf.Internal.DnssecPolicies[name] = tmp
		}

		if _, exists := conf.Internal.DnssecPolicies["default"]; !exists {
			log.Fatalf("Error: DnssecPolicy 'default' not defined. Default policy is required.")
			// return errors.New("ParseConfig: DnssecPolicy 'default' not defined. Default policy is required.")
		}

		// dump.P(conf.Internal.DnssecPolicies)
	}

	var dpn []string
	for name, _ := range conf.Internal.DnssecPolicies {
		dpn = append(dpn, name)
	}
	log.Printf("*** ParseConfig: DnssecPolicy configs: %v", dpn)

	// conf.Internal.MultiSignerConfigs = make(map[string]MultiSignerConf)
	for msname, msconf := range conf.MultiSigner {
		if len(msconf.Controller.Notify.Addresses) == 0 {
			log.Printf("Error: MultiSigner config %s has no notify addresses specified. MultiSigner config ignored.", msname)
			delete(conf.MultiSigner, msname)
			continue
		}
		if msconf.Controller.Notify.Port == "" {
			log.Printf("Error: MultiSigner config %s has no notify port specified. MultiSigner config ignored.", msname)
			delete(conf.MultiSigner, msname)
			continue
		}
		for _, addr := range msconf.Controller.Notify.Addresses {
			target := net.JoinHostPort(string(addr), msconf.Controller.Notify.Port)
			msconf.Controller.Notify.Targets = append(msconf.Controller.Notify.Targets, target)
		}

		if msconf.Controller.API.BaseURL == "" || msconf.Controller.API.ApiKey == "" {
			log.Printf("Error: MultiSigner %s has no API base URL or API key. MultiSigner config ignored.", msname)
			delete(conf.MultiSigner, msname)
			continue
		}
	}

	var msc []string
	for name, _ := range conf.MultiSigner {
		msc = append(msc, name)
	}
	log.Printf("*** ParseConfig: MultiSigner configs: %v", msc)

	// dump.P(conf.Registrars)
	for reg, regdata := range conf.Registrars {
		log.Printf("*** ParseConfig: Registrar %s has %d DSYNC records; parsing them for correctness", reg, len(regdata))
		for _, regdsync := range regdata {
			_, err := dns.NewRR(regdsync)
			if err != nil {
				log.Printf("*** ParseConfig: Error parsing registrar %s DSYNC: %v\nFailed DSYNC RR: \"%s\"", reg, err, regdsync)
			}
		}
	}

	// If a zone config file is found, read it in.
	cfgdata, err := os.ReadFile(conf.Internal.ZonesCfgFile)
	if err != nil {
		log.Fatalf("Error from ReadFile: %v", err)
	}

	var zconf Zconfig

	err = yaml.Unmarshal(cfgdata, &zconf)
	if err != nil {
		log.Fatalf("Error from yaml.Unmarshal(Zconfig): %v", err)
	}

	// This kludge is to allow the zones to be a map[string]ZoneConf,
	// with the zone name as the key (which viper doesn't allow)
	conf.Zones = zconf.Zones

	fmt.Printf("YAML parsed. There are %d zones:", len(conf.Zones))
	for key := range conf.Zones {
		fmt.Printf(" [%s]", key)
	}
	fmt.Println()

	kdb := conf.Internal.KeyDB
	// fmt.Printf("DEBUG: conf.AppName: %s AppMode: %s\n", conf.AppName, conf.AppMode)
	if !reload || kdb == nil {

		dbFile := viper.GetString("db.file")
		if conf.AppName != "sidecar-cli" && conf.AppName != "tdns-cli" {
			// Verify that we have a MUSIC DB file.
			fmt.Printf("Verifying existence of TDNS DB file: %s\n", dbFile)
			if _, err := os.Stat(dbFile); os.IsNotExist(err) {
				log.Printf("ParseConfig: TDNS DB file '%s' does not exist.", dbFile)
				log.Printf("Please initialize TDNS DB using 'tdns-cli|sidecar-cli db init -f %s'.", dbFile)
				return errors.New("ParseConfig: TDNS DB file does not exist")
			}
		}

		kdb, err := NewKeyDB(dbFile, false)
		if err != nil {
			log.Fatalf("Error from NewKeyDB: %v", err)
		}
		conf.Internal.KeyDB = kdb
	}

	// XXX: I don't think we want this anymore.
	//	if err != nil {
	//		log.Fatalf("Error from LoadDnskeyTrustAnchors(): %v", err)
	//	}
	//	err = kdb.LoadSig0ChildKeys()
	//	if err != nil {
	//		log.Fatalf("Error from LoadSig0ChildKeys(): %v", err)
	//	}

	ValidateConfig(nil, DefaultCfgFile) // will terminate on error

	if Globals.Debug {
		log.Printf("ParseConfig: exit")
	}
	return nil
}

// func ParseZones(zones map[string]tdns.ZoneConf, zrch chan tdns.ZoneRefresher) error {
func ParseZones(conf *Config, zrch chan ZoneRefresher, reload bool) ([]string, error) {
	if Globals.Debug {
		log.Printf("ParseZones: enter")
	}
	var all_zones []string

	zonescfgfile := conf.Internal.ZonesCfgFile
	if zonescfgfile == "" {
		zonescfgfile = ZonesCfgFile
	}
	log.Printf("ParseZones: using zone configs from file: %s\n", zonescfgfile)

	// If a zone config file is found, read it in.
	zonecfgs, err := os.ReadFile(zonescfgfile)
	if err != nil {
		log.Fatalf("Error from ReadFile: %v", err)
	}

	var zconfig Zconfig

	err = yaml.Unmarshal(zonecfgs, &zconfig)
	if err != nil {
		log.Fatalf("Error from yaml.Unmarshal(Zconfig): %v", err)
	}

	//	for name, data := range zconfig.Templates {
	//		fmt.Printf("Template %s:\n%v\n", name, data)
	//	}

	zones := zconfig.Zones
	primary_zones := []string{}

	for zname, zconf := range zconfig.Zones {
		if zname != dns.Fqdn(zname) {
			delete(zones, zname)
			zname = dns.Fqdn(zname)
			zconf.Name = zname
			zones[zname] = zconf
		}

		var tmpl TemplateConf
		var exist bool
		var err error

		if zconf.Template != "" {
			if tmpl, exist = zconfig.Templates[zconf.Template]; exist {
				fmt.Printf("Zone %s uses the existing template %s\n", zname, zconf.Template)
				zconf, err = ExpandTemplate(zconf, tmpl, conf.AppMode)
				if err != nil {
					fmt.Printf("Error expanding template %s for zone %s. Aborting.\n", zconf.Template, zname)
					os.Exit(1)
				} else {
					fmt.Printf("Success expanding template %s for zone %s.\n", zconf.Template, zname)
					// dump.P(zconf)
				}
			} else {
				fmt.Printf("Zone %s refers to the NON-existing template %s. Ignored.\n", zname, zconf.Template)
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
			log.Printf("Zone %s: Unknown zone store type: \"%s\". Zone ignored.", zname, zconf.Store)
			delete(zones, zname)
			continue
		}

		var zonetype ZoneType

		switch strings.ToLower(zconf.Type) {
		case "primary":
			zonetype = Primary
			primary_zones = append(primary_zones, zname)
		case "secondary":
			zonetype = Secondary
			if zconf.Primary == "" {
				log.Printf("Error: Zone %s is a secondary zone but has no primary (upstream) configured. Zone ignored.", zname)
				delete(zones, zname)
				continue
			}

		default:
			log.Printf("Error: Zone %s: Unknown zone type: \"%s\". Zone ignored.", zname, zconf.Type)
			delete(zones, zname)
			continue
		}

		log.Printf("ParseZones: zone %s: checking DNSSEC policy", zname)
		// dump.P(zconf)

		if zconf.DnssecPolicy == "none" {
			log.Printf("ParseZones: Zone %s: DNSSEC policy is \"none\". Zone will not be signed.", zname)
			zconf.DnssecPolicy = ""
		}
		if zconf.DnssecPolicy != "" {
			_, exist = conf.DnssecPolicies[zconf.DnssecPolicy]
			if !exist {
				log.Printf("Error: Zone %s refers to non-existing DNSSEC policy %s. Zone will not be signed.", zname, zconf.DnssecPolicy)
				zconf.DnssecPolicy = ""
			}
			log.Printf("ParseZones: zone %s: DNSSEC policy \"%s\" accepted", zname, zconf.DnssecPolicy)
		}

		log.Printf("ParseZones: zone %s incoming options: %v", zname, zconf.OptionsStrs)
		options := map[ZoneOption]bool{}
		var cleanoptions []ZoneOption
		for _, option := range zconf.OptionsStrs {
			option = strings.ToLower(option)
			opt, exist := StringToZoneOption[option]
			if !exist {
				log.Printf("ParseZones: Zone %s: Unknown option: \"%s\". Ignored.", zname, option)
				continue
			}

			switch opt {
			case OptDelSyncParent, // as a parent, publish supported DSYNC schemes
				OptDelSyncChild,      // as a child, try to sync with parent via DSYNC scheme
				OptAllowUpdates,      // zone allows DNS UPDATEs to authoritiative data
				OptAllowChildUpdates, // zone allows updates to child delegation information
				OptFoldCase,          // fold case of owner names to lower to make query matching case insensitive
				OptBlackLies,         // zone may implement DNSSEC signed negative responses via so-called black lies.
				OptDontPublishKey:    // do not publish a SIG(0) KEY record for the zone (default should be to publish)
				options[opt] = true
				cleanoptions = append(cleanoptions, opt)

			case OptOnlineSigning: // zone may be signed (and re-signed) online as needed; only possible if dnssec policy is set
				if conf.AppMode == "agent" {
					log.Printf("Error: Zone %s: Option \"%s\" is ignored because TDNS-AGENT does not allow online signing.", zname, ZoneOptionToString[opt])
					continue
				}
				if conf.AppMode == "sidecar" {
					log.Printf("Error: Zone %s: Option \"%s\" is ignored because MUSIC-SIDECAR does not allow online signing.", zname, ZoneOptionToString[opt])
					continue
				}
				if zconf.DnssecPolicy != "" {
					options[opt] = true
					cleanoptions = append(cleanoptions, opt)
				} else {
					log.Printf("Error: Zone %s: Option \"online-signing\" is ignored because the DNSSEC policy is not set.", zname)
				}

			case OptMultiSigner:
				if zconf.MultiSigner == "" || zconf.MultiSigner == "none" {
					log.Printf("Error: Zone %s: Option \"%s\" set without a corresponding multisigner config. Option ignored.", zname, ZoneOptionToString[opt])
					continue
				}
				if _, exist := conf.MultiSigner[zconf.MultiSigner]; !exist {
					log.Printf("Error: Zone %s: Option \"%s\" set to non-existing multi-signer config \"%s\". Option ignored.", zname, ZoneOptionToString[opt], zconf.MultiSigner)
					continue
				}
				if conf.Internal.MusicSyncQ == nil {
					log.Printf("Error: Zone %s: Option \"%s\" set but no multi-signer sync channel configured. This is a fatal error.", zname, ZoneOptionToString[opt])
					os.Exit(1)
				}
				options[opt] = true
				cleanoptions = append(cleanoptions, opt)
				log.Printf("ParseZones: Zone %s: option \"%s\" accepted. Using multi-signer config \"%s\"", zname, ZoneOptionToString[opt], zconf.MultiSigner)

			default:
				// Should not happen
				log.Printf("Error: Zone %s: Unknown option: \"%s\". Zone ignored.", zname, ZoneOptionToString[opt])
				delete(zones, zname)
			}
		}
		zconf.Options = cleanoptions
		zones[zname] = zconf
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
			log.Printf("ParseZones: Error: zone %s has an unknown update policy type: \"%s\". Zone ignored.", zname, zconf.UpdatePolicy.Child.Type)
			delete(zones, zname)
		}

		switch zconf.UpdatePolicy.Zone.Type {
		case "selfsub", "self":
			// all ok, we know these
		case "none", "":
			// these are also ok, but imply that no updates are allowed
			options[OptAllowUpdates] = false
		default:
			log.Printf("ParseZones: Error: zone %s has an unknown update policy type: \"%s\". Zone ignored.", zname, zconf.UpdatePolicy.Zone.Type)
			delete(zones, zname)
		}

		var rrt uint16
		// var exist bool
		childrrtypes := map[uint16]bool{}
		for _, rrtype := range zconf.UpdatePolicy.Child.RRtypes {
			rrtype = strings.ToUpper(rrtype)
			if rrt, exist = dns.StringToType[rrtype]; exist {
				childrrtypes[rrt] = true
			}
		}

		zonerrtypes := map[uint16]bool{}
		for _, rrtype := range zconf.UpdatePolicy.Zone.RRtypes {
			rrtype = strings.ToUpper(rrtype)
			if rrt, exist = dns.StringToType[rrtype]; exist {
				zonerrtypes[rrt] = true
			}
		}

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
		all_zones = append(all_zones, zname)

		zrch <- ZoneRefresher{
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
	}

	if conf.AppMode == "agent" && len(primary_zones) > 0 {
		fmt.Printf("Error: The TDNS agent does not support primary zones: %v\n", primary_zones)
		log.Fatalf("Error: The TDNS agent does not support primary zones: %v", primary_zones)
	}

	conf.Zones = zones

	ValidateZones(conf, ZonesCfgFile) // will terminate on error
	log.Printf("All configured zones now refreshing: %v (queued for refresh: %d zones)", all_zones, len(zrch))

	if Globals.Debug {
		log.Printf("ParseConfig: exit")
	}
	return all_zones, nil
}

func ExpandTemplate(zconf ZoneConf, tmpl TemplateConf, appMode string) (ZoneConf, error) {

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
	if appMode != "agent" && tmpl.DnssecPolicy != "" {
		zconf.DnssecPolicy = tmpl.DnssecPolicy
	}

	zconf.MultiSigner = tmpl.MultiSigner

	return zconf, nil
}
