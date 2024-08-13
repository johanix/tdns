/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	// "flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gookit/goutil/dump"
	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/johanix/tdns/tdns"
	// "github.com/orcaman/concurrent-map/v2"
)

type Zconfig struct {
	Templates map[string]tdns.TemplateConf
	Zones     map[string]tdns.ZoneConf
}

type TAtmp map[string]TmpAnchor

type TmpAnchor struct {
	Name   string
	Dnskey string
}

type Sig0tmp map[string]TmpSig0Key

type TmpSig0Key struct {
	Name string
	Key  string
}

func GenKeyLifetime(lifetime, sigvalidity string) tdns.KeyLifetime {
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
	return tdns.KeyLifetime{
		Lifetime:    uint32(lifetime_secs.Seconds()),
		SigValidity: uint32(sigvalidity_secs.Seconds()),
	}
}

func ParseConfig(conf *Config) error {
	log.Printf("Enter ParseConfig")
	viper.SetConfigFile(tdns.DefaultCfgFile)

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	} else {
		log.Fatalf("Could not load config %s: Error: %v", tdns.DefaultCfgFile, err)
	}

	viper.WriteConfigAs("/tmp/tdnsd.parsed.yaml")
	tdns.Globals.IMR = viper.GetString("resolver.address")
	if tdns.Globals.IMR == "" {
		log.Fatalf("Error: IMR undefined.")
	} else {
		log.Printf("*** Using resolver: %s", tdns.Globals.IMR)
	}

	err := viper.Unmarshal(&conf)
	if err != nil {
		log.Fatalf("Error unmarshalling config into struct: %v", err)
	}

	dump.P(conf.DnssecPolicies)

	conf.Internal.DnssecPolicies = make(map[string]tdns.DnssecPolicy)

	for name, dp := range conf.DnssecPolicies {
		tmp := tdns.DnssecPolicy{
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

	dump.P(conf.Internal.DnssecPolicies)

	// If a zone config file is found, read it in.
	cfgdata, err := os.ReadFile(tdns.ZonesCfgFile)
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

	kdb, err := tdns.NewKeyDB(viper.GetString("db.file"), false)
	if err != nil {
		log.Fatalf("Error from NewKeyDB: %v", err)
	}
	conf.Internal.KeyDB = kdb

	err = kdb.LoadDnskeyTrustAnchors()
	if err != nil {
		log.Fatalf("Error from LoadDnskeyTrustAnchors(): %v", err)
	}
	err = kdb.LoadSig0ChildKeys()
	if err != nil {
		log.Fatalf("Error from LoadSig0ChildKeys(): %v", err)
	}

	ValidateConfig(nil, tdns.DefaultCfgFile) // will terminate on error
	return nil
}

// func ParseZones(zones map[string]tdns.ZoneConf, zrch chan tdns.ZoneRefresher) error {
func ParseZones(conf *Config, zrch chan tdns.ZoneRefresher) error {
	var all_zones []string

	// If a zone config file is found, read it in.
	zonecfgs, err := os.ReadFile(tdns.ZonesCfgFile)
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

	for zname, zconf := range zconfig.Zones {
		if zname != dns.Fqdn(zname) {
			delete(zones, zname)
			zname = dns.Fqdn(zname)
			zconf.Name = zname
			zones[zname] = zconf
		}

		all_zones = append(all_zones, zname)

		var tmpl tdns.TemplateConf
		var exist bool
		var err error

		if zconf.Template != "" {
			if tmpl, exist = zconfig.Templates[zconf.Template]; exist {
				fmt.Printf("Zone %s uses the existing template %s\n", zname, zconf.Template)
				zconf, err = ExpandTemplate(zconf, tmpl)
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
		fmt.Printf("Zone %s uses store \"%s\"\n", zconf.Name, zconf.Store)
		var zonestore tdns.ZoneStore
		switch zconf.Store {
		case "xfr":
			zonestore = tdns.XfrZone
		case "map":
			zonestore = tdns.MapZone
		case "slice":
			zonestore = tdns.SliceZone
		default:
			log.Printf("Zone %s: Unknown zone store type: \"%s\". Zone ignored.", zname, zconf.Store)
		}

		var zonetype tdns.ZoneType

		switch strings.ToLower(zconf.Type) {
		case "primary":
			zonetype = tdns.Primary
		case "secondary":
			zonetype = tdns.Secondary
			if zconf.Primary == "" {
				log.Printf("Error: Zone %s is a secondary zone but has no primary (upstream) configured. Zone ignored.", zname)
				delete(zones, zname)
			}

		default:
			log.Printf("Error: Zone %s: Unknown zone type: \"%s\". Zone ignored.", zname, zconf.Type)
			delete(zones, zname)
		}

		dump.P(zconf)

		_, exist = conf.DnssecPolicies[zconf.DnssecPolicy]
		if !exist {
			log.Printf("Error: Zone %s refers to non-existing DNSSEC policy %s. Ignored.", zname, zconf.DnssecPolicy)
			zconf.DnssecPolicy = ""
		}

		log.Printf("ParseZones: zone %s: type: %s, store: %s, primary: %s, notify: %v, zonefile: %s",
			zname, zconf.Type, zconf.Store, zconf.Primary, zconf.Notify, zconf.Zonefile)

		log.Printf("ParseZones: zone %s incoming options: %v", zname, zconf.Options)
		options := map[string]bool{}
		var cleanoptions []string
		for _, option := range zconf.Options {
			option := strings.ToLower(option)
			switch option {
			case "delegation-sync-parent", // as a parent, publish supported DSYNC schemes
				"delegation-sync-child", // as a child, try to sync with parent via DSYNC scheme
				"online-signing",        // zone may be signed (and re-signed) online as needed
				"allow-updates",         // zone allows DNS UPDATEs to authoritiative data
				"allow-child-updates",   // zone allows updates to child delegation information
				"fold-case",             // fold case of owner names to lower to make query matching case insensitive
				"sign-zone",             // keep zone signed
				"black-lies",            // zone may implement DNSSEC signed negative responses via so-called black lies.
				"publish-key":           // publish a SIG(0) KEY recordfor the zone
				options[option] = true
				cleanoptions = append(cleanoptions, option)
			default:
				log.Printf("Error: Zone %s: Unknown option: \"%s\". Zone ignored.", zname, option)
				delete(zones, zname)
			}
		}
		zconf.Options = cleanoptions
		zones[zname] = zconf
		log.Printf("ParseZones: zone %s outgoing options: %v", zname, options)

		log.Printf("ParseZones: zone %s incoming update policy: %v", zname, zconf.UpdatePolicy)

		for _, ptype := range []string{zconf.UpdatePolicy.Child.Type, zconf.UpdatePolicy.Zone.Type} {
			switch ptype {
			case "selfsub", "self":
				// all ok, we know these
			case "none", "":
				// these are also ok, but imply that no updates are allowed
				options["allowupdates"] = false
				options["allowchildupdates"] = false
			default:
				log.Fatalf("Error: zone %s has an unknown update policy type: \"%s\". Terminating.", zname, ptype)
			}
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

		policy := tdns.UpdatePolicy{
			Child: tdns.UpdatePolicyDetail{
				Type:         zconf.UpdatePolicy.Child.Type,
				RRtypes:      childrrtypes,
				KeyBootstrap: zconf.UpdatePolicy.Child.KeyBootstrap,
				KeyUpload:    zconf.UpdatePolicy.Child.KeyUpload,
			},
			Zone: tdns.UpdatePolicyDetail{
				Type:    zconf.UpdatePolicy.Zone.Type,
				RRtypes: zonerrtypes,
			},
		}
		log.Printf("ParseZones: zone %s outgoing options: %v", zname, options)

		zrch <- tdns.ZoneRefresher{
			Name:         zname,
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

	conf.Zones = zones

	ValidateZones(conf, tdns.ZonesCfgFile) // will terminate on error
	log.Printf("All configured zones now refreshing: %v", all_zones)
	return nil
}

func ExpandTemplate(zconf tdns.ZoneConf, tmpl tdns.TemplateConf) (tdns.ZoneConf, error) {

	// for each field in tmpl, check whether it contains any data
	// and if so, then let that data overwrite the same field in zconf

	if tmpl.Type != "" {
		zconf.Type = tmpl.Type
	}
	if tmpl.Store != "" {
		fmt.Printf("ExpandTemplate: zone %s now uses the store \"%s\"\n", zconf.Name, tmpl.Store)
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
	if len(tmpl.Options) > 0 {
		zconf.Options = tmpl.Options
	}
	if (tmpl.UpdatePolicy.Child.Type != "" && len(tmpl.UpdatePolicy.Child.RRtypes) > 0) ||
		(tmpl.UpdatePolicy.Zone.Type != "" && len(tmpl.UpdatePolicy.Zone.RRtypes) > 0) {
		zconf.UpdatePolicy = tmpl.UpdatePolicy
	}

	if tmpl.DnssecPolicy != "" {
		zconf.DnssecPolicy = tmpl.DnssecPolicy
	}

	return zconf, nil
}
