/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	// "flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/johanix/tdns/tdns"
	// "github.com/orcaman/concurrent-map/v2"
)

// var appVersion string
var appMode string

func mainloop(conf *Config) {
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	hupper := make(chan os.Signal, 1)
	signal.Notify(hupper, syscall.SIGHUP)

	var err error
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		for {
			// log.Println("mainloop: signal dispatcher")
			select {
			case <-exit:
				log.Println("mainloop: Exit signal received. Cleaning up.")
				// do whatever we need to do to wrap up nicely
				wg.Done()
			case <-hupper:
				log.Println("mainloop: SIGHUP received. Forcing refresh of all configured zones.")
				err = ParseZones(conf.Zones, conf.Internal.RefreshZoneCh)
				if err != nil {
					log.Fatalf("Error parsing zones: %v", err)
				}

			case <-conf.Internal.APIStopCh:
				log.Println("mainloop: Stop command received. Cleaning up.")
				wg.Done()
			}
		}
	}()
	wg.Wait()

	fmt.Println("mainloop: leaving signal dispatcher")
}

// const DefaultCfgFile = "/etc/axfr.net/tdnsd.yaml"

type Zconfig struct {
	Zones map[string]tdns.ZoneConf
}

func main() {
	var conf Config

	flag.StringVar(&appMode, "mode", "server", "Mode of operation: server | scanner")
	flag.BoolVarP(&tdns.Globals.Debug, "debug", "d", false, "Debug mode")
	flag.BoolVarP(&tdns.Globals.Verbose, "verbose", "v", false, "Verbose mode")
	flag.Parse()

	switch appMode {
	case "server", "scanner":
		fmt.Printf("*** TDNSD mode of operation: %s (verbose: %t, debug: %t)\n", appMode, tdns.Globals.Verbose, tdns.Globals.Debug)
	default:
		log.Fatalf("*** TDNSD: Error: unknown mode of operation: %s", appMode)
	}

	err := ParseConfig(&conf)
	if err != nil {
		log.Fatalf("Error parsing config: %v", err)
	}
	kdb := conf.Internal.KeyDB

	logfile := viper.GetString("log.file")
	tdns.SetupLogging(logfile)
	fmt.Printf("Logging to file: %s\n", logfile)

	fmt.Printf("TDNSD version %s starting.\n", appVersion)

	var stopch = make(chan struct{}, 10)

	conf.Internal.RefreshZoneCh = make(chan tdns.ZoneRefresher, 10)
	conf.Internal.BumpZoneCh = make(chan tdns.BumperData, 10)
	conf.Internal.DelegationSyncQ = make(chan tdns.DelegationSyncRequest, 10)
	go RefreshEngine(&conf, stopch)

	conf.Internal.ValidatorCh = make(chan tdns.ValidatorRequest, 10)
	go ValidatorEngine(&conf, stopch)

	conf.Internal.NotifyQ = make(chan tdns.NotifyRequest, 10)
	go tdns.Notifier(conf.Internal.NotifyQ)

	err = tdns.RegisterNotifyRR()
	if err != nil {
		log.Fatalf("Error registering new RR types: %v", err)
	}

	err = tdns.RegisterDsyncRR()
	if err != nil {
		log.Fatalf("Error registering new RR types: %v", err)
	}

	err = tdns.RegisterDelegRR()
	if err != nil {
		log.Fatalf("Error registering new RR types: %v", err)
	}

	err = ParseZones(conf.Zones, conf.Internal.RefreshZoneCh)
	if err != nil {
		log.Fatalf("Error parsing zones: %v", err)
	}

	apistopper := make(chan struct{}) //
	conf.Internal.APIStopCh = apistopper
	go APIdispatcher(&conf, apistopper)

	conf.Internal.ScannerQ = make(chan tdns.ScanRequest, 5)
	conf.Internal.UpdateQ = kdb.UpdateQ
	conf.Internal.DnsUpdateQ = make(chan tdns.DnsHandlerRequest, 100)
	conf.Internal.DnsNotifyQ = make(chan tdns.DnsHandlerRequest, 100)
	conf.Internal.AuthQueryQ = make(chan tdns.AuthQueryRequest, 100)

	go tdns.AuthQueryEngine(conf.Internal.AuthQueryQ)
	go tdns.ScannerEngine(conf.Internal.ScannerQ, conf.Internal.AuthQueryQ)
	go kdb.UpdaterEngine(stopch)
	go DnsUpdateResponderEngine(&conf)
	go DnsNotifyResponderEngine(&conf)
	go DnsEngine(&conf)
	go DelegationSyncher(&conf)

	mainloop(&conf)
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
	err = kdb.LoadChildSig0Keys()
	if err != nil {
		log.Fatalf("Error from LoadChildSig0Keys(): %v", err)
	}

	ValidateConfig(nil, tdns.DefaultCfgFile) // will terminate on error
	ValidateZones(conf, tdns.ZonesCfgFile)   // will terminate on error
	return nil
}

func ParseZones(zones map[string]tdns.ZoneConf, zrch chan tdns.ZoneRefresher) error {
	var all_zones []string

	for zname, zconf := range zones {
		if zname != dns.Fqdn(zname) {
			delete(zones, zname)
			zname = dns.Fqdn(zname)
			zconf.Name = zname
			zones[zname] = zconf
		}

		all_zones = append(all_zones, zname)

		var zonestore tdns.ZoneStore
		switch strings.ToLower(zconf.Store) {
		case "xfr":
			zonestore = tdns.XfrZone
		case "map":
			zonestore = tdns.MapZone
		case "slice":
			zonestore = tdns.SliceZone
		default:
			log.Fatalf("Unknown zone store type: \"%s\"", zconf.Store)
		}

		var zonetype tdns.ZoneType

		switch strings.ToLower(zconf.Type) {
		case "primary":
			zonetype = tdns.Primary
		case "secondary":
			zonetype = tdns.Secondary
		default:
			log.Fatalf("Unknown zone type: \"%s\"", zconf.Type)
		}

		log.Printf("ParseZones: zone %s: type: %s, store: %s, primary: %s, notify: %v, zonefile: %s",
			zname, zconf.Type, zconf.Store, zconf.Primary, zconf.Notify, zconf.Zonefile)

		log.Printf("ParseZones: zone %s incoming options: %v", zname, zconf.Options)
		options := map[string]bool{}
		var cleanoptions []string
		for _, option := range zconf.Options {
			option := strings.ToLower(option)
			switch option {
			case "delegationsync", "onlinesigning", "allowupdates", "allowchildupdates",
				"foldcase":
				options[option] = true
				cleanoptions = append(cleanoptions, option)
			default:
				log.Fatalf("Zone %s: Unknown option: \"%s\"", zname, option)
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
		var exist bool
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

		//			switch rrt {
		//			case "A", "AAAA", "MX", "TXT", "NS", "DS", "KEY":
		//				rrtypes[dns.StringToType[rrt]] = true
		//			default:
		//				log.Fatalf("Zone %s: Unsupported RRtype in update policy: \"%s\"", zname, rrt)
		//			}

		policy := tdns.UpdatePolicy{
			Child: tdns.UpdatePolicyDetail{
				Type:         zconf.UpdatePolicy.Child.Type,
				RRtypes:      childrrtypes,
				KeyBootstrap: zconf.UpdatePolicy.Child.KeyBootstrap,
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
		}
	}

	log.Printf("All configured zones now refreshing: %v", all_zones)

	return nil
}
