/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/johanix/tdns/tdns"
)

var appVersion string

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

			case <- conf.Internal.APIStopCh:
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
	Zones map[string]ZoneConf
}

func main() {
	var conf Config

	err := ParseConfig(&conf)

	logfile := viper.GetString("log.file")
	tdns.SetupLogging(logfile)
	fmt.Printf("Logging to file: %s\n", logfile)

	fmt.Printf("TDNSD version %s starting.\n", appVersion)

	var stopch = make(chan struct{}, 10)
	conf.Internal.RefreshZoneCh = make(chan tdns.ZoneRefresher, 10)
	conf.Internal.BumpZoneCh = make(chan BumperData, 10)
	go RefreshEngine(&conf, stopch)

	conf.Internal.ValidatorCh = make(chan tdns.ValidatorRequest, 10)
	go ValidatorEngine(&conf, stopch)

	err = ParseZones(conf.Zones, conf.Internal.RefreshZoneCh)
	if err != nil {
		log.Fatalf("Error parsing zones: %v", err)
	}

	err = tdns.RegisterNotifyRR()
	if err != nil {
		log.Fatalf("Error registering new RR types: %v", err)
	}

	err = tdns.RegisterDsyncRR()
	if err != nil {
		log.Fatalf("Error registering new RR types: %v", err)
	}

	apistopper := make(chan struct{}) //
	conf.Internal.APIStopCh = apistopper
	go APIdispatcher(&conf, apistopper)

	conf.Internal.ScannerQ = make(chan ScanRequest, 5)
	conf.Internal.UpdateQ = make(chan UpdateRequest, 5)

	go ScannerEngine(&conf)
	go UpdaterEngine(&conf)
	go DnsEngine(&conf)

	mainloop(&conf)
}

type TAtmp map[string]TmpAnchor

type TmpAnchor struct {
     Name	 string
     Dnskey	 string
}

//type Sig0config map[string]Sig0Key
//
//type Sig0Key struct {
//     Name	 string
//     Key	 dns.KEY
//}

func ParseConfig(conf *Config) error {
	viper.SetConfigFile(tdns.DefaultCfgFile)

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	} else {
		log.Fatalf("Could not load config %s: Error: %v", tdns.DefaultCfgFile, err)
	}

	viper.WriteConfigAs("/tmp/tdnsd.parsed.yaml")

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
	for key, _ := range conf.Zones {
		fmt.Printf(" [%s]", key)
	}
	fmt.Println()

	// If a validator trusted key config file is found, read it in.
	tafile := viper.GetString("validator.dnskey.trusted.file")
	if tafile != "" {
	   cfgdata, err := os.ReadFile(tafile)
	   if err != nil {
		log.Fatalf("Error from ReadFile(%s): %v", tafile, err)
	   }

	   var tatmp TAtmp
	   var taconf = make(tdns.TAconfig, 5)

	   err = yaml.Unmarshal(cfgdata, &tatmp)
	   if err != nil {
		log.Fatalf("Error from yaml.Unmarshal(TAtmp): %v", err)
           }

	   for k, v := range tatmp {
	       k = dns.Fqdn(k)
	       rr, err := dns.NewRR(v.Dnskey)
	       if err != nil {
		  log.Fatalf("Error from dns.NewRR(%s): %v", v.Dnskey, err)
	       }

	       if dnskeyrr, ok := rr.(*dns.DNSKEY); ok {
	       	  taconf[k] = tdns.TrustAnchor{
				Name:	k,
				Dnskey:	*dnskeyrr,
			   }
	       }
	   }
	   conf.Internal.TrustedDnskeys = taconf
	}

	// If a validator trusted key config file is found, read it in.
	sig0file := viper.GetString("validator.sig0.trusted.file")
	if sig0file != "" {
	   cfgdata, err := os.ReadFile(sig0file)
	   if err != nil {
		log.Fatalf("Error from ReadFile(%s): %v", sig0file, err)
	   }

	   var sig0conf tdns.Sig0config

	   err = yaml.Unmarshal(cfgdata, &sig0conf)
	   if err != nil {
		log.Fatalf("Error from yaml.Unmarshal(Sig0config): %v", err)
           }

	   conf.Internal.TrustedSig0keys = sig0conf
	}

	ValidateConfig(nil, tdns.DefaultCfgFile) // will terminate on error
	ValidateZones(conf, tdns.ZonesCfgFile) // will terminate on error
	return nil
}

func ParseZones(zones map[string]ZoneConf, zrch chan tdns.ZoneRefresher) error {
	var all_zones []string

	for zname, conf := range zones {
		all_zones = append(all_zones, zname)

		var zonestore tdns.ZoneStore

		switch strings.ToLower(conf.Store) {
		case "xfr":
			zonestore = tdns.XfrZone
		case "map":
			zonestore = tdns.MapZone
		case "slice":
			zonestore = tdns.SliceZone
		default:
			log.Fatalf("Unknown zone store type: \"%s\"", conf.Store)
		}

		var zonetype tdns.ZoneType

		switch strings.ToLower(conf.Type) {
		case "primary":
			zonetype = tdns.Primary
		case "secondary":
			zonetype = tdns.Secondary
		default:
			log.Fatalf("Unknown zone type: \"%s\"", conf.Type)
		}

		zrch <- tdns.ZoneRefresher{
			Name:      dns.Fqdn(zname),
			ZoneType:  zonetype, // primary | secondary
			Primary:   conf.Primary,
			ZoneStore: zonestore,
			Notify:    conf.Notify,
			Zonefile:  conf.Zonefile,
		}
	}

	log.Printf("All configured zones now refreshing: %v", all_zones)

	return nil
}
