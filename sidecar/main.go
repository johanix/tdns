/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/johanix/tdns/music"
	"github.com/johanix/tdns/music/fsm"
	tdns "github.com/johanix/tdns/tdns"
)

// yes, this must be global
// var tokvip *viper.Viper

// var cliconf = music.CliConfig{}

// var appVersion string
var appMode string

func mainloop(conf *tdns.Config, mconf *music.Config, appMode string) {
	log.Printf("mainloop: starting")
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	hupper := make(chan os.Signal, 1)
	signal.Notify(hupper, syscall.SIGHUP)

	var err error
	var all_zones []string
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
				// err = ParseZones(conf.Zones, conf.Internal.RefreshZoneCh)
				all_zones, err = tdns.ParseZones(conf, conf.Internal.RefreshZoneCh, true) // true = reload
				if err != nil {
					log.Fatalf("Error parsing zones: %v", err)
				} else {
					log.Printf("mainloop: SIGHUP received. Forcing refresh of %d configured zones.", len(all_zones))
				}

			case <-conf.Internal.APIStopCh:
				log.Println("mainloop: Stop command received. Cleaning up.")
				wg.Done()
			}
		}
	}()
	wg.Wait()

	// XXX: From musicd.
	mconf.Internal.TokViper.WriteConfig()
	fmt.Printf("mainloop: saved state of API tokens to disk\n")
	fmt.Println("mainloop: leaving signal dispatcher")

	fmt.Println("mainloop: leaving signal dispatcher")
}

func main() {
	var tconf tdns.Config
	var mconf music.Config

	tconf.AppMode, tdns.Globals.AppMode = "sidecar", "sidecar"
	tconf.ServerBootTime = time.Now()
	tconf.AppVersion, tdns.Globals.AppVersion = appVersion, appVersion
	tconf.AppName, tdns.Globals.AppName = appName, appName
	tconf.AppDate, tdns.Globals.AppDate = appDate, appDate
	// The agent is not a mode of operation, an agent should not be able to run as a server by just starting it with the wrong arguments.
	// flag.StringVar(&appMode, "mode", "agent", "Mode of operation: server | agent | scanner")

	flag.BoolVarP(&tdns.Globals.Debug, "debug", "d", false, "Debug mode")
	flag.BoolVarP(&tdns.Globals.Verbose, "verbose", "v", false, "Verbose mode")
	flag.Parse()

	switch tconf.AppMode {
	case "server", "agent", "sidecar", "scanner":
		fmt.Printf("*** TDNS mode of operation: %s (verbose: %t, debug: %t)\n", tconf.AppMode, tdns.Globals.Verbose, tdns.Globals.Debug)
	default:
		log.Fatalf("*** TDNS: Error: unknown mode of operation: %s", tconf.AppMode)
	}

	// XXX: From musicd.
	flag.Usage = func() {
		flag.PrintDefaults()
	}

	// These are set here to enable various config reload functions to reload from the correct files.
	tconf.Internal.CfgFile = music.DefaultSidecarTdnsCfgFile

	switch mconf.Zones.Config {
	case "":
		tconf.Internal.ZonesCfgFile = music.DefaultZonesCfgFile
	default:
		tconf.Internal.ZonesCfgFile = mconf.Zones.Config
	}

	err := tdns.ParseConfig(&tconf, false) // false = !reload, initial config
	if err != nil {
		log.Fatalf("Error parsing TDNS config %s: %v", music.DefaultSidecarTdnsCfgFile, err)
	}
	kdb := tconf.Internal.KeyDB
	kdb.UpdateQ = make(chan tdns.UpdateRequest, 10)

	tconf.Internal.UpdateQ = kdb.UpdateQ
	mconf.Internal.UpdateQ = kdb.UpdateQ
	mconf.Internal.KeyDB = kdb

	// Load MUSIC config; note that this must be after the TDNS config has been parsed and use viper.MergeConfig()
	music.LoadMusicConfig(&mconf, tconf.AppMode, false) // on initial startup a config error should cause an abort.

	// dump.P(mconf.Sidecar)

	logfile := viper.GetString("log.file")
	err = tdns.SetupLogging(logfile)
	if err != nil {
		log.Fatalf("Error setting up logging: %v", err)
	}
	fmt.Printf("Logging to file: %s\n", logfile)
	log.Printf("Test of logging options.")

	fmt.Printf("TDNS Multi-Signer Agent version %s starting.\n", appVersion)

	var stopch = make(chan struct{}, 10)

	tconf.Internal.RefreshZoneCh = make(chan tdns.ZoneRefresher, 10)
	tconf.Internal.BumpZoneCh = make(chan tdns.BumperData, 10)
	tconf.Internal.DelegationSyncQ = make(chan tdns.DelegationSyncRequest, 10)
	tconf.Internal.MultiSignerSyncQ = make(chan tdns.MultiSignerSyncRequest, 10)

	mconf.Internal.HeartbeatQ = make(chan music.Heartbeat, 10)
	go tdns.RefreshEngine(&tconf, stopch, appMode)

	//	conf.Internal.ValidatorCh = make(chan tdns.ValidatorRequest, 10)
	// 	go ValidatorEngine(&conf, stopch)

	tconf.Internal.NotifyQ = make(chan tdns.NotifyRequest, 10)
	go tdns.Notifier(tconf.Internal.NotifyQ)

	mconf.Internal.MultiSignerSyncQ = tconf.Internal.MultiSignerSyncQ
	// The MusicSyncEngine is started here to ensure that it is running before we start parsing zones.
	go music.MusicSyncEngine(&mconf, stopch)

	// ParseZones will read zone configs from the file specified in tconf.Internal.ZonesCfgFile
	all_zones, err := tdns.ParseZones(&tconf, tconf.Internal.RefreshZoneCh, false) // false = !reload, initial config
	if err != nil {
		log.Fatalf("Error parsing zones: %v", err)
	}

	//	go func() {
	//		time.Sleep(5 * time.Second)
	err = music.LoadSidecarConfig(&mconf, &tconf, all_zones)
	if err != nil {
		fmt.Printf("Error loading sidecar config: %v\n", err)
		log.Fatalf("Error loading sidecar config: %v", err)
	}
	//	}()

	apistopper := make(chan struct{}) //
	tconf.Internal.APIStopCh = apistopper

	go APIdispatcher(&tconf, &mconf, apistopper)          // sidecar mgmt API:
	go MusicSyncAPIdispatcher(&tconf, &mconf, apistopper) // sidecar-to-sidecar sync API:

	tconf.Internal.ScannerQ = make(chan tdns.ScanRequest, 5)
	tconf.Internal.DnsUpdateQ = make(chan tdns.DnsUpdateRequest, 100)
	tconf.Internal.DnsNotifyQ = make(chan tdns.DnsNotifyRequest, 100)
	tconf.Internal.AuthQueryQ = make(chan tdns.AuthQueryRequest, 100)
	tconf.Internal.ResignQ = make(chan *tdns.ZoneData, 10)

	go tdns.AuthQueryEngine(tconf.Internal.AuthQueryQ)
	go tdns.ScannerEngine(tconf.Internal.ScannerQ, tconf.Internal.AuthQueryQ)
	go kdb.ZoneUpdaterEngine(stopch)
	go tdns.UpdateHandler(&tconf)
	go tdns.NotifyHandler(&tconf)
	go tdns.DnsEngine(&tconf)
	go kdb.DelegationSyncher(tconf.Internal.DelegationSyncQ, tconf.Internal.NotifyQ)

	// The ResignerEngine is needed only for the sidecar auto zones.
	go tdns.ResignerEngine(tconf.Internal.ResignQ, make(chan struct{}))

	mconf.Internal.EngineCheck = make(chan music.EngineCheck, 100)

	mconf.Internal.MusicDB, err = music.NewDB(viper.GetString("db.file"), viper.GetString("db.mode"), false) // Don't drop status tables if they exist
	if err != nil {
		log.Fatalf("Error from NewDB(%s): %v", viper.GetString("db.file"), err)
	}

	mconf.Internal.TokViper = music.TokVip
	mconf.Internal.MusicDB.Tokvip = music.TokVip
	fsml := fsm.NewFSMlist()
	mconf.Internal.Processes = fsml
	mconf.Internal.MusicDB.FSMlist = fsml

	// deSEC stuff
	mconf.Internal.DesecFetch = make(chan music.SignerOp, 100)
	mconf.Internal.DesecUpdate = make(chan music.SignerOp, 100)
	mconf.Internal.DdnsFetch = make(chan music.SignerOp, 100)
	mconf.Internal.DdnsUpdate = make(chan music.SignerOp, 100)

	rootcafile := viper.GetString("common.rootCA")
	desecapi, err := music.DesecSetupClient(rootcafile, music.CliConf.Verbose, music.CliConf.Debug)
	if err != nil {
		log.Fatalf("Error from DesecSetupClient: %v\n", err)
	}
	desecapi.TokViper = music.TokVip

	rldu := music.Updaters["rldesec-api"]
	rldu.SetChannels(mconf.Internal.DesecFetch, mconf.Internal.DesecUpdate)
	rldu.SetApi(*desecapi)
	du := music.Updaters["desec-api"]
	du.SetApi(*desecapi) // it is ok to reuse the same object here

	rlddu := music.Updaters["rlddns"]
	rlddu.SetChannels(mconf.Internal.DdnsFetch, mconf.Internal.DdnsUpdate)

	var done = make(chan struct{}, 1)

	// XXX: From musicd.
	go music.DbUpdater(&mconf)
	go music.DeSECmgr(&mconf, done)
	go music.DdnsMgr(&mconf, done)
	go music.FSMEngine(&mconf, done)

	mainloop(&tconf, &mconf, appMode)
}
