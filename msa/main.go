/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"fmt"
	"log"

	"github.com/johanix/tdns/music"
	"github.com/johanix/tdns/music/fsm"
	"github.com/johanix/tdns/tdns"
)

func main() {
	var tconf tdns.Config
	var mconf music.Config

	tconf.App.Mode = tdns.AppTypeMSA
	tconf.App.Version = appVersion
	tconf.App.Name = appName
	tconf.App.Date = appDate

	// These are set here to enable various config reload functions to reload from the correct files.
	tconf.Internal.CfgFile = music.DefaultMSACfgFile

	// XXX: Zones should be loaded from the main config
	switch mconf.Zones.Config {
	case "":
		tconf.Internal.ZonesCfgFile = music.DefaultZonesCfgFile
	default:
		tconf.Internal.ZonesCfgFile = mconf.Zones.Config
	}

	err := tdns.MainInit(&tconf)
	if err != nil {
		tdns.Shutdowner(&tconf, fmt.Sprintf("Error initializing TDNS: %v", err))
	}

	mconf.Internal.KeyDB = tconf.Internal.KeyDB
	mconf.Internal.UpdateQ = tconf.Internal.UpdateQ
	mconf.Internal.DeferredUpdateQ = tconf.Internal.DeferredUpdateQ

	// Load MUSIC config; note that this must be after the TDNS config has been parsed and use viper.MergeConfig()
	err = music.LoadMusicConfig(&mconf, tconf.App.Mode, false) // on initial startup a config error should cause an abort.
	if err != nil {
		tdns.Shutdowner(&tconf, fmt.Sprintf("Error loading MUSIC config: %v", err))
	}

	mconf.Internal.MusicSyncQ = tconf.Internal.MusicSyncQ
	// The MusicSyncEngine is started here to ensure that it is running before we start parsing zones.
	go music.MusicSyncEngine(&mconf, tconf.Internal.StopCh)

	// ParseZones will read zone configs from the file specified in tconf.Internal.ZonesCfgFile
	all_zones, err := tdns.ParseZones(&tconf, tconf.Internal.RefreshZoneCh, false) // false = !reload, initial config
	if err != nil {
		tdns.Shutdowner(&tconf, fmt.Sprintf("Error parsing zones: %v", err))
	}

	err = mconf.LoadSidecarConfig(&tconf, all_zones)
	if err != nil {
		tdns.Shutdowner(&tconf, fmt.Sprintf("Error loading sidecar config: %v", err))
	}

	apirouter, err := music.SetupAPIRouter(&tconf, &mconf) // sidecar mgmt API is a combo of TDNS and MUSIC
	if err != nil {
		tdns.Shutdowner(&tconf, fmt.Sprintf("Error setting up API router: %v", err))
	}
	err = tdns.MainStartThreads(&tconf, apirouter)
	if err != nil {
		tdns.Shutdowner(&tconf, fmt.Sprintf("Error starting TDNS threads: %v", err))
	}

	err = music.MainInit(&tconf, &mconf)
	if err != nil {
		tdns.Shutdowner(&tconf, fmt.Sprintf("Error initializing MUSIC: %v", err))
	}

	mconf.Internal.TokViper = music.TokVip

	fsml := fsm.NewFSMlist()
	mconf.Internal.Processes = fsml
	mconf.Internal.MusicDB.FSMlist = fsml

	tdns.MainLoop(&tconf)

	err = mconf.Internal.TokViper.WriteConfig()
	if err != nil {
		log.Printf("Error saving state of API tokens to disk: %v", err)
	} else {
		log.Printf("Saved state of API tokens to disk\n")
	}

}
