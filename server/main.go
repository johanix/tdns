/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	// "flag"
	"fmt"

	_ "github.com/mattn/go-sqlite3"

	"github.com/johanix/tdns/tdns"
	// "github.com/orcaman/concurrent-map/v2"
)

func main() {
	var conf tdns.Config

	conf.App.Mode = "server"
	conf.App.Version = appVersion
	conf.App.Name = appName
	conf.App.Date = appDate

	// These are the defaults, but they are defined here to make it possible for eg. MUSIC to use a different defaul
	conf.Internal.ZonesCfgFile = tdns.ZonesCfgFile
	conf.Internal.CfgFile = tdns.DefaultCfgFile

	err := tdns.MainInit(&conf)
	if err != nil {
		tdns.Shutdowner(&conf, fmt.Sprintf("Error initializing TDNS: %v", err))
	}

	_, err = tdns.ParseZones(&conf, conf.Internal.RefreshZoneCh, false) // false: not reload, initial parsing
	if err != nil {
		tdns.Shutdowner(&conf, fmt.Sprintf("Error parsing zones: %v", err))
	}

	apirouter, err := tdns.SetupAPIRouter(&conf)
	if err != nil {
		tdns.Shutdowner(&conf, fmt.Sprintf("Error setting up API router: %v", err))
	}
	err = tdns.MainStartThreads(&conf, apirouter)
	if err != nil {
		tdns.Shutdowner(&conf, fmt.Sprintf("Error starting TDNS threads: %v", err))
	}

	tdns.MainLoop(&conf)
}
