/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	// "flag"
	"fmt"

	_ "github.com/mattn/go-sqlite3"

	"github.com/johanix/tdns/tdns"
)

func main() {
	var conf tdns.Config

	tdns.Globals.App.Type = tdns.AppTypeAgent
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Date = appDate

	// These are the defaults, but they are defined here to make it possible for eg. MUSIC to use a different defaul
	// conf.Internal.ZonesCfgFile = tdns.ZonesCfgFile
	// conf.Internal.CfgFile = tdns.DefaultAgentCfgFile

	err := conf.MainInit(tdns.DefaultAgentCfgFile)
	if err != nil {
		tdns.Shutdowner(&conf, fmt.Sprintf("Error initializing TDNS: %v", err))
	}

	// _, err = tdns.ParseZones(&conf, conf.Internal.RefreshZoneCh, false) // false = !reload, initial config
	// if err != nil {
	// 	tdns.Shutdowner(&conf, fmt.Sprintf("Error parsing zones: %v", err))
	// }

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
