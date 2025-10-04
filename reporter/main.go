/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"fmt"

	"github.com/johanix/tdns/tdns"
)

func main() {
	var tconf tdns.Config

	tdns.Globals.App.Type = tdns.AppTypeReporter
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Date = appDate

	// These are set here to enable various config reload functions to reload from the correct files.
	// tconf.Internal.CfgFile = tdns.DefaultReporterCfgFile
	// tconf.Internal.ZonesCfgFile = tdns.ZonesCfgFile

	err := tconf.MainInit(tdns.DefaultReporterCfgFile)
	if err != nil {
		tdns.Shutdowner(&tconf, fmt.Sprintf("Error initializing TDNS: %v", err))
	}

	apirouter, err := tdns.SetupAPIRouter(&tconf) // sidecar mgmt API is a combo of TDNS and MUSIC
	if err != nil {
		tdns.Shutdowner(&tconf, fmt.Sprintf("Error setting up API router: %v", err))
	}
	err = tdns.MainStartThreads(&tconf, apirouter)
	if err != nil {
		tdns.Shutdowner(&tconf, fmt.Sprintf("Error starting TDNS threads: %v", err))
	}

	tdns.MainLoop(&tconf)
}
