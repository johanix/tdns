/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	"context"
	"fmt"

	_ "github.com/mattn/go-sqlite3"

	"github.com/johanix/tdns/tdns"
	// "github.com/orcaman/concurrent-map/v2"
)

func main() {
	var conf tdns.Config

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

	// Set application globals
	tdns.Globals.App.Type = tdns.AppTypeServer
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Date = appDate

	// Define command-line flags
	//	pflag.StringVar(&conf.Internal.CfgFile, "config", tdns.DefaultServerCfgFile, "config file path")
	//	pflag.BoolVarP(&tdns.Globals.Verbose, "verbose", "v", false, "verbose output")
	//	pflag.BoolVarP(&tdns.Globals.Debug, "debug", "d", false, "debug output")

	// Parse command-line flags
	//	pflag.Parse()

	// Print help if requested
	//	if pflag.NArg() > 0 && (pflag.Arg(0) == "help" || pflag.Arg(0) == "--help" || pflag.Arg(0) == "-h") {
	//		fmt.Printf("Usage of %s:\n", os.Args[0])
	//		pflag.PrintDefaults()
	//		os.Exit(0)
	//	}

	// Display version information if in verbose mode
	if tdns.Globals.Verbose {
		fmt.Printf("%s %s (%s)\n", tdns.Globals.App.Name, tdns.Globals.App.Version, tdns.Globals.App.Date)
	}

	// Initialize the application
	err := conf.MainInit(tdns.DefaultServerCfgFile)
	if err != nil {
		tdns.Shutdowner(&conf, fmt.Sprintf("Error initializing TDNS: %v", err))
	}

	// Set up API router
	apirouter, err := tdns.SetupAPIRouter(&conf)
	if err != nil {
		tdns.Shutdowner(&conf, fmt.Sprintf("Error setting up API router: %v", err))
	}

	// Start application threads
    err = tdns.MainStartThreads(ctx, &conf, apirouter)
	if err != nil {
		tdns.Shutdowner(&conf, fmt.Sprintf("Error starting TDNS threads: %v", err))
	}

	// Enter main loop
    tdns.MainLoop(ctx, cancel, &conf)
}
