/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// StartImrForCli initializes and starts the internal IMR for CLI commands.
// It sets up the minimal config, starts RecursorEngine, and waits for initialization.
// Returns the context, cancel function, and the Imr instance, or an error if initialization fails.
func StartImrForCli(rootHints string) (context.Context, context.CancelFunc, *tdns.Imr, error) {
	// Set up minimal config for IMR
	active := true
	Conf.Imr.Active = &active
	if rootHints != "" {
		Conf.Imr.RootHints = rootHints
	}
	Conf.Imr.Verbose = tdns.Globals.Verbose
	Conf.Imr.Debug = tdns.Globals.Debug
	Conf.Internal.RecursorCh = make(chan tdns.ImrRequest, 10)

	// Start ImrEngine to initialize the internal IMR
	// Pass quiet=true to suppress startup logging
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		err := Conf.ImrEngine(ctx, true)
		if err != nil {
			cancel()
			log.Fatalf("Error: %v", err)
		}
	}()

	// Wait for ImrEngine to initialize and create the Imr instance
	// ImrEngine creates the Imr synchronously before entering its main loop
	maxWait := 2 * time.Second
	checkInterval := 50 * time.Millisecond
	waited := time.Duration(0)
	for Conf.Internal.ImrEngine == nil && waited < maxWait {
		time.Sleep(checkInterval)
		waited += checkInterval
	}

	// Check if ImrEngine is available
	if Conf.Internal.ImrEngine == nil {
		cancel()
		return nil, nil, nil, fmt.Errorf("ImrEngine not initialized after %v. RecursorEngine may not have started properly", maxWait)
	}

	return ctx, cancel, Conf.Internal.ImrEngine, nil
}

var DsyncDiscoveryCmd = &cobra.Command{
	Use:   "dsync-query",
	Short: "Send a DNS query for 'zone. DSYNC' and present the result.",
	Run: func(cmd *cobra.Command, args []string) {

		PrepArgs("zonename")
		tdns.Globals.Zonename = dns.Fqdn(tdns.Globals.Zonename)

		// Initialize internal IMR
		ctx, cancel, imr, err := StartImrForCli("")
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		defer cancel()

		// Use internal IMR to discover DSYNC records
		dsync_res, err := imr.DsyncDiscovery(ctx, tdns.Globals.Zonename, tdns.Globals.Verbose)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		fmt.Printf("Parent: %s\n", dsync_res.Parent)
		if len(dsync_res.Rdata) == 0 {
			fmt.Printf("No DSYNC record associated with '%s'\n", tdns.Globals.Zonename)
		} else {
			for _, nr := range dsync_res.Rdata {
				fmt.Printf("%s\tIN\tDSYNC\t%s\n", dsync_res.Qname, nr.String())
			}
		}
	},
}
