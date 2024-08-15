/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cmd

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/johanix/tdns/tdns"
	"github.com/spf13/cobra"
)

var pings int

var PingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Send an API ping request and present the response",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 0 {
			log.Fatal("ping must have no arguments")
		}

		pr, err := tdns.Globals.Api.SendPing(tdns.Globals.PingCount, false)
		if err != nil {
			if strings.Contains(err.Error(), "connection refused") {
				fmt.Printf("Error: connection refused. Most likely the daemon is not running\n")
				os.Exit(1)
			} else {
				log.Fatalf("Error from SendPing: %v", err)
			}
		}

		uptime := time.Now().Sub(pr.BootTime).Truncate(time.Second)
		if tdns.Globals.Verbose {
			fmt.Printf("%s from %s @ %s (version %s): pings: %d, pongs: %d, uptime: %v time: %s, client: %s\n",
				pr.Msg, pr.Daemon, pr.ServerHost, pr.Version, pr.Pings,
				pr.Pongs, uptime, pr.Time.Format(timelayout), pr.Client)
		} else {
			fmt.Printf("%s: pings: %d, pongs: %d, uptime: %v, time: %s\n",
				pr.Msg, pr.Pings, pr.Pongs, uptime, pr.Time.Format(timelayout))
		}
	},
}
