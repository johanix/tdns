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
		weeks := uptime / (7 * 24 * time.Hour)
		uptime %= 7 * 24 * time.Hour
		days := uptime / (24 * time.Hour)
		uptime %= 24 * time.Hour
		hours := uptime / time.Hour
		uptime %= time.Hour
		minutes := uptime / time.Minute
		uptime %= time.Minute
		seconds := uptime / time.Second

		var uptimeStr string
		if weeks > 0 {
			uptimeStr = fmt.Sprintf("%dw%dd", weeks, days)
		} else if days > 0 {
			uptimeStr = fmt.Sprintf("%dd%dh", days, hours)
		} else if hours > 0 {
			uptimeStr = fmt.Sprintf("%dh%dm", hours, minutes)
		} else {
			uptimeStr = fmt.Sprintf("%dm%ds", minutes, seconds)
		}

		if tdns.Globals.Verbose {
			fmt.Printf("%s (version %s): pings: %d, pongs: %d, uptime: %s, time: %s, client: %s\n",
				pr.Msg, pr.Version, pr.Pings, pr.Pongs, uptimeStr, pr.Time.Format(timelayout), pr.Client)
		} else {
			fmt.Printf("%s: pings: %d, pongs: %d, uptime: %s, time: %s\n",
				pr.Msg, pr.Pings, pr.Pongs, uptimeStr, pr.Time.Format(timelayout))
		}
	},
}
