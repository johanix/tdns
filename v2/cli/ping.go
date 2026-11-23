/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

// NewPingCmd returns a fresh ping *cobra.Command bound to the given role.
// Each attachment site must create its own command (Cobra does not allow
// the same *cobra.Command under multiple parents). The role string is
// the registry key from RegisterRole.
func NewPingCmd(role string) *cobra.Command {
	c := &cobra.Command{
		Use:   "ping",
		Short: "Send an API ping request and present the response",
		Run: func(cmd *cobra.Command, args []string) {
			runPing(role, cmd, args)
		},
	}
	c.Flags().IntVarP(&tdns.Globals.PingCount, "count", "c", 0, "#pings to send")
	c.Flags().BoolVarP(&newapi, "newapi", "n", false, "use new api client")
	return c
}

func runPing(role string, cmd *cobra.Command, args []string) {
	if len(args) != 0 {
		log.Fatal("ping must have no arguments")
	}

	api, err := GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error getting API client for %s: %v", role, err)
	}

	pr, err := api.SendPing(tdns.Globals.PingCount, false)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			fmt.Printf("Error: connection refused. Most likely the daemon is not running\n")
			os.Exit(1)
		} else {
			log.Fatalf("Error from SendPing: %v", err)
		}
	}

	uptime := time.Since(pr.BootTime).Truncate(time.Second)
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
	// How this CLI reached the daemon, and who the daemon took it for: the
	// first things to look at when access does not work as expected. The
	// local admin socket is chosen at run time (through config-file:), so
	// the CLI config alone does not say which was used. Older daemons do not
	// report who they took the caller for.
	fmt.Printf("%s\n", pingVia(api))
	if pr.Auth != "" {
		fmt.Printf("%s\n", pr.Auth)
	}
}

// pingVia says how api reaches its daemon: over its local admin socket, or
// over TCP to its base URL.
func pingVia(api *tdns.ApiClient) string {
	if api.Socket != "" {
		return "via the local admin socket " + api.Socket
	}
	return "via TCP " + api.BaseUrl
}

func init() {
	AgentCmd.AddCommand(NewPingCmd("agent"))
}
