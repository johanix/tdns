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

	"github.com/johanix/tdns/tdns"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// getClientKeyFromParent maps a parent command name to its corresponding clientKey.
// Returns empty string if parent is unknown.
func getClientKeyFromParent(parent string) string {
	switch parent {
	case "auth", "server":
		return "tdns-auth"
	case "combiner":
		return "tdns-combiner"
	case "msa":
		return "tdns-msa"
	case "agent":
		return "tdns-agent"
	case "scanner":
		return "tdns-scanner"
	case "imr":
		return "tdns-imr"
	case "kdc":
		return "tdns-kdc"
	case "krs":
		return "tdns-krs"
	default:
		return ""
	}
}

func getApiClient(parent string, dieOnError bool) (*tdns.ApiClient, error) {
	clientKey := getClientKeyFromParent(parent)
	if clientKey == "" {
		if dieOnError {
			log.Fatalf("Unknown parent command: %s", parent)
		}
		return nil, fmt.Errorf("unknown parent command: %s", parent)
	}

	client := tdns.Globals.ApiClients[clientKey]
	if client == nil {
		if dieOnError {
			keys := make([]string, 0, len(tdns.Globals.ApiClients))
			for k := range tdns.Globals.ApiClients {
				keys = append(keys, k)
			}
			log.Fatalf("No API client found for %s (have clients for: %v)", clientKey, keys)
		}
		return nil, fmt.Errorf("no API client found for %s", clientKey)
	}

	if tdns.Globals.Debug {
		fmt.Printf("Using API client for %q:\nBaseUrl: %s\n", clientKey, client.BaseUrl)
	}
	return client, nil
}

// getApiDetailsByClientKey retrieves the ApiDetails configuration for a given clientKey
// by looking it up in the CLI config via viper.
func getApiDetailsByClientKey(clientKey string) map[string]interface{} {
	apiservers := viper.Get("apiservers")
	if apiservers == nil {
		return nil
	}

	servers, ok := apiservers.([]interface{})
	if !ok {
		return nil
	}

	for _, server := range servers {
		serverMap, ok := server.(map[string]interface{})
		if !ok {
			continue
		}
		if name, ok := serverMap["name"].(string); ok && name == clientKey {
			return serverMap
		}
	}
	return nil
}

// getCommandContext takes the current command name and returns both the immediate parent
// and the full command chain from os.Args
//
// This is a workaround, as cobra is not able to get the correct parent command name when
// using the same command for different parents.
func getCommandContext(cmdName string) (parent string, chain []string) {
	args := os.Args[1:] // Skip program name
	for i, arg := range args {
		if arg == cmdName {
			if i > 0 {
				parent = args[i-1]
			} else {
				parent = "server" // Default to "server" for backward compatibility
			}
			if tdns.Globals.Debug {
				// fmt.Printf("getCommandContext: parent: %s, chain: %v\n", parent, args[:i+1])
			}
			return parent, args[:i+1]
		}
	}
	if tdns.Globals.Debug {
		fmt.Printf("getCommandContext: default case, parent: %s, chain: %v\n", parent, args)
	}
	return "server", nil // Default case if command not found (shouldn't happen)
}

var PingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Send an API ping request and present the response",
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("ping")
		// fmt.Printf("Actual parent: %s, Full chain: %v\n", parent, chain)

		if len(args) != 0 {
			log.Fatal("ping must have no arguments")
		}

		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client for %s: %v", prefixcmd, err)
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
	},
}

func init() {
	CombinerCmd.AddCommand(PingCmd)
	AgentCmd.AddCommand(PingCmd)
	// ScannerCmd.AddCommand will be called from scanner_cmds.go init()
}
