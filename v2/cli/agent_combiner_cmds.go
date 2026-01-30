/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * tdns-cli agent combiner ... — commands to the agent regarding the combiner.
 * ping: CHUNK-based (default) or API-based ping to the combiner; use --dns or --api (mutually exclusive).
 */

package cli

import (
	"fmt"
	"log"

	tdns "github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

// AgentCombinerCmd is the prefix for agent commands regarding the combiner.
var AgentCombinerCmd = &cobra.Command{
	Use:   "combiner",
	Short: "Commands to the agent regarding the combiner",
	Long:  `Commands that instruct the agent to perform an action toward the combiner (e.g. ping).`,
}

var (
	combinerPingDns  bool
	combinerPingApi  bool
)

var agentCombinerPingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Ping the combiner (CHUNK or API)",
	Long:  `Ask the agent to ping the combiner. Default is CHUNK-based (--dns). Use --api for HTTPS API ping.`,
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("combiner")
		if prefixcmd != "agent" {
			log.Fatalf("combiner commands must be run under agent (e.g. tdns-cli agent combiner ping)")
		}

		if combinerPingDns && combinerPingApi {
			log.Fatalf("use either --dns or --api, not both")
		}
		useAPI := combinerPingApi
		// default is --dns
		if !combinerPingDns && !combinerPingApi {
			useAPI = false
		}

		agentCmd := "combiner-dnsping"
		if useAPI {
			agentCmd = "combiner-apiping"
		}

		amr, err := SendAgentMgmtCmd(&tdns.AgentMgmtPost{
			Command: agentCmd,
		}, "combiner")
		if err != nil {
			log.Fatalf("Request failed: %v", err)
		}

		if amr.Error {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", amr.ErrorMsg)
			return
		}
		fmt.Println(amr.Msg)
	},
}

func init() {
	agentCombinerPingCmd.Flags().BoolVar(&combinerPingDns, "dns", false, "use CHUNK-based ping (default)")
	agentCombinerPingCmd.Flags().BoolVar(&combinerPingApi, "api", false, "use HTTPS API ping")
	AgentCombinerCmd.AddCommand(agentCombinerPingCmd)
	AgentCmd.AddCommand(AgentCombinerCmd)
}
