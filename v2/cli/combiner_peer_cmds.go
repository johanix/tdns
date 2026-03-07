/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * tdns-cli combiner peer ... — commands to the combiner regarding peers.
 * ping: CHUNK-based DNS ping from combiner to a specific agent.
 * resync: ask agents to re-send all zone data to the combiner.
 */

package cli

import (
	"fmt"
	"log"

	tdns "github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

// combinerPeerCmd is the prefix for combiner commands regarding peers.
var combinerPeerCmd = &cobra.Command{
	Use:   "peer",
	Short: "Commands to the combiner regarding peers",
	Long:  `Commands that instruct the combiner to perform an action toward a peer agent (e.g. ping, resync).`,
}

var combinerPeerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all known peer agents",
	Long: `Show all peer agents that this combiner knows about.
Displays both DNS and API transports independently with their current state.

Example:
  tdns-cliv2 combiner peer list
  tdns-cliv2 combiner peer list --verbose`,
	Run: func(cmd *cobra.Command, args []string) {
		listDistribPeers(cmd, "combiner")
	},
}

var combinerPeerPingID string

var combinerPeerPingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Ping an agent via DNS CHUNK",
	Long: `Ask the combiner to send a DNS CHUNK ping to the specified agent and report the result.

Example:
  tdns-cliv2 combiner peer ping --id agent.alpha.dnslab.`,
	Run: func(cmd *cobra.Command, args []string) {
		if combinerPeerPingID == "" {
			log.Fatalf("--id flag is required")
		}

		resp, err := SendCombinerDebugCmd(tdns.CombinerDebugPost{
			Command: "agent-ping",
			AgentID: combinerPeerPingID,
		})
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp.Error {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", resp.ErrorMsg)
			return
		}
		fmt.Println(resp.Msg)
	},
}

var combinerPeerResyncCmd = &cobra.Command{
	Use:   "resync",
	Short: "Ask agents to re-send all zone data to the combiner",
	Long: `Send an RFI SYNC to configured agents, requesting them to re-send all their
local zone data. Useful after combiner restart when in-memory agent contributions
are lost.

By default, sends to all agents for all zones. Use --zone and --agent to narrow scope.

Example:
  tdns-cliv2 combiner peer resync
  tdns-cliv2 combiner peer resync --zone=whisky.dnslab.
  tdns-cliv2 combiner peer resync --agent=agent.alpha.dnslab.`,
	Run: func(cmd *cobra.Command, args []string) {
		zone, _ := cmd.Flags().GetString("zone")
		agentID, _ := cmd.Flags().GetString("agent")

		resp, err := SendCombinerDebugCmd(tdns.CombinerDebugPost{
			Command: "agent-resync",
			Zone:    zone,
			AgentID: agentID,
		})
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp.Error {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", resp.ErrorMsg)
			return
		}
		fmt.Print(resp.Msg)
	},
}

func init() {
	combinerPeerCmd.AddCommand(combinerPeerListCmd)
	combinerPeerCmd.AddCommand(combinerPeerPingCmd)
	combinerPeerCmd.AddCommand(combinerPeerResyncCmd)
	CombinerCmd.AddCommand(combinerPeerCmd)

	combinerPeerListCmd.Flags().Bool("verbose", false, "Show detailed per-peer statistics")
	combinerPeerPingCmd.Flags().StringVar(&combinerPeerPingID, "id", "", "Identity of the peer to ping (required)")
	combinerPeerResyncCmd.Flags().String("zone", "", "Resync only this zone (default: all zones)")
	combinerPeerResyncCmd.Flags().String("agent", "", "Resync only this agent (default: all agents)")
}
