/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"fmt"
	"log"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

var agentParentSyncCmd = &cobra.Command{
	Use:   "parentsync",
	Short: "Parent delegation sync commands",
}

var agentParentSyncStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show parent sync status for a zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename", cmd)
		zone := cmd.Flag("zone").Value.String()

		amr, err := SendAgentMgmtCmd(&tdns.AgentMgmtPost{
			Command: "parentsync-status",
			Zone:    tdns.ZoneName(zone),
		}, "parentsync")
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		if amr.Error {
			log.Fatalf("Error from agent: %s", amr.ErrorMsg)
		}

		dataMap, ok := amr.Data.(map[string]interface{})
		if !ok {
			fmt.Printf("Parent Sync Status for %s: no data available\n", zone)
			return
		}

		fmt.Printf("Parent Sync Status for %s\n", zone)

		// Leader info
		leader, _ := dataMap["leader"].(string)
		isLeader, _ := dataMap["is_leader"].(bool)
		term, _ := dataMap["election_term"].(float64)

		leaderDisplay := leader
		if leaderDisplay == "" {
			leaderDisplay = "(none)"
		}
		if isLeader {
			leaderDisplay += "  (self"
			if expiryStr, ok := dataMap["leader_expiry"].(string); ok {
				if expiry, err := time.Parse(time.RFC3339Nano, expiryStr); err == nil {
					remaining := time.Until(expiry).Truncate(time.Second)
					leaderDisplay += fmt.Sprintf(", expires in %s", remaining)
				}
			}
			leaderDisplay += ")"
		}
		fmt.Printf("  Leader:          %s\n", leaderDisplay)
		fmt.Printf("  Election term:   %.0f\n", term)

		// KEY info
		keyAlg, _ := dataMap["key_algorithm"].(string)
		keyID, _ := dataMap["key_id"].(float64)
		keyRR, _ := dataMap["key_rr"].(string)
		if keyAlg != "" {
			fmt.Printf("  SIG(0) KEY:      %s (key-id %d)\n", keyAlg, int(keyID))
			fmt.Printf("  KEY RDATA:       %s\n", keyRR)
		} else {
			fmt.Printf("  SIG(0) KEY:      (none)\n")
		}

		// Apex publication
		apexPublished, _ := dataMap["apex_published"].(bool)
		if apexPublished {
			fmt.Printf("  Apex KEY:        PUBLISHED\n")
		} else {
			fmt.Printf("  Apex KEY:        NOT PUBLISHED\n")
		}

		// _signal KEY publication per child NS
		keyPub, _ := dataMap["key_publication"].(map[string]interface{})
		if len(keyPub) > 0 {
			fmt.Printf("  _signal KEY Publication (child NS):\n")
			for ownerName, published := range keyPub {
				pub, _ := published.(bool)
				status := "NOT PUBLISHED"
				if pub {
					status = "PUBLISHED"
				}
				fmt.Printf("    %-55s %s\n", ownerName, status)
			}
		}
	},
}

var agentParentSyncElectionCmd = &cobra.Command{
	Use:   "election",
	Short: "Trigger leader re-election for a zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename", cmd)
		zone := cmd.Flag("zone").Value.String()

		amr, err := SendAgentMgmtCmd(&tdns.AgentMgmtPost{
			Command: "parentsync-election",
			Zone:    tdns.ZoneName(zone),
		}, "parentsync")
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		if amr.Error {
			log.Fatalf("Error from agent: %s", amr.ErrorMsg)
		}

		fmt.Printf("%s\n", amr.Msg)
	},
}

func init() {
	AgentCmd.AddCommand(agentParentSyncCmd)
	agentParentSyncCmd.AddCommand(agentParentSyncStatusCmd)
	agentParentSyncCmd.AddCommand(agentParentSyncElectionCmd)

	agentParentSyncStatusCmd.Flags().StringP("zone", "z", "", "Zone name (required)")
	agentParentSyncStatusCmd.MarkFlagRequired("zone")

	agentParentSyncElectionCmd.Flags().StringP("zone", "z", "", "Zone name (required)")
	agentParentSyncElectionCmd.MarkFlagRequired("zone")
}
