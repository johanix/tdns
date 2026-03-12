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
		PrepArgs(cmd, "zonename")
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

		displayParentSyncStatus(zone, dataMap)
	},
}

var agentParentSyncElectionCmd = &cobra.Command{
	Use:   "election",
	Short: "Trigger leader re-election for a zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "zonename")
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

func displayParentSyncStatus(zone string, d map[string]interface{}) {
	fmt.Printf("Parent Sync Status for %s\n", zone)

	// --- Leader Election ---
	fmt.Printf("\n  Leader Election:\n")
	leader, _ := d["leader"].(string)
	isLeader, _ := d["is_leader"].(bool)
	term, _ := d["election_term"].(float64)

	leaderDisplay := leader
	if leaderDisplay == "" {
		leaderDisplay = "(none)"
	}
	if isLeader {
		leaderDisplay += "  (self"
		if expiryStr, ok := d["leader_expiry"].(string); ok {
			if expiry, err := time.Parse(time.RFC3339Nano, expiryStr); err == nil {
				remaining := time.Until(expiry).Truncate(time.Second)
				leaderDisplay += fmt.Sprintf(", expires in %s", remaining)
			}
		}
		leaderDisplay += ")"
	}
	fmt.Printf("    Leader:        %s\n", leaderDisplay)
	fmt.Printf("    Term:          %.0f\n", term)

	// --- Parent Sync Schemes ---
	fmt.Printf("\n  Parent Sync Schemes:\n")
	parentZone, _ := d["parent_zone"].(string)
	if parentZone != "" {
		fmt.Printf("    Parent zone:   %s\n", parentZone)
	}
	activeScheme, _ := d["active_scheme"].(string)
	if activeScheme != "" {
		fmt.Printf("    Active scheme: %s\n", activeScheme)
	}
	if schemes, ok := d["sync_schemes"].([]interface{}); ok && len(schemes) > 0 {
		fmt.Printf("    Available DSYNC schemes:\n")
		for _, sRaw := range schemes {
			if s, ok := sRaw.(map[string]interface{}); ok {
				scheme, _ := s["scheme"].(string)
				rrtype, _ := s["type"].(string)
				target, _ := s["target"].(string)
				port, _ := s["port"].(float64)
				fmt.Printf("      %-8s  type=%-6s  target=%s:%d\n", scheme, rrtype, target, int(port))
			}
		}
	} else {
		fmt.Printf("    (no DSYNC records found in parent)\n")
	}

	// --- SIG(0) KEY ---
	fmt.Printf("\n  SIG(0) KEY (for UPDATE scheme):\n")
	keyAlg, _ := d["key_algorithm"].(string)
	keyID, _ := d["key_id"].(float64)
	keyRR, _ := d["key_rr"].(string)
	if keyAlg != "" {
		fmt.Printf("    Algorithm:     %s (key-id %d)\n", keyAlg, int(keyID))
		fmt.Printf("    KEY RDATA:     %s\n", keyRR)
	} else {
		fmt.Printf("    Key:           (none generated)\n")
	}

	apexPublished, _ := d["apex_published"].(bool)
	if apexPublished {
		fmt.Printf("    Apex KEY:      PUBLISHED\n")
	} else {
		fmt.Printf("    Apex KEY:      NOT PUBLISHED\n")
	}

	// _signal KEY publication per child NS
	keyPub, _ := d["key_publication"].(map[string]interface{})
	if len(keyPub) > 0 {
		fmt.Printf("    _signal KEY:\n")
		for ownerName, published := range keyPub {
			pub, _ := published.(bool)
			st := "NOT PUBLISHED"
			if pub {
				st = "PUBLISHED"
			}
			fmt.Printf("      %-55s %s\n", ownerName, st)
		}
	}

	// --- CDS/CSYNC (for NOTIFY scheme / signed zones) ---
	zoneSigned, _ := d["zone_signed"].(bool)
	fmt.Printf("\n  CDS/CSYNC (for NOTIFY scheme):\n")
	fmt.Printf("    Zone signed:   %s\n", yesNo(zoneSigned))
	cdsPublished, _ := d["cds_published"].(bool)
	csyncPublished, _ := d["csync_published"].(bool)
	fmt.Printf("    CDS:           %s\n", publishedStatus(cdsPublished))
	fmt.Printf("    CSYNC:         %s\n", publishedStatus(csyncPublished))

	// --- Peers ---
	if peers, ok := d["peers"].([]interface{}); ok && len(peers) > 0 {
		fmt.Printf("\n  Peer Agents (%d):\n", len(peers))
		for _, pRaw := range peers {
			if p, ok := pRaw.(map[string]interface{}); ok {
				identity, _ := p["identity"].(string)
				state, _ := p["state"].(string)
				transport, _ := p["transport"].(string)
				operational, _ := p["operational"].(bool)
				opTag := ""
				if operational {
					opTag = "  OK"
				}
				fmt.Printf("    %-35s  state=%-12s  transport=%-4s%s\n", identity, state, transport, opTag)
			}
		}
	} else {
		fmt.Printf("\n  Peer Agents: (none)\n")
	}

	// --- Child NS ---
	if nsRaw, ok := d["child_ns"].([]interface{}); ok && len(nsRaw) > 0 {
		fmt.Printf("\n  Child NS:\n")
		for _, ns := range nsRaw {
			if s, ok := ns.(string); ok {
				fmt.Printf("    %s\n", s)
			}
		}
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func publishedStatus(b bool) string {
	if b {
		return "PUBLISHED"
	}
	return "NOT PUBLISHED"
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
