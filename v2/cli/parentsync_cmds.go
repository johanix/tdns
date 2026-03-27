/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/ryanuber/columnize"
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

var agentParentSyncBootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Trigger SIG(0) KEY bootstrap with parent for a zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "zonename")
		zone := cmd.Flag("zone").Value.String()

		amr, err := SendAgentMgmtCmd(&tdns.AgentMgmtPost{
			Command: "parentsync-bootstrap",
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

var agentParentSyncInquireCmd = &cobra.Command{
	Use:   "inquire",
	Short: "KeyState EDNS(0) inquiry commands",
}

var agentParentSyncInquireUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Send KeyState EDNS(0) inquiry about the current SIG(0) key to the parent",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "zonename")
		zone := cmd.Flag("zone").Value.String()

		amr, err := SendAgentMgmtCmd(&tdns.AgentMgmtPost{
			Command: "parentsync-inquire",
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
			fmt.Printf("%s\n", amr.Msg)
			return
		}

		displayKeyStateInquiry(dataMap)
	},
}

func displayKeyStateInquiry(d map[string]interface{}) {
	zone, _ := d["zone"].(string)
	keyid, _ := d["keyid"].(float64)
	stateName, _ := d["state_name"].(string)
	state, _ := d["state"].(float64)
	extra, _ := d["extra_text"].(string)

	fmt.Printf("KeyState Inquiry for %s\n", zone)
	fmt.Printf("  KeyID:        %d\n", int(keyid))
	fmt.Printf("  Parent says:  %s (code %d)\n", stateName, int(state))
	if extra != "" {
		fmt.Printf("  Extra:        %s\n", extra)
	}
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

	// Parent trust state (from last KeyState inquiry)
	parentStateName, _ := d["parent_state_name"].(string)
	if parentStateName != "" {
		fmt.Printf("    Parent trust:  %s\n", parentStateName)
	} else {
		fmt.Printf("    Parent trust:  (not checked)\n")
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

var agentParentSyncDeltaCmd = &cobra.Command{
	Use:   "delta",
	Short: "Compute delta between parent delegation data and child zone data",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		prefixcmd, _ := GetCommandContext("parentsync")
		api, err := GetApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		if schemestr != "" {
			val, err := strconv.ParseUint(schemestr, 10, 8)
			if err != nil {
				fmt.Printf("Error: invalid scheme value %q: %s\n", schemestr, err)
				return
			}
			scheme = uint8(val)
		}

		dr, err := SendDelegationCmd(api, tdns.DelegationPost{
			Command: "status",
			Zone:    tdns.Globals.Zonename,
		})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		if dr.Error {
			fmt.Printf("Error: %s\n", dr.ErrorMsg)
			os.Exit(1)
		}

		fmt.Printf("%s\n", dr.Msg)
		if dr.SyncStatus.InSync {
			fmt.Printf("Delegation information in parent %s is in sync with child %s. No action needed.\n",
				dr.SyncStatus.Parent, dr.SyncStatus.ZoneName)
			os.Exit(0)
		}
		fmt.Printf("Delegation information in parent %q is NOT in sync with child %q. Changes needed:\n",
			dr.SyncStatus.Parent, dr.SyncStatus.ZoneName)
		out := []string{"Change|RR"}
		for _, rr := range dr.SyncStatus.NsAddsStr {
			out = append(out, fmt.Sprintf("ADD NS|%s", rr))
		}
		for _, rr := range dr.SyncStatus.NsRemovesStr {
			out = append(out, fmt.Sprintf("DEL NS|%s", rr))
		}
		for _, rr := range dr.SyncStatus.AAddsStr {
			out = append(out, fmt.Sprintf("ADD IPv4 GLUE|%s", rr))
		}
		for _, rr := range dr.SyncStatus.ARemovesStr {
			out = append(out, fmt.Sprintf("DEL IPv4 GLUE|%s", rr))
		}
		for _, rr := range dr.SyncStatus.AAAAAddsStr {
			out = append(out, fmt.Sprintf("ADD IPv6 GLUE|%s", rr))
		}
		for _, rr := range dr.SyncStatus.AAAARemovesStr {
			out = append(out, fmt.Sprintf("DEL IPv6 GLUE|%s", rr))
		}
		fmt.Printf("%s\n", columnize.SimpleFormat(out))
	},
}

var agentParentSyncSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync delegation data in parent zone via DDNS UPDATE",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		prefixcmd, _ := GetCommandContext("parentsync")
		api, err := GetApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		if schemestr != "" {
			val, err := strconv.ParseUint(schemestr, 10, 8)
			if err != nil {
				fmt.Printf("Error: invalid scheme value %q: %s\n", schemestr, err)
				return
			}
			scheme = uint8(val)
		}

		dr, err := SendDelegationCmd(api, tdns.DelegationPost{
			Command: "sync",
			Scheme:  scheme,
			Zone:    tdns.Globals.Zonename,
		})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		if dr.Error {
			fmt.Printf("Error: %s\n", dr.ErrorMsg)
			os.Exit(1)
		}

		fmt.Printf("%s\n", dr.Msg)
	},
}

func init() {
	AgentCmd.AddCommand(agentParentSyncCmd)
	agentParentSyncCmd.AddCommand(agentParentSyncStatusCmd)
	agentParentSyncCmd.AddCommand(agentParentSyncElectionCmd)
	agentParentSyncCmd.AddCommand(agentParentSyncBootstrapCmd)
	agentParentSyncCmd.AddCommand(agentParentSyncInquireCmd)
	agentParentSyncCmd.AddCommand(agentParentSyncDeltaCmd)
	agentParentSyncCmd.AddCommand(agentParentSyncSyncCmd)
	agentParentSyncInquireCmd.AddCommand(agentParentSyncInquireUpdateCmd)

	agentParentSyncStatusCmd.Flags().StringP("zone", "z", "", "Zone name (required)")
	agentParentSyncStatusCmd.MarkFlagRequired("zone")

	agentParentSyncElectionCmd.Flags().StringP("zone", "z", "", "Zone name (required)")
	agentParentSyncElectionCmd.MarkFlagRequired("zone")

	agentParentSyncBootstrapCmd.Flags().StringP("zone", "z", "", "Zone name (required)")
	agentParentSyncBootstrapCmd.MarkFlagRequired("zone")

	agentParentSyncInquireUpdateCmd.Flags().StringP("zone", "z", "", "Zone name (required)")
	agentParentSyncInquireUpdateCmd.MarkFlagRequired("zone")

	agentParentSyncSyncCmd.Flags().StringVarP(&schemestr, "scheme", "S", "", "Scheme to use for synchronization of delegation")
}
