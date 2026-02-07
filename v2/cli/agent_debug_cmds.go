/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/gookit/goutil/dump"
	"github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var myIdentity, notifyRRtype, rfitype string

var DebugAgentCmd = &cobra.Command{
	Use:   "agent",
	Short: "TDNS-AGENT debugging commands",
}

var DebugAgentSendNotifyCmd = &cobra.Command{
	Use:   "send-notify",
	Short: "Tell agent to send a NOTIFY message to the other agents",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename", "identity")

		notifyRRtype = strings.ToUpper(notifyRRtype)
		if notifyRRtype != "NS" && notifyRRtype != "DNSKEY" {
			log.Fatalf("Error: RR type must be either NS or DNSKEY (is %q)", notifyRRtype)
		}

		if dnsRecord == "" {
			log.Fatalf("Error: DNS record is required")
		}

		var rr dns.RR
		var err error

		if rr, err = dns.NewRR(dnsRecord); err != nil {
			log.Fatalf("Error: Invalid DNS record (did not parse): %v", err)
		}

		rrs := []string{rr.String()}

		rrtype := dns.StringToType[notifyRRtype]
		if rrtype == 0 {
			log.Fatalf("Error: Invalid RR type: %s", notifyRRtype)
		}

		req := tdns.AgentMgmtPost{
			Command:     "send-notify",
			MessageType: tdns.AgentMsgNotify,
			RRType:      rrtype,
			Zone:        tdns.ZoneName(tdns.Globals.Zonename),
			AgentId:     tdns.Globals.AgentId,
			RRs:         rrs,
		}

		_, err = SendAgentDebugCmd(req, true)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
	},
}

var DebugAgentSendRfiCmd = &cobra.Command{
	Use:   "send-rfi",
	Short: "Tell agent to send an RFI message to another agent",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename", "identity")

		rfitype = strings.ToUpper(rfitype)
		if rfitype != "UPSTREAM" && rfitype != "DOWNSTREAM" {
			log.Fatalf("Error: RFI type must be either UPSTREAM or DOWNSTREAM (is %q)", rfitype)
		}

		req := tdns.AgentMgmtPost{
			Command:     "send-rfi",
			MessageType: tdns.AgentMsgRfi,
			RfiType:     rfitype,
			Zone:        tdns.ZoneName(tdns.Globals.Zonename),
			AgentId:     tdns.Globals.AgentId,
		}

		amr, err := SendAgentDebugCmd(req, false)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		// dump.P(amr)

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		fmt.Printf("Result from %s RFI message sent to agent %q:\n", amr.RfiType, amr.Identity)
		if len(amr.RfiResponse) > 0 {
			var out []string
			if tdns.Globals.ShowHeaders {
				out = append(out, "Zone|Provider|Where|XFR src|XFR dst|XFR auth")
			}
			for aid, rfidata := range amr.RfiResponse {
				if len(rfidata.ZoneXfrSrcs) > 0 {
					out = append(out, fmt.Sprintf("%s|%s|UPSTREAM|%v|%v|%v", tdns.Globals.Zonename, aid, rfidata.ZoneXfrSrcs, "", rfidata.ZoneXfrAuth))
				}
				if len(rfidata.ZoneXfrDsts) > 0 {
					out = append(out, fmt.Sprintf("%s|%s|DOWNSTREAM|%v|%v|%v", tdns.Globals.Zonename, aid, "", rfidata.ZoneXfrDsts, rfidata.ZoneXfrAuth))
				}
				// if len(rfidata.ZoneXfrAuth) > 0 {
				// 	fmt.Printf("ZoneXfrAuth for %q: %s", aid, rfidata.ZoneXfrAuth)
				// }
			}
			fmt.Printf("%s\n", columnize.SimpleFormat(out))
		} else {
			fmt.Printf("No RFI data in response from agent %q", amr.Identity)
		}
	},
}

var DebugAgentDumpAgentRegistryCmd = &cobra.Command{
	Use:   "dump-agentregistry",
	Short: "Dump the agent registry",
	Run: func(cmd *cobra.Command, args []string) {
		req := tdns.AgentMgmtPost{
			Command: "dump-agentregistry",
		}

		amr, err := SendAgentDebugCmd(req, false)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		// dump.P(amr.AgentRegistry)
		if len(amr.AgentRegistry.RegularS) == 0 {
			fmt.Printf("No agent registry data in response from agent %q", amr.Identity)
			os.Exit(1)
		}

		if len(amr.AgentRegistry.RegularS) > 0 {
			var agentNames []tdns.AgentId
			for _, agent := range amr.AgentRegistry.RegularS {
				agentNames = append(agentNames, agent.Identity)
			}
			fmt.Printf("Agent registry contains %d agents: %v\n", len(agentNames), agentNames)
			for _, agent := range amr.AgentRegistry.RegularS {
				err := PrintAgent(agent, false)
				if err != nil {
					log.Printf("Error printing agent: %v", err)
				}
				fmt.Println()
			}
		} else {
			fmt.Printf("No remote agents found in the agent registry data from agent %q", amr.Identity)
		}
	},
}

var DebugAgentDumpZoneDataRepoCmd = &cobra.Command{
	Use:   "dump-zonedatarepo",
	Short: "Dump the zone data repo",
	Run: func(cmd *cobra.Command, args []string) {
		req := tdns.AgentMgmtPost{
			Command: "dump-zonedatarepo",
		}

		amr, err := SendAgentDebugCmd(req, false)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		// dump.P(amr)

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		if tdns.Globals.Debug {
			dump.P(amr.ZoneDataRepo)
		}

		if len(amr.ZoneDataRepo) > 0 {
			for zone, agentRepo := range amr.ZoneDataRepo {
				fmt.Printf("*** Zone: %s\n", zone)
				for agentId, data := range agentRepo {
					fmt.Printf("*** Data from agent %s:\n", agentId)
					// dump.P(data)
					for rrtype, rrset := range data {
						fmt.Printf("*** RRType: %s\n", dns.TypeToString[rrtype])
						// dump.P(rrset)
						for _, rr := range rrset {
							fmt.Printf("*** RR: %s\n", rr)
						}
					}
				}
			}
		} else {
			fmt.Printf("No ZoneDataRepo data in response from agent %q", amr.Identity)
		}
	},
}

var DebugAgentRegistryCmd = &cobra.Command{
	Use:   "agentregistry",
	Short: "Test the agent registry",
	Run: func(cmd *cobra.Command, args []string) {
		conf := tdns.Config{
			Agent: &tdns.LocalAgentConf{
				Identity: "local",
			},
		}
		ar := conf.NewAgentRegistry()
		ar.LocateInterval = 10
		ar.S.Set("local", &tdns.Agent{
			Identity: "local",
		})

		ar.AddRemoteAgent("agent.example.com", &tdns.Agent{
			Identity: "agent.example.com",
		})

		ar.AddRemoteAgent("agent.example.org", &tdns.Agent{
			Identity: "agent.example.org",
		})

		fmt.Printf("Agent registry:\ntype=%T\n", ar.S)
		fmt.Printf("Agent registry:\n%d shards\n", ar.S.NumShards())
		for item := range ar.S.IterBuffered() {
			// agent, _ := item.Val.(*tdns.Agent)
			fmt.Printf("Agent registry:\n%s\n", item.Key)
			fmt.Printf("Agent registry:\n%+v\n", item.Val)
		}
	},
}

var DebugAgentTriggerSyncCmd = &cobra.Command{
	Use:   "trigger-sync",
	Short: "Trigger a sync operation for testing",
	Long: `Simulate a zone change and trigger sync to peers.
This is equivalent to hsync-inject-sync API endpoint.

Example:
  tdns-cliv2 debug agent trigger-sync --zone example.com --from agent.alpha --rr "test A 1.2.3.4"`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		fromAgent, _ := cmd.Flags().GetString("from")
		if fromAgent == "" {
			log.Fatalf("Error: --from agent ID is required")
		}

		rr, _ := cmd.Flags().GetString("rr")
		if rr == "" {
			log.Fatalf("Error: --rr is required")
		}

		req := tdns.AgentMgmtPost{
			Command: "hsync-inject-sync",
			Zone:    tdns.ZoneName(tdns.Globals.Zonename),
			AgentId: tdns.AgentId(fromAgent),
			RRs:     []string{rr},
		}

		amr, err := SendAgentDebugCmd(req, false)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		fmt.Printf("Sync triggered successfully:\n%s\n", amr.Msg)
	},
}

var DebugAgentForceSyncCmd = &cobra.Command{
	Use:   "force-sync",
	Short: "Force sync with a specific peer",
	Long: `Force synchronization with a specific peer agent.

Example:
  tdns-cliv2 debug agent force-sync --zone example.com --peer agent.bravo --rr "test A 1.2.3.4"`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		peerID, _ := cmd.Flags().GetString("peer")
		if peerID == "" {
			log.Fatalf("Error: --peer agent ID is required")
		}

		rr, _ := cmd.Flags().GetString("rr")
		var rrs []string
		if rr != "" {
			rrs = []string{rr}
		}

		req := tdns.AgentMgmtPost{
			Command: "hsync-force-sync",
			Zone:    tdns.ZoneName(tdns.Globals.Zonename),
			AgentId: tdns.AgentId(peerID),
			RRs:     rrs,
		}

		amr, err := SendAgentDebugCmd(req, false)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		fmt.Printf("Force sync completed:\n%s\n", amr.Msg)
		if amr.Data != nil {
			if corrID, ok := amr.Data.(map[string]interface{})["correlation_id"]; ok {
				fmt.Printf("Correlation ID: %v\n", corrID)
			}
		}
	},
}

var DebugAgentSyncStateCmd = &cobra.Command{
	Use:   "sync-state",
	Short: "Show sync state for a zone",
	Long: `Display the current synchronization state for a zone.

Example:
  tdns-cliv2 debug agent sync-state --zone example.com`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		req := tdns.AgentMgmtPost{
			Command: "hsync-sync-state",
			Zone:    tdns.ZoneName(tdns.Globals.Zonename),
		}

		amr, err := SendAgentDebugCmd(req, false)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		fmt.Printf("Sync State for zone %s:\n", tdns.Globals.Zonename)
		fmt.Printf("%s\n", amr.Msg)

		if amr.Data != nil {
			if dataMap, ok := amr.Data.(map[string]interface{}); ok {
				if zdr, ok := dataMap["zone_data_repo"]; ok {
					dump.P(zdr)
				}
			}
		}
	},
}

var DebugAgentSendToCombinerCmd = &cobra.Command{
	Use:   "send-to-combiner",
	Short: "Send test data to combiner",
	Long: `Send test zone data to the combiner for processing.

Example:
  tdns-cliv2 debug agent send-to-combiner --zone example.com --rr "test A 1.2.3.4"`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		rr, _ := cmd.Flags().GetString("rr")
		if rr == "" {
			log.Fatalf("Error: --rr is required")
		}

		req := tdns.AgentMgmtPost{
			Command: "hsync-send-to-combiner",
			Zone:    tdns.ZoneName(tdns.Globals.Zonename),
			RRs:     []string{rr},
		}

		amr, err := SendAgentDebugCmd(req, false)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		fmt.Printf("Data sent to combiner:\n%s\n", amr.Msg)
	},
}

var DebugAgentTestChainCmd = &cobra.Command{
	Use:   "test-chain",
	Short: "Run full end-to-end test chain",
	Long: `Execute a full end-to-end test including:
1. Local zone update
2. Sync to remote peers
3. Combiner processing

Example:
  tdns-cliv2 debug agent test-chain --zone example.com --scenario add --rr "test A 1.2.3.4"`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		scenario, _ := cmd.Flags().GetString("scenario")
		if scenario == "" {
			scenario = "add"
		}

		rr, _ := cmd.Flags().GetString("rr")
		if rr == "" {
			log.Fatalf("Error: --rr is required")
		}

		req := tdns.AgentMgmtPost{
			Command: "hsync-test-chain",
			Zone:    tdns.ZoneName(tdns.Globals.Zonename),
			RRs:     []string{rr},
			Data: map[string]interface{}{
				"scenario": scenario,
			},
		}

		amr, err := SendAgentDebugCmd(req, false)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if amr.Error {
			log.Fatalf("Error: %s", amr.ErrorMsg)
		}

		fmt.Printf("Test Chain Results:\n")
		fmt.Printf("===================\n\n")
		fmt.Printf("%s\n\n", amr.Msg)

		if amr.Data != nil {
			if dataMap, ok := amr.Data.(map[string]interface{}); ok {
				fmt.Printf("Scenario: %v\n", dataMap["scenario"])
				fmt.Printf("Zone: %v\n", dataMap["zone"])
				fmt.Printf("RRs Count: %v\n\n", dataMap["rrs_count"])

				if step1, ok := dataMap["step1_local_update"].(map[string]interface{}); ok {
					fmt.Printf("Step 1 (Local Update):\n")
					if success, ok := step1["success"].(bool); ok && success {
						fmt.Printf("  ✓ Success: %v\n", step1["message"])
					} else {
						fmt.Printf("  ✗ Failed: %v\n", step1["error"])
					}
				}

				if step2, ok := dataMap["step2_peer_sync"].(map[string]interface{}); ok {
					fmt.Printf("\nStep 2 (Peer Sync):\n")
					if skipped, ok := step2["skipped"].(bool); ok && skipped {
						fmt.Printf("  ⊘ Skipped: %v\n", step2["reason"])
					} else {
						fmt.Printf("  Peers synced: %v\n", step2["peers_synced"])
						if results, ok := step2["results"].(map[string]interface{}); ok {
							for peer, result := range results {
								if peerResult, ok := result.(map[string]interface{}); ok {
									if success, ok := peerResult["success"].(bool); ok && success {
										fmt.Printf("    ✓ %s: %v\n", peer, peerResult["message"])
									} else {
										fmt.Printf("    ✗ %s: %v\n", peer, peerResult["error"])
									}
								}
							}
						}
					}
				}
			}
		}
	},
}

func init() {
	DebugCmd.AddCommand(DebugAgentCmd)
	DebugAgentCmd.AddCommand(DebugAgentSendNotifyCmd)
	DebugAgentCmd.AddCommand(DebugAgentSendRfiCmd)
	DebugAgentCmd.AddCommand(DebugAgentDumpAgentRegistryCmd)
	DebugAgentCmd.AddCommand(DebugAgentDumpZoneDataRepoCmd)
	DebugAgentCmd.AddCommand(DebugAgentRegistryCmd)
	DebugAgentCmd.AddCommand(DebugAgentTriggerSyncCmd)
	DebugAgentCmd.AddCommand(DebugAgentForceSyncCmd)
	DebugAgentCmd.AddCommand(DebugAgentSyncStateCmd)
	DebugAgentCmd.AddCommand(DebugAgentSendToCombinerCmd)
	DebugAgentCmd.AddCommand(DebugAgentTestChainCmd)

	DebugAgentSendNotifyCmd.Flags().StringVarP(&myIdentity, "id", "I", "", "agent identity to claim")
	DebugAgentSendNotifyCmd.Flags().StringVarP(&notifyRRtype, "rrtype", "R", "", "RR type sent notify for")
	DebugAgentSendNotifyCmd.Flags().StringVarP(&dnsRecord, "RR", "", "", "DNS record to send")
	DebugAgentSendRfiCmd.Flags().StringVarP(&rfitype, "rfi", "", "", "RFI type (UPSTREAM|DOWNSTREAM)")

	// New command flags
	DebugAgentTriggerSyncCmd.Flags().String("from", "", "Source agent ID")
	DebugAgentTriggerSyncCmd.Flags().String("rr", "", "DNS record to sync")
	DebugAgentForceSyncCmd.Flags().String("peer", "", "Target peer agent ID")
	DebugAgentForceSyncCmd.Flags().String("rr", "", "DNS record to sync (optional)")
	DebugAgentSendToCombinerCmd.Flags().String("rr", "", "DNS record to send")
	DebugAgentTestChainCmd.Flags().String("scenario", "add", "Test scenario (add|update|delete)")
	DebugAgentTestChainCmd.Flags().String("rr", "", "DNS record for test")

	// DebugAgentSendRfiCmd.Flags().StringVarP(&rfiupstream, "upstream", "", "", "Identity of upstream agent")
	// DebugAgentSendRfiCmd.Flags().StringVarP(&rfidownstream, "downstream", "", "", "Identity of downstream agent")
}

func SendAgentDebugCmd(req tdns.AgentMgmtPost, printJson bool) (*tdns.AgentMgmtResponse, error) {
	prefixcmd, _ := getCommandContext("debug")
	api, err := getApiClient(prefixcmd, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	api.Debug = true

	_, buf, err := api.RequestNG("POST", "/agent/debug", req, true)
	if err != nil {
		log.Fatalf("API request failed: %v", err)
	}

	var amr tdns.AgentMgmtResponse
	if err := json.Unmarshal(buf, &amr); err != nil {
		log.Fatalf("Failed to parse response: %v", err)
	}

	if printJson {
		var prettyJSON bytes.Buffer
		err = json.Indent(&prettyJSON, buf, "", "  ")
		if err != nil {
			log.Println("JSON parse error: ", err)
		}
		fmt.Printf("Agent debug response:\n%s\n", prettyJSON.String())
		return &amr, nil
	}

	if amr.Error {
		log.Fatalf("API error: %s", amr.ErrorMsg)
	}

	return &amr, nil
}
