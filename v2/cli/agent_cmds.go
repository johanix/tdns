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

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var dnsRecord string

var AgentCmd = &cobra.Command{
	Use:   "agent",
	Short: "TDNS Agent commands",
}

var agentLocalCmd = &cobra.Command{
	Use:   "local",
	Short: "TDNS Agent local commands",
}

var agentLocalZoneDataCmd = &cobra.Command{
	Use:   "zonedata",
	Short: "TDNS Agent local zone data commands (adding or removing local data about zones)",
}

var agentLocalConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Show details of the local agent config",
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("local")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := tdns.AgentMgmtPost{
			Command: "config",
		}

		_, buf, err := api.RequestNG("POST", "/agent", req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}

		var amr tdns.AgentMgmtResponse
		if err := json.Unmarshal(buf, &amr); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}

		if amr.Error {
			log.Fatalf("API error: %s", amr.ErrorMsg)
		}

		var prettyYaml bytes.Buffer
		err = yaml.NewEncoder(&prettyYaml).Encode(amr.AgentConfig)
		if err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}
		fmt.Printf("Agent config for %q:\n%s\n", amr.AgentConfig.Identity, prettyYaml.String())
	},
}

var agentLocalZoneDataAddRRCmd = &cobra.Command{
	Use:   "add-rr",
	Short: "Add a new local DNS record for an existing zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		err := VerifyAndSendLocalDNSRecord(tdns.Globals.Zonename, dnsRecord, "add-rr")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	},
}

var agentLocalZoneDataRemoveRRCmd = &cobra.Command{
	Use:   "remove-rr",
	Short: "Remove a local DNS record for an existing zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		err := VerifyAndSendLocalDNSRecord(tdns.Globals.Zonename, dnsRecord, "remove-rr")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	},
}

var agentLocalZoneDataRemoveRRsetCmd = &cobra.Command{
	Use:   "remove-rrset",
	Short: "Remove a local DNS RRset for an existing zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		err := VerifyAndSendLocalDNSRecord(tdns.Globals.Zonename, dnsRecord, "remove-rrset")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	},
}

var agentDiscoverCmd = &cobra.Command{
	Use:   "discover <agent-identity>",
	Short: "Trigger DNS discovery for a remote agent",
	Long: `Discover a remote agent by querying DNS for its URI, JWK, TLSA, and SVCB records.
This triggers async discovery which will:
1. Query DNS for agent metadata (URI, JWK, TLSA, SVCB)
2. Register the agent in PeerRegistry
3. Start Hello retry loop if authorized
4. Progress agent through state machine to OPERATIONAL

Example:
  tdns-cli agent discover agent2.example.com`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentIdentity := args[0]

		amr, err := SendAgentMgmtCmd(&tdns.AgentMgmtPost{
			Command: "discover",
			AgentId: tdns.AgentId(agentIdentity),
		}, "discover")

		if err != nil {
			fmt.Printf("Error sending discover command: %v\n", err)
			os.Exit(1)
		}

		if amr.Error {
			fmt.Printf("Error from agent %q: %s\n", amr.Identity, amr.ErrorMsg)
			os.Exit(1)
		}

		fmt.Printf("%s\n", amr.Msg)
		fmt.Printf("\nDiscovery is asynchronous. Use 'tdns-cli agent hsync agentstatus %s' to check status.\n", agentIdentity)
	},
}

var agentPeersCmd = &cobra.Command{
	Use:   "peers",
	Short: "List all known peer agents",
	Long: `Show all peer agents that this agent has discovered and established communication with.
Displays both API and DNS transports independently with their current state.

This shows all peers regardless of transport type - both API (TLS) and DNS (JOSE) transports
are displayed as separate entries to show their independent states.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Import the function from distrib_cmds.go
		listDistribPeers(cmd, "agent")
	},
}

var agentPeersZonesCmd = &cobra.Command{
	Use:   "zones",
	Short: "List shared zones for each peer agent",
	Long: `Show which zones are shared with each peer agent.
Displays agent identity and their shared zones in a compact format.`,
	Run: func(cmd *cobra.Command, args []string) {
		listPeerZones(cmd, "agent")
	},
}

var agentPeersZoneCmd = &cobra.Command{
	Use:   "zone --zone <zonename>",
	Short: "List peer agents for a specific zone",
	Long: `Show which peer agents share a specific zone with us.
Displays all agents that have the specified zone in their shared zones list.`,
	Run: func(cmd *cobra.Command, args []string) {
		zoneName, _ := cmd.Flags().GetString("zone")
		if zoneName == "" {
			log.Fatal("--zone flag is required")
		}
		listAgentsForZone(cmd, "agent", zoneName)
	},
}

var resyncPush, resyncPull, resyncFull bool

var agentPeersResyncCmd = &cobra.Command{
	Use:   "resync",
	Short: "Re-synchronize zone data with peers and combiner",
	Long: `Re-synchronize zone data between this agent, its peers, and the combiner.

Modes:
  --push   Re-send all local data to combiner and remote agents
  --pull   Request all remote agents to re-send their data (RFI SYNC)
  --full   Both push and pull (default if no flag specified)`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		// Default to --full if no flag specified
		if !resyncPush && !resyncPull && !resyncFull {
			resyncFull = true
		}

		zone := tdns.ZoneName(tdns.Globals.Zonename)

		// Push: re-send local data to combiner and remote agents
		if resyncPush || resyncFull {
			fmt.Printf("Resync push: re-sending local data for zone %s...\n", zone)
			req := &tdns.AgentMgmtPost{Command: "resync", Zone: zone}
			amr, err := SendAgentMgmtCmd(req, "peers")
			if err != nil {
				fmt.Printf("Error sending resync push: %v\n", err)
				os.Exit(1)
			}
			if amr.Error {
				fmt.Printf("Resync push error: %s\n", amr.ErrorMsg)
				os.Exit(1)
			}
			fmt.Printf("Resync push: %s\n", amr.Msg)
		}

		// Pull: send RFI SYNC to all remote agents
		if resyncPull || resyncFull {
			fmt.Printf("Resync pull: requesting peers to re-send data for zone %s...\n", zone)
			req := &tdns.AgentMgmtPost{
				Command:     "send-rfi",
				MessageType: tdns.AgentMsgRfi,
				RfiType:     "SYNC",
				Zone:        zone,
			}
			amr, err := SendAgentMgmtCmd(req, "peers")
			if err != nil {
				fmt.Printf("Error sending resync pull: %v\n", err)
				os.Exit(1)
			}
			if amr.Error {
				fmt.Printf("Resync pull error: %s\n", amr.ErrorMsg)
				os.Exit(1)
			}
			fmt.Printf("Resync pull: %s\n", amr.Msg)
			for agentId, rfiData := range amr.RfiResponse {
				if rfiData.Error {
					fmt.Printf("  %s: error: %s\n", agentId, rfiData.ErrorMsg)
				} else {
					fmt.Printf("  %s: %s\n", agentId, rfiData.Msg)
				}
			}
		}
	},
}

func init() {
	AgentCmd.AddCommand(agentLocalCmd)
	AgentCmd.AddCommand(agentDiscoverCmd)
	AgentCmd.AddCommand(agentPeersCmd)
	AgentCmd.AddCommand(DebugAgentCmd) // Add debug commands under agent

	// Add subcommands under "agent peers"
	agentPeersCmd.AddCommand(agentPeersZonesCmd)
	agentPeersCmd.AddCommand(agentPeersZoneCmd)
	agentPeersCmd.AddCommand(agentPeersResyncCmd)

	agentLocalCmd.AddCommand(agentLocalConfigCmd)
	agentLocalCmd.AddCommand(agentLocalZoneDataCmd)
	agentLocalZoneDataCmd.AddCommand(agentLocalZoneDataAddRRCmd)
	agentLocalZoneDataCmd.AddCommand(agentLocalZoneDataRemoveRRCmd)
	agentLocalZoneDataCmd.AddCommand(agentLocalZoneDataRemoveRRsetCmd)

	// agentLocalZoneDataCmd.PersistentFlags().StringVarP(&localRRtype, "rrtype", "R", "", "RR type to add")
	agentLocalZoneDataCmd.PersistentFlags().StringVarP(&dnsRecord, "RR", "", "", "DNS record to add")
	agentPeersCmd.Flags().BoolP("verbose", "v", false, "Verbose output (show full details)")
	agentPeersZoneCmd.Flags().StringP("zone", "z", "", "Zone name to list agents for (required)")

	agentPeersResyncCmd.Flags().BoolVar(&resyncPush, "push", false, "Re-send local data to combiner and peers")
	agentPeersResyncCmd.Flags().BoolVar(&resyncPull, "pull", false, "Request peers to re-send their data (RFI SYNC)")
	agentPeersResyncCmd.Flags().BoolVar(&resyncFull, "full", false, "Both push and pull (default)")
}

func SendAgentMgmtCmd(req *tdns.AgentMgmtPost, prefix string) (*tdns.AgentMgmtResponse, error) {
	prefixcmd, _ := getCommandContext(prefix)
	api, err := getApiClient(prefixcmd, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	// api.Debug = true

	_, buf, err := api.RequestNG("POST", "/agent", req, true)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %v", err)
	}

	var amr tdns.AgentMgmtResponse
	if err := json.Unmarshal(buf, &amr); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &amr, nil
}

func VerifyAndSendLocalDNSRecord(zonename, dnsRecord, cmd string) error {
	var rr dns.RR
	var err error

	if dnsRecord == "" {
		return fmt.Errorf("error: DNS record is required")
	}

	if rr, err = dns.NewRR(dnsRecord); err != nil {
		return fmt.Errorf("error: invalid DNS record (did not parse): %v", err)
	}

	if !strings.HasSuffix(rr.Header().Name, zonename) {
		return fmt.Errorf("DNS record name %q is not part of zone %q",
			rr.Header().Name, zonename)
	}

	switch rr.(type) {
	// let's only support NS, DNSKEY and KEYfor now
	case *dns.NS, *dns.DNSKEY, *dns.KEY:
		// all good
	default:
		return fmt.Errorf("invalid RR type: %s (only NS, DNSKEY and KEY allowed)", dns.TypeToString[rr.Header().Rrtype])
	}

	switch cmd {
	case "add-rr":
		// This is a normal add RR, signaled by the CLASS=IN
		rr.Header().Class = dns.ClassINET
	case "remove-rr":
		// This is a delete RR, signaled by the CLASS=NONE
		rr.Header().Class = dns.ClassNONE
	case "remove-rrset":
		// This is a delete RRset, signaled by the CLASS=ANY
		rr.Header().Class = dns.ClassANY
	default:
		return fmt.Errorf("invalid command: %s", cmd)
	}

	rrs := []string{rr.String()}

	amr, err := SendAgentMgmtCmd(&tdns.AgentMgmtPost{
		Command: "update-local-zonedata",
		RRType:  rr.Header().Rrtype,
		Zone:    tdns.ZoneName(tdns.Globals.Zonename),
		AgentId: tdns.AgentId(myIdentity),
		RRs:     rrs,
	}, "local")

	if err != nil {
		fmt.Printf("Error sending agent management command: %v\n", err)
		os.Exit(1)
	}

	if amr.Error {
		fmt.Printf("Error: from agent %q: %s\n", amr.Identity, amr.ErrorMsg)
		os.Exit(1)
	}

	fmt.Printf("Agent management command sent successfully. Response: %s\n", amr.Msg)
	return nil
}

// listPeerZones shows shared zones for each peer agent
func listPeerZones(cmd *cobra.Command, component string) {
	prefixcmd, _ := getCommandContext("peers")
	api, err := getApiClient(prefixcmd, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	endpoint := fmt.Sprintf("/%s/distrib", component)
	req := map[string]interface{}{
		"command": "peer-zones",
	}

	_, buf, err := api.RequestNG("POST", endpoint, req, true)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(buf, &resp); err != nil {
		log.Fatalf("Failed to parse response: %v", err)
	}

	if resp["error"] == true {
		log.Fatalf("Error: %v", resp["error_msg"])
	}

	// Display results
	if data, ok := resp["data"].([]interface{}); ok && len(data) > 0 {
		fmt.Println("Peer Agent Shared Zones:")
		fmt.Println("========================")
		for _, item := range data {
			if entry, ok := item.(map[string]interface{}); ok {
				peerID := entry["peer_id"].(string)
				zones := entry["zones"].([]interface{})

				if len(zones) == 0 {
					fmt.Printf("%-40s  (LEGACY - no shared zones)\n", peerID)
				} else {
					// Build zone display with serials
					zoneStrs := make([]string, len(zones))
					for i, z := range zones {
						if zoneInfo, ok := z.(map[string]interface{}); ok {
							zoneName := zoneInfo["name"].(string)
							if serial, hasSerial := zoneInfo["serial"]; hasSerial {
								// Convert serial to uint32 (JSON unmarshals numbers as float64)
								serialUint := uint32(serial.(float64))
								zoneStrs[i] = fmt.Sprintf("%s (serial: %d)", zoneName, serialUint)
							} else {
								zoneStrs[i] = zoneName
							}
						} else {
							// Fallback for old format (plain string)
							zoneStrs[i] = z.(string)
						}
					}
					fmt.Printf("%-40s  %s\n", peerID, strings.Join(zoneStrs, ", "))
				}
			}
		}
	} else {
		fmt.Println("No peers found")
	}
}

// listAgentsForZone shows which peer agents share a specific zone
func listAgentsForZone(cmd *cobra.Command, component string, zoneName string) {
	prefixcmd, _ := getCommandContext("peers")
	api, err := getApiClient(prefixcmd, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	// Normalize zone name to FQDN
	zoneName = dns.Fqdn(zoneName)

	endpoint := fmt.Sprintf("/%s/distrib", component)
	req := map[string]interface{}{
		"command": "zone-agents",
		"zone":    zoneName,
	}

	_, buf, err := api.RequestNG("POST", endpoint, req, true)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(buf, &resp); err != nil {
		log.Fatalf("Failed to parse response: %v", err)
	}

	if resp["error"] == true {
		log.Fatalf("Error: %v", resp["error_msg"])
	}

	// Display results
	if agents, ok := resp["agents"].([]interface{}); ok && len(agents) > 0 {
		fmt.Printf("Peer agents sharing zone %q:\n", zoneName)
		fmt.Println("================================")
		for _, agent := range agents {
			if agentID, ok := agent.(string); ok {
				fmt.Printf("  %s\n", agentID)
			}
		}
	} else {
		fmt.Printf("No peer agents found for zone %q\n", zoneName)
	}
}
