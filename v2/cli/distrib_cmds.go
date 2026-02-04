/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Distribution management CLI commands for agents and combiners
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"

	tdns "github.com/johanix/tdns/v2"
)

var AgentDistribCmd = &cobra.Command{
	Use:   "distrib",
	Short: "Manage distributions",
	Long:  `Commands for managing distributions created by this agent, including listing distributions and purging completed distributions.`,
}

var CombinerDistribCmd = &cobra.Command{
	Use:   "distrib",
	Short: "Manage distributions",
	Long:  `Commands for managing distributions created by this combiner, including listing distributions and purging completed distributions.`,
}

var agentDistribListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all distributions from this agent",
	Run: func(cmd *cobra.Command, args []string) {
		listDistributions(cmd, "agent")
	},
}

var combinerDistribListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all distributions from this combiner",
	Run: func(cmd *cobra.Command, args []string) {
		listDistributions(cmd, "combiner")
	},
}

var agentDistribPurgeCmd = &cobra.Command{
	Use:   "purge [--force]",
	Short: "Delete distributions",
	Long:  "Delete distributions from the database. By default, only completed distributions are deleted. Use --force to delete ALL distributions regardless of status.",
	Run: func(cmd *cobra.Command, args []string) {
		purgeDistributions(cmd, "agent")
	},
}

var agentDistribPeersCmd = &cobra.Command{
	Use:   "peers",
	Short: "List all known peer agents with working keys",
	Long:  "Show all recipient agents that this agent has established keys with and can send distributions to.",
	Run: func(cmd *cobra.Command, args []string) {
		listDistribPeers(cmd, "agent")
	},
}

var combinerDistribPurgeCmd = &cobra.Command{
	Use:   "purge [--force]",
	Short: "Delete distributions",
	Long:  "Delete distributions from the database. By default, only completed distributions are deleted. Use --force to delete ALL distributions regardless of status.",
	Run: func(cmd *cobra.Command, args []string) {
		purgeDistributions(cmd, "combiner")
	},
}

var combinerDistribPeersCmd = &cobra.Command{
	Use:   "peers",
	Short: "List all known peer agents with working keys",
	Long:  "Show all recipient agents that this combiner has established keys with and can send distributions to.",
	Run: func(cmd *cobra.Command, args []string) {
		listDistribPeers(cmd, "combiner")
	},
}

var agentDistribOpCmd = &cobra.Command{
	Use:   "op [operation]",
	Short: "Run an operation toward a peer",
	Long:  `Run an operation toward a peer by identity (e.g. ping to combiner or a peer agent). Use "distrib peers" to list identities. Supported operations: ping (use --dns or --api for combiner ping).`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runDistribOp(cmd, args[0])
	},
}

func listDistributions(cmd *cobra.Command, component string) {
	prefixcmd, _ := getCommandContext("distrib")
	api, err := getApiClient(prefixcmd, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	// Determine API endpoint based on component
	endpoint := fmt.Sprintf("/%s/distrib", component)

	req := map[string]interface{}{
		"command": "list",
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

	if msg, ok := resp["msg"].(string); ok && msg != "" {
		fmt.Printf("%s\n", msg)
	}

	// Check for verbose flag
	verbose := false
	if v, err := cmd.Flags().GetBool("verbose"); err == nil {
		verbose = v
	}

	// Try to get summaries/distributions list
	if summariesRaw, ok := resp["summaries"].([]interface{}); ok && len(summariesRaw) > 0 {
		displayDistributions(summariesRaw, verbose, api, component)
	} else if dists, ok := resp["distributions"].([]interface{}); ok {
		// Fallback to simple list format
		if len(dists) == 0 {
			fmt.Println("No distributions found")
		} else {
			fmt.Println("\nDistribution IDs:")
			for _, dist := range dists {
				fmt.Printf("  %s\n", dist)
			}
		}
	} else {
		fmt.Println("No distributions found")
	}
}

func displayDistributions(summaries []interface{}, verbose bool, api *tdns.ApiClient, component string) {
	if verbose {
		// Verbose mode: show full multiline information
		fmt.Println("\nDistributions:")
		for _, sRaw := range summaries {
			if s, ok := sRaw.(map[string]interface{}); ok {
				distID := getStringValue(s, "distribution_id")
				fmt.Printf("\n  Distribution ID: %s\n", distID)

				if sender, ok := s["sender_id"].(string); ok && sender != "" {
					fmt.Printf("    Sender: %s\n", sender)
				}

				if receiver, ok := s["receiver_id"].(string); ok && receiver != "" {
					fmt.Printf("    Receiver: %s\n", receiver)
				}

				if operation, ok := s["operation"].(string); ok && operation != "" {
					fmt.Printf("    Operation: %s\n", operation)
				}

				if contentType, ok := s["content_type"].(string); ok && contentType != "" {
					fmt.Printf("    Content Type: %s\n", contentType)
				}

				if opCount, ok := s["operation_count"].(float64); ok {
					fmt.Printf("    Operation Count: %d\n", int(opCount))
				}

				if createdAt, ok := s["created_at"].(string); ok && createdAt != "" {
					if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
						fmt.Printf("    Created: %s\n", t.Format("2006-01-02 15:04:05"))
					} else {
						fmt.Printf("    Created: %s\n", createdAt)
					}
				}

				if completedAt, ok := s["completed_at"].(string); ok && completedAt != "" {
					if t, err := time.Parse(time.RFC3339, completedAt); err == nil {
						fmt.Printf("    Completed: %s\n", t.Format("2006-01-02 15:04:05"))
					} else {
						fmt.Printf("    Completed: %s\n", completedAt)
					}
				}

				if state, ok := s["state"].(string); ok && state != "" {
					fmt.Printf("    State: %s\n", state)
				}
			}
		}
	} else {
		// Default mode: show tabular format
		var rows []string
		rows = append(rows, "Id | State | Time | Receiver | Operation | Query")

		for _, sRaw := range summaries {
			if s, ok := sRaw.(map[string]interface{}); ok {
				distID := getStringValue(s, "distribution_id")
				if distID == "" {
					continue
				}

				// Get receiver
				receiver := getStringValue(s, "receiver_id")

				// Get operation
				operation := getStringValue(s, "operation")
				if operation == "" {
					operation = getStringValue(s, "content_type")
				}

				// Build CHUNK QNAME: <receiver>.<distributionID>.<sender>. CHUNK
				// For agent distributions, the format depends on the receiver
				queryStr := ""
				sender := getStringValue(s, "sender_id")
				if receiver != "" && distID != "" && sender != "" {
					// Ensure receiver is FQDN
					receiverFQDN := receiver
					if !strings.HasSuffix(receiverFQDN, ".") {
						receiverFQDN = receiverFQDN + "."
					}
					// Ensure sender is FQDN
					senderFQDN := sender
					if !strings.HasSuffix(senderFQDN, ".") {
						senderFQDN = senderFQDN + "."
					}
					// QNAME format: <receiver><distributionID>.<sender> CHUNK
					senderClean := strings.TrimSuffix(senderFQDN, ".")
					queryStr = fmt.Sprintf("%s%s.%s. CHUNK", receiverFQDN, distID, senderClean)
				}

				// Get state and time
				state := getStringValue(s, "state")
				if state == "" {
					state = "pending"
				}

				timeStr := ""
				if completedAt, ok := s["completed_at"].(string); ok && completedAt != "" {
					if t, err := time.Parse(time.RFC3339, completedAt); err == nil {
						timeStr = t.Format("2006-01-02 15:04:05")
					} else {
						timeStr = completedAt
					}
				} else if createdAt, ok := s["created_at"].(string); ok && createdAt != "" {
					if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
						timeStr = t.Format("2006-01-02 15:04:05")
					} else {
						timeStr = createdAt
					}
				}

				rows = append(rows, fmt.Sprintf("%s | %s | %s | %s | %s | %s",
					distID, state, timeStr, receiver, operation, queryStr))
			}
		}

		if len(rows) > 1 {
			output := columnize.SimpleFormat(rows)
			fmt.Println(output)
		}
	}
}

func purgeDistributions(cmd *cobra.Command, component string) {
	force, _ := cmd.Flags().GetBool("force")

	prefixcmd, _ := getCommandContext("distrib")
	api, err := getApiClient(prefixcmd, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	// Determine API endpoint based on component
	endpoint := fmt.Sprintf("/%s/distrib", component)

	reqBody := map[string]interface{}{
		"command": "purge",
		"force":   force,
	}

	_, buf, err := api.RequestNG("POST", endpoint, reqBody, true)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(buf, &resp); err != nil {
		log.Fatalf("Failed to parse response: %v", err)
	}

	if msg, ok := resp["msg"].(string); ok {
		fmt.Println(msg)
	} else if errorMsg, ok := resp["error_msg"].(string); ok {
		fmt.Printf("Error: %s\n", errorMsg)
		os.Exit(1)
	}
}

func runDistribOp(cmd *cobra.Command, operation string) {
	prefixcmd, _ := getCommandContext("distrib")
	if prefixcmd != "agent" {
		log.Fatalf("distrib op must be run under agent (e.g. tdns-cliv2 agent distrib op ping --to combiner)")
	}
	to, err := cmd.Flags().GetString("to")
	if err != nil || to == "" {
		log.Fatalf("--to is required (e.g. --to combiner or --to agent.delta.dnslab.)")
	}
	api, err := getApiClient(prefixcmd, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	req := map[string]interface{}{
		"command": "op",
		"op":      operation,
		"to":      strings.TrimSpace(to),
	}
	if strings.TrimSpace(strings.ToLower(operation)) == "ping" {
		dnsFlag, _ := cmd.Flags().GetBool("dns")
		apiFlag, _ := cmd.Flags().GetBool("api")
		if dnsFlag && apiFlag {
			log.Fatalf("use either --dns or --api, not both")
		}
		if apiFlag {
			req["ping_transport"] = "api"
		} else {
			req["ping_transport"] = "dns"
		}
	}

	_, buf, err := api.RequestNG("POST", "/agent/distrib", req, true)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(buf, &resp); err != nil {
		log.Fatalf("Failed to parse response: %v", err)
	}

	if resp["error"] == true {
		if msg, ok := resp["error_msg"].(string); ok {
			log.Fatalf("Error: %s", msg)
		}
		log.Fatalf("Error: %v", resp["error_msg"])
	}

	if msg, ok := resp["msg"].(string); ok && msg != "" {
		fmt.Printf("%s\n", msg)
	}
}

func listDistribPeers(cmd *cobra.Command, component string) {
	prefixcmd, _ := getCommandContext("distrib")
	api, err := getApiClient(prefixcmd, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	// Determine API endpoint based on component
	endpoint := fmt.Sprintf("/%s/distrib", component)

	req := map[string]interface{}{
		"command": "peers",
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

	if msg, ok := resp["msg"].(string); ok && msg != "" {
		fmt.Printf("%s\n", msg)
	}

	// Check for verbose flag
	verbose := false
	if v, err := cmd.Flags().GetBool("verbose"); err == nil {
		verbose = v
	}

	// Get peers list
	if peersRaw, ok := resp["peers"].([]interface{}); ok && len(peersRaw) > 0 {
		displayPeers(peersRaw, verbose)
	} else {
		fmt.Println("No peers found")
	}
}

func displayPeers(peers []interface{}, verbose bool) {
	// Always use tabular format (compact and readable)
	var rows []string
	rows = append(rows, "Identity | Type | Address | Crypto | # Distribs")

	for _, pRaw := range peers {
		if p, ok := pRaw.(map[string]interface{}); ok {
			peerID := getStringValue(p, "peer_id", "id")
			if peerID == "" {
				continue
			}

			peerType := getStringValue(p, "peer_type", "type")
			if peerType == "" {
				peerType = "-"
			}

			address := getStringValue(p, "address")
			if address == "" {
				address = "-"
			}

			cryptoType := getStringValue(p, "crypto_type", "crypto")
			if cryptoType == "" {
				cryptoType = "JOSE"
			}

			distribSent := 0
			if ds, ok := p["distrib_sent"].(float64); ok {
				distribSent = int(ds)
			}

			rows = append(rows, fmt.Sprintf("%s | %s | %s | %s | %d", peerID, peerType, address, cryptoType, distribSent))
		}
	}

	if len(rows) > 1 {
		output := columnize.SimpleFormat(rows)
		fmt.Println(output)
	}
}

// Helper function for extracting string values from JSON maps
func getStringValue(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if v, ok := m[key]; ok && v != nil {
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

// agentDistribDiscoverCmd performs DNS-based discovery of an agent's contact information
var agentDistribDiscoverCmd = &cobra.Command{
	Use:   "discover <agent-identity>",
	Short: "Discover and register agent contact information via DNS",
	Long: `Performs DNS-based discovery of an agent's contact information and registers it.

Looks up URI, KEY, TLSA, and A/AAAA records to discover:
  - API endpoint (_https._tcp.<identity> URI)
  - DNS endpoint (_dns._udp.<identity> URI)
  - Public key (<identity> KEY)
  - TLS certificate (_443._tcp.<identity> TLSA)
  - IP addresses (<identity> A/AAAA)

After discovery, the agent is registered in PeerRegistry and can be used
with 'distrib op' commands.

Example:
  tdns-cliv2 agent distrib discover agent.delta.dnslab.
  tdns-cliv2 agent distrib discover provider.example.com`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentIdentity := args[0]
		runAgentDiscover(agentIdentity)
	},
}

func runAgentDiscover(agentIdentity string) {
	prefixcmd, _ := getCommandContext("distrib")
	api, err := getApiClient(prefixcmd, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	reqBody := map[string]interface{}{
		"command":  "discover",
		"agent_id": agentIdentity,
	}

	fmt.Printf("Discovering agent %s...\n", agentIdentity)

	_, buf, err := api.RequestNG("POST", "/agent/distrib", reqBody, true)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(buf, &resp); err != nil {
		log.Fatalf("Error parsing response: %v", err)
	}

	if errVal, ok := resp["error"].(bool); ok && errVal {
		if errMsg, ok := resp["error_msg"].(string); ok {
			log.Fatalf("Error: %s", errMsg)
		}
		log.Fatalf("Discovery failed")
	}

	if msg, ok := resp["msg"].(string); ok {
		fmt.Println(msg)
	}

	// Display discovered information if available
	if discoveryInfo, ok := resp["discovery"].(map[string]interface{}); ok {
		fmt.Println("\nDiscovered information:")
		if apiUri, ok := discoveryInfo["api_uri"].(string); ok && apiUri != "" {
			fmt.Printf("  API endpoint:  %s\n", apiUri)
		}
		if dnsUri, ok := discoveryInfo["dns_uri"].(string); ok && dnsUri != "" {
			fmt.Printf("  DNS endpoint:  %s\n", dnsUri)
		}
		if addrs, ok := discoveryInfo["addresses"].([]interface{}); ok && len(addrs) > 0 {
			fmt.Printf("  IP addresses:  ")
			for i, addr := range addrs {
				if i > 0 {
					fmt.Print(", ")
				}
				fmt.Print(addr)
			}
			fmt.Println()
		}
		if partial, ok := discoveryInfo["partial"].(bool); ok && partial {
			fmt.Println("  Warning: Partial discovery (some DNS records missing)")
		}
	}
}

func init() {
	// Register distrib commands under agent
	AgentDistribCmd.AddCommand(agentDistribListCmd, agentDistribPurgeCmd, agentDistribPeersCmd, agentDistribOpCmd, agentDistribDiscoverCmd)
	agentDistribListCmd.Flags().BoolP("verbose", "v", false, "Verbose output (show full details)")
	agentDistribPurgeCmd.Flags().Bool("force", false, "Delete ALL distributions (not just completed ones)")
	agentDistribPeersCmd.Flags().BoolP("verbose", "v", false, "Verbose output (show full details)")
	agentDistribOpCmd.Flags().StringP("to", "t", "", "Recipient identity (e.g. combiner, agent.delta.dnslab.)")
	agentDistribOpCmd.MarkFlagRequired("to")
	agentDistribOpCmd.Flags().Bool("dns", false, "For ping: use CHUNK-based DNS ping (default)")
	agentDistribOpCmd.Flags().Bool("api", false, "For ping: use HTTPS API ping")

	// Register distrib commands under combiner
	CombinerDistribCmd.AddCommand(combinerDistribListCmd, combinerDistribPurgeCmd, combinerDistribPeersCmd)
	combinerDistribListCmd.Flags().BoolP("verbose", "v", false, "Verbose output (show full details)")
	combinerDistribPurgeCmd.Flags().Bool("force", false, "Delete ALL distributions (not just completed ones)")
	combinerDistribPeersCmd.Flags().BoolP("verbose", "v", false, "Verbose output (show full details)")
}
