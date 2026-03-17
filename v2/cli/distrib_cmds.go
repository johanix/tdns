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
	"sort"
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
	// Sort by distribution ID (hex monotonic counter — lexicographic order = chronological order)
	sort.Slice(summaries, func(i, j int) bool {
		si, _ := summaries[i].(map[string]interface{})
		sj, _ := summaries[j].(map[string]interface{})
		return getStringValue(si, "distribution_id") < getStringValue(sj, "distribution_id")
	})

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

				if payloadSize := getUint64Value(s, "payload_size"); payloadSize > 0 {
					fmt.Printf("    Payload Size: %d bytes\n", payloadSize)
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
		rows = append(rows, "Id | Size | State | Time | Receiver | Operation | Query")

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

				// Format payload size for display
				sizeStr := "-"
				if payloadSize := getUint64Value(s, "payload_size"); payloadSize > 0 {
					if payloadSize >= 1024*1024 {
						sizeStr = fmt.Sprintf("%.1fM", float64(payloadSize)/(1024*1024))
					} else if payloadSize >= 1024 {
						sizeStr = fmt.Sprintf("%.1fK", float64(payloadSize)/1024)
					} else {
						sizeStr = fmt.Sprintf("%d", payloadSize)
					}
				}

				rows = append(rows, fmt.Sprintf("%s | %s | %s | %s | %s | %s | %s",
					distID, sizeStr, state, timeStr, receiver, operation, queryStr))
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
	// Determine parent command to select the right API client.
	// Called from "agent peer list" (parent of "peer" = "agent") or
	// "agent distrib peers" / "combiner distrib peers" (parent of "distrib" = component).
	prefixcmd, _ := getCommandContext("peer")
	if prefixcmd == "server" {
		prefixcmd, _ = getCommandContext("distrib")
	}
	api, err := getApiClient(prefixcmd, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	// Determine API endpoint based on component
	endpoint := fmt.Sprintf("/%s/distrib", component)

	req := map[string]interface{}{
		"command": "peer-list",
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

	// Show leader election status
	parentsyncZones, _ := resp["parentsync_zones"].([]interface{})
	hasParentsync := len(parentsyncZones) > 0

	if leadersRaw, ok := resp["leaders"].([]interface{}); ok && len(leadersRaw) > 0 {
		fmt.Println("\nLeader elections:")
		for _, lRaw := range leadersRaw {
			if l, ok := lRaw.(map[string]interface{}); ok {
				zone := getStringValue(l, "zone")
				status := getStringValue(l, "status")

				switch status {
				case "pending":
					fmt.Printf("  %-30s (pending — waiting for operational peers)\n", zone)
				default:
					leader := getStringValue(l, "leader")
					isSelf := false
					if v, ok := l["is_self"].(bool); ok {
						isSelf = v
					}
					term := l["term"]
					ttl := l["ttl_secs"]
					selfTag := ""
					if isSelf {
						selfTag = " (self)"
					}
					fmt.Printf("  %-30s leader=%s%s  term=%v  ttl=%vs\n", zone, leader, selfTag, term, ttl)
				}
			}
		}
	} else if !hasParentsync {
		fmt.Println("\nLeader elections: none (no zones with parentsync=agent)")
	} else {
		fmt.Println("\nLeader elections: none")
	}
}

func displayPeers(peers []interface{}, verbose bool) {
	// Sort peers: combiners first, then by state priority (OPERATIONAL > INTRODUCED > KNOWN > NEEDED)
	sortedPeers := sortPeersForDisplay(peers)

	if verbose {
		// Verbose mode: show detailed information for each peer
		for i, pRaw := range sortedPeers {
			if i > 0 {
				fmt.Println() // Blank line between peers
			}
			if p, ok := pRaw.(map[string]interface{}); ok {
				displayPeerVerbose(p)
			}
		}
		return
	}

	// Compact mode: use tabular format
	var rows []string
	rows = append(rows, "Identity | Type | Transport | Address | Crypto | State")

	for _, pRaw := range sortedPeers {
		if p, ok := pRaw.(map[string]interface{}); ok {
			peerID := getStringValue(p, "peer_id", "id")
			if peerID == "" {
				continue
			}

			peerType := getStringValue(p, "peer_type", "type")
			if peerType == "" {
				peerType = "-"
			}

			transport := getStringValue(p, "transport")
			if transport == "" {
				transport = "-"
			}

			address := getStringValue(p, "address")
			if address == "" {
				address = "-"
			}

			cryptoType := getStringValue(p, "crypto_type", "crypto")
			if cryptoType == "" {
				cryptoType = "-"
			}

			state := getStringValue(p, "state")
			if state == "" {
				state = "-"
			}

			rows = append(rows, fmt.Sprintf("%s | %s | %s | %s | %s | %s", peerID, peerType, transport, address, cryptoType, state))
		}
	}

	if len(rows) > 1 {
		output := columnize.SimpleFormat(rows)
		fmt.Println(output)
	}
}

// sortPeersForDisplay sorts peers with combiners first, then agents by state priority
// State priority: OPERATIONAL > INTRODUCED > KNOWN > NEEDED > LEGACY > DEGRADED > INTERRUPTED > ERROR
func sortPeersForDisplay(peers []interface{}) []interface{} {
	// State priority mapping (higher number = higher priority)
	statePriority := map[string]int{
		"OPERATIONAL": 5,
		"INTRODUCED":  4,
		"KNOWN":       3,
		"NEEDED":      2,
		"LEGACY":      1,
		"DEGRADED":    0,
		"INTERRUPTED": -1,
		"ERROR":       -2,
	}

	// Create a sortable slice
	type peerSortKey struct {
		peer       interface{}
		isCombiner bool
		stateValue int
		identity   string
		transport  string
	}

	var sortKeys []peerSortKey
	for _, pRaw := range peers {
		if p, ok := pRaw.(map[string]interface{}); ok {
			peerType := getStringValue(p, "peer_type", "type")
			state := getStringValue(p, "state")
			identity := getStringValue(p, "peer_id", "id")
			transport := getStringValue(p, "transport")

			stateVal := statePriority[state]
			if _, exists := statePriority[state]; !exists {
				stateVal = -10 // Unknown states go last
			}

			sortKeys = append(sortKeys, peerSortKey{
				peer:       pRaw,
				isCombiner: peerType == "combiner",
				stateValue: stateVal,
				identity:   identity,
				transport:  transport,
			})
		}
	}

	// Sort: combiners first, then ALL entries by state priority (descending), then by identity, then by transport
	for i := 0; i < len(sortKeys); i++ {
		for j := i + 1; j < len(sortKeys); j++ {
			swap := false

			// Primary: combiners before agents
			if sortKeys[i].isCombiner != sortKeys[j].isCombiner {
				swap = !sortKeys[i].isCombiner && sortKeys[j].isCombiner
			} else if sortKeys[i].stateValue != sortKeys[j].stateValue {
				// Secondary: higher state priority first (OPERATIONAL > INTRODUCED > KNOWN > NEEDED)
				swap = sortKeys[i].stateValue < sortKeys[j].stateValue
			} else if sortKeys[i].identity != sortKeys[j].identity {
				// Tertiary: alphabetical by identity
				swap = sortKeys[i].identity > sortKeys[j].identity
			} else {
				// Quaternary: alphabetical by transport (API before DNS)
				swap = sortKeys[i].transport > sortKeys[j].transport
			}

			if swap {
				sortKeys[i], sortKeys[j] = sortKeys[j], sortKeys[i]
			}
		}
	}

	// Extract sorted peers
	sorted := make([]interface{}, len(sortKeys))
	for i, sk := range sortKeys {
		sorted[i] = sk.peer
	}
	return sorted
}

func displayPeerVerbose(p map[string]interface{}) {
	peerID := getStringValue(p, "peer_id", "id")
	if peerID == "" {
		return
	}

	fmt.Printf("=== Peer: %s ===\n", peerID)
	fmt.Printf("  Type:           %s\n", getStringValue(p, "peer_type", "type"))
	fmt.Printf("  Transport:      %s\n", getStringValue(p, "transport"))
	fmt.Printf("  Crypto:         %s\n", getStringValue(p, "crypto_type", "crypto"))

	// Endpoint information
	if apiUri := getStringValue(p, "api_uri"); apiUri != "" {
		fmt.Printf("  API URI:        %s\n", apiUri)
	}
	if dnsUri := getStringValue(p, "dns_uri"); dnsUri != "" {
		fmt.Printf("  DNS URI:        %s\n", dnsUri)
	}
	if address := getStringValue(p, "address"); address != "" && address != "-" {
		fmt.Printf("  Address:        %s\n", address)
	}

	// Port
	if port, ok := p["port"].(float64); ok && port > 0 {
		fmt.Printf("  Port:           %d\n", int(port))
	}

	// IP addresses
	if addrs, ok := p["addresses"].([]interface{}); ok && len(addrs) > 0 {
		fmt.Printf("  IP Addresses:   ")
		for i, addr := range addrs {
			if i > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("%v", addr)
		}
		fmt.Println()
	}

	// Key information
	fmt.Println()
	if hasJWK, ok := p["has_jwk"].(bool); ok && hasJWK {
		fmt.Printf("  JWK Record:     ✓ Present\n")
		if algorithm := getStringValue(p, "key_algorithm"); algorithm != "" {
			fmt.Printf("    Algorithm:    %s\n", algorithm)
		}
		if jwkData := getStringValue(p, "jwk_data"); jwkData != "" {
			if len(jwkData) <= 80 {
				fmt.Printf("    Data:         %s\n", jwkData)
			} else {
				fmt.Printf("    Data:         %s... (%d bytes)\n", jwkData[:77], len(jwkData))
			}
		}
	} else {
		fmt.Printf("  JWK Record:     ✗ Not found\n")
	}
	if hasKEY, ok := p["has_key"].(bool); ok && hasKEY {
		fmt.Printf("  KEY Record:     ✓ Present (legacy fallback)\n")
	} else if hasJWK, ok := p["has_jwk"].(bool); !ok || !hasJWK {
		// Only show "not found" if also no JWK
		fmt.Printf("  KEY Record:     ✗ Not found\n")
	}
	if hasTLSA, ok := p["has_tlsa"].(bool); ok && hasTLSA {
		fmt.Printf("  TLSA Record:    ✓ Present\n")
	} else if transport := getStringValue(p, "transport"); transport == "API" {
		// Only show "not found" for API transport
		fmt.Printf("  TLSA Record:    ✗ Not found\n")
	}

	// State information
	if state := getStringValue(p, "state"); state != "" {
		fmt.Printf("  State:          %s\n", state)
	}
	if contactInfo := getStringValue(p, "contact_info"); contactInfo != "" {
		fmt.Printf("  Contact Info:   %s\n", contactInfo)
	}

	// Partial discovery warning
	if partial, ok := p["partial"].(bool); ok && partial {
		fmt.Printf("  ⚠ Discovery:    Partial (some records missing)\n")
	}

	// Usage statistics - show detailed per-message-type breakdown
	fmt.Println()
	totalSent := getUint64Value(p, "total_sent")
	totalRecv := getUint64Value(p, "total_received")

	if totalSent > 0 || totalRecv > 0 {
		fmt.Printf("  Message Statistics:\n")
		fmt.Printf("    Total:        %d sent, %d received\n", totalSent, totalRecv)

		// Show per-message-type breakdown if any non-zero
		helloSent := getUint64Value(p, "hello_sent")
		helloRecv := getUint64Value(p, "hello_received")
		beatSent := getUint64Value(p, "beat_sent")
		beatRecv := getUint64Value(p, "beat_received")
		syncSent := getUint64Value(p, "sync_sent")
		syncRecv := getUint64Value(p, "sync_received")
		pingSent := getUint64Value(p, "ping_sent")
		pingRecv := getUint64Value(p, "ping_received")

		if helloSent > 0 || helloRecv > 0 {
			fmt.Printf("    Hello:        %d sent, %d received\n", helloSent, helloRecv)
		}
		if beatSent > 0 || beatRecv > 0 {
			fmt.Printf("    Beat:         %d sent, %d received\n", beatSent, beatRecv)
		}
		if syncSent > 0 || syncRecv > 0 {
			fmt.Printf("    Sync:         %d sent, %d received\n", syncSent, syncRecv)
		}
		if pingSent > 0 || pingRecv > 0 {
			fmt.Printf("    Ping:         %d sent, %d received\n", pingSent, pingRecv)
		}
	}

	if lastUsedStr := getStringValue(p, "last_used"); lastUsedStr != "" && lastUsedStr != "0001-01-01T00:00:00Z" {
		fmt.Printf("  Last Used:      %s\n", lastUsedStr)
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

// Helper function for extracting uint64 values from JSON maps
func getUint64Value(m map[string]interface{}, key string) uint64 {
	if v, ok := m[key]; ok && v != nil {
		switch val := v.(type) {
		case float64:
			return uint64(val)
		case int:
			return uint64(val)
		case int64:
			return uint64(val)
		case uint64:
			return val
		}
	}
	return 0
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
