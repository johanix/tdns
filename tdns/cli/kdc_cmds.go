/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * CLI commands for tdns-kdc management
 */
package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/johanix/tdns/tdns"
	"github.com/johanix/tdns/tdns/hpke"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var nodeid, nodename, pubkeyfile string

var KdcCmd = &cobra.Command{
	Use:   "kdc",
	Short: "Interact with tdns-kdc via API",
	Long:  `Manage zones, nodes, and keys in the Key Distribution Center (KDC)`,
}

var KdcZoneCmd = &cobra.Command{
	Use:   "zone",
	Short: "Manage zones in KDC",
}

var KdcDistribCmd = &cobra.Command{
	Use:   "distrib",
	Short: "Manage key distributions",
	Long:  `Commands for managing key distributions, including listing distributions, checking their state, marking them as completed, and distributing keys to edge nodes.`,
}

var KdcNodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Manage edge nodes in KDC",
}

var KdcConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage KDC configuration",
}

// Zone commands
var kdcZoneAddCmd = &cobra.Command{
	Use:   "add --zone <zone-name>",
	Short: "Add a new zone to KDC",
	// Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "add",
			"zone": map[string]interface{}{
				"id":      tdns.Globals.Zonename,
				"name":    tdns.Globals.Zonename,
				"active":  true,
				"comment": "",
			},
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcZoneListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all zones in KDC",
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "list",
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		// Debug: print raw response in verbose mode
		if tdns.Globals.Verbose {
			rawJSON, _ := json.MarshalIndent(resp, "", "  ")
			fmt.Printf("DEBUG: Raw API response:\n%s\n", rawJSON)
		}

		zonesRaw, ok := resp["zones"]
		if !ok {
			fmt.Printf("Error: 'zones' key not found in response\n")
			fmt.Printf("Response keys: %v\n", getMapKeys(resp))
			return
		}

		zones, ok := zonesRaw.([]interface{})
		if !ok {
			fmt.Printf("Error: 'zones' is not an array (got %T)\n", zonesRaw)
			if tdns.Globals.Verbose {
				fmt.Printf("Value: %+v\n", zonesRaw)
			}
			return
		}

		if len(zones) == 0 {
			fmt.Println("No zones configured")
			return
		}

		fmt.Printf("%-30s %-30s %-10s %s\n", "ID", "Name", "Active", "Comment")
		fmt.Println(strings.Repeat("-", 100))
		for i, z := range zones {
			if tdns.Globals.Verbose {
				fmt.Printf("DEBUG: zone[%d] type: %T, value: %+v\n", i, z, z)
			}
			
			zone, ok := z.(map[string]interface{})
			if !ok {
				fmt.Printf("Warning: zone[%d] is not a map (got %T), skipping\n", i, z)
				continue
			}

			// Extract fields with proper type handling
			id := getString(zone, "id", "ID")
			name := getString(zone, "name", "Name")
			comment := getString(zone, "comment", "Comment")
			active := getBool(zone, "active", "Active")

			fmt.Printf("%-30s %-30s %-10v %s\n", id, name, active, comment)
		}
	},
}

var kdcZoneGetCmd = &cobra.Command{
	Use:   "get --zone <zone-id>",
	Short: "Get zone details from KDC",
	// Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get",
			"zone_id": tdns.Globals.Zonename,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		if zone, ok := resp["zone"].(map[string]interface{}); ok {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(zone)
		} else {
			fmt.Printf("Response: %+v\n", resp)
		}
	},
}

var KdcZoneDnssecCmd = &cobra.Command{
	Use:   "dnssec",
	Short: "Manage DNSSEC keys for a zone",
}

var kdcZoneDnssecListCmd = &cobra.Command{
	Use:   "list [--zone <zone-id>]",
	Short: "List all DNSSEC keys for a zone (or all zones if zone not specified)",
	Run: func(cmd *cobra.Command, args []string) {
		// Zone is optional - if provided, normalize it
		if tdns.Globals.Zonename != "" {
			tdns.Globals.Zonename = dns.Fqdn(tdns.Globals.Zonename)
		}

		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get-keys",
		}
		// Only include zone_id if zone was specified
		if tdns.Globals.Zonename != "" {
			req["zone_id"] = tdns.Globals.Zonename
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		keysRaw, ok := resp["keys"]
		if !ok {
			fmt.Printf("Error: 'keys' key not found in response\n")
			fmt.Printf("Response keys: %v\n", getMapKeys(resp))
			return
		}

		keys, ok := keysRaw.([]interface{})
		if !ok {
			fmt.Printf("Error: 'keys' is not an array (got %T)\n", keysRaw)
			if tdns.Globals.Verbose {
				fmt.Printf("Value: %+v\n", keysRaw)
			}
			return
		}

		if len(keys) == 0 {
			if tdns.Globals.Zonename != "" {
				fmt.Println("No keys configured for this zone")
			} else {
				fmt.Println("No keys configured for any zone")
			}
			return
		}

		var lines []string
		lines = append(lines, "Zone | Key ID | Type | Algorithm | State | Flags | Comment")

		for i, k := range keys {
			if tdns.Globals.Verbose {
				fmt.Printf("DEBUG: key[%d] type: %T, value: %+v\n", i, k, k)
			}

			key, ok := k.(map[string]interface{})
			if !ok {
				fmt.Printf("Warning: key[%d] is not a map (got %T), skipping\n", i, k)
				continue
			}

			// Get zone name (zone_id is the zone identifier, which is typically the zone name)
			zoneID := getString(key, "zone_id", "ZoneID")
			keyID := getString(key, "id", "ID")
			keyType := getString(key, "key_type", "KeyType")
			state := getString(key, "state", "State")
			flags := getString(key, "flags", "Flags")
			comment := getString(key, "comment", "Comment")

			// Get algorithm (may be number from JSON or string)
			var algStr string
			if algVal, ok := key["algorithm"]; ok {
				switch v := algVal.(type) {
				case float64:
					// JSON numbers come as float64
					algNum := uint8(v)
					if algName, ok := dns.AlgorithmToString[algNum]; ok {
						algStr = algName
					} else {
						algStr = fmt.Sprintf("%d", algNum)
					}
				case string:
					algStr = v
				default:
					algStr = fmt.Sprintf("%v", v)
				}
			} else {
				algStr = "?"
			}

			line := fmt.Sprintf("%s | %s | %s | %s | %s | %s | %s", zoneID, keyID, keyType, algStr, state, flags, comment)
			lines = append(lines, line)
		}

		fmt.Println(columnize.SimpleFormat(lines))
	},
}

var kdcZoneDeleteCmd = &cobra.Command{
	Use:   "delete --zone <zone-id>",
	Short: "Delete a zone from KDC",
	// Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "delete",
			"zone_id": tdns.Globals.Zonename,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

// Node commands
var kdcNodeAddCmd = &cobra.Command{
	Use:   "add --node <node-id> --name <node-name> --pubkey <pubkey-file>",
	Short: "Add a new edge node to KDC",
	Long:  `Add a new edge node. pubkey-file should contain the HPKE public key (32 bytes, hex or base64 encoded)`,
	// Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		// Validate required flags
		if nodeid == "" {
			log.Fatalf("Error: --nodeid is required")
		}
		if nodename == "" {
			log.Fatalf("Error: --nodename is required")
		}
		if pubkeyfile == "" {
			log.Fatalf("Error: --pubkeyfile is required")
		}

		prefixcmd, _ := getCommandContext("node")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		// Read public key file
		pubkeyData, err := os.ReadFile(pubkeyfile)
		if err != nil {
			log.Fatalf("Error reading public key file: %v", err)
		}

		// Extract key from file (skip comment lines starting with #)
		lines := strings.Split(string(pubkeyData), "\n")
		var keyLines []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				keyLines = append(keyLines, line)
			}
		}
		pubkeyStr := strings.Join(keyLines, "")

		// Decode hex or base64 (try hex first, then base64)
		var pubkey []byte
		
		// Try hex decoding first (64 hex chars = 32 bytes)
		if len(pubkeyStr) == 64 {
			pubkey, err = hex.DecodeString(pubkeyStr)
			if err != nil {
				log.Fatalf("Error decoding hex public key: %v", err)
			}
		} else {
			// Try base64
			pubkey, err = base64.StdEncoding.DecodeString(pubkeyStr)
			if err != nil {
				log.Fatalf("Error decoding base64 public key: %v", err)
			}
		}

		if len(pubkey) != 32 {
			log.Fatalf("Public key must be 32 bytes (X25519), got %d bytes", len(pubkey))
		}

		// Ensure node ID is FQDN
		nodeIDFQDN := dns.Fqdn(nodeid)

		req := map[string]interface{}{
			"command": "add",
			"node": map[string]interface{}{
				"id":               nodeIDFQDN,
				"name":             nodename,
				"long_term_pub_key": pubkey,
				"state":            "online",
				"comment":          "",
			},
		}

		resp, err := sendKdcRequest(api, "/kdc/node", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcNodeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all edge nodes in KDC",
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("node")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "list",
		}

		resp, err := sendKdcRequest(api, "/kdc/node", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		if nodes, ok := resp["nodes"].([]interface{}); ok {
			if len(nodes) == 0 {
				fmt.Println("No nodes configured")
				return
			}
			fmt.Printf("%-30s %-30s %-25s %-15s %s\n", "ID", "Name", "Notify Address", "State", "Comment")
			fmt.Println(strings.Repeat("-", 120))
			for _, n := range nodes {
				if node, ok := n.(map[string]interface{}); ok {
					id := fmt.Sprintf("%v", node["id"])
					name := fmt.Sprintf("%v", node["name"])
					notifyAddr := ""
					if addr, ok := node["notify_address"]; ok && addr != nil {
						notifyAddr = fmt.Sprintf("%v", addr)
					}
					state := fmt.Sprintf("%v", node["state"])
					comment := fmt.Sprintf("%v", node["comment"])
					fmt.Printf("%-30s %-30s %-25s %-15s %s\n", id, name, notifyAddr, state, comment)
				}
			}
		} else {
			fmt.Printf("Response: %+v\n", resp)
		}
	},
}

var kdcNodeGetCmd = &cobra.Command{
	Use:   "get [node-id]",
	Short: "Get node details from KDC",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("node")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get",
			"node_id": args[0],
		}

		resp, err := sendKdcRequest(api, "/kdc/node", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		if node, ok := resp["node"].(map[string]interface{}); ok {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(node)
		} else {
			fmt.Printf("Response: %+v\n", resp)
		}
	},
}

var kdcNodeUpdateCmd = &cobra.Command{
	Use:   "update --nodeid <node-id> [--name <name>] [--notify-address <address:port>] [--comment <comment>]",
	Short: "Update node details (name, notify address, comment)",
	Run: func(cmd *cobra.Command, args []string) {
		updateNodeID := cmd.Flag("nodeid").Value.String()
		if updateNodeID == "" {
			log.Fatalf("Error: --nodeid is required")
		}

		// Ensure node ID is FQDN
		updateNodeIDFQDN := dns.Fqdn(updateNodeID)

		prefixcmd, _ := getCommandContext("node")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		// Get current node to preserve fields not being updated
		getReq := map[string]interface{}{
			"command": "get",
			"node_id": updateNodeIDFQDN,
		}
		getResp, err := sendKdcRequest(api, "/kdc/node", getReq)
		if err != nil {
			log.Fatalf("Error getting current node: %v", err)
		}
		if getResp["error"] == true {
			log.Fatalf("Error getting current node: %v", getResp["error_msg"])
		}

		nodeMap, ok := getResp["node"].(map[string]interface{})
		if !ok {
			log.Fatalf("Error: invalid node data in response")
		}

		// Update fields if provided
		updateNode := map[string]interface{}{
			"id": updateNodeIDFQDN,
		}

		// Preserve or update name
		if nameFlag := cmd.Flag("name").Value.String(); nameFlag != "" {
			updateNode["name"] = nameFlag
		} else if name, ok := nodeMap["name"]; ok {
			updateNode["name"] = name
		}

		// Preserve or update notify_address
		if notifyAddrFlag := cmd.Flag("notify-address").Value.String(); notifyAddrFlag != "" {
			updateNode["notify_address"] = notifyAddrFlag
		} else if addr, ok := nodeMap["notify_address"]; ok {
			updateNode["notify_address"] = addr
		}

		// Preserve long_term_pub_key (required field)
		// JSON encodes []byte as base64 string, so we need to decode it back to []byte
		if pubkeyVal, ok := nodeMap["long_term_pub_key"]; ok {
			var pubkeyBytes []byte
			if pubkeyStr, ok := pubkeyVal.(string); ok {
				// Decode base64 string back to []byte
				pubkeyBytes, err = base64.StdEncoding.DecodeString(pubkeyStr)
				if err != nil {
					log.Fatalf("Error decoding public key from response: %v", err)
				}
			} else {
				log.Fatalf("Error: public key has unexpected type: %T", pubkeyVal)
			}
			updateNode["long_term_pub_key"] = pubkeyBytes
		} else {
			log.Fatalf("Error: public key not found in node data")
		}

		// Preserve state
		if state, ok := nodeMap["state"]; ok {
			updateNode["state"] = state
		} else {
			updateNode["state"] = "online"
		}

		// Preserve or update comment
		if commentFlag := cmd.Flag("comment").Value.String(); commentFlag != "" {
			updateNode["comment"] = commentFlag
		} else if comment, ok := nodeMap["comment"]; ok {
			updateNode["comment"] = comment
		} else {
			updateNode["comment"] = ""
		}

		req := map[string]interface{}{
			"command": "update",
			"node":    updateNode,
		}

		resp, err := sendKdcRequest(api, "/kdc/node", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcNodeSetStateCmd = &cobra.Command{
	Use:   "set-state [node-id] [state]",
	Short: "Set node state (online, offline, compromised, suspended)",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient("tdns-kdc", true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "set-state",
			"node_id": args[0],
			"state":   args[1],
		}

		resp, err := sendKdcRequest(api, "/kdc/node", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcNodeDeleteCmd = &cobra.Command{
	Use:   "delete [node-id]",
	Short: "Delete a node from KDC",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("node")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		// Ensure node ID is FQDN
		nodeIDFQDN := dns.Fqdn(args[0])

		req := map[string]interface{}{
			"command": "delete",
			"node_id": nodeIDFQDN,
		}

		resp, err := sendKdcRequest(api, "/kdc/node", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var KdcDebugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Debug utilities for KDC",
}

var KdcDebugDistribCmd = &cobra.Command{
	Use:   "distrib",
	Short: "Manage test distributions",
	Long:  `Commands for creating, listing, and deleting test distributions.`,
}

var kdcDebugDistribGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Create a test distribution with clear_text or encrypted_text content",
	Long:  `Creates a persistent test distribution that can be queried by KRS. The distribution will contain text read from a file (or default lorem ipsum if no file specified) that will be chunked and distributed. Use --content-type to choose 'clear_text' (default) or 'encrypted_text' (HPKE encrypted).`,
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient("kdc", true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		distributionID := cmd.Flag("id").Value.String()
		nodeID := cmd.Flag("node-id").Value.String()
		testTextFile := cmd.Flag("file").Value.String()

		if distributionID == "" {
			log.Fatalf("Error: --id is required")
		}
		if nodeID == "" {
			log.Fatalf("Error: --node-id is required")
		}

		// Ensure node ID is FQDN
		nodeIDFQDN := dns.Fqdn(nodeID)

		var testText string
		if testTextFile != "" {
			// Read from file
			data, err := os.ReadFile(testTextFile)
			if err != nil {
				log.Fatalf("Error reading file %s: %v", testTextFile, err)
			}
			testText = string(data)
		}

		contentType := cmd.Flag("content-type").Value.String()
		if contentType == "" {
			contentType = "clear_text" // Default
		}
		if contentType != "clear_text" && contentType != "encrypted_text" {
			log.Fatalf("Error: --content-type must be 'clear_text' or 'encrypted_text' (got: %s)", contentType)
		}

		req := map[string]interface{}{
			"command":        "test-distribution",
			"distribution_id": distributionID,
			"node_id":        nodeIDFQDN,
			"content_type":   contentType,
		}
		if testText != "" {
			req["test_text"] = testText
		}

		resp, err := sendKdcRequest(api, "/kdc/debug", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("Test distribution created successfully\n")
		fmt.Printf("  Distribution ID: %s\n", resp["distribution_id"])
		fmt.Printf("  Node ID: %s\n", nodeIDFQDN)
		if chunkCount, ok := resp["chunk_count"].(float64); ok {
			fmt.Printf("  Chunk count: %.0f\n", chunkCount)
		}
		fmt.Printf("  Message: %s\n", resp["msg"])
	},
}

var kdcDebugDistribListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all distribution IDs",
	Long:  `Lists all distribution IDs (both test and real) currently stored in the KDC.`,
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient("kdc", true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "list-distributions",
		}

		resp, err := sendKdcRequest(api, "/kdc/debug", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
		
		// Try to get distribution_infos first (new format with node info)
		if distInfosRaw, ok := resp["distribution_infos"].([]interface{}); ok {
			if len(distInfosRaw) > 0 {
				fmt.Printf("\nDistribution IDs:\n")
				for _, distInfoRaw := range distInfosRaw {
					if distInfo, ok := distInfoRaw.(map[string]interface{}); ok {
						distID, _ := distInfo["distribution_id"].(string)
						nodesRaw, _ := distInfo["nodes"].([]interface{})
						nodes := make([]string, 0, len(nodesRaw))
						for _, nodeRaw := range nodesRaw {
							if node, ok := nodeRaw.(string); ok {
								nodes = append(nodes, node)
							}
						}
						if len(nodes) > 0 {
							fmt.Printf("  - %s (applies to nodes %s)\n", distID, strings.Join(nodes, ", "))
						} else {
							fmt.Printf("  - %s\n", distID)
						}
					}
				}
			}
		} else if distributions, ok := resp["distributions"].([]interface{}); ok {
			// Fallback to old format (backward compatibility)
			if len(distributions) > 0 {
				fmt.Printf("\nDistribution IDs:\n")
				for _, distID := range distributions {
					if id, ok := distID.(string); ok {
						fmt.Printf("  - %s\n", id)
					}
				}
			}
		}
	},
}

var kdcDebugDistribDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a distribution by ID",
	Long:  `Deletes a distribution (both from database and cache) by its distribution ID.`,
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient("kdc", true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		distributionID := cmd.Flag("id").Value.String()
		if distributionID == "" {
			log.Fatalf("Error: --id is required")
		}

		req := map[string]interface{}{
			"command":        "delete-distribution",
			"distribution_id": distributionID,
		}

		resp, err := sendKdcRequest(api, "/kdc/debug", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcDebugSetChunkSizeCmd = &cobra.Command{
	Use:   "set-chunk-size",
	Short: "Set the maximum chunk size for new distributions",
	Long:  `Sets the maximum chunk size (in bytes) for JSONCHUNK records. This only affects new distributions created after this change. Existing distributions are not affected.`,
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("debug")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		chunkSizeStr := cmd.Flag("size").Value.String()
		if chunkSizeStr == "" {
			log.Fatalf("Error: --size is required")
		}

		var chunkSize int
		if _, err := fmt.Sscanf(chunkSizeStr, "%d", &chunkSize); err != nil {
			log.Fatalf("Error: invalid chunk size: %v", err)
		}

		if chunkSize <= 0 {
			log.Fatalf("Error: chunk size must be greater than 0")
		}

		req := map[string]interface{}{
			"command":   "set-chunk-size",
			"chunk_size": chunkSize,
		}

		resp, err := sendKdcRequest(api, "/kdc/debug", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
		if size, ok := resp["chunk_size"].(float64); ok {
			fmt.Printf("  Current chunk size: %.0f bytes\n", size)
		}
	},
}

var kdcDebugGetChunkSizeCmd = &cobra.Command{
	Use:   "get-chunk-size",
	Short: "Get the current maximum chunk size",
	Long:  `Gets the current maximum chunk size (in bytes) for JSONCHUNK records.`,
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("debug")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get-chunk-size",
		}

		resp, err := sendKdcRequest(api, "/kdc/debug", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
		if size, ok := resp["chunk_size"].(float64); ok {
			fmt.Printf("  Current chunk size: %.0f bytes\n", size)
		}
	},
}

var kdcDebugHpkeEncryptCmd = &cobra.Command{
	Use:   "hpke-encrypt --zone <zone-id> --keyid <key-id> --nodeid <node-id> [--output <file>]",
	Short: "Test HPKE encryption of a DNSSEC key for a node",
	Long:  `Encrypts a DNSSEC key's private key material using HPKE with a node's long-term public key. This is a test/debug command.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		prefixcmd, _ := getCommandContext("debug")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		keyID := cmd.Flag("keyid").Value.String()
		nodeID := cmd.Flag("nodeid").Value.String()
		outputFile := cmd.Flag("output").Value.String()

		if keyID == "" {
			log.Fatalf("Error: --keyid is required")
		}
		if nodeID == "" {
			log.Fatalf("Error: --nodeid is required")
		}

		// Request encryption via API
		req := map[string]interface{}{
			"command": "encrypt-key",
			"zone_id": tdns.Globals.Zonename,
			"key_id":  keyID,
			"node_id": nodeID,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		// Extract encrypted data
		encryptedKeyRaw, ok := resp["encrypted_key"]
		if !ok {
			log.Fatalf("Error: 'encrypted_key' not found in response")
		}

		ephemeralPubKeyRaw, ok := resp["ephemeral_pub_key"]
		if !ok {
			log.Fatalf("Error: 'ephemeral_pub_key' not found in response")
		}

		distributionID := getString(resp, "distribution_id", "DistributionID")

		// Convert to []byte (assuming base64 encoding from JSON)
		var encryptedKey, ephemeralPubKey []byte
		if encStr, ok := encryptedKeyRaw.(string); ok {
			encryptedKey, err = base64.StdEncoding.DecodeString(encStr)
			if err != nil {
				log.Fatalf("Error decoding encrypted_key: %v", err)
			}
		} else if encBytes, ok := encryptedKeyRaw.([]byte); ok {
			encryptedKey = encBytes
		} else {
			log.Fatalf("Error: encrypted_key has unexpected type: %T", encryptedKeyRaw)
		}

		if ephemStr, ok := ephemeralPubKeyRaw.(string); ok {
			ephemeralPubKey, err = base64.StdEncoding.DecodeString(ephemStr)
			if err != nil {
				log.Fatalf("Error decoding ephemeral_pub_key: %v", err)
			}
		} else if ephemBytes, ok := ephemeralPubKeyRaw.([]byte); ok {
			ephemeralPubKey = ephemBytes
		} else {
			log.Fatalf("Error: ephemeral_pub_key has unexpected type: %T", ephemeralPubKeyRaw)
		}

		// Output results
		fmt.Printf("Encryption successful!\n")
		fmt.Printf("Distribution ID: %s\n", distributionID)
		fmt.Printf("Encrypted key size: %d bytes\n", len(encryptedKey))
		fmt.Printf("Ephemeral public key size: %d bytes\n", len(ephemeralPubKey))
		fmt.Printf("Ephemeral public key (hex): %x\n", ephemeralPubKey)

		if outputFile != "" {
			// Write encrypted key to file
			output := fmt.Sprintf("# HPKE-encrypted DNSSEC key\n")
			output += fmt.Sprintf("# Distribution ID: %s\n", distributionID)
			output += fmt.Sprintf("# Zone: %s\n", tdns.Globals.Zonename)
			output += fmt.Sprintf("# Key ID: %s\n", keyID)
			output += fmt.Sprintf("# Node ID: %s\n", nodeID)
			output += fmt.Sprintf("# Encrypted at: %s\n", time.Now().Format(time.RFC3339))
			output += fmt.Sprintf("# Ephemeral public key (hex): %x\n", ephemeralPubKey)
			output += fmt.Sprintf("# Encrypted key (base64):\n")
			output += base64.StdEncoding.EncodeToString(encryptedKey) + "\n"

			if err := os.WriteFile(outputFile, []byte(output), 0600); err != nil {
				log.Fatalf("Error writing output file: %v", err)
			}
			fmt.Printf("\nEncrypted key written to: %s\n", outputFile)
		}
	},
}

var kdcDebugHpkeGenerateCmd = &cobra.Command{
	Use:   "hpke-generate [prefix]",
	Short: "Generate an HPKE keypair for testing",
	Long:  `Generates an HPKE keypair and writes the public key to {prefix}.publickey and private key to {prefix}.privatekey (both hex encoded).`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		prefix := args[0]
		pubKeyFile := prefix + ".publickey"
		privKeyFile := prefix + ".privatekey"
		
		// Generate HPKE keypair
		pubKey, privKey, err := hpke.GenerateKeyPair()
		if err != nil {
			log.Fatalf("Error generating HPKE keypair: %v", err)
		}

		// Format keys as hex
		pubKeyHex := fmt.Sprintf("%x", pubKey)
		privKeyHex := fmt.Sprintf("%x", privKey)

		// Create public key file with comments
		pubKeyContent := fmt.Sprintf(`# HPKE Public Key (X25519)
# Generated: %s
# Algorithm: X25519 (HPKE KEM)
# Key Size: 32 bytes (256 bits)
# Format: Hexadecimal
# 
# This is the public key for HPKE (Hybrid Public Key Encryption).
# It can be safely shared and used to encrypt data for the holder of the corresponding private key.
#
%s
`, time.Now().Format(time.RFC3339), pubKeyHex)

		// Create private key file with comments
		privKeyContent := fmt.Sprintf(`# HPKE Private Key (X25519)
# Generated: %s
# Algorithm: X25519 (HPKE KEM)
# Key Size: 32 bytes (256 bits)
# Format: Hexadecimal
# 
# WARNING: This is a PRIVATE KEY. Keep it secret and secure!
# Do not share this key with anyone. Anyone with access to this key can decrypt
# data encrypted with the corresponding public key.
#
%s
`, time.Now().Format(time.RFC3339), privKeyHex)

		// Write public key file (readable by owner and group, not others)
		if err := os.WriteFile(pubKeyFile, []byte(pubKeyContent), 0644); err != nil {
			log.Fatalf("Error writing public key to file: %v", err)
		}

		// Write private key file (readable only by owner)
		if err := os.WriteFile(privKeyFile, []byte(privKeyContent), 0600); err != nil {
			log.Fatalf("Error writing private key to file: %v", err)
		}

		fmt.Printf("HPKE keypair generated successfully:\n")
		fmt.Printf("  Public key:  %s\n", pubKeyFile)
		fmt.Printf("  Private key: %s\n", privKeyFile)
		fmt.Printf("\nTo add this as a node, use:\n")
		fmt.Printf("  tdns-cli kdc node add --nodeid <node-id> --nodename <node-name> --pubkeyfile %s\n", pubKeyFile)
	},
}

var kdcDebugHpkeDecryptCmd = &cobra.Command{
	Use:   "hpke-decrypt --encrypted-file <file> --private-key-file <file>",
	Short: "Test HPKE decryption of an encrypted DNSSEC key",
	Long:  `Decrypts an HPKE-encrypted DNSSEC key file using a node's private key. This is a test/debug command.`,
	Run: func(cmd *cobra.Command, args []string) {
		encryptedFile := cmd.Flag("encrypted-file").Value.String()
		privateKeyFile := cmd.Flag("private-key-file").Value.String()

		if encryptedFile == "" {
			log.Fatalf("Error: --encrypted-file is required")
		}
		if privateKeyFile == "" {
			log.Fatalf("Error: --private-key-file is required")
		}

		// Read encrypted key file
		encryptedData, err := os.ReadFile(encryptedFile)
		if err != nil {
			log.Fatalf("Error reading encrypted file: %v", err)
		}

		// Parse the encrypted file (it has comments and base64 data)
		lines := strings.Split(string(encryptedData), "\n")
		var encryptedKeyBase64 string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, "Encrypted key (base64):") {
				// The base64 data should be on the next line
				continue
			} else if len(line) > 50 {
				// Likely the base64 encrypted key
				encryptedKeyBase64 = line
			}
		}

		if encryptedKeyBase64 == "" {
			log.Fatalf("Error: could not find encrypted key in file")
		}

		// Decode base64 encrypted key
		encryptedKey, err := base64.StdEncoding.DecodeString(encryptedKeyBase64)
		if err != nil {
			log.Fatalf("Error decoding base64 encrypted key: %v", err)
		}

		// Read private key file
		privateKeyData, err := os.ReadFile(privateKeyFile)
		if err != nil {
			log.Fatalf("Error reading private key file: %v", err)
		}

		// Parse private key (skip comments, decode hex)
		privKeyLines := strings.Split(string(privateKeyData), "\n")
		var privKeyHex string
		for _, line := range privKeyLines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				privKeyHex += line
			}
		}

		if privKeyHex == "" {
			log.Fatalf("Error: could not find private key in file")
		}

		// Decode hex private key
		privateKey, err := hex.DecodeString(privKeyHex)
		if err != nil {
			log.Fatalf("Error decoding hex private key: %v", err)
		}

		if len(privateKey) != 32 {
			log.Fatalf("Error: private key must be 32 bytes (got %d)", len(privateKey))
		}

		// Decrypt using HPKE
		// Note: HPKE Base mode extracts ephemeral key from ciphertext, so we don't need ephemeralPubKeyHex
		plaintext, err := hpke.Decrypt(privateKey, nil, encryptedKey)
		if err != nil {
			log.Fatalf("Error decrypting: %v", err)
		}

		fmt.Printf("Decryption successful!\n")
		fmt.Printf("Decrypted key size: %d bytes\n", len(plaintext))
		fmt.Printf("\nDecrypted private key (PEM format):\n")
		fmt.Printf("%s\n", string(plaintext))
	},
}

var kdcZoneDnssecGenerateCmd = &cobra.Command{
	Use:   "generate --zone <zone-id> --type <KSK|ZSK|CSK> [--algorithm <alg>] [--comment <comment>]",
	Short: "Generate a DNSSEC key for a zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		keyType := cmd.Flag("type").Value.String()
		if keyType == "" {
			keyType = "ZSK" // Default
		}
		if keyType != "KSK" && keyType != "ZSK" && keyType != "CSK" {
			log.Fatalf("Error: key type must be KSK, ZSK, or CSK (got: %s)", keyType)
		}

		algorithmStr := cmd.Flag("algorithm").Value.String()
		var algorithm uint8
		if algorithmStr != "" {
			var algNum int
			if _, err := fmt.Sscanf(algorithmStr, "%d", &algNum); err != nil {
				// Try to parse as algorithm name
				if algNumVal, ok := dns.StringToAlgorithm[strings.ToUpper(algorithmStr)]; ok {
					algorithm = algNumVal
				} else {
					log.Fatalf("Error: invalid algorithm: %s", algorithmStr)
				}
			} else {
				algorithm = uint8(algNum)
			}
		}
		// If algorithm is 0, API will use default (ED25519)

		req := map[string]interface{}{
			"command": "generate-key",
			"zone_id": tdns.Globals.Zonename,
			"key_type": keyType,
		}
		if algorithm != 0 {
			req["algorithm"] = algorithm
		}
		if comment := cmd.Flag("comment").Value.String(); comment != "" {
			req["comment"] = comment
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

// Config commands
var kdcConfigGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get KDC configuration",
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("config")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get",
		}

		resp, err := sendKdcRequest(api, "/kdc/config", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		configRaw, ok := resp["config"]
		if !ok {
			fmt.Printf("Error: 'config' key not found in response\n")
			return
		}

		config, ok := configRaw.(map[string]interface{})
		if !ok {
			fmt.Printf("Error: 'config' is not an object (got %T)\n", configRaw)
			return
		}

		// Pretty print the config
		configJSON, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling config: %v\n", err)
			return
		}
		fmt.Printf("%s\n", string(configJSON))
	},
}

var kdcDistribSingleCmd = &cobra.Command{
	Use:   "single --zone <zone-id> --keyid <key-id>",
	Short: "Trigger distribution of a specific standby ZSK to all nodes",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		keyid := cmd.Flag("keyid").Value.String()
		if keyid == "" {
			log.Fatalf("Error: --keyid is required")
		}

		prefixcmd, _ := getCommandContext("distrib")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "distribute-zsk",
			"zone_id": tdns.Globals.Zonename,
			"key_id":  keyid,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcDistribMultiCmd = &cobra.Command{
	Use:   "multi [zone1] [zone2] ...",
	Short: "Distribute standby ZSK keys for one or more zones (auto-selects standby keys)",
	Long:  `Distributes standby ZSK keys for the specified zones. For each zone, automatically selects a standby ZSK and distributes it to all active nodes.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Normalize zone names to FQDNs
		zones := make([]string, len(args))
		for i, zone := range args {
			zones[i] = dns.Fqdn(zone)
		}

		prefixcmd, _ := getCommandContext("distrib")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "distrib-multi",
			"zones":   zones,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
		
		// If there are results, display them
		if resultsRaw, ok := resp["results"]; ok {
			if results, ok := resultsRaw.([]interface{}); ok {
				for _, result := range results {
					if resultMap, ok := result.(map[string]interface{}); ok {
						zoneID := getString(resultMap, "zone_id", "ZoneID")
						keyID := getString(resultMap, "key_id", "KeyID")
						status := getString(resultMap, "status", "Status")
						msg := getString(resultMap, "msg", "Msg")
						if status == "success" {
							fmt.Printf("  %s: Key %s distributed successfully\n", zoneID, keyID)
						} else {
							fmt.Printf("  %s: %s\n", zoneID, msg)
						}
					}
				}
			}
		}
	},
}

var kdcZoneTransitionCmd = &cobra.Command{
	Use:   "transition --zone <zone-id> --keyid <key-id>",
	Short: "Transition a key state (created->published or standby->active, auto-detected)",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		keyid := cmd.Flag("keyid").Value.String()
		if keyid == "" {
			log.Fatalf("Error: --keyid is required")
		}

		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "transition",
			"zone_id": tdns.Globals.Zonename,
			"key_id":  keyid,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcZoneDnssecHashCmd = &cobra.Command{
	Use:   "hash --zone <zone-id> --keyid <key-id>",
	Short: "Compute SHA-256 hash of a key's private key material",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		keyid := cmd.Flag("keyid").Value.String()
		if keyid == "" {
			log.Fatalf("Error: --keyid is required")
		}

		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "hash",
			"zone_id": tdns.Globals.Zonename,
			"key_id":  keyid,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		hash := getString(resp, "msg", "Msg")
		if hash == "" {
			log.Fatalf("Error: hash not found in response")
		}

		fmt.Printf("Key Hash (SHA-256): %s\n", hash)
	},
}

var kdcZoneDnssecDeleteCmd = &cobra.Command{
	Use:   "delete --zone <zone-id> --keyid <key-id>",
	Short: "Delete a DNSSEC key",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		keyid := cmd.Flag("keyid").Value.String()
		if keyid == "" {
			log.Fatalf("Error: --keyid is required")
		}

		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "delete-key",
			"zone_id": tdns.Globals.Zonename,
			"key_id":  keyid,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcDistribListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all ongoing distributions",
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("distrib")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "list",
		}

		resp, err := sendKdcRequest(api, "/kdc/distrib", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
		
		if dists, ok := resp["distributions"].([]interface{}); ok {
			if len(dists) == 0 {
				fmt.Println("No distributions found")
			} else {
				fmt.Println("\nDistribution IDs:")
				for _, dist := range dists {
					fmt.Printf("  %s\n", dist)
				}
			}
		}
	},
}

var kdcDistribStateCmd = &cobra.Command{
	Use:   "state --id <distribution-id>",
	Short: "Show detailed state of a distribution",
	Run: func(cmd *cobra.Command, args []string) {
		distID := cmd.Flag("id").Value.String()
		if distID == "" {
			log.Fatalf("Error: --id is required")
		}

		prefixcmd, _ := getCommandContext("distrib")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command":        "state",
			"distribution_id": distID,
		}

		resp, err := sendKdcRequest(api, "/kdc/distrib", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n\n", resp["msg"])
		
		if stateRaw, ok := resp["state"]; ok {
			if state, ok := stateRaw.(map[string]interface{}); ok {
				fmt.Printf("Distribution ID: %s\n", getString(state, "distribution_id", "DistributionID"))
				fmt.Printf("Zone: %s\n", getString(state, "zone_id", "ZoneID"))
				fmt.Printf("Key ID: %s\n", getString(state, "key_id", "KeyID"))
				fmt.Printf("Key State: %s\n", getString(state, "key_state", "KeyState"))
				fmt.Printf("Created At: %s\n", getString(state, "created_at", "CreatedAt"))
				fmt.Printf("All Confirmed: %v\n\n", getBool(state, "all_confirmed", "AllConfirmed"))
				
				if confirmedNodes, ok := state["confirmed_nodes"].([]interface{}); ok {
					fmt.Printf("Confirmed Nodes (%d):\n", len(confirmedNodes))
					for _, node := range confirmedNodes {
						fmt.Printf("  - %s\n", node)
					}
				}
				
				if pendingNodes, ok := state["pending_nodes"].([]interface{}); ok {
					fmt.Printf("\nPending Nodes (%d):\n", len(pendingNodes))
					if len(pendingNodes) == 0 {
						fmt.Println("  (none - all confirmed)")
					} else {
						for _, node := range pendingNodes {
							fmt.Printf("  - %s\n", node)
						}
					}
				}
			}
		}
	},
}

var kdcDistribCompletedCmd = &cobra.Command{
	Use:   "completed --id <distribution-id>",
	Short: "Force mark a distribution as completed (even if nodes haven't confirmed)",
	Run: func(cmd *cobra.Command, args []string) {
		distID := cmd.Flag("id").Value.String()
		if distID == "" {
			log.Fatalf("Error: --id is required")
		}

		prefixcmd, _ := getCommandContext("distrib")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command":        "completed",
			"distribution_id": distID,
		}

		resp, err := sendKdcRequest(api, "/kdc/distrib", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcZoneSetStateCmd = &cobra.Command{
	Use:   "setstate --zone <zone-id> --keyid <key-id> --state <state>",
	Short: "Set a key to any state (debug command)",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")
		keyid := cmd.Flag("keyid").Value.String()
		newState := cmd.Flag("state").Value.String()
		if keyid == "" {
			log.Fatalf("Error: --keyid is required")
		}
		if newState == "" {
			log.Fatalf("Error: --state is required")
		}

		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command":  "setstate",
			"zone_id":  tdns.Globals.Zonename,
			"key_id":   keyid,
			"new_state": newState,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

func init() {
	KdcZoneDnssecCmd.AddCommand(kdcZoneDnssecListCmd, kdcZoneDnssecGenerateCmd, kdcZoneDnssecDeleteCmd, kdcZoneDnssecHashCmd)
	KdcZoneCmd.AddCommand(kdcZoneAddCmd, kdcZoneListCmd, kdcZoneGetCmd, KdcZoneDnssecCmd, kdcZoneDeleteCmd,
		kdcZoneTransitionCmd, kdcZoneSetStateCmd)
	KdcDistribCmd.AddCommand(kdcDistribListCmd, kdcDistribStateCmd, kdcDistribCompletedCmd, kdcDistribSingleCmd, kdcDistribMultiCmd)
	KdcNodeCmd.AddCommand(kdcNodeAddCmd, kdcNodeListCmd, kdcNodeGetCmd, kdcNodeUpdateCmd, kdcNodeSetStateCmd, kdcNodeDeleteCmd)
	KdcDebugDistribCmd.AddCommand(kdcDebugDistribGenerateCmd, kdcDebugDistribListCmd, kdcDebugDistribDeleteCmd)
	KdcDebugCmd.AddCommand(kdcDebugHpkeGenerateCmd, kdcDebugHpkeEncryptCmd, kdcDebugHpkeDecryptCmd, 
		KdcDebugDistribCmd, kdcDebugSetChunkSizeCmd, kdcDebugGetChunkSizeCmd)
	KdcConfigCmd.AddCommand(kdcConfigGetCmd)
	KdcCmd.AddCommand(KdcZoneCmd, KdcNodeCmd, KdcConfigCmd, KdcDebugCmd, KdcDistribCmd, PingCmd)

	kdcDistribSingleCmd.Flags().StringP("keyid", "k", "", "Key ID (must be a ZSK in standby state)")
	kdcDistribSingleCmd.MarkFlagRequired("keyid")
	
	kdcDistribStateCmd.Flags().String("id", "", "Distribution ID")
	kdcDistribStateCmd.MarkFlagRequired("id")
	
	kdcDistribCompletedCmd.Flags().String("id", "", "Distribution ID")
	kdcDistribCompletedCmd.MarkFlagRequired("id")
	
	kdcZoneTransitionCmd.Flags().StringP("keyid", "k", "", "Key ID (transition auto-detected: created->published or standby->active)")
	kdcZoneTransitionCmd.MarkFlagRequired("keyid")
	
	kdcZoneDnssecDeleteCmd.Flags().StringP("keyid", "k", "", "Key ID to delete")
	kdcZoneDnssecDeleteCmd.MarkFlagRequired("keyid")

	kdcZoneDnssecHashCmd.Flags().StringP("keyid", "k", "", "Key ID")
	kdcZoneDnssecHashCmd.MarkFlagRequired("keyid")
	
	kdcZoneSetStateCmd.Flags().StringP("keyid", "k", "", "Key ID")
	kdcZoneSetStateCmd.Flags().StringP("state", "s", "", "New state")
	kdcZoneSetStateCmd.MarkFlagRequired("keyid")
	kdcZoneSetStateCmd.MarkFlagRequired("state")

	KdcNodeCmd.PersistentFlags().StringVarP(&nodeid, "nodeid", "n", "", "node id")
	KdcNodeCmd.PersistentFlags().StringVarP(&nodename, "nodename", "N", "", "node name")
	KdcNodeCmd.PersistentFlags().StringVarP(&pubkeyfile, "pubkeyfile", "p", "", "public key file")
	
	kdcNodeUpdateCmd.Flags().StringP("nodeid", "n", "", "Node ID (required)")
	kdcNodeUpdateCmd.MarkFlagRequired("nodeid")
	kdcNodeUpdateCmd.Flags().StringP("name", "", "", "Node name")
	kdcNodeUpdateCmd.Flags().StringP("notify-address", "a", "", "Notify address:port (e.g., 192.0.2.1:53)")
	kdcNodeUpdateCmd.Flags().StringP("comment", "c", "", "Comment")

	kdcZoneDnssecGenerateCmd.Flags().StringP("type", "t", "ZSK", "Key type: KSK, ZSK, or CSK")
	kdcZoneDnssecGenerateCmd.Flags().StringP("algorithm", "a", "", "DNSSEC algorithm (number or name, e.g., 15 or ED25519)")
	kdcZoneDnssecGenerateCmd.Flags().StringP("comment", "c", "", "Optional comment for the key")

	kdcDebugHpkeEncryptCmd.Flags().StringP("keyid", "k", "", "DNSSEC key ID to encrypt")
	kdcDebugHpkeEncryptCmd.Flags().StringP("nodeid", "n", "", "Node ID to encrypt for")
	kdcDebugHpkeEncryptCmd.Flags().StringP("output", "o", "", "Output file for encrypted key (optional)")
	kdcDebugHpkeEncryptCmd.MarkFlagRequired("keyid")
	kdcDebugHpkeEncryptCmd.MarkFlagRequired("nodeid")

	kdcDebugHpkeDecryptCmd.Flags().StringP("encrypted-file", "e", "", "File containing encrypted key")
	kdcDebugHpkeDecryptCmd.Flags().StringP("private-key-file", "p", "", "File containing node's HPKE private key (hex)")
	kdcDebugHpkeDecryptCmd.MarkFlagRequired("encrypted-file")
	kdcDebugHpkeDecryptCmd.MarkFlagRequired("private-key-file")

	kdcDebugDistribGenerateCmd.Flags().String("id", "", "Distribution ID (hex, e.g., a1b2)")
	kdcDebugDistribGenerateCmd.Flags().StringP("node-id", "n", "", "Node ID")
	kdcDebugDistribGenerateCmd.Flags().StringP("file", "f", "", "File containing text (if not provided, uses default lorem ipsum)")
	kdcDebugDistribGenerateCmd.Flags().StringP("content-type", "t", "clear_text", "Content type: 'clear_text' or 'encrypted_text' (default: clear_text)")
	kdcDebugDistribGenerateCmd.MarkFlagRequired("id")
	kdcDebugDistribGenerateCmd.MarkFlagRequired("node-id")

	kdcDebugDistribDeleteCmd.Flags().String("id", "", "Distribution ID to delete")
	kdcDebugDistribDeleteCmd.MarkFlagRequired("id")

	kdcDebugSetChunkSizeCmd.Flags().StringP("size", "s", "", "Chunk size in bytes")
	kdcDebugSetChunkSizeCmd.MarkFlagRequired("size")
}

// sendKdcRequest sends a JSON POST request to the KDC API
func sendKdcRequest(api *tdns.ApiClient, endpoint string, data interface{}) (map[string]interface{}, error) {
	var result map[string]interface{}

	bytebuf := new(bytes.Buffer)
	if err := json.NewEncoder(bytebuf).Encode(data); err != nil {
		return nil, fmt.Errorf("error encoding request: %v", err)
	}

	status, buf, err := api.Post(endpoint, bytebuf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error from API POST: %v", err)
	}

	if tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	if err := json.Unmarshal(buf, &result); err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %v", err)
	}

	return result, nil
}

// Helper functions for extracting values from JSON maps
func getString(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if v, ok := m[key]; ok && v != nil {
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

func getBool(m map[string]interface{}, keys ...string) bool {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			switch val := v.(type) {
			case bool:
				return val
			case string:
				return val == "true" || val == "1"
			case float64:
				return val != 0
			case int:
				return val != 0
			}
		}
	}
	return false
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

