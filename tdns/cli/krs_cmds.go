/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * CLI commands for tdns-krs management
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var KrsCmd = &cobra.Command{
	Use:   "krs",
	Short: "Interact with tdns-krs via API",
	Long:  `Manage received keys and node configuration in the Key Receiving Service (KRS)`,
}

var KrsKeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage received keys",
}

var KrsConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage node configuration",
}

var KrsQueryCmd = &cobra.Command{
	Use:   "query",
	Short: "Query KDC for keys",
}

var KrsDebugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Debug utilities for KRS",
}

var KrsDebugDistribCmd = &cobra.Command{
	Use:   "distrib",
	Short: "Manage test distributions",
	Long:  `Commands for fetching and processing distributions.`,
}

// Key commands
var krsKeysListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all received keys",
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("keys")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "list",
		}

		resp, err := sendKrsRequest(api, "/krs/keys", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		keysRaw, ok := resp["keys"]
		if !ok {
			fmt.Printf("Error: 'keys' key not found in response\n")
			return
		}

		keys, ok := keysRaw.([]interface{})
		if !ok {
			fmt.Printf("Error: 'keys' is not an array (got %T)\n", keysRaw)
			return
		}

		if len(keys) == 0 {
			fmt.Println("No keys received")
			return
		}

		// Sort keys by zone name, then by key ID
		sort.Slice(keys, func(i, j int) bool {
			keyI, okI := keys[i].(map[string]interface{})
			keyJ, okJ := keys[j].(map[string]interface{})
			if !okI || !okJ {
				return false
			}
			
			zoneI := getString(keyI, "zone_name", "ZoneName")
			zoneJ := getString(keyJ, "zone_name", "ZoneName")
			
			// First sort by zone name
			if zoneI != zoneJ {
				return zoneI < zoneJ
			}
			
			// If same zone, sort by key ID
			keyIDI := getString(keyI, "key_id", "KeyID")
			keyIDJ := getString(keyJ, "key_id", "KeyID")
			return keyIDI < keyIDJ
		})

		var lines []string
		lines = append(lines, "Zone | Key ID | Type | Alg | State | Received At")
		for _, k := range keys {
			key, ok := k.(map[string]interface{})
			if !ok {
				continue
			}

			zoneID := getString(key, "zone_name", "ZoneName")
			dnskeyID := getString(key, "key_id", "KeyID")
			keyType := getString(key, "key_type", "KeyType")
			state := getString(key, "state", "State")
			receivedAtStr := getString(key, "received_at", "ReceivedAt")

			// Format date: "2025-12-19 16:55:03" (year-mo-dy hr:min:sec)
			receivedAt := formatDateTime(receivedAtStr)

			// Get algorithm
			var algStr string
			if algVal, ok := key["algorithm"]; ok {
				switch v := algVal.(type) {
				case float64:
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

			lines = append(lines, fmt.Sprintf("%s | %s | %s | %s | %s | %s",
				zoneID, dnskeyID, keyType, algStr, state, receivedAt))
		}
		fmt.Println(columnize.SimpleFormat(lines))
	},
}

var krsKeysHashCmd = &cobra.Command{
	Use:   "hash --keyid <key-id> [--zone <zone-id>]",
	Short: "Compute SHA-256 hash of a key's private key material",
	Run: func(cmd *cobra.Command, args []string) {
		keyID := cmd.Flag("keyid").Value.String()
		zoneID := cmd.Flag("zone").Value.String()
		
		if keyID == "" {
			log.Fatalf("Error: --keyid is required")
		}

		// Construct the full key ID: if zone is provided, use <zone>-<keyid>, otherwise use keyid as-is
		fullKeyID := keyID
		if zoneID != "" {
			// Normalize zone to FQDN
			zoneID = dns.Fqdn(zoneID)
			fullKeyID = fmt.Sprintf("%s-%s", zoneID, keyID)
		}

		prefixcmd, _ := getCommandContext("keys")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "hash",
			"key_id":  fullKeyID,
		}

		resp, err := sendKrsRequest(api, "/krs/keys", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		hash := getString(resp, "msg", "Msg")
		if hash == "" {
			log.Fatalf("Error: hash not found in response")
		}

		fmt.Printf("Key Hash (SHA-256): %s\n", hash)
	},
}

var krsKeysGetCmd = &cobra.Command{
	Use:   "get --keyid <key-id>",
	Short: "Get a specific received key",
	Run: func(cmd *cobra.Command, args []string) {
		keyID := cmd.Flag("keyid").Value.String()
		if keyID == "" {
			log.Fatalf("Error: --keyid is required")
		}

		prefixcmd, _ := getCommandContext("keys")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get",
			"key_id":  keyID,
		}

		resp, err := sendKrsRequest(api, "/krs/keys", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		keyRaw, ok := resp["key"]
		if !ok {
			fmt.Printf("Error: 'key' key not found in response\n")
			return
		}

		key, ok := keyRaw.(map[string]interface{})
		if !ok {
			fmt.Printf("Error: 'key' is not an object (got %T)\n", keyRaw)
			return
		}

		// Pretty print the key (excluding private key)
		keyJSON, err := json.MarshalIndent(key, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling key: %v\n", err)
			return
		}
		fmt.Println(string(keyJSON))
	},
}

var krsKeysGetByZoneCmd = &cobra.Command{
	Use:   "get-by-zone --zone <zone-id>",
	Short: "Get all received keys for a zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		prefixcmd, _ := getCommandContext("keys")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get-by-zone",
			"zone_id": tdns.Globals.Zonename,
		}

		resp, err := sendKrsRequest(api, "/krs/keys", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		keysRaw, ok := resp["keys"]
		if !ok {
			fmt.Printf("Error: 'keys' key not found in response\n")
			return
		}

		keys, ok := keysRaw.([]interface{})
		if !ok {
			fmt.Printf("Error: 'keys' is not an array (got %T)\n", keysRaw)
			return
		}

		if len(keys) == 0 {
			fmt.Printf("No keys received for zone %s\n", tdns.Globals.Zonename)
			return
		}

		var lines []string
		lines = append(lines, "ID | Key ID | Type | Alg | State | Received At")
		for _, k := range keys {
			key, ok := k.(map[string]interface{})
			if !ok {
				continue
			}

			keyID := getString(key, "id", "ID")
			dnskeyID := getString(key, "key_id", "KeyID")
			keyType := getString(key, "key_type", "KeyType")
			state := getString(key, "state", "State")
			receivedAt := getString(key, "received_at", "ReceivedAt")

			// Get algorithm
			var algStr string
			if algVal, ok := key["algorithm"]; ok {
				switch v := algVal.(type) {
				case float64:
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

			lines = append(lines, fmt.Sprintf("%s | %s | %s | %s | %s | %s",
				keyID, dnskeyID, keyType, algStr, state, receivedAt))
		}
		fmt.Println(columnize.SimpleFormat(lines))
	},
}

// Config commands
var krsConfigGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get node configuration",
	Run: func(cmd *cobra.Command, args []string) {
		prefixcmd, _ := getCommandContext("config")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get",
		}

		resp, err := sendKrsRequest(api, "/krs/config", req)
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
		fmt.Println(string(configJSON))
	},
}

// Query commands
var krsQueryKmreqCmd = &cobra.Command{
	Use:   "query-kmreq --distribution-id <id> --zone <zone>",
	Short: "Force a KMREQ query to KDC",
	Run: func(cmd *cobra.Command, args []string) {
		distributionID := cmd.Flag("distribution-id").Value.String()
		PrepArgs("zonename")

		if distributionID == "" {
			log.Fatalf("Error: --distribution-id is required")
		}
		if tdns.Globals.Zonename == "" {
			log.Fatalf("Error: --zone is required")
		}

		prefixcmd, _ := getCommandContext("query")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command":        "query-kmreq",
			"distribution_id": distributionID,
			"zone_id":        tdns.Globals.Zonename,
		}

		resp, err := sendKrsRequest(api, "/krs/query", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		fmt.Printf("%s\n", getString(resp, "msg"))
	},
}

// Debug commands
var krsDebugDistribFetchCmd = &cobra.Command{
	Use:   "fetch --id <id>",
	Short: "Fetch and process a distribution from KDC",
	Long:  `Fetches a distribution by querying JSONMANIFEST and JSONCHUNK records from the KDC, reassembles the chunks, and processes the content. For clear_text distributions, displays the text. For encrypted_text distributions, displays base64 transport, ciphertext, and decrypted cleartext.`,
	Run: func(cmd *cobra.Command, args []string) {
		distributionID := cmd.Flag("id").Value.String()

		if distributionID == "" {
			log.Fatalf("Error: --id is required")
		}

		api, err := getApiClient("krs", true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command":        "fetch-distribution",
			"distribution_id": distributionID,
		}

		resp, err := sendKrsRequest(api, "/krs/debug", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		fmt.Printf("%s\n", getString(resp, "msg"))
		
		// If content is present (clear_text or encrypted_text), display it
		if content := getString(resp, "content"); content != "" {
			fmt.Printf("\n%s\n", content)
		}
	},
}

// sendKrsRequest sends a JSON POST request to the KRS API
func sendKrsRequest(api *tdns.ApiClient, endpoint string, data interface{}) (map[string]interface{}, error) {
	var result map[string]interface{}

	bytebuf := new(bytes.Buffer)
	if err := json.NewEncoder(bytebuf).Encode(data); err != nil {
		return nil, fmt.Errorf("error encoding request: %v", err)
	}

	status, buf, err := api.Post(endpoint, bytebuf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error from API POST: %v", err)
	}

	// Only print status if it's not 200 (success) - useful for debugging errors
	if status != 200 && tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	if err := json.Unmarshal(buf, &result); err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %v", err)
	}

	return result, nil
}

func init() {
	KrsKeysCmd.AddCommand(krsKeysListCmd, krsKeysGetCmd, krsKeysGetByZoneCmd, krsKeysHashCmd)
	KrsConfigCmd.AddCommand(krsConfigGetCmd)
	KrsQueryCmd.AddCommand(krsQueryKmreqCmd)
	KrsDebugDistribCmd.AddCommand(krsDebugDistribFetchCmd)
	KrsDebugCmd.AddCommand(KrsDebugDistribCmd)
	KrsCmd.AddCommand(KrsKeysCmd, KrsConfigCmd, KrsQueryCmd, KrsDebugCmd, PingCmd)

	krsKeysGetCmd.Flags().StringP("keyid", "k", "", "Key ID")
	krsKeysGetCmd.MarkFlagRequired("keyid")

	krsKeysHashCmd.Flags().StringP("keyid", "k", "", "Key ID (DNSSEC keytag)")
	krsKeysHashCmd.Flags().StringP("zone", "z", "", "Zone ID (optional, if provided constructs full ID as <zone>-<keyid>)")
	krsKeysHashCmd.MarkFlagRequired("keyid")

	krsQueryKmreqCmd.Flags().String("distribution-id", "", "Distribution ID")
	krsQueryKmreqCmd.MarkFlagRequired("distribution-id")

	krsDebugDistribFetchCmd.Flags().String("id", "", "Distribution ID")
	krsDebugDistribFetchCmd.MarkFlagRequired("id")
}

// formatDateTime formats an ISO 8601 datetime string to "year-mo-dy hr:min:sec"
// Input format: "2025-12-19T16:55:03.508771+01:00" or similar
// Output format: "2025-12-19 16:55:03"
func formatDateTime(isoStr string) string {
	if isoStr == "" {
		return ""
	}
	
	// Try parsing as RFC3339 (ISO 8601)
	t, err := time.Parse(time.RFC3339, isoStr)
	if err != nil {
		// Try parsing without timezone
		t, err = time.Parse("2006-01-02T15:04:05", isoStr)
		if err != nil {
			// Try parsing with microseconds but no timezone
			t, err = time.Parse("2006-01-02T15:04:05.999999", isoStr)
			if err != nil {
				// Fallback: return as-is if we can't parse
				return isoStr
			}
		}
	}
	
	// Format as "year-mo-dy hr:min:sec"
	return t.Format("2006-01-02 15:04:05")
}

