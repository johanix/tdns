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

		var lines []string
		lines = append(lines, "ID | Zone | Key ID | Type | Alg | State | Received At")
		for _, k := range keys {
			key, ok := k.(map[string]interface{})
			if !ok {
				continue
			}

			keyID := getString(key, "id", "ID")
			zoneID := getString(key, "zone_id", "ZoneID")
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

			lines = append(lines, fmt.Sprintf("%s | %s | %s | %s | %s | %s | %s",
				keyID, zoneID, dnskeyID, keyType, algStr, state, receivedAt))
		}
		fmt.Println(columnize.SimpleFormat(lines))
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

	if tdns.Globals.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	if err := json.Unmarshal(buf, &result); err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %v", err)
	}

	return result, nil
}

func init() {
	KrsKeysCmd.AddCommand(krsKeysListCmd, krsKeysGetCmd, krsKeysGetByZoneCmd)
	KrsConfigCmd.AddCommand(krsConfigGetCmd)
	KrsQueryCmd.AddCommand(krsQueryKmreqCmd)
	KrsCmd.AddCommand(KrsKeysCmd, KrsConfigCmd, KrsQueryCmd, PingCmd)

	krsKeysGetCmd.Flags().StringP("keyid", "k", "", "Key ID")
	krsKeysGetCmd.MarkFlagRequired("keyid")

	krsQueryKmreqCmd.Flags().String("distribution-id", "", "Distribution ID")
	krsQueryKmreqCmd.MarkFlagRequired("distribution-id")
}

