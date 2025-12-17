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

var KdcNodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Manage edge nodes in KDC",
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
	Use:   "list --zone <zone-id>",
	Short: "List all DNSSEC keys for a zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		prefixcmd, _ := getCommandContext("zone")
		api, err := getApiClient(prefixcmd, true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get-keys",
			"zone_id": tdns.Globals.Zonename,
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
			fmt.Println("No keys configured for this zone")
			return
		}

		var lines []string
		lines = append(lines, "Key ID | Type | Algorithm | State | Flags | Comment")

		for i, k := range keys {
			if tdns.Globals.Verbose {
				fmt.Printf("DEBUG: key[%d] type: %T, value: %+v\n", i, k, k)
			}

			key, ok := k.(map[string]interface{})
			if !ok {
				fmt.Printf("Warning: key[%d] is not a map (got %T), skipping\n", i, k)
				continue
			}

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

			line := fmt.Sprintf("%s | %s | %s | %s | %s | %s", keyID, keyType, algStr, state, flags, comment)
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

		req := map[string]interface{}{
			"command": "add",
			"node": map[string]interface{}{
				"id":               nodeid,
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
			fmt.Printf("%-30s %-30s %-15s %s\n", "ID", "Name", "State", "Comment")
			fmt.Println(strings.Repeat("-", 100))
			for _, n := range nodes {
				if node, ok := n.(map[string]interface{}); ok {
					id := fmt.Sprintf("%v", node["id"])
					name := fmt.Sprintf("%v", node["name"])
					state := fmt.Sprintf("%v", node["state"])
					comment := fmt.Sprintf("%v", node["comment"])
					fmt.Printf("%-30s %-30s %-15s %s\n", id, name, state, comment)
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

		req := map[string]interface{}{
			"command": "delete",
			"node_id": args[0],
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
	Long:  `Generates an HPKE keypair and writes the public key to {prefix}.publicKey and private key to {prefix}.PrivateKey (both hex encoded).`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		prefix := args[0]
		pubKeyFile := prefix + ".publicKey"
		privKeyFile := prefix + ".PrivateKey"
		
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

func init() {
	KdcZoneDnssecCmd.AddCommand(kdcZoneDnssecListCmd, kdcZoneDnssecGenerateCmd)
	KdcZoneCmd.AddCommand(kdcZoneAddCmd, kdcZoneListCmd, kdcZoneGetCmd, KdcZoneDnssecCmd, kdcZoneDeleteCmd)
	KdcNodeCmd.AddCommand(kdcNodeAddCmd, kdcNodeListCmd, kdcNodeGetCmd, kdcNodeSetStateCmd, kdcNodeDeleteCmd)
	KdcDebugCmd.AddCommand(kdcDebugHpkeGenerateCmd, kdcDebugHpkeEncryptCmd, kdcDebugHpkeDecryptCmd)
	KdcCmd.AddCommand(KdcZoneCmd, KdcNodeCmd, KdcDebugCmd)

	KdcNodeCmd.PersistentFlags().StringVarP(&nodeid, "nodeid", "n", "", "node id")
	KdcNodeCmd.PersistentFlags().StringVarP(&nodename, "nodename", "N", "", "node name")
	KdcNodeCmd.PersistentFlags().StringVarP(&pubkeyfile, "pubkeyfile", "p", "", "public key file")

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

