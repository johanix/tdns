/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"

	"github.com/johanix/tdns-transport/v2/crypto"
	josecrypto "github.com/johanix/tdns-transport/v2/crypto/jose"
	"github.com/johanix/tdns/v2/core"
)

var JwtCmd = &cobra.Command{
	Use:   "jwt",
	Short: "JWT inspection and manipulation commands",
}

var jwtInspectCmd = &cobra.Command{
	Use:   "inspect [file|-]",
	Short: "Inspect JWT from CHUNK or JWK RDATA from JWK records",
	Long: `Inspect JWT-wrapped payloads from CHUNK records, or decode JWK RDATA from JWK records.

Reads DNS wire or text (dig-style) from stdin (or file). If the response contains a CHUNK RR,
decodes and inspects the JWT (with optional verify/decrypt). If it contains a JWK RR,
base64-decodes the RDATA and prints the JWK as pretty JSON.

Examples:
  # Inspect CHUNK (JWT)
  dogv2 node.dist123.kdc. CHUNK | tdns-cli jwt inspect -

  # Inspect JWK (pretty-print JSON)
  dogv2 dns.agent.provider. JWK | tdns-cli jwt inspect -

  # With signature verification (CHUNK only)
  dogv2 node.dist123.kdc. CHUNK | tdns-cli jwt inspect - --verify --verify-key /path/to/kdc.jose.pub

Input format auto-detection:
  - DNS wire format (from dogv2/dig): CHUNK → JWT; JWK → base64-decode and pretty JSON
  - DNS text format (zone file / dig style): same
  - Base64-encoded JWT (starts with eyJ...)
  - Raw CHUNK RDATA`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		inputFile := "-"
		if len(args) > 0 {
			inputFile = args[0]
		}

		verifyFlag, _ := cmd.Flags().GetBool("verify")
		verifyKeyFile, _ := cmd.Flags().GetString("verify-key")
		decryptFlag, _ := cmd.Flags().GetBool("decrypt")
		decryptKeyFile, _ := cmd.Flags().GetString("decrypt-key")
		backend, _ := cmd.Flags().GetString("backend")
		outputFormat, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Flags().GetBool("verbose")

		// Read input
		var input []byte
		var err error
		if inputFile == "-" {
			input, err = io.ReadAll(os.Stdin)
		} else {
			input, err = os.ReadFile(inputFile)
		}
		if err != nil {
			log.Fatalf("Error reading input: %v", err)
		}

		if len(input) == 0 {
			log.Fatal("No input data")
		}

		// Extract payload from input (JWT from CHUNK or base64 from JWK)
		payloadType, data, chunkInfo, err := extractPayloadFromInput(input)
		if err != nil {
			log.Fatalf("Error extracting payload: %v", err)
		}

		if payloadType == "jwk" {
			// JWK RDATA: base64url-decode and pretty-print JSON
			decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(data)))
			if err != nil {
				log.Fatalf("Error decoding JWK RDATA (base64url): %v", err)
			}
			var j map[string]interface{}
			if err := json.Unmarshal(decoded, &j); err != nil {
				log.Fatalf("Error parsing JWK JSON: %v", err)
			}
			out, err := json.MarshalIndent(j, "", "  ")
			if err != nil {
				log.Fatalf("Error formatting JSON: %v", err)
			}
			fmt.Println(string(out))
			return
		}

		// CHUNK/JWT path
		result, err := inspectJWT(data, chunkInfo, verifyFlag, verifyKeyFile, decryptFlag, decryptKeyFile, backend, verbose)
		if err != nil {
			log.Fatalf("Error inspecting JWT: %v", err)
		}

		if outputFormat == "json" {
			jsonOut, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				log.Fatalf("Error marshaling JSON: %v", err)
			}
			fmt.Println(string(jsonOut))
		} else {
			printTextOutput(result, verbose)
		}
	},
}

func init() {
	JwtCmd.AddCommand(jwtInspectCmd)

	jwtInspectCmd.Flags().Bool("verify", false, "Verify JWS signature (requires --verify-key)")
	jwtInspectCmd.Flags().String("verify-key", "", "Public key file for signature verification (JWK JSON or PEM)")
	jwtInspectCmd.Flags().Bool("decrypt", false, "Decrypt JWE payload (requires --decrypt-key)")
	jwtInspectCmd.Flags().String("decrypt-key", "", "Private key file for decryption (JWK JSON for JOSE, hex for HPKE)")
	jwtInspectCmd.Flags().String("backend", "auto", "Crypto backend: jose, hpke, auto (default: auto)")
	jwtInspectCmd.Flags().String("output", "text", "Output format: text, json (default: text)")
	jwtInspectCmd.Flags().BoolP("verbose", "v", false, "Verbose output (show all headers)")
}

// extractPayloadFromInput auto-detects input format and extracts JWT (from CHUNK) or JWK RDATA.
// Returns payloadType "jwt" or "jwk", data (JWT bytes or base64 JWK string), and optional chunkInfo for CHUNK.
func extractPayloadFromInput(input []byte) (payloadType string, data []byte, info *chunkInfo, err error) {
	trimmed := strings.TrimSpace(string(input))

	// Try base64 JWT first (starts with eyJ...) - most common and fastest check
	if len(trimmed) > 10 && strings.HasPrefix(trimmed, "eyJ") {
		if strings.Count(trimmed, ".") >= 2 {
			return "jwt", []byte(trimmed), &chunkInfo{Format: "raw-jwt"}, nil
		}
	}

	// Try DNS wire format (may contain CHUNK or JWK)
	if kind, payload, info, e := tryDNSWireFormat(input); e == nil {
		return kind, payload, info, nil
	}

	// Try DNS text format (may contain CHUNK or JWK)
	if kind, payload, info, e := tryDNSTextFormat(input); e == nil {
		return kind, payload, info, nil
	}

	// Try raw CHUNK RDATA
	if jwt, info, e := tryRawCHUNK(input); e == nil {
		return "jwt", jwt, info, nil
	}

	return "", nil, nil, fmt.Errorf("unable to detect input format (tried: base64 JWT, DNS wire, DNS text, raw CHUNK)")
}

type chunkInfo struct {
	Format     string
	Sequence   uint16
	Total      uint16
	DataLength uint16
	HMAC       []byte
}

func tryDNSWireFormat(input []byte) (payloadType string, data []byte, info *chunkInfo, err error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(input); err != nil {
		return "", nil, nil, err
	}

	for _, rr := range msg.Answer {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		if prr.Hdr.Rrtype == core.TypeCHUNK {
			if chunk, ok := prr.Data.(*core.CHUNK); ok && chunk != nil {
				info := &chunkInfo{
					Format:     fmt.Sprintf("DNS wire, CHUNK format=%d", chunk.Format),
					Sequence:   chunk.Sequence,
					Total:      chunk.Total,
					DataLength: chunk.DataLength,
					HMAC:       chunk.HMAC,
				}
				return "jwt", chunk.Data, info, nil
			}
		}
		if prr.Hdr.Rrtype == core.TypeJWK {
			if jwk, ok := prr.Data.(*core.JWK); ok && jwk != nil && jwk.JWKData != "" {
				return "jwk", []byte(jwk.JWKData), nil, nil
			}
		}
	}

	return "", nil, nil, fmt.Errorf("no CHUNK or JWK RR found in DNS message")
}

func tryDNSTextFormat(input []byte) (payloadType string, data []byte, info *chunkInfo, err error) {
	scanner := bufio.NewScanner(strings.NewReader(string(input)))
	var jwkBuf strings.Builder
	inJwk := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, ";") {
			continue
		}

		// Check for JWK line: " JWK " or " JWK (" (multi-line)
		if strings.Contains(trimmed, " JWK ") {
			idx := strings.Index(trimmed, " JWK ")
			rest := strings.TrimSpace(trimmed[idx+5:]) // after " JWK "
			inJwk = true
			jwkBuf.Reset()
			jwkBuf.WriteString(rest)
			if s := extractQuotedBase64(jwkBuf.String()); s != "" {
				return "jwk", []byte(s), nil, nil
			}
			continue
		}
		if inJwk {
			jwkBuf.WriteString(strings.TrimSpace(trimmed)) // no space between continuation lines (base64 is contiguous)
			if s := extractQuotedBase64(jwkBuf.String()); s != "" {
				return "jwk", []byte(s), nil, nil
			}
			continue
		}

		// CHUNK line
		if !strings.Contains(trimmed, "CHUNK") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 9 {
			continue
		}
		if fields[3] != "CHUNK" {
			continue
		}
		var sequence, total uint64
		if sequence, err = strconv.ParseUint(fields[4], 10, 16); err != nil {
			continue
		}
		if total, err = strconv.ParseUint(fields[5], 10, 16); err != nil {
			continue
		}
		jwt := fields[len(fields)-1]
		if strings.HasPrefix(jwt, "eyJ") && strings.Count(jwt, ".") >= 2 {
			info := &chunkInfo{
				Format:     fmt.Sprintf("DNS text, CHUNK format=%s", fields[6]),
				Sequence:   uint16(sequence),
				Total:      uint16(total),
				DataLength: uint16(len(jwt)),
			}
			return "jwt", []byte(jwt), info, nil
		}
	}

	return "", nil, nil, fmt.Errorf("no CHUNK or JWK RR found in DNS text format")
}

// extractQuotedBase64 finds a substring between first " and last " (JWK RDATA is base64url, no internal quotes).
// Returns empty string if no complete quoted string is present.
func extractQuotedBase64(s string) string {
	start := strings.Index(s, "\"")
	if start < 0 {
		return ""
	}
	end := strings.LastIndex(s, "\"")
	if end <= start {
		return ""
	}
	return s[start+1 : end]
}

func tryRawCHUNK(input []byte) ([]byte, *chunkInfo, error) {
	// Try parsing as raw CHUNK RDATA
	// This is a simplified parser - may need adjustment based on actual RDATA format
	if len(input) < 10 {
		return nil, nil, fmt.Errorf("input too short for CHUNK RDATA")
	}

	// CHUNK RDATA format: Format(1) HMACLen(1) HMAC(n) Sequence(2) Total(2) DataLength(2) Data(n)
	format := input[0]
	hmacLen := input[1]
	if len(input) < int(2+hmacLen+6) {
		return nil, nil, fmt.Errorf("invalid CHUNK RDATA length")
	}

	hmac := input[2 : 2+hmacLen]
	offset := 2 + hmacLen
	sequence := uint16(input[offset])<<8 | uint16(input[offset+1])
	total := uint16(input[offset+2])<<8 | uint16(input[offset+3])
	dataLen := uint16(input[offset+4])<<8 | uint16(input[offset+5])
	data := input[offset+6:]

	if len(data) != int(dataLen) {
		return nil, nil, fmt.Errorf("data length mismatch: expected %d, got %d", dataLen, len(data))
	}

	info := &chunkInfo{
		Format:     fmt.Sprintf("raw CHUNK, format=%d", format),
		Sequence:   sequence,
		Total:      total,
		DataLength: dataLen,
		HMAC:       hmac,
	}

	return data, info, nil
}

type inspectionResult struct {
	ChunkInfo       *chunkInfo               `json:"chunk_info,omitempty"`
	JWTStructure    string                   `json:"jwt_structure"`
	JWSHeader       map[string]interface{}   `json:"jws_header,omitempty"`
	JWSVerified     *bool                    `json:"jws_verified,omitempty"`
	JWSError        string                   `json:"jws_error,omitempty"`
	JWEHeader       map[string]interface{}   `json:"jwe_header,omitempty"`
	JWEDecrypted    *bool                    `json:"jwe_decrypted,omitempty"`
	JWEError        string                   `json:"jwe_error,omitempty"`
	PlaintextLength *int                     `json:"plaintext_length,omitempty"`
	Manifest        map[string]interface{}   `json:"manifest,omitempty"`
	Operations      []map[string]interface{} `json:"operations,omitempty"`
}

func inspectJWT(jwt []byte, chunkInfo *chunkInfo, verify bool, verifyKeyFile string, decrypt bool, decryptKeyFile string, backendName string, verbose bool) (*inspectionResult, error) {
	result := &inspectionResult{
		ChunkInfo: chunkInfo,
	}

	// Try parsing as JWS
	jws, err := jose.ParseSigned(string(jwt), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("failed to parse as JWS: %v", err)
	}

	result.JWTStructure = "JWS(...)"

	// Extract JWS header
	if len(jws.Signatures) > 0 {
		result.JWSHeader = make(map[string]interface{})
		result.JWSHeader["alg"] = string(jws.Signatures[0].Header.Algorithm)
		if jws.Signatures[0].Header.KeyID != "" {
			result.JWSHeader["kid"] = jws.Signatures[0].Header.KeyID
		}
		if jws.Signatures[0].Header.ExtraHeaders != nil {
			for k, v := range jws.Signatures[0].Header.ExtraHeaders {
				result.JWSHeader[string(k)] = v
			}
		}
	}

	// Get JWS payload (without verification)
	jwsPayload := jws.UnsafePayloadWithoutVerification()

	// Try parsing payload as JWE (allow multiple encryption algorithms)
	jwe, err := jose.ParseEncrypted(string(jwsPayload),
		[]jose.KeyAlgorithm{jose.ECDH_ES},
		[]jose.ContentEncryption{jose.A128GCM, jose.A192GCM, jose.A256GCM})
	if err == nil {
		result.JWTStructure = "JWS(JWE(...))"
		result.JWEHeader = make(map[string]interface{})
		result.JWEHeader["alg"] = string(jwe.Header.Algorithm)

		// Extract actual enc algorithm from ExtraHeaders
		if enc, ok := jwe.Header.ExtraHeaders[jose.HeaderKey("enc")]; ok {
			result.JWEHeader["enc"] = enc
		}

		if jwe.Header.KeyID != "" {
			result.JWEHeader["kid"] = jwe.Header.KeyID
		}
	} else {
		// Not JWE - try parsing as plain JSON (manifest metadata)
		if len(jwsPayload) > 0 && jwsPayload[0] == '{' {
			var manifest map[string]interface{}
			if err := json.Unmarshal(jwsPayload, &manifest); err == nil {
				result.Manifest = manifest
			}
		}
	}

	// Verify JWS signature if requested
	if verify {
		if verifyKeyFile == "" {
			return nil, fmt.Errorf("--verify requires --verify-key")
		}

		verifyKey, err := loadVerifyKey(verifyKeyFile)
		if err != nil {
			result.JWSError = fmt.Sprintf("Failed to load verify key: %v", err)
			verified := false
			result.JWSVerified = &verified
		} else {
			_, err := jws.Verify(verifyKey)
			verified := (err == nil)
			result.JWSVerified = &verified
			if err != nil {
				result.JWSError = fmt.Sprintf("Signature verification failed: %v", err)
			}
		}
	}

	// Decrypt JWE payload if requested
	if decrypt {
		if decryptKeyFile == "" {
			return nil, fmt.Errorf("--decrypt requires --decrypt-key")
		}

		if jwe == nil {
			return nil, fmt.Errorf("payload is not JWE-encrypted (structure: %s)", result.JWTStructure)
		}

		plaintext, err := decryptJWE(jwe, decryptKeyFile, backendName)
		if err != nil {
			decrypted := false
			result.JWEDecrypted = &decrypted
			result.JWEError = fmt.Sprintf("Decryption failed: %v", err)
		} else {
			decrypted := true
			result.JWEDecrypted = &decrypted
			length := len(plaintext)
			result.PlaintextLength = &length

			// Try parsing plaintext as JSON
			if len(plaintext) > 0 && plaintext[0] == '{' {
				// It's a JSON object (manifest)
				var manifest map[string]interface{}
				if err := json.Unmarshal(plaintext, &manifest); err == nil {
					// Check if it's a distribution manifest or raw operations
					if entries, ok := manifest["entries"]; ok {
						// It's a wrapped manifest
						result.Manifest = manifest
						if entriesArray, ok := entries.([]interface{}); ok {
							result.Operations = make([]map[string]interface{}, 0, len(entriesArray))
							for _, entry := range entriesArray {
								if entryMap, ok := entry.(map[string]interface{}); ok {
									result.Operations = append(result.Operations, entryMap)
								}
							}
						}
					} else {
						// It's a single manifest metadata object
						result.Manifest = manifest
					}
				}
			} else if len(plaintext) > 0 && plaintext[0] == '[' {
				// It's a JSON array of operations
				var operations []map[string]interface{}
				if err := json.Unmarshal(plaintext, &operations); err == nil {
					result.Operations = operations
				}
			}
		}
	}

	return result, nil
}

func loadVerifyKey(keyFile string) (interface{}, error) {
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %v", err)
	}

	// Try parsing as JWK JSON
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(keyData, &jwk); err == nil {
		return jwk.Key, nil
	}

	// Try parsing as PEM (not implemented yet)
	return nil, fmt.Errorf("only JWK JSON format is currently supported for verify keys")
}

func decryptJWE(jwe *jose.JSONWebEncryption, keyFile string, backendName string) ([]byte, error) {
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %v", err)
	}

	// Auto-detect backend if needed
	if backendName == "auto" {
		// Check if file looks like JWK JSON
		var jwk jose.JSONWebKey
		if err := json.Unmarshal(keyData, &jwk); err == nil {
			backendName = "jose"
		} else {
			backendName = "hpke"
		}
	}

	if backendName == "jose" {
		// JOSE backend - use go-jose directly for JWE decryption
		joseBackend := josecrypto.NewBackend()
		privKey, err := joseBackend.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse JOSE private key: %v", err)
		}

		// Use the crypto backend's Decrypt method
		plaintext, err := joseBackend.Decrypt(privKey, []byte(jwe.FullSerialize()))
		if err != nil {
			return nil, fmt.Errorf("JWE decryption failed: %v", err)
		}

		return plaintext, nil
	} else if backendName == "hpke" {
		// HPKE backend - use crypto abstraction layer
		backend, err := crypto.GetBackend("hpke")
		if err != nil {
			return nil, fmt.Errorf("HPKE backend not available: %v", err)
		}

		// Parse HPKE private key (raw 32 bytes for X25519)
		privKey, err := backend.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse HPKE private key: %v", err)
		}

		// Use the crypto backend's Decrypt method
		plaintext, err := backend.Decrypt(privKey, []byte(jwe.FullSerialize()))
		if err != nil {
			return nil, fmt.Errorf("HPKE JWE decryption failed: %v", err)
		}

		return plaintext, nil
	}

	return nil, fmt.Errorf("unsupported backend: %s", backendName)
}

func printTextOutput(result *inspectionResult, verbose bool) {
	if result.ChunkInfo != nil {
		fmt.Printf("CHUNK Record Found:\n")
		fmt.Printf("  Format: %s\n", result.ChunkInfo.Format)
		fmt.Printf("  Sequence: %d", result.ChunkInfo.Sequence)
		if result.ChunkInfo.Sequence == 0 {
			fmt.Printf(" (manifest)")
		}
		fmt.Printf("\n")
		fmt.Printf("  Total: %d\n", result.ChunkInfo.Total)
		fmt.Printf("  Data Length: %d bytes\n", result.ChunkInfo.DataLength)
		if len(result.ChunkInfo.HMAC) > 0 {
			fmt.Printf("  HMAC: %d bytes\n", len(result.ChunkInfo.HMAC))
		}
		fmt.Println()
	}

	fmt.Printf("JWT Structure: %s\n\n", result.JWTStructure)

	if result.JWSHeader != nil {
		fmt.Printf("JWS Outer Layer:\n")
		for k, v := range result.JWSHeader {
			fmt.Printf("  %s: %v\n", k, v)
		}
		fmt.Println()
	}

	if result.JWSVerified != nil {
		if *result.JWSVerified {
			fmt.Printf("JWS Verification: ✓ PASSED\n")
		} else {
			fmt.Printf("JWS Verification: ✗ FAILED\n")
		}
		if result.JWSError != "" {
			fmt.Printf("  Error: %s\n", result.JWSError)
		}
		fmt.Println()
	}

	if result.JWEHeader != nil {
		fmt.Printf("JWE Inner Layer:\n")
		if result.JWEDecrypted == nil {
			fmt.Printf("  (encrypted - cannot inspect without decryption)\n")
		}
		for k, v := range result.JWEHeader {
			fmt.Printf("  %s: %v\n", k, v)
		}
		fmt.Println()
	}

	if result.JWEDecrypted != nil {
		if *result.JWEDecrypted {
			fmt.Printf("JWE Decryption: ✓ SUCCESS\n")
			if result.PlaintextLength != nil {
				fmt.Printf("  Plaintext: %d bytes\n", *result.PlaintextLength)
			}
		} else {
			fmt.Printf("JWE Decryption: ✗ FAILED\n")
		}
		if result.JWEError != "" {
			fmt.Printf("  Error: %s\n", result.JWEError)
		}
		fmt.Println()
	}

	if result.Manifest != nil {
		fmt.Printf("Manifest Metadata:\n")
		for k, v := range result.Manifest {
			if k != "entries" { // Skip entries, we'll show operations separately
				fmt.Printf("  %s: %v\n", k, v)
			}
		}
		fmt.Println()
	}

	if result.Operations != nil && len(result.Operations) > 0 {
		fmt.Printf("Operations:\n")
		for i, op := range result.Operations {
			fmt.Printf("  %d. %v\n", i+1, op["operation"])
			if verbose {
				for k, v := range op {
					if k != "operation" && k != "private_key" { // Skip operation (already shown) and private key (sensitive)
						fmt.Printf("     %s: %v\n", k, v)
					}
				}
			} else {
				// Show key fields only
				if zone, ok := op["zone_name"]; ok {
					fmt.Printf("     Zone: %v\n", zone)
				}
				if keyType, ok := op["key_type"]; ok {
					fmt.Printf("     Key Type: %v\n", keyType)
				}
				if alg, ok := op["algorithm"]; ok {
					fmt.Printf("     Algorithm: %v\n", alg)
				}
				if keyID, ok := op["key_id"]; ok {
					fmt.Printf("     Key ID: %v\n", keyID)
				}
			}
		}
	}

	if result.JWEDecrypted == nil && result.JWEHeader != nil {
		fmt.Printf("\nNote: Use --decrypt to view payload contents\n")
	}
}
