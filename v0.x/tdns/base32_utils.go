/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"encoding/base32"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	// DNS limitations
	MaxDomainLength = 253 // Maximum length of a domain name (RFC 1035)
	MaxLabelLength  = 63  // Maximum length of a single label (RFC 1035)

	// Default cookie for chunk identification
	DefaultCookie = "c0"

	// Sequence number format (e.g., "00-")
	SequenceFormat = "%02d-"
	SequenceLength = 3 // XX- is 3 characters
)

// StructToBase32Domains converts a Go struct to a set of domain names
// Each domain name contains chunks of base32-encoded data with maximized label sizes
func StructToBase32Domains(data interface{}, domainSuffix string, cookie string) ([]string, error) {
	// Validate domain suffix
	if domainSuffix == "" {
		return nil, fmt.Errorf("domain suffix is required")
	}

	// Convert struct to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal struct to JSON: %v", err)
	}

	return JsonToBase32Domains(jsonData, domainSuffix, cookie)
}

// JsonToBase32Domains converts JSON data to a set of domain names
// Each domain name contains chunks of base32-encoded data with maximized label sizes
func JsonToBase32Domains(jsonData []byte, domainSuffix string, cookie string) ([]string, error) {
	// Validate domain suffix
	if domainSuffix == "" {
		return nil, fmt.Errorf("domain suffix is required")
	}

	// Apply default cookie if needed
	if cookie == "" {
		cookie = DefaultCookie
	}

	// Convert JSON to base32
	base32Data := Base32Encode(jsonData)

	// Split into chunks with maximum size
	chunks := ChunkBase32Data(base32Data, cookie)

	// Create domain names from chunks
	domains := ChunksToDomains(chunks, domainSuffix)

	return domains, nil
}

// Base32Encode encodes data to base32
func Base32Encode(data []byte) string {
	return base32.StdEncoding.EncodeToString(data)
}

// Base32Decode decodes base32 data
func Base32Decode(data string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(data)
}

// ChunkBase32Data splits base32 data into chunks of maximum size
// and adds cookie and sequence prefixes
func ChunkBase32Data(base32Data string, cookie string) []string {
	var chunks []string

	// Calculate prefix length (cookie + sequence number)
	prefixLength := len(cookie) + SequenceLength

	// Calculate maximum data size per chunk
	maxDataSize := MaxLabelLength - prefixLength

	// Calculate how many chunks we'll need
	totalChunks := (len(base32Data) + maxDataSize - 1) / maxDataSize

	// Split the data into chunks
	for i := 0; i < totalChunks; i++ {
		start := i * maxDataSize
		end := start + maxDataSize
		if end > len(base32Data) {
			end = len(base32Data)
		}

		// Add cookie and sequence prefix
		prefix := cookie + fmt.Sprintf(SequenceFormat, i)
		chunk := prefix + base32Data[start:end]

		chunks = append(chunks, chunk)
	}

	return chunks
}

// ChunksToDomains combines chunks into domain names
// It dynamically calculates how many chunks can fit in each domain
func ChunksToDomains(chunks []string, domainSuffix string) []string {
	var domains []string

	// Ensure domain suffix ends with a dot if it doesn't already
	if !strings.HasSuffix(domainSuffix, ".") {
		domainSuffix += "."
	}

	// Calculate suffix length including the dot
	suffixLen := len(domainSuffix)

	// Process chunks
	i := 0
	for i < len(chunks) {
		domain := ""
		domainLen := 0
		chunksInDomain := 0

		// Add chunks until we reach the limit
		for i < len(chunks) {
			// Calculate length if we add this chunk
			// +1 for the dot between chunks
			newLen := domainLen
			if domainLen > 0 {
				newLen += 1 // dot between chunks
			}
			newLen += len(chunks[i])

			// Check if adding this chunk would exceed the limit
			if newLen+suffixLen > MaxDomainLength {
				break
			}

			// Add the chunk
			if domainLen > 0 {
				domain += "."
			}
			domain += chunks[i]
			domainLen = newLen
			chunksInDomain++
			i++
		}

		// Add the suffix
		domain += "." + domainSuffix
		domains = append(domains, domain)
	}

	return domains
}

// DomainsToBase32 extracts and combines base32 data from domain names
func DomainsToBase32(domains []string, cookie string) (string, error) {
	// Apply default cookie if needed
	if cookie == "" {
		cookie = DefaultCookie
	}

	var chunks []string
	cookieLen := len(cookie)

	// Extract chunks from domains
	for _, domain := range domains {
		// Split domain into parts
		parts := strings.Split(domain, ".")

		// Process only the parts that have the cookie prefix
		for _, part := range parts {
			// Check if this part has our cookie prefix
			if len(part) > cookieLen+SequenceLength && strings.HasPrefix(part, cookie) {
				// Extract the part after cookie and sequence number (XX-)
				chunkStart := cookieLen + SequenceLength
				if chunkStart < len(part) {
					chunk := part[chunkStart:]
					chunks = append(chunks, chunk)
				}
			}
		}
	}

	// Combine chunks
	return strings.Join(chunks, ""), nil
}

// DomainsToJson converts domain names back to JSON
func DomainsToJson(domains []string, cookie string) ([]byte, error) {
	// Extract base32 data from domains
	base32Data, err := DomainsToBase32(domains, cookie)
	if err != nil {
		return nil, err
	}

	// Decode base32 data
	jsonData, err := Base32Decode(base32Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base32 data: %v", err)
	}

	return jsonData, nil
}

// DomainsToStruct converts domain names back to a struct
func DomainsToStruct(domains []string, cookie string, result interface{}) error {
	// Convert domains to JSON
	jsonData, err := DomainsToJson(domains, cookie)
	if err != nil {
		return err
	}

	// Unmarshal JSON to struct
	err = json.Unmarshal(jsonData, result)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON to struct: %v", err)
	}

	return nil
}
