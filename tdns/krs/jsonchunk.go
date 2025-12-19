/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * JSONMANIFEST and JSONCHUNK query handling for tdns-krs
 */

package krs

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/johanix/tdns/tdns/core"
	"github.com/miekg/dns"
)

// QueryJSONMANIFEST queries the KDC for a JSONMANIFEST record
func QueryJSONMANIFEST(krsDB *KrsDB, conf *KrsConf, nodeID, distributionID string) (*core.JSONMANIFEST, error) {
	nodeConfig, err := krsDB.GetNodeConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get node config: %v", err)
	}

	// Use KDC address from config, fallback to database if not in config
	kdcAddress := conf.Node.KdcAddress
	if kdcAddress == "" {
		kdcAddress = nodeConfig.KdcAddress
	}
	if kdcAddress == "" {
		return nil, fmt.Errorf("KDC address not configured")
	}

	// Build QNAME: <nodeid><distributionID>.<controlzone>
	// Node ID is an FQDN (with trailing dot), so we concatenate directly
	controlZoneClean := conf.ControlZone
	if !strings.HasSuffix(controlZoneClean, ".") {
		controlZoneClean += "."
	}
	// Ensure nodeID is FQDN
	nodeIDFQDN := nodeID
	if !strings.HasSuffix(nodeIDFQDN, ".") {
		nodeIDFQDN = dns.Fqdn(nodeID)
	}
	qname := fmt.Sprintf("%s%s.%s", nodeIDFQDN, distributionID, controlZoneClean)

	// Create JSONMANIFEST query
	msg := new(dns.Msg)
	msg.SetQuestion(qname, core.TypeJSONMANIFEST)
	msg.RecursionDesired = false

	log.Printf("KRS: Querying JSONMANIFEST for node %s, distribution %s", nodeID, distributionID)
	log.Printf("KRS: JSONMANIFEST query: QNAME=%s, QTYPE=JSONMANIFEST", qname)

	// Send query to KDC (try UDP first, fallback to TCP if truncated)
	udpClient := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	resp, _, err := udpClient.Exchange(msg, kdcAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to send JSONMANIFEST query: %v", err)
	}
	
	// Check for truncation and retry with TCP
	if resp.Truncated {
		log.Printf("KRS: JSONMANIFEST response truncated (TC=1), retrying with TCP")
		tcpClient := &dns.Client{Net: "tcp", Timeout: 10 * time.Second}
		resp, _, err = tcpClient.Exchange(msg, kdcAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to send JSONMANIFEST query over TCP: %v", err)
		}
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("JSONMANIFEST query returned rcode %s", dns.RcodeToString[resp.Rcode])
	}

	// Parse JSONMANIFEST from response
	if len(resp.Answer) == 0 {
		return nil, fmt.Errorf("JSONMANIFEST response has no answer RRs")
	}

	rr := resp.Answer[0]
	if privRR, ok := rr.(*dns.PrivateRR); ok && privRR.Hdr.Rrtype == core.TypeJSONMANIFEST {
		if manifest, ok := privRR.Data.(*core.JSONMANIFEST); ok {
			log.Printf("KRS: Parsed JSONMANIFEST: chunk_count=%d, chunk_size=%d, checksum=%s", manifest.ChunkCount, manifest.ChunkSize, manifest.Checksum)
			if manifest.Metadata != nil {
				if content, ok := manifest.Metadata["content"].(string); ok {
					log.Printf("KRS: JSONMANIFEST content type: %s", content)
				}
			}
			// If chunk size is specified and large, prefer TCP for chunk queries
			if manifest.ChunkSize > 0 && manifest.ChunkSize > 1180 {
				log.Printf("KRS: Manifest indicates large chunks (%d bytes), will use TCP for JSONCHUNK queries", manifest.ChunkSize)
			}
			return manifest, nil
		}
	}

	return nil, fmt.Errorf("failed to parse JSONMANIFEST from response")
}

// QueryJSONCHUNK queries the KDC for a specific JSONCHUNK record
// chunkSize is the expected chunk size from the manifest (0 if unknown)
// If chunkSize > 1180 bytes, TCP is used directly (UDP max is ~1232 bytes including headers)
func QueryJSONCHUNK(krsDB *KrsDB, conf *KrsConf, nodeID, distributionID string, chunkID uint16, chunkSize uint16) (*core.JSONCHUNK, error) {
	nodeConfig, err := krsDB.GetNodeConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get node config: %v", err)
	}

	// Use KDC address from config, fallback to database if not in config
	kdcAddress := conf.Node.KdcAddress
	if kdcAddress == "" {
		kdcAddress = nodeConfig.KdcAddress
	}
	if kdcAddress == "" {
		return nil, fmt.Errorf("KDC address not configured")
	}

	// Build QNAME: <chunkid>.<nodeid><distributionID>.<controlzone>
	// Node ID is an FQDN (with trailing dot), so we concatenate directly
	controlZoneClean := conf.ControlZone
	if !strings.HasSuffix(controlZoneClean, ".") {
		controlZoneClean += "."
	}
	// Ensure nodeID is FQDN
	nodeIDFQDN := nodeID
	if !strings.HasSuffix(nodeIDFQDN, ".") {
		nodeIDFQDN = dns.Fqdn(nodeID)
	}
	qname := fmt.Sprintf("%d.%s%s.%s", chunkID, nodeIDFQDN, distributionID, controlZoneClean)

	// Create JSONCHUNK query
	msg := new(dns.Msg)
	msg.SetQuestion(qname, core.TypeJSONCHUNK)
	msg.RecursionDesired = false
	// Set EDNS0 to allow larger messages
	msg.SetEdns0(dns.DefaultMsgSize, true)

	log.Printf("KRS: Querying JSONCHUNK chunk %d for node %s, distribution %s", chunkID, nodeID, distributionID)
	log.Printf("KRS: JSONCHUNK query: QNAME=%s, QTYPE=JSONCHUNK", qname)
	
	// UDP DNS message max size is ~1232 bytes (with EDNS0), but we need to account for
	// DNS header (~12 bytes) and QNAME (~50-100 bytes typically), leaving ~1180 bytes for payload
	// If chunk size is known and > 1180 bytes, use TCP directly
	useTCP := chunkSize > 1180
	
	var resp *dns.Msg
	
	if useTCP {
		log.Printf("KRS: Using TCP for JSONCHUNK (chunk size %d > 1180 bytes)", chunkSize)
		tcpClient := &dns.Client{Net: "tcp", Timeout: 10 * time.Second}
		resp, _, err = tcpClient.Exchange(msg, kdcAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to send JSONCHUNK query over TCP: %v", err)
		}
	} else {
		// Try UDP first for smaller chunks, fallback to TCP if truncated
		udpClient := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
		resp, _, err = udpClient.Exchange(msg, kdcAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to send JSONCHUNK query: %v", err)
		}
		
		// Check for truncation and retry with TCP
		if resp.Truncated {
			log.Printf("KRS: JSONCHUNK response truncated (TC=1), retrying with TCP")
			tcpClient := &dns.Client{Net: "tcp", Timeout: 10 * time.Second}
			resp, _, err = tcpClient.Exchange(msg, kdcAddress)
			if err != nil {
				return nil, fmt.Errorf("failed to send JSONCHUNK query over TCP: %v", err)
			}
		}
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("JSONCHUNK query returned rcode %s", dns.RcodeToString[resp.Rcode])
	}

	// Parse JSONCHUNK from response
	if len(resp.Answer) == 0 {
		return nil, fmt.Errorf("JSONCHUNK response has no answer RRs")
	}

	rr := resp.Answer[0]
	if privRR, ok := rr.(*dns.PrivateRR); ok && privRR.Hdr.Rrtype == core.TypeJSONCHUNK {
		if chunk, ok := privRR.Data.(*core.JSONCHUNK); ok {
			log.Printf("KRS: Parsed JSONCHUNK: sequence=%d, total=%d, data_len=%d", chunk.Sequence, chunk.Total, len(chunk.Data))
			return chunk, nil
		}
	}

	log.Printf("KRS: Failed to parse JSONCHUNK from response")
	return nil, fmt.Errorf("failed to parse JSONCHUNK from response")
}

// ReassembleChunks reassembles chunks into the complete base64-encoded data
func ReassembleChunks(chunks []*core.JSONCHUNK) ([]byte, error) {
	if len(chunks) == 0 {
		return nil, fmt.Errorf("no chunks to reassemble")
	}

	total := int(chunks[0].Total)
	if len(chunks) != total {
		return nil, fmt.Errorf("chunk count mismatch: expected %d, got %d", total, len(chunks))
	}

	// Sort chunks by sequence number
	chunkMap := make(map[uint16]*core.JSONCHUNK)
	for _, chunk := range chunks {
		if int(chunk.Sequence) >= total {
			return nil, fmt.Errorf("chunk sequence %d out of range (max %d)", chunk.Sequence, total-1)
		}
		chunkMap[chunk.Sequence] = chunk
	}

	// Reassemble in order
	reassembled := make([]byte, 0)
	for i := uint16(0); i < uint16(total); i++ {
		chunk, ok := chunkMap[i]
		if !ok {
			return nil, fmt.Errorf("missing chunk %d", i)
		}
		reassembled = append(reassembled, chunk.Data...)
	}

	return reassembled, nil
}

// ProcessDistribution processes a complete distribution event
// Queries MANIFEST, fetches all chunks, reassembles, and processes based on content type
// If processTextResult is not nil, test_text content will be stored there instead of printed
func ProcessDistribution(krsDB *KrsDB, conf *KrsConf, distributionID string, processTextResult *string) error {
	// Use node ID from config file, not database
	// Ensure it's an FQDN
	nodeID := conf.Node.ID
	if nodeID == "" {
		return fmt.Errorf("node ID not configured in config file")
	}
	nodeID = dns.Fqdn(nodeID)

	log.Printf("KRS: Processing distribution %s for node %s", distributionID, nodeID)

	// Query JSONMANIFEST
	manifest, err := QueryJSONMANIFEST(krsDB, conf, nodeID, distributionID)
	if err != nil {
		return fmt.Errorf("failed to query JSONMANIFEST: %v", err)
	}

	// Extract content type from metadata
	contentType := "unknown"
	if manifest.Metadata != nil {
		if c, ok := manifest.Metadata["content"].(string); ok {
			contentType = c
		}
	}

	log.Printf("KRS: Distribution content type: %s, chunk_count: %d", contentType, manifest.ChunkCount)

	// Fetch all chunks
	// Pass chunk size from manifest to QueryJSONCHUNK so it can decide UDP vs TCP
	var chunks []*core.JSONCHUNK
	for i := uint16(0); i < manifest.ChunkCount; i++ {
		chunk, err := QueryJSONCHUNK(krsDB, conf, nodeID, distributionID, i, manifest.ChunkSize)
		if err != nil {
			return fmt.Errorf("failed to query JSONCHUNK %d: %v", i, err)
		}
		chunks = append(chunks, chunk)
		log.Printf("KRS: Fetched chunk %d/%d", i+1, manifest.ChunkCount)
	}

	// Reassemble chunks
	reassembled, err := ReassembleChunks(chunks)
	if err != nil {
		return fmt.Errorf("failed to reassemble chunks: %v", err)
	}

	log.Printf("KRS: Reassembled %d bytes from %d chunks", len(reassembled), len(chunks))

	// Verify checksum if present
	if manifest.Checksum != "" {
		hash := sha256.Sum256(reassembled)
		expectedChecksum := fmt.Sprintf("sha256:%x", hash)
		if manifest.Checksum != expectedChecksum {
			return fmt.Errorf("checksum mismatch: expected %s, got %s", manifest.Checksum, expectedChecksum)
		}
		log.Printf("KRS: Checksum verified successfully")
	}

	// Process based on content type
	switch contentType {
	case "test_text":
		text, err := ProcessTestText(reassembled)
		if err != nil {
			return err
		}
		// Store text for API response (will be nil if not called from API)
		if processTextResult != nil {
			*processTextResult = text
		}
		return nil
	case "zonelist":
		return ProcessZoneList(krsDB, reassembled)
	case "encrypted_keys":
		return ProcessEncryptedKeys(krsDB, reassembled)
	default:
		return fmt.Errorf("unknown content type: %s", contentType)
	}
}

// ProcessTestText processes test_text content
// Returns the decoded text. If called directly (not from API), prints to stdout
func ProcessTestText(data []byte) (string, error) {
	// Data is base64-encoded, decode it
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 test text: %v", err)
	}

	text := string(decoded)
	log.Printf("KRS: ===== TEST TEXT CONTENT =====")
	fmt.Println(text)
	log.Printf("KRS: ===== END TEST TEXT =====")

	return text, nil
}

// ProcessZoneList processes zonelist content (JSON array of zone names)
func ProcessZoneList(krsDB *KrsDB, data []byte) error {
	// Data is base64-encoded JSON, decode it
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return fmt.Errorf("failed to decode base64 zone list: %v", err)
	}

	var zones []string
	if err := json.Unmarshal(decoded, &zones); err != nil {
		return fmt.Errorf("failed to unmarshal zone list JSON: %v", err)
	}

	log.Printf("KRS: Received zone list with %d zones", len(zones))
	for _, zone := range zones {
		log.Printf("KRS:   - %s", zone)
	}

	// TODO: Process zone list (e.g., trigger KMREQ queries for each zone)
	return nil
}

// ProcessEncryptedKeys processes encrypted_keys content
func ProcessEncryptedKeys(krsDB *KrsDB, data []byte) error {
	// Data is base64-encoded encrypted blob, decode it
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return fmt.Errorf("failed to decode base64 encrypted keys: %v", err)
	}

	log.Printf("KRS: Received encrypted keys blob (%d bytes)", len(decoded))

	// TODO: Decrypt using HPKE and store keys
	return fmt.Errorf("encrypted_keys processing not yet implemented")
}

