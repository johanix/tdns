/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * CHUNK EDNS(0) option implementation
 * This option uses the same structure as CHUNK RDATA but without Sequence and Total fields
 * (since EDNS options cannot be fragmented)
 */

package edns0

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"

	"github.com/johanix/tdns/v0.x/core"
	"github.com/miekg/dns"
)

// CHUNK option content types
const (
	CHUNKContentTypeKeyStatus            = 1 // Key installation status report (failed/successful keys)
	CHUNKContentTypeBootstrapConfirmation = 2 // Bootstrap confirmation (encrypted confirmation data)
	CHUNKContentTypeComponentStatus      = 3 // Component installation status report (failed/successful components)
)

// ChunkOption represents a CHUNK EDNS(0) option
// Structure matches CHUNK RDATA but without Sequence and Total fields
type ChunkOption struct {
	Format     uint8  // Format identifier
	HMACLen    uint16 // HMAC length (0 if no HMAC)
	HMAC       []byte // HMAC-SHA256 checksum (only present if HMACLen > 0)
	DataLength uint16 // Length of data
	Data       []byte // Format-specific data (content type + payload)
}

// KeyStatusReport represents a key installation status report
// This is the payload for CHUNKContentTypeKeyStatus
type KeyStatusReport struct {
	SuccessfulKeys []KeyStatusEntry `json:"successful_keys,omitempty"` // Keys that were successfully installed
	FailedKeys     []KeyStatusEntry `json:"failed_keys,omitempty"`     // Keys that failed to install
}

// KeyStatusEntry represents a single key's installation status
type KeyStatusEntry struct {
	ZoneName string `json:"zone_name"` // Zone name
	KeyID    string `json:"key_id"`    // Key ID
	Error    string `json:"error,omitempty"` // Error message if failed
}

// ComponentStatusReport represents a component installation status report
// This is the payload for CHUNKContentTypeComponentStatus
type ComponentStatusReport struct {
	SuccessfulComponents []ComponentStatusEntry `json:"successful_components,omitempty"` // Components that were successfully installed
	FailedComponents     []ComponentStatusEntry `json:"failed_components,omitempty"`     // Components that failed to install
}

// ComponentStatusEntry represents a single component's installation status
type ComponentStatusEntry struct {
	ComponentID string `json:"component_id"` // Component ID
	Error       string `json:"error,omitempty"` // Error message if failed
}

// BootstrapConfirmation represents a bootstrap confirmation message
// This is the payload for CHUNKContentTypeBootstrapConfirmation
// Note: This struct represents the decrypted confirmation data.
// The actual EDNS(0) option contains encrypted data.
type BootstrapConfirmation struct {
	NodeID         string `json:"node_id"`          // Assigned node ID
	Status         string `json:"status"`           // Status: "success" or "error"
	KdcHpkePubKey  string `json:"kdc_hpke_pubkey"` // KDC HPKE public key (hex encoded)
	Timestamp      string `json:"timestamp"`        // RFC3339 timestamp
	ErrorMessage   string `json:"error_message,omitempty"` // Error message if status is "error"
}

// CreateChunkOption creates a CHUNK EDNS(0) option
// format: Format identifier (e.g., core.FormatJSON)
// hmac: HMAC bytes (nil if no HMAC)
// data: The data payload (will be JSON encoded if format is FormatJSON)
func CreateChunkOption(format uint8, hmac []byte, data []byte) *dns.EDNS0_LOCAL {
	option := &ChunkOption{
		Format:     format,
		HMACLen:    uint16(len(hmac)),
		HMAC:       hmac,
		DataLength: uint16(len(data)),
		Data:       data,
	}

	// Pack the option data
	optionData := option.Pack()

	return &dns.EDNS0_LOCAL{
		Code: EDNS0_CHUNK_OPTION_CODE,
		Data: optionData,
	}
}

// CreateKeyStatusChunkOption creates a CHUNK EDNS(0) option with key status report content
func CreateKeyStatusChunkOption(successfulKeys, failedKeys []KeyStatusEntry) (*dns.EDNS0_LOCAL, error) {
	report := KeyStatusReport{
		SuccessfulKeys: successfulKeys,
		FailedKeys:     failedKeys,
	}

	// Encode the report as JSON
	jsonData, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key status report: %v", err)
	}

	// Prepend content type byte to the data
	data := make([]byte, 1+len(jsonData))
	data[0] = CHUNKContentTypeKeyStatus
	copy(data[1:], jsonData)

	// Create option with no HMAC (key status reports don't need HMAC)
	return CreateChunkOption(core.FormatJSON, nil, data), nil
}

// CreateComponentStatusChunkOption creates a CHUNK EDNS(0) option with component status report content
func CreateComponentStatusChunkOption(successfulComponents, failedComponents []ComponentStatusEntry) (*dns.EDNS0_LOCAL, error) {
	report := ComponentStatusReport{
		SuccessfulComponents: successfulComponents,
		FailedComponents:     failedComponents,
	}

	// Encode the report as JSON
	jsonData, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal component status report: %v", err)
	}

	// Prepend content type byte to the data
	data := make([]byte, 1+len(jsonData))
	data[0] = CHUNKContentTypeComponentStatus
	copy(data[1:], jsonData)

	// Create option with no HMAC (component status reports don't need HMAC)
	return CreateChunkOption(core.FormatJSON, nil, data), nil
}

// CreateBootstrapConfirmationOption creates a CHUNK EDNS(0) option with bootstrap confirmation content
// The confirmation data is encrypted using HPKE Auth mode before being placed in the option.
// encryptedConfirmation: HPKE-encrypted confirmation data (ciphertext)
// Returns: CHUNK EDNS(0) option, error
func CreateBootstrapConfirmationOption(encryptedConfirmation []byte) (*dns.EDNS0_LOCAL, error) {
	if len(encryptedConfirmation) == 0 {
		return nil, fmt.Errorf("encrypted confirmation data cannot be empty")
	}

	// Prepend content type byte to the encrypted data
	data := make([]byte, 1+len(encryptedConfirmation))
	data[0] = CHUNKContentTypeBootstrapConfirmation
	copy(data[1:], encryptedConfirmation)

	// Create option with no HMAC (bootstrap confirmation is already encrypted)
	return CreateChunkOption(core.FormatJSON, nil, data), nil
}

// Pack packs the ChunkOption into wire format
func (opt *ChunkOption) Pack() []byte {
	// Calculate total length: Format(1) + HMACLen(2) + HMAC(variable) + DataLength(2) + Data(variable)
	totalLen := 1 + 2 + int(opt.HMACLen) + 2 + int(opt.DataLength)
	buf := make([]byte, totalLen)
	off := 0

	// Pack Format (uint8)
	buf[off] = opt.Format
	off += 1

	// Pack HMAC length (uint16)
	binary.BigEndian.PutUint16(buf[off:], opt.HMACLen)
	off += 2

	// Pack HMAC (only if HMACLen > 0)
	if opt.HMACLen > 0 {
		copy(buf[off:], opt.HMAC)
		off += int(opt.HMACLen)
	}

	// Pack Data length (uint16)
	binary.BigEndian.PutUint16(buf[off:], opt.DataLength)
	off += 2

	// Pack Data
	copy(buf[off:], opt.Data)

	return buf
}

// ParseChunkOption parses a CHUNK EDNS(0) option from wire format
func ParseChunkOption(opt *dns.EDNS0_LOCAL) (*ChunkOption, error) {
	if opt.Code != EDNS0_CHUNK_OPTION_CODE {
		return nil, fmt.Errorf("invalid option code: %d (expected %d)", opt.Code, EDNS0_CHUNK_OPTION_CODE)
	}

	data := opt.Data
	if len(data) < 5 {
		return nil, fmt.Errorf("CHUNK option data too short: %d bytes (minimum 5)", len(data))
	}

	off := 0

	// Unpack Format (uint8)
	format := data[off]
	off += 1

	// Unpack HMAC length (uint16)
	if len(data) < off+2 {
		return nil, fmt.Errorf("CHUNK option data too short for HMAC length")
	}
	hmacLen := binary.BigEndian.Uint16(data[off:])
	off += 2

	// Unpack HMAC (only if HMACLen > 0)
	var hmac []byte
	if hmacLen > 0 {
		if len(data) < off+int(hmacLen) {
			return nil, fmt.Errorf("CHUNK option data too short for HMAC: need %d bytes, have %d", int(hmacLen), len(data)-off)
		}
		hmac = make([]byte, hmacLen)
		copy(hmac, data[off:off+int(hmacLen)])
		off += int(hmacLen)
	}

	// Unpack Data length (uint16)
	if len(data) < off+2 {
		return nil, fmt.Errorf("CHUNK option data too short for data length")
	}
	dataLen := binary.BigEndian.Uint16(data[off:])
	off += 2

	// Unpack Data
	if len(data) < off+int(dataLen) {
		return nil, fmt.Errorf("CHUNK option data too short for data: need %d bytes, have %d", int(dataLen), len(data)-off)
	}
	optionData := make([]byte, dataLen)
	copy(optionData, data[off:off+int(dataLen)])

	return &ChunkOption{
		Format:     format,
		HMACLen:    hmacLen,
		HMAC:       hmac,
		DataLength: dataLen,
		Data:       optionData,
	}, nil
}

// ParseKeyStatusReport parses a key status report from CHUNK option data
// Returns the content type and the parsed report
func ParseKeyStatusReport(chunkOpt *ChunkOption) (uint8, *KeyStatusReport, error) {
	if len(chunkOpt.Data) < 1 {
		return 0, nil, fmt.Errorf("CHUNK option data too short for content type")
	}

	contentType := chunkOpt.Data[0]
	jsonData := chunkOpt.Data[1:]

	if contentType != CHUNKContentTypeKeyStatus {
		return contentType, nil, fmt.Errorf("unsupported content type: %d", contentType)
	}

	var report KeyStatusReport
	if err := json.Unmarshal(jsonData, &report); err != nil {
		return contentType, nil, fmt.Errorf("failed to parse key status report JSON: %v", err)
	}

	return contentType, &report, nil
}

// ParseComponentStatusReport parses a component status report from CHUNK option data
// Returns the content type and the parsed report
func ParseComponentStatusReport(chunkOpt *ChunkOption) (uint8, *ComponentStatusReport, error) {
	if len(chunkOpt.Data) < 1 {
		return 0, nil, fmt.Errorf("CHUNK option data too short for content type")
	}

	contentType := chunkOpt.Data[0]
	jsonData := chunkOpt.Data[1:]

	if contentType != CHUNKContentTypeComponentStatus {
		return contentType, nil, fmt.Errorf("unsupported content type: %d", contentType)
	}

	var report ComponentStatusReport
	if err := json.Unmarshal(jsonData, &report); err != nil {
		return contentType, nil, fmt.Errorf("failed to parse component status report JSON: %v", err)
	}

	return contentType, &report, nil
}

// ParseBootstrapConfirmation parses a bootstrap confirmation from CHUNK option data
// Returns the content type and the encrypted confirmation data
// Note: The returned data is still encrypted and must be decrypted using HPKE Auth mode
func ParseBootstrapConfirmation(chunkOpt *ChunkOption) (uint8, []byte, error) {
	if len(chunkOpt.Data) < 1 {
		return 0, nil, fmt.Errorf("CHUNK option data too short for content type")
	}

	contentType := chunkOpt.Data[0]
	encryptedData := chunkOpt.Data[1:]

	if contentType != CHUNKContentTypeBootstrapConfirmation {
		return contentType, nil, fmt.Errorf("unsupported content type: %d (expected %d)", contentType, CHUNKContentTypeBootstrapConfirmation)
	}

	return contentType, encryptedData, nil
}

// ExtractChunkOption extracts the CHUNK EDNS0 option from an OPT RR
// Returns the ChunkOption and true if found, or nil and false if not found
func ExtractChunkOption(opt *dns.OPT) (*ChunkOption, bool) {
	if opt == nil {
		return nil, false
	}

	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_CHUNK_OPTION_CODE {
				chunkOpt, err := ParseChunkOption(localOpt)
				if err != nil {
					log.Printf("Error parsing CHUNK option: %v", err)
					return nil, false
				}
				return chunkOpt, true
			}
		}
	}

	return nil, false
}

// AddChunkOptionToMessage adds a CHUNK EDNS0 option to a message
func AddChunkOptionToMessage(msg *dns.Msg, chunkOpt *dns.EDNS0_LOCAL) error {
	if msg == nil || chunkOpt == nil {
		return fmt.Errorf("message or option is nil")
	}

	// Ensure there is an OPT RR
	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(4096, true)
		opt = msg.IsEdns0()
	}

	// Remove any existing CHUNK options to avoid duplicates
	filtered := make([]dns.EDNS0, 0, len(opt.Option))
	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_CHUNK_OPTION_CODE {
				continue
			}
		}
		filtered = append(filtered, option)
	}
	opt.Option = filtered

	// Append the new CHUNK option
	opt.Option = append(opt.Option, chunkOpt)

	return nil
}

