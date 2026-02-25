/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * DNS message handler for processing incoming NOTIFY(CHUNK) messages.
 * This integrates the DNS transport with the hsyncengine event loop.
 */

package transport

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// IncomingMessage represents a message received via DNS transport.
// This is routed to the hsyncengine for processing.
type IncomingMessage struct {
	Type           string    // "hello", "beat", "ping", "sync", "update", "relocate", "confirm"
	DistributionID string    // Distribution ID from QNAME (unique identifier for this CHUNK distribution)
	SenderID       string    // Sender identity
	Zone           string    // Zone (for zone-scoped operations)
	Payload        []byte    // Raw payload (JSON)
	ReceivedAt     time.Time // When the message was received
	SourceAddr     string    // Source address of the sender
}

// MessageHandler processes incoming DNS messages and routes them appropriately.
type MessageHandler struct {
	// Transport is the DNS transport instance
	Transport *DNSTransport

	// ControlZone is the zone suffix to strip from QNAMEs
	ControlZone string

	// IncomingChan receives parsed incoming messages for the hsyncengine
	IncomingChan chan *IncomingMessage
}

// NewMessageHandler creates a new MessageHandler.
func NewMessageHandler(transport *DNSTransport) *MessageHandler {
	return &MessageHandler{
		Transport:    transport,
		ControlZone:  transport.ControlZone,
		IncomingChan: make(chan *IncomingMessage, 100),
	}
}

// HandleNotify processes an incoming NOTIFY(CHUNK) message.
// This should be called from the DNS server's NOTIFY handler.
//
// Parameters:
//   - msg: The incoming DNS message
//   - sourceAddr: The source address of the sender (IP:port)
//
// Returns:
//   - response: DNS response message to send back
//   - error: Any error that occurred
func (h *MessageHandler) HandleNotify(msg *dns.Msg, sourceAddr string) (*dns.Msg, error) {
	if len(msg.Question) == 0 {
		return h.makeErrorResponse(msg, dns.RcodeFormatError), nil
	}

	q := msg.Question[0]

	// Only handle CHUNK type NOTIFY
	if q.Qtype != TypeCHUNK {
		log.Printf("DNS Handler: Ignoring NOTIFY for non-CHUNK type: %s", dns.TypeToString[q.Qtype])
		return h.makeErrorResponse(msg, dns.RcodeNotImplemented), nil
	}

	// Extract correlation ID from QNAME
	distributionID, err := h.extractDistributionID(q.Name)
	if err != nil {
		log.Printf("DNS Handler: Failed to extract correlation ID from %s: %v", q.Name, err)
		return h.makeErrorResponse(msg, dns.RcodeFormatError), nil
	}

	// Extract CHUNK payload from EDNS0 option
	payload, err := h.extractChunkPayload(msg)
	if err != nil {
		log.Printf("DNS Handler: Failed to extract CHUNK payload: %v", err)
		return h.makeErrorResponse(msg, dns.RcodeFormatError), nil
	}

	// Parse the payload to determine message type
	incomingMsg, err := h.parsePayload(distributionID, payload, sourceAddr)
	if err != nil {
		log.Printf("DNS Handler: Failed to parse payload: %v", err)
		return h.makeErrorResponse(msg, dns.RcodeFormatError), nil
	}

	// Route the message based on type
	switch incomingMsg.Type {
	case "confirm":
		// Confirmations go to the pending confirmation handler
		h.handleConfirmation(incomingMsg)
	default:
		// All other messages go to the hsyncengine via IncomingChan
		select {
		case h.IncomingChan <- incomingMsg:
			log.Printf("DNS Handler: Routed %s message from %s (correlation: %s)",
				incomingMsg.Type, incomingMsg.SenderID, incomingMsg.DistributionID)
		default:
			log.Printf("DNS Handler: Incoming channel full, dropping %s message", incomingMsg.Type)
		}
	}

	// Return success response
	return h.makeSuccessResponse(msg), nil
}

// extractDistributionID extracts the correlation ID from a QNAME.
// QNAME format: <distributionID>.<zone> — the first label is the correlation ID; the rest is the sender's
// control zone. We do not require QNAME to end with our control zone: NOTIFY(CHUNK) can be agent-to-agent.
func (h *MessageHandler) extractDistributionID(qname string) (string, error) {
	qname = dns.Fqdn(qname)
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	if len(labels) == 0 {
		return "", fmt.Errorf("empty QNAME")
	}
	distributionID := labels[0]
	if distributionID == "" {
		return "", fmt.Errorf("no correlation ID in QNAME %s", qname)
	}
	return distributionID, nil
}

// extractChunkPayload extracts the CHUNK payload from the EDNS0 option.
func (h *MessageHandler) extractChunkPayload(msg *dns.Msg) ([]byte, error) {
	opt := msg.IsEdns0()
	if opt == nil {
		return nil, fmt.Errorf("no EDNS0 OPT record")
	}

	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == edns0.EDNS0_CHUNK_OPTION_CODE {
				return localOpt.Data, nil
			}
		}
	}

	return nil, fmt.Errorf("no CHUNK EDNS0 option found")
}

// parsePayload parses the JSON payload to determine message type and content.
func (h *MessageHandler) parsePayload(distributionID string, payload []byte, sourceAddr string) (*IncomingMessage, error) {
	// First, parse just the type field
	var typeOnly struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(payload, &typeOnly); err != nil {
		return nil, fmt.Errorf("failed to parse message type: %w", err)
	}

	// Parse sender_id and zone if present
	var common struct {
		SenderID string `json:"sender_id"`
		Zone     string `json:"zone"`
	}
	json.Unmarshal(payload, &common) // Ignore error, fields are optional

	return &IncomingMessage{
		Type:           typeOnly.Type,
		DistributionID: distributionID,
		SenderID:       common.SenderID,
		Zone:           common.Zone,
		Payload:        payload,
		ReceivedAt:     time.Now(),
		SourceAddr:     sourceAddr,
	}, nil
}

// handleConfirmation processes an incoming confirmation message.
func (h *MessageHandler) handleConfirmation(msg *IncomingMessage) {
	// Parse confirmation details
	var confirm DnsConfirmPayload
	if err := json.Unmarshal(msg.Payload, &confirm); err != nil {
		log.Printf("DNS Handler: Failed to parse confirmation: %v", err)
		return
	}

	// Convert status string to ConfirmStatus
	status := parseConfirmStatus(confirm.Status)

	// Route to transport's confirmation handler
	h.Transport.HandleIncomingConfirmation(&IncomingConfirmation{
		DistributionID: confirm.DistributionID,
		PeerID:         confirm.SenderID,
		Status:         status,
		Message:        confirm.Message,
		Timestamp:      time.Unix(confirm.Timestamp, 0),
	})
}

// parseConfirmStatus converts a status string to ConfirmStatus.
// Accepts both the legacy agent format (SUCCESS/PARTIAL/FAILED) and
// the combiner format (ok/partial/error).
func parseConfirmStatus(s string) ConfirmStatus {
	switch strings.ToUpper(s) {
	case "SUCCESS", "OK":
		return ConfirmSuccess
	case "PARTIAL":
		return ConfirmPartial
	case "FAILED", "ERROR":
		return ConfirmFailed
	case "REJECTED":
		return ConfirmRejected
	case "PENDING":
		return ConfirmPending
	default:
		return ConfirmFailed
	}
}

// makeSuccessResponse creates a success response to a NOTIFY.
func (h *MessageHandler) makeSuccessResponse(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.Rcode = dns.RcodeSuccess
	return resp
}

// makeErrorResponse creates an error response to a NOTIFY.
func (h *MessageHandler) makeErrorResponse(req *dns.Msg, rcode int) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.Rcode = rcode
	return resp
}

// ParseHelloPayload parses a hello message payload.
func ParseHelloPayload(payload []byte) (*DnsHelloPayload, error) {
	var p DnsHelloPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ParseBeatPayload parses a beat message payload.
func ParseBeatPayload(payload []byte) (*DnsBeatPayload, error) {
	var p DnsBeatPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ParseSyncPayload parses a sync message payload.
func ParseSyncPayload(payload []byte) (*DnsSyncPayload, error) {
	var p DnsSyncPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ParseRelocatePayload parses a relocate message payload.
func ParseRelocatePayload(payload []byte) (*DnsRelocatePayload, error) {
	var p DnsRelocatePayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ParseConfirmPayload parses a confirm message payload.
func ParseConfirmPayload(payload []byte) (*DnsConfirmPayload, error) {
	var p DnsConfirmPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ParseSyncTypeFromString converts a sync type string to SyncType.
func ParseSyncTypeFromString(s string) SyncType {
	switch strings.ToUpper(s) {
	case "NS":
		return SyncTypeNS
	case "DNSKEY":
		return SyncTypeDNSKEY
	case "GLUE":
		return SyncTypeGLUE
	case "CDS":
		return SyncTypeCDS
	case "CSYNC":
		return SyncTypeCSYNC
	default:
		return 0 // Unknown
	}
}
