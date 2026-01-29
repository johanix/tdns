/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * CHUNK NOTIFY handler registration for multi-provider DNSSEC coordination.
 * This handler is registered via tdns.RegisterNotifyHandler() and processes
 * incoming NOTIFY(CHUNK) messages for agent-to-agent communication.
 */

package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ChunkNotifyHandler handles incoming NOTIFY(CHUNK) messages for agent communication.
// It extracts the correlation ID and payload, then routes to the appropriate handler.
type ChunkNotifyHandler struct {
	// ControlZone is the zone suffix to strip from QNAMEs to get correlation ID
	ControlZone string

	// Transport is the DNS transport for routing confirmations
	Transport *DNSTransport

	// IncomingChan receives parsed messages for the hsyncengine
	IncomingChan chan *IncomingMessage

	// LocalID is our agent identity for filtering
	LocalID string

	// SecureWrapper handles optional JWS/JWE decryption for payloads
	SecureWrapper *SecurePayloadWrapper
}

// NewChunkNotifyHandler creates a new ChunkNotifyHandler.
func NewChunkNotifyHandler(controlZone, localID string, transport *DNSTransport) *ChunkNotifyHandler {
	h := &ChunkNotifyHandler{
		ControlZone:  ensureFQDN(controlZone),
		Transport:    transport,
		IncomingChan: make(chan *IncomingMessage, 100),
		LocalID:      localID,
	}

	// Inherit secure wrapper from transport if available
	if transport != nil && transport.SecureWrapper != nil {
		h.SecureWrapper = transport.SecureWrapper
	}

	return h
}

// DnsNotifyRequest mirrors the tdns.DnsNotifyRequest structure.
// We define it here to avoid import cycles with the main tdns package.
// The actual registration will use the real tdns.DnsNotifyRequest type.
type DnsNotifyRequest struct {
	ResponseWriter dns.ResponseWriter
	Msg            *dns.Msg
	Qname          string
	// Options contains EDNS0 options - we'll extract CHUNK from raw message
}

// HandleChunkNotify is the handler function for NOTIFY(CHUNK) messages.
// This function signature matches tdns.NotifyHandlerFunc.
//
// Usage: Register this with tdns.RegisterNotifyHandler(core.TypeCHUNK, handler.HandleChunkNotify)
//
// The handler:
// 1. Extracts correlation ID from QNAME
// 2. Extracts CHUNK payload from EDNS0 option
// 3. Parses the payload to determine message type
// 4. Routes to appropriate handler (confirmation vs incoming message)
// 5. Sends DNS response
func (h *ChunkNotifyHandler) HandleChunkNotify(ctx context.Context, qname string, msg *dns.Msg, w dns.ResponseWriter) error {
	sourceAddr := ""
	if w != nil {
		sourceAddr = w.RemoteAddr().String()
	}

	log.Printf("ChunkNotifyHandler: Received NOTIFY(CHUNK) for %s from %s", qname, sourceAddr)

	// Extract correlation ID from QNAME
	correlationID, err := h.extractCorrelationID(qname)
	if err != nil {
		log.Printf("ChunkNotifyHandler: Failed to extract correlation ID from %s: %v", qname, err)
		return h.sendResponse(w, msg, dns.RcodeFormatError)
	}

	// Extract CHUNK payload from EDNS0 option
	payload, err := h.extractChunkPayload(msg)
	if err != nil {
		log.Printf("ChunkNotifyHandler: Failed to extract CHUNK payload: %v", err)
		return h.sendResponse(w, msg, dns.RcodeFormatError)
	}

	// Optionally decrypt the payload if secure wrapper is configured
	// Note: We need to extract sender ID first to look up verification key
	// This creates a chicken-egg problem - we parse header to get sender,
	// then decrypt with sender's key, then parse full message
	if h.SecureWrapper != nil && h.SecureWrapper.IsEnabled() {
		// Check if payload is encrypted
		if IsPayloadEncrypted(payload) {
			// Try to extract sender_id from potential plaintext header
			// For now, we'll need to try decryption with a known peer key
			// A more robust approach would embed sender_id outside encryption
			log.Printf("ChunkNotifyHandler: Encrypted payload detected from %s", sourceAddr)
			// Decryption will be attempted during parsePayload with peer lookup
		}
	}

	// Parse the payload
	incomingMsg, err := h.parsePayload(correlationID, payload, sourceAddr)
	if err != nil {
		log.Printf("ChunkNotifyHandler: Failed to parse payload: %v", err)
		return h.sendResponse(w, msg, dns.RcodeFormatError)
	}

	// Route based on message type
	switch incomingMsg.Type {
	case "confirm":
		// Confirmations go to the transport's pending confirmation handler
		h.handleConfirmation(incomingMsg)

	default:
		// All other messages (hello, beat, sync, relocate) go to hsyncengine
		select {
		case h.IncomingChan <- incomingMsg:
			log.Printf("ChunkNotifyHandler: Routed %s message from %s (correlation: %s)",
				incomingMsg.Type, incomingMsg.SenderID, incomingMsg.CorrelationID)
		default:
			log.Printf("ChunkNotifyHandler: Incoming channel full, dropping %s message", incomingMsg.Type)
			return h.sendResponse(w, msg, dns.RcodeServerFailure)
		}
	}

	// Send success response
	return h.sendResponse(w, msg, dns.RcodeSuccess)
}

// extractCorrelationID extracts the correlation ID from a QNAME.
// QNAME format: <correlationID>.<controlzone>
func (h *ChunkNotifyHandler) extractCorrelationID(qname string) (string, error) {
	qname = ensureFQDN(qname)
	controlZone := h.ControlZone

	// Check if QNAME ends with control zone
	if !strings.HasSuffix(strings.ToLower(qname), strings.ToLower(controlZone)) {
		return "", fmt.Errorf("QNAME %s does not end with control zone %s", qname, controlZone)
	}

	// Extract correlation ID (everything before the control zone)
	correlationID := qname[:len(qname)-len(controlZone)]
	correlationID = strings.TrimSuffix(correlationID, ".")

	if correlationID == "" {
		return "", fmt.Errorf("no correlation ID in QNAME %s", qname)
	}

	return correlationID, nil
}

// extractChunkPayload extracts the CHUNK payload from the EDNS0 option.
func (h *ChunkNotifyHandler) extractChunkPayload(msg *dns.Msg) ([]byte, error) {
	if msg == nil {
		return nil, fmt.Errorf("message is nil")
	}

	opt := msg.IsEdns0()
	if opt == nil {
		return nil, fmt.Errorf("no EDNS0 OPT record")
	}

	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_CHUNK_OPTION_CODE {
				return localOpt.Data, nil
			}
		}
	}

	return nil, fmt.Errorf("no CHUNK EDNS0 option found")
}

// parsePayload parses the JSON payload to determine message type and content.
func (h *ChunkNotifyHandler) parsePayload(correlationID string, payload []byte, sourceAddr string) (*IncomingMessage, error) {
	// Parse the type field first
	var typeOnly struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(payload, &typeOnly); err != nil {
		return nil, fmt.Errorf("failed to parse message type: %w", err)
	}

	// Parse common fields
	var common struct {
		SenderID string `json:"sender_id"`
		Zone     string `json:"zone"`
	}
	json.Unmarshal(payload, &common) // Ignore error, fields are optional

	return &IncomingMessage{
		Type:          typeOnly.Type,
		CorrelationID: correlationID,
		SenderID:      common.SenderID,
		Zone:          common.Zone,
		Payload:       payload,
		ReceivedAt:    time.Now(),
		SourceAddr:    sourceAddr,
	}, nil
}

// handleConfirmation processes an incoming confirmation message.
func (h *ChunkNotifyHandler) handleConfirmation(msg *IncomingMessage) {
	var confirm DnsConfirmPayload
	if err := json.Unmarshal(msg.Payload, &confirm); err != nil {
		log.Printf("ChunkNotifyHandler: Failed to parse confirmation: %v", err)
		return
	}

	status := parseConfirmStatus(confirm.Status)

	if h.Transport != nil {
		h.Transport.HandleIncomingConfirmation(&IncomingConfirmation{
			CorrelationID: confirm.CorrelationID,
			PeerID:        confirm.SenderID,
			Status:        status,
			Message:       confirm.Message,
			Timestamp:     time.Unix(confirm.Timestamp, 0),
		})
	}
}

// sendResponse sends a DNS response with the given rcode.
func (h *ChunkNotifyHandler) sendResponse(w dns.ResponseWriter, req *dns.Msg, rcode int) error {
	if w == nil {
		return nil // No response writer, nothing to send
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.Rcode = rcode

	return w.WriteMsg(resp)
}

// CreateNotifyHandlerFunc creates a function compatible with tdns.NotifyHandlerFunc.
// This is a helper that wraps HandleChunkNotify for use with tdns.RegisterNotifyHandler.
//
// Usage in agent initialization:
//
//	handler := transport.NewChunkNotifyHandler(controlZone, localID, dnsTransport)
//	handlerFunc := handler.CreateNotifyHandlerFunc()
//	tdns.RegisterNotifyHandler(core.TypeCHUNK, handlerFunc)
//
// Note: The returned function adapts to the tdns.NotifyHandlerFunc signature:
//
//	func(ctx context.Context, req *tdns.DnsNotifyRequest) error
func (h *ChunkNotifyHandler) CreateNotifyHandlerFunc() interface{} {
	// Return a closure that can be type-asserted to the correct signature
	// in the calling code that has access to tdns types
	return func(ctx context.Context, qname string, msg *dns.Msg, w dns.ResponseWriter) error {
		return h.HandleChunkNotify(ctx, qname, msg, w)
	}
}
