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
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/johanix/tdns/v2/notifyerrors"
	"github.com/miekg/dns"
)

// ChunkNotifyHandler handles incoming NOTIFY(CHUNK) messages for agent communication.
// It extracts the distribution ID and payload, then routes to the appropriate handler.
type ChunkNotifyHandler struct {
	// ControlZone is the zone suffix to strip from QNAMEs to get distribution ID
	ControlZone string

	// Transport is the DNS transport for routing confirmations
	Transport *DNSTransport

	// Router handles message routing and middleware (optional, if nil uses legacy routing)
	Router *DNSMessageRouter

	// IncomingChan receives parsed messages for the hsyncengine
	IncomingChan chan *IncomingMessage

	// LocalID is our agent identity for filtering
	LocalID string

	// SecureWrapper handles optional JWS/JWE decryption for payloads
	SecureWrapper *SecurePayloadWrapper

	// GetPeerAddress returns the configured address (host:port) for a peer by identity.
	// Used in chunk_mode=query when NOTIFY has no EDNS0 CHUNK_QUERY_ENDPOINT: receiver uses
	// this to send the CHUNK query to the correct host:port (e.g. from agent.peers config).
	// If nil, fallback is NOTIFY source with port 53.
	GetPeerAddress func(senderID string) (address string, ok bool)

	// IsAgentAuthorized checks if a sender is authorized to send us messages.
	// This is called BEFORE expensive operations (decryption, query fetch) to prevent DoS attacks.
	// If nil, no authorization check is performed (not recommended for production).
	IsAgentAuthorized func(senderID string, zone string) (authorized bool, reason string)

	// OnPeerDiscoveryNeeded is called when we receive a message from an authorized peer
	// but don't have their verification key yet. Handler should trigger discovery asynchronously.
	OnPeerDiscoveryNeeded func(peerID string)

	// OnConfirmationReceived is called when a confirmation is received for a distribution ID.
	// Used by TransportManager to mark messages as confirmed in the ReliableMessageQueue
	// and to forward per-RR detail to the SynchedDataEngine.
	OnConfirmationReceived func(distributionID string, senderID string, status ConfirmStatus,
		zone string, applied []string, removed []string, rejected []RejectedItemDTO, truncated bool)

	// unsolicitedCount tracks rejected messages from unauthorized senders (DoS mitigation)
	// Use atomic operations to increment (accessed from multiple NOTIFY handler goroutines)
	unsolicitedCount uint64
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
// 1. Extracts distribution ID from QNAME
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

	// Extract distribution ID from QNAME
	distributionID, err := h.extractDistributionID(qname)
	if err != nil {
		log.Printf("ChunkNotifyHandler: Failed to extract distribution ID from %s: %v", qname, err)
		_ = h.sendResponse(w, msg, dns.RcodeFormatError)
		return notifyerrors.ErrNotifyHandlerErrorResponse
	}

	// SECURITY: Authorization check BEFORE expensive operations (DoS mitigation)
	// Extract sender hint from QNAME (cheap operation) and check authorization
	senderHint := extractSenderHintFromQname(qname)
	if h.IsAgentAuthorized != nil && senderHint != "" {
		// Extract zone from QNAME if available (for HSYNC-based authorization)
		var zone string
		if len(msg.Question) > 0 {
			zone = msg.Question[0].Name
		}

		authorized, reason := h.IsAgentAuthorized(senderHint, zone)
		if !authorized {
			// NOT AUTHORIZED: Increment counter, log, and silently drop (no response to avoid info leak)
			count := atomic.AddUint64(&h.unsolicitedCount, 1)
			log.Printf("ChunkNotifyHandler: REJECTED unauthorized NOTIFY from %s (hint: %s): %s [total rejected: %d]",
				sourceAddr, senderHint, reason, count)
			// Do NOT send response - silent drop to avoid confirming we exist
			return nil
		}
		log.Printf("ChunkNotifyHandler: Sender %s authorized: %s", senderHint, reason)
	}

	// Extract CHUNK payload: first try EDNS0 (edns0 mode); if absent, fetch via CHUNK query (query mode)
	payload, err := h.extractChunkPayload(msg)
	if err != nil {
		// Query mode: NOTIFY has no EDNS0 payload; fetch using {receiver}.{distid}.{sender} from sender
		payload, err = h.fetchChunkViaQuery(ctx, qname, distributionID, msg, w)
		if err != nil {
			log.Printf("ChunkNotifyHandler: Failed to get CHUNK payload (EDNS0 and query mode): %v", err)
			_ = h.sendResponse(w, msg, dns.RcodeFormatError)
			return notifyerrors.ErrNotifyHandlerErrorResponse
		}
	}

	// Decrypt the payload if it is encrypted
	// SECURITY: Use strict decryption - ONLY try the authorized peer's key to prevent DoS
	if h.SecureWrapper != nil && h.SecureWrapper.IsEnabled() && IsPayloadEncrypted(payload) {
		log.Printf("ChunkNotifyHandler: Encrypted payload detected from %s", sourceAddr)

		// Use strict decryption: ONLY the senderHint's key (prevents DoS via QNAME forgery)
		decrypted, err := h.SecureWrapper.UnwrapIncomingFromPeer(payload, senderHint)
		if err != nil {
			// Check if error is due to missing verification key (peer not yet discovered)
			if strings.Contains(err.Error(), "no verification key for") {
				log.Printf("ChunkNotifyHandler: Missing verification key for authorized peer %s from %s - triggering discovery, sender should retry",
					senderHint, sourceAddr)
				// Trigger discovery asynchronously so we have the key for next retry
				if h.OnPeerDiscoveryNeeded != nil {
					go h.OnPeerDiscoveryNeeded(senderHint)
				}
				// Drop this message - sender will retry and we'll have the key by then
				return nil
			} else {
				// Decryption failed with the authorized peer's key - this is a FORGERY ATTEMPT
				count := atomic.AddUint64(&h.unsolicitedCount, 1)
				log.Printf("ChunkNotifyHandler: FORGERY ATTEMPT detected from %s: QNAME claimed to be %s but crypto verification failed: %v [total rejected: %d]",
					sourceAddr, senderHint, err, count)
				// Silent drop - don't confirm we exist or give error details to attacker
				return nil
			}
		}
		payload = decrypted
		log.Printf("ChunkNotifyHandler: Successfully decrypted payload from %s using key for %s", sourceAddr, senderHint)
	}

	// Parse the payload
	incomingMsg, err := h.parsePayload(distributionID, payload, sourceAddr)
	if err != nil {
		log.Printf("ChunkNotifyHandler: Failed to parse payload: %v", err)
		_ = h.sendResponse(w, msg, dns.RcodeFormatError)
		return notifyerrors.ErrNotifyHandlerErrorResponse
	}

	// Route based on message type
	switch incomingMsg.Type {
	case "confirm":
		// Confirmations go to the transport's pending confirmation handler
		h.handleConfirmation(incomingMsg)
		// Confirm messages get a bare DNS ACK (no EDNS0 needed — sender doesn't wait for confirm-of-confirm)
		return h.sendResponse(w, msg, dns.RcodeSuccess)

	case "ping":
		// Ping: validate and send confirmation with echoed nonce in same response
		return h.handlePing(w, msg, distributionID, payload)
	default:
		// All other messages (hello, beat, sync, relocate) go to hsyncengine
		select {
		case h.IncomingChan <- incomingMsg:
			log.Printf("ChunkNotifyHandler: Routed %s message from %s (correlation: %s)",
				incomingMsg.Type, incomingMsg.SenderID, incomingMsg.DistributionID)
		default:
			log.Printf("ChunkNotifyHandler: Incoming channel full, dropping %s message", incomingMsg.Type)
			_ = h.sendResponse(w, msg, dns.RcodeServerFailure)
			return notifyerrors.ErrNotifyHandlerErrorResponse
		}
	}

	// Send success response with EDNS0 confirmation payload.
	// The sender checks for this to distinguish "message received and routed"
	// from a bare DNS ACK (which could come from any DNS server).
	return h.sendConfirmResponse(w, msg, distributionID, incomingMsg.Type)
}

// extractDistributionID extracts the distribution ID from a QNAME.
// QNAME format: <distributionID>.<zone> — the first label is the distribution ID; the rest is the sender's
// control zone (or any zone). We do not require QNAME to end with our control zone: NOTIFY(CHUNK)
// can be sent agent-to-agent, so the sender uses its own control zone in the QNAME.
func (h *ChunkNotifyHandler) extractDistributionID(qname string) (string, error) {
	qname = ensureFQDN(qname)
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	if len(labels) == 0 {
		return "", fmt.Errorf("empty QNAME")
	}
	distributionID := labels[0]
	if distributionID == "" {
		return "", fmt.Errorf("no distribution ID in QNAME %s", qname)
	}
	return distributionID, nil
}

// extractSenderHintFromQname returns the sender identity hint from QNAME for decryption order.
// QNAME format: <distributionID>.<senderZone> e.g. "6981284f.agent.alpha.dnslab." → "agent.alpha.dnslab."
// Used to try the sender's key first when decrypting (avoids trying "combiner" first for agent-to-agent NOTIFYs).
func extractSenderHintFromQname(qname string) string {
	qname = ensureFQDN(qname)
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	if len(labels) < 2 {
		return ""
	}
	return ensureFQDN(strings.Join(labels[1:], "."))
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
			if localOpt.Code == edns0.EDNS0_CHUNK_OPTION_CODE {
				return localOpt.Data, nil
			}
		}
	}

	return nil, fmt.Errorf("no CHUNK EDNS0 option found")
}

// extractChunkQueryEndpointFromMsg returns the sender's CHUNK query endpoint (host:port) from NOTIFY EDNS0 option 65005, or "" if absent.
func extractChunkQueryEndpointFromMsg(msg *dns.Msg) string {
	if msg == nil {
		return ""
	}
	opt := msg.IsEdns0()
	if opt == nil {
		return ""
	}
	for _, o := range opt.Option {
		if local, ok := o.(*dns.EDNS0_LOCAL); ok && local.Code == edns0.EDNS0_CHUNK_QUERY_ENDPOINT_CODE {
			s := string(local.Data)
			if s != "" {
				return s
			}
		}
	}
	return ""
}

// fetchChunkViaQuery fetches the CHUNK payload via DNS CHUNK query when NOTIFY had no EDNS0 payload (chunk_mode=query).
// Builds qname as {receiver}.{distid}.{sender} and queries the sender (from EDNS0 option 65005 or NOTIFY source).
func (h *ChunkNotifyHandler) fetchChunkViaQuery(ctx context.Context, qname, distributionID string, msg *dns.Msg, w dns.ResponseWriter) ([]byte, error) {
	if h.Transport == nil {
		return nil, fmt.Errorf("no transport for CHUNK query")
	}
	senderFromQname := extractSenderHintFromQname(qname)
	if senderFromQname == "" {
		return nil, fmt.Errorf("cannot derive sender from NOTIFY qname %q for query mode", qname)
	}
	// CHUNK query qname = {receiver}.{distid}.{sender}
	chunkQueryQname := buildChunkQueryQname(h.LocalID, distributionID, senderFromQname)
	queryTarget := extractChunkQueryEndpointFromMsg(msg)
	if queryTarget == "" && h.GetPeerAddress != nil {
		// Use configured peer address (e.g. from agent.peers) so we use correct host:port
		if addr, ok := h.GetPeerAddress(senderFromQname); ok && addr != "" {
			queryTarget = addr
		}
	}
	if queryTarget == "" && w != nil {
		// Fallback: NOTIFY source; CHUNK query goes to DNS port (53)
		queryTarget = w.RemoteAddr().String()
		if host, _, err := net.SplitHostPort(queryTarget); err == nil && host != "" {
			queryTarget = net.JoinHostPort(host, "53")
		}
	}
	if queryTarget == "" {
		return nil, fmt.Errorf("no CHUNK payload in EDNS0 and no CHUNK query endpoint (no EDNS0 option 65005, no peer address for %q)", senderFromQname)
	}
	payload, _, err := h.Transport.FetchChunkViaQuery(ctx, queryTarget, chunkQueryQname)
	return payload, err
}

// parsePayload parses the JSON payload to determine message type and content.
func (h *ChunkNotifyHandler) parsePayload(distributionID string, payload []byte, sourceAddr string) (*IncomingMessage, error) {
	var fields struct {
		MessageType string `json:"MessageType"` // Standard format (string: "sync", "beat", etc.)
		Type        string `json:"type"`        // Legacy format (fallback)
		MyIdentity  string `json:"MyIdentity"`
		SenderID    string `json:"sender_id"` // Legacy
		Zone        string `json:"Zone"`
		LegacyZone  string `json:"zone"` // Legacy
	}
	if err := json.Unmarshal(payload, &fields); err != nil {
		return nil, fmt.Errorf("failed to parse message: %w", err)
	}

	// Determine message type: prefer MessageType, fall back to legacy "type"
	msgType := fields.MessageType
	if msgType == "" {
		msgType = fields.Type
	}
	if msgType == "" {
		return nil, fmt.Errorf("no message type found in payload")
	}

	// Get sender ID: prefer MyIdentity, fall back to legacy sender_id
	senderID := fields.MyIdentity
	if senderID == "" {
		senderID = fields.SenderID
	}

	// Get zone: prefer Zone, fall back to legacy zone
	zone := fields.Zone
	if zone == "" {
		zone = fields.LegacyZone
	}

	return &IncomingMessage{
		Type:           msgType,
		DistributionID: distributionID,
		SenderID:       senderID,
		Zone:           zone,
		Payload:        payload,
		ReceivedAt:     time.Now(),
		SourceAddr:     sourceAddr,
	}, nil
}

// handlePing processes an incoming ping: parse payload, echo nonce in EDNS0 CHUNK response.
func (h *ChunkNotifyHandler) handlePing(w dns.ResponseWriter, req *dns.Msg, distributionID string, payload []byte) error {
	var ping DnsPingPayload
	if err := json.Unmarshal(payload, &ping); err != nil {
		log.Printf("ChunkNotifyHandler: Failed to parse ping payload: %v", err)
		_ = h.sendResponse(w, req, dns.RcodeFormatError)
		return notifyerrors.ErrNotifyHandlerErrorResponse
	}
	if ping.Type != "ping" || ping.Nonce == "" {
		log.Printf("ChunkNotifyHandler: Invalid ping payload (type=%q nonce=%q)", ping.Type, ping.Nonce)
		_ = h.sendResponse(w, req, dns.RcodeFormatError)
		return notifyerrors.ErrNotifyHandlerErrorResponse
	}

	confirm := &DnsPingConfirmPayload{
		Type:           "ping_confirm",
		SenderID:       h.LocalID,
		Nonce:          ping.Nonce,
		DistributionID: distributionID,
		Status:         "ok",
		Timestamp:      time.Now().Unix(),
	}
	confirmJSON, err := json.Marshal(confirm)
	if err != nil {
		_ = h.sendResponse(w, req, dns.RcodeServerFailure)
		return notifyerrors.ErrNotifyHandlerErrorResponse
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.Rcode = dns.RcodeSuccess
	resp.SetEdns0(4096, true)
	opt := resp.IsEdns0()
	if opt != nil {
		opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
			Code: edns0.EDNS0_CHUNK_OPTION_CODE,
			Data: confirmJSON,
		})
	}
	if w != nil {
		return w.WriteMsg(resp)
	}
	return nil
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
			DistributionID: confirm.DistributionID,
			PeerID:         confirm.SenderID,
			Status:         status,
			Message:        confirm.Message,
			Timestamp:      time.Unix(confirm.Timestamp, 0),
			Zone:           confirm.Zone,
			AppliedRecords: confirm.AppliedRecords,
			RemovedRecords: confirm.RemovedRecords,
			RejectedItems:  confirm.RejectedItems,
			Truncated:      confirm.Truncated,
		})
	}

	// Forward confirmation detail (all statuses carry useful information)
	if h.OnConfirmationReceived != nil && confirm.DistributionID != "" {
		h.OnConfirmationReceived(confirm.DistributionID, confirm.SenderID, status,
			confirm.Zone, confirm.AppliedRecords, confirm.RemovedRecords, confirm.RejectedItems, confirm.Truncated)
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

// sendConfirmResponse sends a DNS response with an EDNS0 CHUNK confirmation payload.
// This proves to the sender that the message was received and routed (not just DNS-level ACK).
func (h *ChunkNotifyHandler) sendConfirmResponse(w dns.ResponseWriter, req *dns.Msg, distributionID, msgType string) error {
	if w == nil {
		return nil
	}

	confirmPayload := struct {
		Type           string `json:"type"`
		DistributionID string `json:"distribution_id"`
		Status         string `json:"status"`
		Message        string `json:"message"`
		Timestamp      int64  `json:"timestamp"`
	}{
		Type:           "confirm",
		DistributionID: distributionID,
		Status:         "ok",
		Message:        fmt.Sprintf("%s received", msgType),
		Timestamp:      time.Now().Unix(),
	}
	payloadBytes, err := json.Marshal(confirmPayload)
	if err != nil {
		return h.sendResponse(w, req, dns.RcodeServerFailure)
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.Rcode = dns.RcodeSuccess
	resp.SetEdns0(4096, true)
	opt := resp.IsEdns0()
	if opt != nil {
		opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
			Code: edns0.EDNS0_CHUNK_OPTION_CODE,
			Data: payloadBytes,
		})
	}
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

// UnsolicitedMessageCount returns the number of rejected messages from unauthorized senders.
// This counter is used for DoS attack monitoring and should be exported via metrics/monitoring.
func (h *ChunkNotifyHandler) UnsolicitedMessageCount() uint64 {
	return atomic.LoadUint64(&h.unsolicitedCount)
}

// RouteViaRouter routes a message through the DNS message router with middleware.
// This is the new routing path that uses the modular router architecture.
// Falls back to legacy HandleChunkNotify if Router is not configured.
func (h *ChunkNotifyHandler) RouteViaRouter(ctx context.Context, qname string, msg *dns.Msg, w dns.ResponseWriter) error {
	// Fallback to legacy routing if no router configured
	if h.Router == nil {
		return h.HandleChunkNotify(ctx, qname, msg, w)
	}

	sourceAddr := ""
	if w != nil {
		sourceAddr = w.RemoteAddr().String()
	}

	log.Printf("RouteViaRouter: Received NOTIFY(CHUNK) for %s from %s", qname, sourceAddr)

	// Extract distribution ID from QNAME
	distributionID, err := h.extractDistributionID(qname)
	if err != nil {
		log.Printf("RouteViaRouter: Failed to extract distribution ID from %s: %v", qname, err)
		return h.sendResponse(w, msg, dns.RcodeFormatError)
	}

	// Extract sender hint from QNAME
	senderHint := extractSenderHintFromQname(qname)

	// Extract CHUNK payload: first try EDNS0 (edns0 mode); if absent, fetch via CHUNK query (query mode)
	payload, err := h.extractChunkPayload(msg)
	if err != nil {
		// Query mode: NOTIFY has no EDNS0 payload; fetch using {receiver}.{distid}.{sender} from sender
		payload, err = h.fetchChunkViaQuery(ctx, qname, distributionID, msg, w)
		if err != nil {
			log.Printf("RouteViaRouter: Failed to get CHUNK payload (EDNS0 and query mode): %v", err)
			return h.sendResponse(w, msg, dns.RcodeFormatError)
		}
	}

	// Decrypt the payload if it is encrypted
	// SECURITY: Use strict decryption - ONLY try the authorized peer's key to prevent DoS
	if h.SecureWrapper != nil {
		log.Printf("RouteViaRouter: Attempting to decrypt payload from %s using key for %s", sourceAddr, senderHint)

		// Use strict decryption: ONLY the senderHint's key (prevents DoS via QNAME forgery)
		decrypted, err := h.SecureWrapper.UnwrapIncomingFromPeer(payload, senderHint)
		if err != nil {
			// Check if error is due to missing verification key (peer not yet discovered)
			if strings.Contains(err.Error(), "no verification key for") {
				log.Printf("RouteViaRouter: Missing verification key for authorized peer %s from %s - triggering discovery, sender should retry",
					senderHint, sourceAddr)
				// Trigger discovery asynchronously so we have the key for next retry
				if h.OnPeerDiscoveryNeeded != nil {
					go h.OnPeerDiscoveryNeeded(senderHint)
				}
				// Drop this message - sender will retry and we'll have the key by then
				return nil
			}

			log.Printf("RouteViaRouter: Decryption failed with %s's key: %v", senderHint, err)

			// Try decryption with combiner's key as fallback (for combiner-to-agent messages)
			if senderHint != "combiner" {
				decrypted, err = h.SecureWrapper.UnwrapIncomingFromPeer(payload, "combiner")
				if err != nil {
					// Check if combiner key is also missing
					if strings.Contains(err.Error(), "no verification key for") {
						log.Printf("RouteViaRouter: Missing verification key for combiner from %s", sourceAddr)
						// Don't trigger discovery for combiner via this path
						return nil
					}
					log.Printf("RouteViaRouter: Decryption failed with combiner's key: %v", err)
					// Decryption failed with the authorized peer's key - this is a FORGERY ATTEMPT
					log.Printf("RouteViaRouter: SECURITY: Decryption failed for NOTIFY from %s claiming to be %s", sourceAddr, senderHint)
					return h.sendResponse(w, msg, dns.RcodeRefused)
				}
			} else {
				return h.sendResponse(w, msg, dns.RcodeRefused)
			}
		}
		payload = decrypted
		log.Printf("RouteViaRouter: Successfully decrypted payload from %s using key for %s", sourceAddr, senderHint)
	}

	// Parse payload to normalize message format (converts numeric MessageType to string Type)
	incomingMsg, err := h.parsePayload(distributionID, payload, sourceAddr)
	if err != nil {
		log.Printf("RouteViaRouter: Failed to parse payload: %v", err)
		return h.sendResponse(w, msg, dns.RcodeFormatError)
	}

	msgType := MessageType(incomingMsg.Type)
	log.Printf("RouteViaRouter: Message type: %s from %s", msgType, incomingMsg.SenderID)

	// Create message context
	msgCtx := NewMessageContext(msg, sourceAddr)
	msgCtx.DistributionID = distributionID
	msgCtx.PeerID = senderHint
	msgCtx.ChunkPayload = payload
	msgCtx.RemoteAddr = sourceAddr
	// Mark that we've already handled decryption (payload is now plaintext)
	msgCtx.ChunkCrypted = false
	msgCtx.SignatureValid = true // We verified during decryption above
	msgCtx.SignatureReason = "decrypted_by_router"
	// Store the parsed message so handlers don't need to re-parse
	msgCtx.Data["incoming_message"] = incomingMsg
	// Extract zone for authorization middleware (HSYNC check)
	if incomingMsg.Zone != "" {
		msgCtx.Data["zone"] = incomingMsg.Zone
		log.Printf("RouteViaRouter: Extracted zone %q for authorization check", incomingMsg.Zone)
	} else if msgType == MessageType("beat") {
		// For beat messages, extract zones from the Zones array
		// Parse the raw payload to get the Zones field from AgentBeatPost
		var beatPayload struct {
			Zones []string `json:"Zones"`
		}
		if err := json.Unmarshal(payload, &beatPayload); err == nil && len(beatPayload.Zones) > 0 {
			// Use first shared zone for authorization
			msgCtx.Data["zone"] = beatPayload.Zones[0]
			log.Printf("RouteViaRouter: Extracted zone %q from beat message for authorization check", beatPayload.Zones[0])
		}
	}

	// Route through router (middleware + handlers)
	// The SendResponseMiddleware will send the DNS response
	responseMiddleware := SendResponseMiddleware(w, msg)
	err = responseMiddleware(msgCtx, func(ctx *MessageContext) error {
		return h.Router.Route(ctx, msgType)
	})

	if err != nil {
		log.Printf("RouteViaRouter: Routing failed: %v", err)
		return h.sendResponse(w, msg, dns.RcodeServerFailure)
	}

	return nil
}
