/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Combiner CHUNK NOTIFY handler for multi-provider DNSSEC coordination (HSYNC).
 * Receives NOTIFY(CHUNK) messages from agents and applies updates to the zone.
 *
 * This handler is registered via RegisterNotifyHandler(core.TypeCHUNK, ...) and
 * handles incoming sync updates from local agents using the same DNS transport
 * as agent-to-agent communication.
 */

package tdns

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/johanix/tdns/v2/agent/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// buildChunkQueryQname constructs the CHUNK query qname: {receiver}.{distid}.{sender}.
// Used when chunk_mode=query: sender stores under this key; receiver fetches with this qname.
// Example: buildChunkQueryQname("combiner.alpha.dnslab", "698b1b0b", "agent.alpha.dnslab")
// Returns: "combiner.alpha.dnslab.698b1b0b.agent.alpha.dnslab."
func buildChunkQueryQname(receiverID, distID, senderID string) string {
	r := strings.TrimSuffix(dns.Fqdn(receiverID), ".")
	s := strings.TrimSuffix(dns.Fqdn(senderID), ".")
	return dns.Fqdn(r + "." + distID + "." + s)
}

// CombinerSyncRequest represents a sync request to the combiner.
// Uses the same data structure as CombinerPost.Data for transport neutrality.
type CombinerSyncRequest struct {
	SenderID       string              // Identity of the sending agent
	Zone           string              // Zone being updated
	SyncType       string              // Type of sync: "NS", "DNSKEY", "CDS", "CSYNC", "GLUE"
	Records        map[string][]string // RR strings grouped by owner name (same as CombinerPost.Data)
	Serial         uint32              // Zone serial (optional)
	DistributionID string              // Distribution ID for tracking
	Timestamp      time.Time           // When the request was created
}

// CombinerSyncResponse represents a confirmation from the combiner.
type CombinerSyncResponse struct {
	DistributionID string         // Echoed from request
	Zone           string         // Zone that was updated
	Status         string         // "ok", "partial", "error"
	Message        string         // Human-readable message
	AppliedRecords []string       // RRs that were successfully applied (additions)
	RemovedRecords []string       // RRs that were successfully removed (deletions)
	RejectedItems  []RejectedItem // Items that were rejected with reasons
	Timestamp      time.Time      // When the response was created
}

// RejectedItem describes an RR that was rejected and why.
type RejectedItem struct {
	Record string // The RR string
	Reason string // Why it was rejected
}

// CombinerChunkHandler processes CHUNK NOTIFY messages for the combiner.
// It extracts the sync payload from incoming NOTIFY(CHUNK) messages and
// applies the updates to the appropriate zone.
type CombinerChunkHandler struct {
	// RequestChan receives sync requests (for async processing if needed)
	RequestChan chan *CombinerSyncRequestPlus

	// Debug enables verbose logging
	Debug bool

	// LocalID is the combiner's identity (FQDN), used to construct CHUNK query qnames
	// when agents use chunk_mode=query. Format: {combiner-id}.{distid}.{sender-id}
	LocalID string

	// SecureWrapper handles decryption of incoming JWS/JWE payloads from the agent.
	// Uses the generic transport crypto infrastructure.
	// If nil, payloads are expected to be plaintext JSON.
	SecureWrapper *transport.SecurePayloadWrapper

	// Router handles message routing and middleware (optional).
	// If set, RouteViaRouter dispatches through the router; if nil, falls back to HandleChunkNotify.
	Router *transport.DNSMessageRouter

	// ErrorJournal records errors during CHUNK NOTIFY processing for operational diagnostics.
	// Queried via "transaction errors" CLI commands. If nil, errors are only logged.
	ErrorJournal *ErrorJournal
}

// CombinerSyncRequestPlus includes a response channel for async processing.
type CombinerSyncRequestPlus struct {
	Request  *CombinerSyncRequest
	Response chan *CombinerSyncResponse
}

// NewCombinerChunkHandler creates a new combiner CHUNK handler.
// Control zone is derived dynamically from each NOTIFY qname as qname minus the leftmost label (no static config).
// localID is the combiner's identity (FQDN), required for constructing CHUNK query qnames when agents use chunk_mode=query.
func NewCombinerChunkHandler(localID string) *CombinerChunkHandler {
	return &CombinerChunkHandler{
		RequestChan:  make(chan *CombinerSyncRequestPlus, 100),
		LocalID:      localID,
		ErrorJournal: NewErrorJournal(1000, 24*time.Hour),
	}
}

// CreateNotifyHandlerFunc creates a function compatible with tdns.NotifyHandlerFunc.
// Usage: RegisterNotifyHandler(core.TypeCHUNK, handler.CreateNotifyHandlerFunc())
// If Router is set, dispatches through the router; otherwise falls back to HandleChunkNotify.
func (h *CombinerChunkHandler) CreateNotifyHandlerFunc() NotifyHandlerFunc {
	return func(ctx context.Context, req *DnsNotifyRequest) error {
		if h.Router != nil {
			return h.RouteViaRouter(ctx, req)
		}
		return h.HandleChunkNotify(ctx, req)
	}
}

// RouteViaRouter dispatches a CHUNK NOTIFY through the DNSMessageRouter with middleware.
// Reuses the same EDNS0/CHUNK extraction and decryption as HandleChunkNotify, then
// creates a transport.MessageContext and routes through the router. The router's
// registered handlers (CombinerHandlePing/Beat/Sync) store responses in ctx.Data,
// and SendResponseMiddleware sends the DNS reply with the EDNS0 CHUNK payload.
func (h *CombinerChunkHandler) RouteViaRouter(ctx context.Context, req *DnsNotifyRequest) error {
	if req == nil || req.Msg == nil {
		return fmt.Errorf("nil request or message")
	}

	sourceAddr := ""
	if req.ResponseWriter != nil {
		sourceAddr = req.ResponseWriter.RemoteAddr().String()
	}

	// Extract distribution ID and sender identity from QNAME
	distributionID, controlZone, err := h.extractDistributionIDAndControlZone(req.Qname)
	if err != nil {
		log.Printf("CombinerRouteViaRouter: Failed to extract distribution ID from %s: %v", req.Qname, err)
		return ErrNotHandled
	}

	log.Printf("CombinerRouteViaRouter: Received CHUNK NOTIFY qname=%q distrib=%q sender=%q",
		req.Qname, distributionID, controlZone)

	// Get CHUNK payload (EDNS0 or query mode)
	payload, chunkQueryQname, err := h.getChunkPayload(ctx, req)
	if err != nil {
		log.Printf("CombinerRouteViaRouter: Failed to get CHUNK payload for qname %s: %v", req.Qname, err)
		errorQname := chunkQueryQname
		if errorQname == "" {
			errorQname = req.Qname
		}
		h.recordError(distributionID, controlZone, "unknown", fmt.Sprintf("failed to get CHUNK payload: %v", err), errorQname)
		return fmt.Errorf("failed to get CHUNK payload: %w", err)
	}

	// Decrypt payload if secure wrapper is configured
	if h.SecureWrapper != nil && h.SecureWrapper.IsEnabled() {
		decrypted, err := h.SecureWrapper.UnwrapIncoming("agent", payload)
		if err != nil {
			log.Printf("CombinerRouteViaRouter: Failed to decrypt payload for dist %s: %v", distributionID, err)
			h.recordError(distributionID, controlZone, "unknown", fmt.Sprintf("failed to decrypt payload: %v", err), req.Qname)
			return fmt.Errorf("failed to decrypt payload: %w", err)
		}
		payload = decrypted
	}

	// Determine message type
	msgType := transport.DetermineMessageType(payload)
	if msgType == transport.MessageTypeUnknown {
		log.Printf("CombinerRouteViaRouter: Unknown message type in payload for dist %s", distributionID)
		h.recordError(distributionID, controlZone, "unknown", "unknown message type", req.Qname)
		return h.sendErrorResponse(req, distributionID, "unknown message type")
	}

	log.Printf("CombinerRouteViaRouter: Message type: %s from %s", msgType, controlZone)

	// Create message context for the router
	msgCtx := transport.NewMessageContext(req.Msg, sourceAddr)
	msgCtx.DistributionID = distributionID
	msgCtx.PeerID = controlZone // sender identity from QNAME
	msgCtx.ChunkPayload = payload
	// Payload is already decrypted — skip crypto middleware
	msgCtx.ChunkCrypted = false
	msgCtx.SignatureValid = true
	msgCtx.SignatureReason = "decrypted_by_combiner"

	// Route through router with SendResponseMiddleware wrapping it
	responseMiddleware := transport.SendResponseMiddleware(req.ResponseWriter, req.Msg)
	err = responseMiddleware(msgCtx, func(innerCtx *transport.MessageContext) error {
		return h.Router.Route(innerCtx, msgType)
	})

	if err != nil {
		log.Printf("CombinerRouteViaRouter: Routing failed for dist %s: %v", distributionID, err)
		h.recordError(distributionID, controlZone, string(msgType), fmt.Sprintf("routing failed: %v", err), req.Qname)
		// SendResponseMiddleware already sent an error response (SERVFAIL) on error
	}

	return nil
}

// recordError records an error in the ErrorJournal if available.
func (h *CombinerChunkHandler) recordError(distID, sender, messageType, errMsg, qname string) {
	if h.ErrorJournal == nil {
		return
	}
	h.ErrorJournal.Record(ErrorJournalEntry{
		DistributionID: distID,
		Sender:         sender,
		MessageType:    messageType,
		ErrorMsg:       errMsg,
		QNAME:          qname,
		Timestamp:      time.Now(),
	})
}

// HandleChunkNotify processes a CHUNK NOTIFY message for the combiner.
// It extracts the sync payload from the EDNS0 option and applies the update.
func (h *CombinerChunkHandler) HandleChunkNotify(ctx context.Context, req *DnsNotifyRequest) error {
	if req == nil || req.Msg == nil {
		return fmt.Errorf("nil request or message")
	}

	// Extract distribution ID and control zone from QNAME: {distid}.{controlzone}. (distid = first label, control zone = rest)
	distributionID, controlZone, err := h.extractDistributionIDAndControlZone(req.Qname)
	if err != nil {
		log.Printf("CombinerChunkHandler: Failed to extract distribution ID from %s: %v", req.Qname, err)
		return ErrNotHandled // Let other handlers try
	}

	log.Printf("CombinerChunkHandler: Received CHUNK NOTIFY qname=%q distribution_id=%q control_zone=%q", req.Qname, distributionID, controlZone)

	// Get CHUNK payload: from EDNS0 (edns0 mode) or via CHUNK query to NOTIFY source (query mode or fallback)
	payload, chunkQueryQname, err := h.getChunkPayload(ctx, req)
	if err != nil {
		// Pre-parse error: we don't know the message type and the transport is likely
		// broken (e.g. CHUNK query REFUSED), so we can't reliably send a response.
		// Log and return — the agent will timeout and retry.
		log.Printf("CombinerChunkHandler: Failed to get CHUNK payload for qname %s (dist %s, sender %s): %v", req.Qname, distributionID, controlZone, err)
		// Use the CHUNK query qname if available (shows the actual qname that was queried);
		// fall back to NOTIFY qname for EDNS0-only failures where no query was attempted.
		errorQname := chunkQueryQname
		if errorQname == "" {
			errorQname = req.Qname
		}
		h.recordError(distributionID, controlZone, "unknown", fmt.Sprintf("failed to get CHUNK payload: %v", err), errorQname)
		return fmt.Errorf("failed to get CHUNK payload: %w", err)
	}

	// Decrypt payload if secure wrapper is configured
	if h.SecureWrapper != nil && h.SecureWrapper.IsEnabled() {
		decrypted, err := h.SecureWrapper.UnwrapIncoming("agent", payload)
		if err != nil {
			// Pre-parse error: payload is encrypted and we can't decrypt it.
			// We still don't know the message type. Log and return.
			log.Printf("CombinerChunkHandler: Failed to decrypt payload for dist %s: %v", distributionID, err)
			h.recordError(distributionID, controlZone, "unknown", fmt.Sprintf("failed to decrypt payload: %v", err), req.Qname)
			return fmt.Errorf("failed to decrypt payload: %w", err)
		}
		payload = decrypted
		previewLen := len(payload)
		if previewLen > 100 {
			previewLen = 100
		}
		log.Printf("CombinerChunkHandler: Decrypted payload (%d bytes): %s", len(payload), string(payload[:previewLen]))
	}

	// Determine message type: check MessageType (string) first, fall back to legacy "type" field.
	// Since MessageType is now a string ("sync", "beat", "ping", etc.), both formats
	// are unified — no more numeric vs string dual dispatch.
	var msgType struct {
		MessageType string `json:"MessageType"` // New unified format
		Type        string `json:"type"`        // Legacy format (fallback)
	}
	if err := json.Unmarshal(payload, &msgType); err != nil {
		// Pre-parse error: payload is not valid JSON so we don't know the message type.
		// Log and return.
		log.Printf("CombinerChunkHandler: Failed to parse message type fields for dist %s: %v", distributionID, err)
		h.recordError(distributionID, controlZone, "unknown", fmt.Sprintf("failed to parse message type: %v", err), req.Qname)
		return fmt.Errorf("failed to parse message type: %w", err)
	}

	messageType := msgType.MessageType
	if messageType == "" {
		messageType = msgType.Type // Fall back to legacy "type" field
	}

	log.Printf("CombinerChunkHandler: Message type: %q", messageType)

	switch messageType {
	case "ping":
		return h.handlePing(req, distributionID, controlZone, payload)

	case "beat":
		return h.handleBeat(req, distributionID, controlZone, payload)

	case "sync":
		syncReq, err := h.parseAgentMsgNotify(payload, distributionID)
		if err != nil {
			log.Printf("CombinerChunkHandler: Failed to parse sync payload: %v", err)
			h.recordError(distributionID, controlZone, "sync", fmt.Sprintf("failed to parse sync: %v", err), req.Qname)
			return h.sendErrorResponse(req, distributionID, fmt.Sprintf("failed to parse sync: %v", err))
		}
		resp := h.ProcessUpdate(syncReq)
		if resp.Status == "error" {
			h.recordError(distributionID, controlZone, "sync", resp.Message, req.Qname)
		}
		return h.sendConfirmResponse(req, resp)

	default:
		log.Printf("CombinerChunkHandler: Unknown message type %q", messageType)
		h.recordError(distributionID, controlZone, messageType, fmt.Sprintf("unknown message type %q", messageType), req.Qname)
		return h.sendErrorResponse(req, distributionID, fmt.Sprintf("unknown message type %q", messageType))
	}
}

// extractDistributionIDAndControlZone derives distribution ID and control zone from the QNAME.
// QNAME format: {distid}.{controlzone}. — distid has no dots (single label), so distribution ID = first label, control zone = rest (qname minus leftmost label).
func (h *CombinerChunkHandler) extractDistributionIDAndControlZone(qname string) (distributionID, controlZone string, err error) {
	qname = dns.Fqdn(qname)
	labels := dns.SplitDomainName(qname)
	if len(labels) == 0 {
		return "", "", fmt.Errorf("qname %s has no labels", qname)
	}
	distributionID = labels[0]
	if len(labels) == 1 {
		controlZone = ""
		return distributionID, controlZone, nil
	}
	// Control zone = qname minus leftmost label (e.g. 65a1b2c3.agent.provider. -> agent.provider.)
	controlZone = qname[len(labels[0])+1:] // +1 for the dot after first label
	return distributionID, controlZone, nil
}

// handlePing responds to a ping with ping_confirm (echoed nonce); no zone state change.
// Both success and error use the same ping_confirm struct — errors set Status:"error"
// with a Message describing the problem (follows the TDNS Error/ErrorMsg pattern).
func (h *CombinerChunkHandler) handlePing(req *DnsNotifyRequest, distributionID, controlZone string, payload []byte) error {
	// AgentPingPost has no json tags — fields serialize with Go names.
	var ping struct {
		MessageType  string `json:"MessageType"`
		MyIdentity   string `json:"MyIdentity"`
		YourIdentity string `json:"YourIdentity"`
		Nonce        string `json:"Nonce"`
	}
	if err := json.Unmarshal(payload, &ping); err != nil {
		log.Printf("CombinerChunkHandler: Failed to parse ping payload: %v", err)
		h.recordError(distributionID, controlZone, "ping", "invalid ping payload", req.Qname)
		return h.sendPingResponse(req, distributionID, "", "error", "invalid ping payload")
	}
	if ping.MessageType != "ping" || ping.Nonce == "" {
		log.Printf("CombinerChunkHandler: Invalid ping (MessageType=%q Nonce=%q)", ping.MessageType, ping.Nonce)
		h.recordError(distributionID, controlZone, "ping", "invalid ping", req.Qname)
		return h.sendPingResponse(req, distributionID, "", "error", "invalid ping")
	}

	return h.sendPingResponse(req, distributionID, ping.Nonce, "ok", "")
}

// sendPingResponse builds and sends a ping_confirm response. Used for both success and error.
func (h *CombinerChunkHandler) sendPingResponse(req *DnsNotifyRequest, distributionID, nonce, status, message string) error {
	log.Printf("CombinerChunkHandler: Sending ping_confirm for distribution %s status=%s", distributionID, status)

	confirmPayload := struct {
		Type           string `json:"type"`
		SenderID       string `json:"sender_id"`
		Nonce          string `json:"nonce"`
		DistributionID string `json:"distribution_id"`
		Status         string `json:"status"`
		Message        string `json:"message,omitempty"`
		Timestamp      int64  `json:"timestamp"`
	}{
		Type:           "ping_confirm",
		SenderID:       h.LocalID,
		Nonce:          nonce,
		DistributionID: distributionID,
		Status:         status,
		Message:        message,
		Timestamp:      time.Now().Unix(),
	}
	payloadBytes, err := json.Marshal(confirmPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal ping_confirm: %w", err)
	}

	return h.sendGenericEdns0Response(req, payloadBytes)
}

// handleBeat responds to a heartbeat with beat_confirm; no zone state change.
// Both success and error use the same confirm struct — errors set Status:"error"
// with a Message describing the problem (follows the TDNS Error/ErrorMsg pattern).
func (h *CombinerChunkHandler) handleBeat(req *DnsNotifyRequest, distributionID, controlZone string, payload []byte) error {
	var beat struct {
		MessageType  string    `json:"MessageType"`  // "beat"
		MyIdentity   string    `json:"MyIdentity"`   // Sender's identity
		YourIdentity string    `json:"YourIdentity"` // Should be "combiner"
		Time         time.Time `json:"Time"`
	}
	if err := json.Unmarshal(payload, &beat); err != nil {
		log.Printf("CombinerChunkHandler: Failed to parse beat payload: %v", err)
		h.recordError(distributionID, controlZone, "beat", "invalid beat payload", req.Qname)
		return h.sendBeatResponse(req, distributionID, "error", "invalid beat payload")
	}

	log.Printf("CombinerChunkHandler: Received heartbeat from %s", beat.MyIdentity)

	return h.sendBeatResponse(req, distributionID, "ok", "beat acknowledged")
}

// sendBeatResponse builds and sends a beat confirm response. Used for both success and error.
func (h *CombinerChunkHandler) sendBeatResponse(req *DnsNotifyRequest, distributionID, status, message string) error {
	log.Printf("CombinerChunkHandler: Sending beat confirm for distribution %s status=%s", distributionID, status)

	confirmPayload := struct {
		Type           string `json:"type"`
		DistributionID string `json:"distribution_id"`
		Status         string `json:"status"`
		Message        string `json:"message"`
		Timestamp      int64  `json:"timestamp"`
	}{
		Type:           "confirm",
		DistributionID: distributionID,
		Status:         status,
		Message:        message,
		Timestamp:      time.Now().Unix(),
	}
	payloadBytes, err := json.Marshal(confirmPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal beat confirm: %w", err)
	}

	return h.sendGenericEdns0Response(req, payloadBytes)
}

// getChunkPayload returns the CHUNK payload from the NOTIFY. Receiver adapts: first try EDNS(0) CHUNK option;
// if none, fetch via CHUNK query to the sender. Query target is the CHUNK query endpoint from the NOTIFY (if present), else the connection peer (may fail for ephemeral ports).
// Returns (payload, chunkQueryQname, error). chunkQueryQname is the CHUNK query qname used (empty if payload came from EDNS0).
func (h *CombinerChunkHandler) getChunkPayload(ctx context.Context, req *DnsNotifyRequest) ([]byte, string, error) {
	// Always try EDNS0 first; receiver adapts to sender's choice
	payload, err := h.extractChunkPayload(req.Msg)
	if err == nil {
		return payload, "", nil
	}

	// No EDNS0 payload: fetch via CHUNK query
	// NOTIFY qname format: {distid}.{sender-controlzone} e.g. "698b1b0b.agent.alpha.dnslab."
	// CHUNK query qname format: {receiver}.{distid}.{sender-controlzone} e.g. "combiner.alpha.dnslab.698b1b0b.agent.alpha.dnslab."
	// Build proper CHUNK query qname using combiner's identity
	distributionID, senderControlZone, err := h.extractDistributionIDAndControlZone(req.Qname)
	if err != nil {
		return nil, "", fmt.Errorf("failed to extract distribution ID from NOTIFY qname %q: %w", req.Qname, err)
	}

	chunkQueryQname := buildChunkQueryQname(h.LocalID, distributionID, senderControlZone)

	// Use CHUNK_QUERY_ENDPOINT from NOTIFY if present, else static config (combiner.agent.address).
	queryTarget := extractChunkQueryEndpoint(req.Msg)
	if queryTarget == "" && Conf.Combiner != nil && Conf.Combiner.Agent != nil && Conf.Combiner.Agent.Address != "" {
		queryTarget = strings.TrimSpace(Conf.Combiner.Agent.Address)
	}
	if queryTarget == "" {
		return nil, chunkQueryQname, fmt.Errorf("no CHUNK payload in EDNS0 and no CHUNK query endpoint (no EDNS0 option, no combiner.agent.address)")
	}
	data, err := fetchChunkPayloadViaQuery(ctx, queryTarget, chunkQueryQname)
	return data, chunkQueryQname, err
}

// extractChunkQueryEndpoint returns the sender's CHUNK query endpoint (host:port) from the NOTIFY EDNS0 option (code 65005), or "" if absent.
func extractChunkQueryEndpoint(msg *dns.Msg) string {
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

// fetchChunkPayloadViaQuery queries the given DNS server for qname CHUNK and returns the first CHUNK RR's Data.
func fetchChunkPayloadViaQuery(ctx context.Context, serverAddr, qname string) ([]byte, error) {
	// Ensure server has a port (default 53)
	if host, port, err := net.SplitHostPort(serverAddr); err != nil {
		if host != "" {
			serverAddr = net.JoinHostPort(host, "53")
		} else {
			serverAddr = net.JoinHostPort(serverAddr, "53")
		}
	} else if port == "" {
		serverAddr = net.JoinHostPort(host, "53")
	}

	m := new(dns.Msg)
	q := dns.Fqdn(qname)
	m.SetQuestion(q, core.TypeCHUNK)
	m.RecursionDesired = false

	// Use TCP for CHUNK queries - encrypted payloads (JWS/JWE + base64) are too large for UDP
	c := &dns.Client{Timeout: 5 * time.Second, Net: "tcp"}
	in, _, err := c.ExchangeContext(ctx, m, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("CHUNK query %s to %s failed: %w", qname, serverAddr, err)
	}
	if in == nil || in.Rcode != dns.RcodeSuccess {
		rcode := dns.RcodeSuccess
		if in != nil {
			rcode = in.Rcode
		}
		return nil, fmt.Errorf("CHUNK query %s to %s returned rcode %s", qname, serverAddr, dns.RcodeToString[rcode])
	}
	for _, rr := range in.Answer {
		if prr, ok := rr.(*dns.PrivateRR); ok && prr.Hdr.Rrtype == core.TypeCHUNK {
			if chunk, ok := prr.Data.(*core.CHUNK); ok && chunk != nil {
				return chunk.Data, nil
			}
		}
	}
	return nil, fmt.Errorf("no CHUNK RR in response from %s for qname %s", serverAddr, qname)
}

// extractChunkPayload extracts the CHUNK data from EDNS0 option (code 65004).
func (h *CombinerChunkHandler) extractChunkPayload(msg *dns.Msg) ([]byte, error) {
	opt := msg.IsEdns0()
	if opt == nil {
		return nil, fmt.Errorf("no EDNS0 in message")
	}

	for _, option := range opt.Option {
		if local, ok := option.(*dns.EDNS0_LOCAL); ok {
			if local.Code == edns0.EDNS0_CHUNK_OPTION_CODE {
				return local.Data, nil
			}
		}
	}

	return nil, fmt.Errorf("no CHUNK option (code %d) in EDNS0", edns0.EDNS0_CHUNK_OPTION_CODE)
}

// parseAgentMsgNotify parses a sync payload into a CombinerSyncRequest.
// Handles both the standard AgentMsgPost format (MessageType/MyIdentity/Records)
// and legacy format (type/sender_id/records). Records are already grouped by owner.
func (h *CombinerChunkHandler) parseAgentMsgNotify(data []byte, distributionID string) (*CombinerSyncRequest, error) {
	// Use a unified struct that accepts fields from both formats
	var msg struct {
		// Standard AgentMsgPost fields
		MyIdentity string              `json:"MyIdentity"`
		Zone       string              `json:"Zone"`
		Records    map[string][]string `json:"Records"`
		Time       time.Time           `json:"Time"`

		// Legacy format fields (fallback)
		SenderID       string              `json:"sender_id"`
		LegacyZone     string              `json:"zone"`
		LegacyRecords  map[string][]string `json:"records"`
		SyncType       string              `json:"sync_type"`
		Serial         uint32              `json:"serial"`
		DistributionID string              `json:"distribution_id"`
		Timestamp      int64               `json:"timestamp"`
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	// Resolve fields: prefer standard format, fall back to legacy
	senderID := msg.MyIdentity
	if senderID == "" {
		senderID = msg.SenderID
	}
	if senderID == "" {
		return nil, fmt.Errorf("missing sender identity (MyIdentity or sender_id)")
	}

	zone := msg.Zone
	if zone == "" {
		zone = msg.LegacyZone
	}
	if zone == "" {
		return nil, fmt.Errorf("missing Zone")
	}

	records := msg.Records
	if len(records) == 0 {
		records = msg.LegacyRecords
	}
	if records == nil {
		records = make(map[string][]string)
	}

	// Use distribution ID from payload if present, otherwise from QNAME
	corrID := msg.DistributionID
	if corrID == "" {
		corrID = distributionID
	}

	timestamp := msg.Time
	if timestamp.IsZero() && msg.Timestamp > 0 {
		timestamp = time.Unix(msg.Timestamp, 0)
	}

	rrCount := 0
	for _, rrs := range records {
		rrCount += len(rrs)
	}
	log.Printf("CombinerChunkHandler: Parsed sync from %q for zone %q (%d RRs, %d owners)",
		senderID, zone, rrCount, len(records))

	return &CombinerSyncRequest{
		SenderID:       senderID,
		Zone:           zone,
		SyncType:       msg.SyncType,
		Records:        records,
		Serial:         msg.Serial,
		DistributionID: corrID,
		Timestamp:      timestamp,
	}, nil
}

// ProcessUpdate handles a sync request and returns a response.
// This is the main entry point for CHUNK-based and API-based updates to the combiner.
// Both transports use the same data structure (map[string][]string) for transport neutrality.
//
// RR class determines the operation:
//   - ClassINET: add/update the RR (existing behavior)
//   - ClassNONE: delete this specific RR from the agent's contributions
//   - ClassANY:  delete the entire RRset for the RR's type from the agent's contributions
func (h *CombinerChunkHandler) ProcessUpdate(req *CombinerSyncRequest) *CombinerSyncResponse {
	// Count total records for logging
	totalRecords := 0
	for _, rrs := range req.Records {
		totalRecords += len(rrs)
	}
	log.Printf("CombinerChunkHandler: Processing sync from %q for zone %q (%d owners, %d records)",
		req.SenderID, req.Zone, len(req.Records), totalRecords)

	resp := &CombinerSyncResponse{
		DistributionID: req.DistributionID,
		Zone:           req.Zone,
		Timestamp:      time.Now(),
	}

	// Get the zone data
	zonename := dns.Fqdn(req.Zone)
	zd, exists := Zones.Get(zonename)
	if !exists {
		resp.Status = "error"
		resp.Message = fmt.Sprintf("zone %q not found", req.Zone)
		return resp
	}

	// Separate records into adds, deletes (ClassNONE), and bulk deletes (ClassANY)
	addOwnerRRs := make(map[string][]string)     // ClassINET: owner → RR strings
	deleteOwnerRRs := make(map[string][]string)  // ClassNONE: owner → RR strings (with ClassINET for removal matching)
	bulkDeleteOwner := make(map[string][]uint16) // ClassANY: owner → rrtypes to delete entirely

	var appliedRecords []string
	var removedRecords []string
	var rejectedItems []RejectedItem

	for owner, rrStrings := range req.Records {
		for _, rrStr := range rrStrings {
			// Parse to validate
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				rejectedItems = append(rejectedItems, RejectedItem{
					Record: rrStr,
					Reason: fmt.Sprintf("parse error: %v", err),
				})
				continue
			}

			// Check if RRtype is allowed
			rrtype := rr.Header().Rrtype
			if !AllowedLocalRRtypes[rrtype] {
				rejectedItems = append(rejectedItems, RejectedItem{
					Record: rrStr,
					Reason: fmt.Sprintf("RRtype %s not allowed for combiner updates", dns.TypeToString[rrtype]),
				})
				continue
			}

			// Check if owner is at zone apex (combiner only accepts apex updates)
			if owner != zonename {
				rejectedItems = append(rejectedItems, RejectedItem{
					Record: rrStr,
					Reason: fmt.Sprintf("owner %q is not at zone apex %q", owner, zonename),
				})
				continue
			}

			// Route by class
			switch rr.Header().Class {
			case dns.ClassINET:
				addOwnerRRs[owner] = append(addOwnerRRs[owner], rrStr)
				appliedRecords = append(appliedRecords, rrStr)

			case dns.ClassNONE:
				// Convert to ClassINET string for removal matching in AgentContributions.
				// The stored contributions use ClassINET strings.
				delRR := dns.Copy(rr)
				delRR.Header().Class = dns.ClassINET
				deleteOwnerRRs[owner] = append(deleteOwnerRRs[owner], delRR.String())

			case dns.ClassANY:
				bulkDeleteOwner[owner] = append(bulkDeleteOwner[owner], rrtype)

			default:
				rejectedItems = append(rejectedItems, RejectedItem{
					Record: rrStr,
					Reason: fmt.Sprintf("unsupported class %d", rr.Header().Class),
				})
			}
		}
	}

	// Apply additions
	if len(addOwnerRRs) > 0 {
		err := zd.AddCombinerDataNG(req.SenderID, addOwnerRRs)
		if err != nil {
			resp.Status = "error"
			resp.Message = fmt.Sprintf("failed to apply add updates: %v", err)
			return resp
		}
	}

	// Apply ClassNONE deletes (specific RR removal)
	if len(deleteOwnerRRs) > 0 {
		removed, err := zd.RemoveCombinerDataNG(req.SenderID, deleteOwnerRRs)
		if err != nil {
			log.Printf("CombinerChunkHandler: Error removing records: %v", err)
			// Don't fail the whole request — report partial success
		}
		removedRecords = append(removedRecords, removed...)
	}

	// Apply ClassANY deletes (entire RRset removal by type)
	for owner, rrtypes := range bulkDeleteOwner {
		for _, rrtype := range rrtypes {
			removed, err := zd.RemoveCombinerDataByRRtype(req.SenderID, owner, rrtype)
			if err != nil {
				log.Printf("CombinerChunkHandler: Error removing RRset %s for owner %s: %v",
					dns.TypeToString[rrtype], owner, err)
			}
			removedRecords = append(removedRecords, removed...)
		}
	}

	// Build response
	resp.AppliedRecords = appliedRecords
	resp.RemovedRecords = removedRecords
	resp.RejectedItems = rejectedItems

	totalActions := len(appliedRecords) + len(removedRecords)
	if len(rejectedItems) == 0 {
		resp.Status = "ok"
		resp.Message = fmt.Sprintf("applied %d added %d removed for zone %q",
			len(appliedRecords), len(removedRecords), req.Zone)
	} else if totalActions > 0 {
		resp.Status = "partial"
		resp.Message = fmt.Sprintf("applied %d added %d removed %d rejected for zone %q",
			len(appliedRecords), len(removedRecords), len(rejectedItems), req.Zone)
	} else {
		resp.Status = "error"
		resp.Message = fmt.Sprintf("all %d records were rejected for zone %q",
			len(rejectedItems), req.Zone)
	}

	log.Printf("CombinerChunkHandler: %s - %s", resp.Status, resp.Message)

	if totalActions > 0 {
		bumperResp, err := zd.BumpSerialOnly()
		if err != nil {
			log.Printf("CombinerChunkHandler: BumpSerialOnly failed for zone %q: %v", req.Zone, err)
		} else {
			log.Printf("CombinerChunkHandler: BumpSerial %s: %d -> %d",
				req.Zone, bumperResp.OldSerial, bumperResp.NewSerial)
		}
	}

	return resp
}

// sendConfirmResponse sends a DNS response with confirmation in EDNS0.
func (h *CombinerChunkHandler) sendConfirmResponse(req *DnsNotifyRequest, resp *CombinerSyncResponse) error {
	if req.ResponseWriter == nil {
		log.Printf("CombinerChunkHandler: No ResponseWriter, cannot send confirmation for distribution %s", resp.DistributionID)
		return nil
	}

	log.Printf("CombinerChunkHandler: Sending confirmation for distribution %s zone %q status=%s applied=%d removed=%d rejected=%d",
		resp.DistributionID, resp.Zone, resp.Status, len(resp.AppliedRecords), len(resp.RemovedRecords), len(resp.RejectedItems))

	// Build per-RR rejected items for the payload
	type rejectedItemJSON struct {
		Record string `json:"record"`
		Reason string `json:"reason"`
	}
	var rejItems []rejectedItemJSON
	for _, ri := range resp.RejectedItems {
		rejItems = append(rejItems, rejectedItemJSON{Record: ri.Record, Reason: ri.Reason})
	}

	// Build confirmation payload with full per-RR detail
	confirmPayload := struct {
		Type           string             `json:"type"`
		DistributionID string             `json:"distribution_id"`
		Zone           string             `json:"zone"`
		Status         string             `json:"status"`
		Message        string             `json:"message"`
		AppliedCount   int                `json:"applied_count"`
		RemovedCount   int                `json:"removed_count"`
		RejectedCount  int                `json:"rejected_count"`
		AppliedRecords []string           `json:"applied_records,omitempty"`
		RemovedRecords []string           `json:"removed_records,omitempty"`
		RejectedItems  []rejectedItemJSON `json:"rejected_items,omitempty"`
		Truncated      bool               `json:"truncated,omitempty"`
		Timestamp      int64              `json:"timestamp"`
	}{
		Type:           "confirm",
		DistributionID: resp.DistributionID,
		Zone:           resp.Zone,
		Status:         resp.Status,
		Message:        resp.Message,
		AppliedCount:   len(resp.AppliedRecords),
		RemovedCount:   len(resp.RemovedRecords),
		RejectedCount:  len(resp.RejectedItems),
		AppliedRecords: resp.AppliedRecords,
		RemovedRecords: resp.RemovedRecords,
		RejectedItems:  rejItems,
		Timestamp:      resp.Timestamp.Unix(),
	}

	payloadBytes, err := json.Marshal(confirmPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal confirm payload: %w", err)
	}

	// Size guard: EDNS0 payload must fit in UDP. If too large, drop applied_records
	// and removed_records (the actionable data is in rejected_items) and set Truncated.
	if len(payloadBytes) > 3500 {
		confirmPayload.AppliedRecords = nil
		confirmPayload.RemovedRecords = nil
		confirmPayload.Truncated = true
		payloadBytes, err = json.Marshal(confirmPayload)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal confirm payload: %w", err)
	}

	return h.sendGenericEdns0Response(req, payloadBytes)
}

// sendGenericEdns0Response builds and sends a DNS response with the given payload in an EDNS0 CHUNK option.
// This is the common response-building pattern used by all message type handlers (ping, beat, sync).
func (h *CombinerChunkHandler) sendGenericEdns0Response(req *DnsNotifyRequest, payload []byte) error {
	if req.ResponseWriter == nil {
		return nil
	}

	resp := new(dns.Msg)
	resp.SetReply(req.Msg)
	resp.Authoritative = true
	resp.Rcode = dns.RcodeSuccess
	resp.SetEdns0(4096, true)
	opt := resp.IsEdns0()
	if opt != nil {
		opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
			Code: edns0.EDNS0_CHUNK_OPTION_CODE,
			Data: payload,
		})
	}
	return req.ResponseWriter.WriteMsg(resp)
}

// sendErrorResponse sends a sync-shaped error response.
// Only used for sync errors and unknown message types where the sync confirmation shape is appropriate.
func (h *CombinerChunkHandler) sendErrorResponse(req *DnsNotifyRequest, distributionID, errMsg string) error {
	resp := &CombinerSyncResponse{
		DistributionID: distributionID,
		Status:         "error",
		Message:        errMsg,
		Timestamp:      time.Now(),
	}
	return h.sendConfirmResponse(req, resp)
}

// --- Router-compatible handler functions ---
// These methods match the transport.MessageHandlerFunc signature
// (func(ctx *MessageContext) error) and can be registered with the
// DNSMessageRouter via InitializeCombinerRouter().
//
// They use ctx.ChunkPayload (already decrypted by middleware) and store
// their response payloads in ctx.Data for SendResponseMiddleware.

// CombinerHandlePing processes a ping message via the router.
// Echoes the nonce back in a ping_confirm response.
func (h *CombinerChunkHandler) CombinerHandlePing(ctx *transport.MessageContext) error {
	log.Printf("CombinerHandlePing: Processing ping from %s (distrib=%s)",
		ctx.PeerID, ctx.DistributionID)

	var ping struct {
		MessageType  string `json:"MessageType"`
		MyIdentity   string `json:"MyIdentity"`
		YourIdentity string `json:"YourIdentity"`
		Nonce        string `json:"Nonce"`
	}
	if err := json.Unmarshal(ctx.ChunkPayload, &ping); err != nil {
		log.Printf("CombinerHandlePing: Failed to parse ping payload: %v", err)
		h.recordError(ctx.DistributionID, ctx.PeerID, "ping", "invalid ping payload", "")
		return fmt.Errorf("invalid ping payload: %w", err)
	}
	if ping.Nonce == "" {
		h.recordError(ctx.DistributionID, ctx.PeerID, "ping", "empty nonce", "")
		return fmt.Errorf("ping has empty nonce")
	}

	// Build ping_confirm response
	confirmPayload := struct {
		Type           string `json:"type"`
		SenderID       string `json:"sender_id"`
		Nonce          string `json:"nonce"`
		DistributionID string `json:"distribution_id"`
		Status         string `json:"status"`
		Timestamp      int64  `json:"timestamp"`
	}{
		Type:           "ping_confirm",
		SenderID:       h.LocalID,
		Nonce:          ping.Nonce,
		DistributionID: ctx.DistributionID,
		Status:         "ok",
		Timestamp:      time.Now().Unix(),
	}
	payloadBytes, err := json.Marshal(confirmPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal ping_confirm: %w", err)
	}

	ctx.Data["ping_response"] = payloadBytes
	log.Printf("CombinerHandlePing: Ping processed from %s, nonce=%s", ctx.PeerID, ping.Nonce)
	return nil
}

// CombinerHandleBeat processes a heartbeat message via the router.
// Acknowledges the beat with a confirm response.
func (h *CombinerChunkHandler) CombinerHandleBeat(ctx *transport.MessageContext) error {
	log.Printf("CombinerHandleBeat: Processing beat from %s (distrib=%s)",
		ctx.PeerID, ctx.DistributionID)

	var beat struct {
		MessageType  string    `json:"MessageType"`
		MyIdentity   string    `json:"MyIdentity"`
		YourIdentity string    `json:"YourIdentity"`
		Time         time.Time `json:"Time"`
	}
	if err := json.Unmarshal(ctx.ChunkPayload, &beat); err != nil {
		log.Printf("CombinerHandleBeat: Failed to parse beat payload: %v", err)
		h.recordError(ctx.DistributionID, ctx.PeerID, "beat", "invalid beat payload", "")
		return fmt.Errorf("invalid beat payload: %w", err)
	}

	log.Printf("CombinerHandleBeat: Received heartbeat from %s", beat.MyIdentity)

	// Build beat confirm response
	confirmPayload := struct {
		Type           string `json:"type"`
		DistributionID string `json:"distribution_id"`
		Status         string `json:"status"`
		Message        string `json:"message"`
		Timestamp      int64  `json:"timestamp"`
	}{
		Type:           "confirm",
		DistributionID: ctx.DistributionID,
		Status:         "ok",
		Message:        "beat acknowledged",
		Timestamp:      time.Now().Unix(),
	}
	payloadBytes, err := json.Marshal(confirmPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal beat confirm: %w", err)
	}

	// Store as sync_response — SendResponseMiddleware checks this key
	ctx.Data["sync_response"] = payloadBytes
	log.Printf("CombinerHandleBeat: Beat processed from %s", ctx.PeerID)
	return nil
}

// CombinerHandleSync processes a sync message via the router.
// Parses the sync payload, applies updates via ProcessUpdate, and
// stores the confirmation response for SendResponseMiddleware.
func (h *CombinerChunkHandler) CombinerHandleSync(ctx *transport.MessageContext) error {
	log.Printf("CombinerHandleSync: Processing sync from %s (distrib=%s)",
		ctx.PeerID, ctx.DistributionID)

	syncReq, err := h.parseAgentMsgNotify(ctx.ChunkPayload, ctx.DistributionID)
	if err != nil {
		log.Printf("CombinerHandleSync: Failed to parse sync payload: %v", err)
		h.recordError(ctx.DistributionID, ctx.PeerID, "sync", fmt.Sprintf("failed to parse sync: %v", err), "")
		return fmt.Errorf("failed to parse sync: %w", err)
	}

	resp := h.ProcessUpdate(syncReq)
	if resp.Status == "error" {
		h.recordError(ctx.DistributionID, ctx.PeerID, "sync", resp.Message, "")
	}

	// Build confirmation payload (same structure as sendConfirmResponse)
	type rejectedItemJSON struct {
		Record string `json:"record"`
		Reason string `json:"reason"`
	}
	var rejItems []rejectedItemJSON
	for _, ri := range resp.RejectedItems {
		rejItems = append(rejItems, rejectedItemJSON{Record: ri.Record, Reason: ri.Reason})
	}

	confirmPayload := struct {
		Type           string             `json:"type"`
		DistributionID string             `json:"distribution_id"`
		Zone           string             `json:"zone"`
		Status         string             `json:"status"`
		Message        string             `json:"message"`
		AppliedCount   int                `json:"applied_count"`
		RemovedCount   int                `json:"removed_count"`
		RejectedCount  int                `json:"rejected_count"`
		AppliedRecords []string           `json:"applied_records,omitempty"`
		RemovedRecords []string           `json:"removed_records,omitempty"`
		RejectedItems  []rejectedItemJSON `json:"rejected_items,omitempty"`
		Truncated      bool               `json:"truncated,omitempty"`
		Timestamp      int64              `json:"timestamp"`
	}{
		Type:           "confirm",
		DistributionID: resp.DistributionID,
		Zone:           resp.Zone,
		Status:         resp.Status,
		Message:        resp.Message,
		AppliedCount:   len(resp.AppliedRecords),
		RemovedCount:   len(resp.RemovedRecords),
		RejectedCount:  len(resp.RejectedItems),
		AppliedRecords: resp.AppliedRecords,
		RemovedRecords: resp.RemovedRecords,
		RejectedItems:  rejItems,
		Timestamp:      resp.Timestamp.Unix(),
	}

	payloadBytes, err := json.Marshal(confirmPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal confirm payload: %w", err)
	}

	// Size guard: EDNS0 payload must fit in UDP
	if len(payloadBytes) > 3500 {
		confirmPayload.AppliedRecords = nil
		confirmPayload.RemovedRecords = nil
		confirmPayload.Truncated = true
		payloadBytes, err = json.Marshal(confirmPayload)
		if err != nil {
			return fmt.Errorf("failed to marshal truncated confirm payload: %w", err)
		}
	}

	ctx.Data["sync_response"] = payloadBytes
	log.Printf("CombinerHandleSync: Sync processed from %s, status=%s", ctx.PeerID, resp.Status)
	return nil
}

// RegisterCombinerChunkHandler registers the combiner's CHUNK handler.
// Control zone is derived per NOTIFY from qname (qname minus leftmost label); no static config.
// localID is the combiner's identity (FQDN), required for constructing CHUNK query qnames.
// If secureWrapper is provided, the handler will decrypt incoming JWT payloads from the agent.
// Returns the created handler so it can be stored for API access (e.g. error journal queries).
func RegisterCombinerChunkHandler(localID string, secureWrapper *transport.SecurePayloadWrapper) (*CombinerChunkHandler, error) {
	handler := NewCombinerChunkHandler(localID)
	handler.SecureWrapper = secureWrapper
	if secureWrapper != nil && secureWrapper.IsEnabled() {
		log.Printf("RegisterCombinerChunkHandler: Registering CHUNK handler for %s with crypto enabled", localID)
	} else {
		log.Printf("RegisterCombinerChunkHandler: Registering CHUNK handler for %s (control zone derived from qname)", localID)
	}
	return handler, RegisterNotifyHandler(core.TypeCHUNK, handler.CreateNotifyHandlerFunc())
}

// SendToCombiner is a helper function that sends a sync request to the combiner
// and waits for a response. This is called from SynchedDataEngine.
// For in-process communication, this calls the handler directly.
func SendToCombiner(handler *CombinerChunkHandler, req *CombinerSyncRequest) *CombinerSyncResponse {
	if handler == nil {
		log.Printf("SendToCombiner: handler is nil, cannot send update")
		return &CombinerSyncResponse{
			DistributionID: req.DistributionID,
			Zone:           req.Zone,
			Status:         "error",
			Message:        "combiner handler not initialized",
			Timestamp:      time.Now(),
		}
	}

	// For in-process communication, we can call directly
	return handler.ProcessUpdate(req)
}

// ConvertZoneUpdateToSyncRequest converts a ZoneUpdate to a CombinerSyncRequest.
// Groups records by owner for transport neutrality (same structure as CombinerPost).
func ConvertZoneUpdateToSyncRequest(update *ZoneUpdate, senderID string, distributionID string) *CombinerSyncRequest {
	// Group records by owner name
	records := make(map[string][]string)

	// First, add RRs if present (these are individual RRs to add)
	for _, rr := range update.RRs {
		owner := rr.Header().Name
		records[owner] = append(records[owner], rr.String())
	}

	// Also add from RRsets (for backwards compatibility)
	for _, rrset := range update.RRsets {
		for _, rr := range rrset.RRs {
			owner := rr.Header().Name
			records[owner] = append(records[owner], rr.String())
		}
	}

	// Determine sync type from the RRs
	syncType := determineSyncType(update)

	return &CombinerSyncRequest{
		SenderID:       senderID,
		Zone:           string(update.Zone),
		SyncType:       syncType,
		Records:        records,
		DistributionID: distributionID,
		Timestamp:      time.Now(),
	}
}

// determineSyncType examines the update and returns an appropriate sync type string.
func determineSyncType(update *ZoneUpdate) string {
	types := make(map[uint16]bool)

	for _, rr := range update.RRs {
		types[rr.Header().Rrtype] = true
	}
	for rrtype := range update.RRsets {
		types[rrtype] = true
	}

	// Return the most specific type, or "MIXED" if multiple types
	if len(types) == 1 {
		for rrtype := range types {
			return dns.TypeToString[rrtype]
		}
	}
	if len(types) > 1 {
		return "MIXED"
	}
	return "UNKNOWN"
}
