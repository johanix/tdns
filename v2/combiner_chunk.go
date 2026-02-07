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

// CombinerSyncRequest represents a sync request to the combiner.
// This mirrors the DnsSyncPayload structure for consistency.
type CombinerSyncRequest struct {
	SenderID      string    // Identity of the sending agent
	Zone          string    // Zone being updated
	SyncType      string    // Type of sync: "NS", "DNSKEY", "CDS", "CSYNC", "GLUE"
	Records       []string  // RR strings to apply
	Serial        uint32    // Zone serial (optional)
	DistributionID string    // Distribution ID for tracking
	Timestamp     time.Time // When the request was created
}

// CombinerSyncResponse represents a confirmation from the combiner.
type CombinerSyncResponse struct {
	DistributionID  string         // Echoed from request
	Zone           string         // Zone that was updated
	Status         string         // "ok", "partial", "error"
	Message        string         // Human-readable message
	AppliedRecords []string       // RRs that were successfully applied
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

	// SecureWrapper handles decryption of incoming JWS/JWE payloads from the agent.
	// Uses the generic transport crypto infrastructure.
	// If nil, payloads are expected to be plaintext JSON.
	SecureWrapper *transport.SecurePayloadWrapper
}

// CombinerSyncRequestPlus includes a response channel for async processing.
type CombinerSyncRequestPlus struct {
	Request  *CombinerSyncRequest
	Response chan *CombinerSyncResponse
}

// NewCombinerChunkHandler creates a new combiner CHUNK handler.
// Control zone is derived dynamically from each NOTIFY qname as qname minus the leftmost label (no static config).
func NewCombinerChunkHandler() *CombinerChunkHandler {
	return &CombinerChunkHandler{
		RequestChan: make(chan *CombinerSyncRequestPlus, 100),
	}
}

// CreateNotifyHandlerFunc creates a function compatible with tdns.NotifyHandlerFunc.
// Usage: RegisterNotifyHandler(core.TypeCHUNK, handler.CreateNotifyHandlerFunc())
func (h *CombinerChunkHandler) CreateNotifyHandlerFunc() NotifyHandlerFunc {
	return func(ctx context.Context, req *DnsNotifyRequest) error {
		return h.HandleChunkNotify(ctx, req)
	}
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
	payload, err := h.getChunkPayload(ctx, req)
	if err != nil {
		log.Printf("CombinerChunkHandler: Failed to get CHUNK payload: %v", err)
		return h.sendErrorResponse(req, distributionID, "failed to get payload")
	}

	// Decrypt payload if secure wrapper is configured
	if h.SecureWrapper != nil && h.SecureWrapper.IsEnabled() {
		decrypted, err := h.SecureWrapper.UnwrapIncoming("agent", payload)
		if err != nil {
			log.Printf("CombinerChunkHandler: Failed to decrypt payload: %v", err)
			return h.sendErrorResponse(req, distributionID, "failed to decrypt payload")
		}
		payload = decrypted
		log.Printf("CombinerChunkHandler: Decrypted payload (%d bytes)", len(payload))
	}

	// Parse type first to handle ping without altering zone state
	var typeOnly struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(payload, &typeOnly); err == nil && typeOnly.Type == "ping" {
		return h.handlePing(req, distributionID, payload)
	}

	// Parse the sync payload
	syncReq, err := h.parseSyncPayload(payload, distributionID)
	if err != nil {
		log.Printf("CombinerChunkHandler: Failed to parse sync payload: %v", err)
		return h.sendErrorResponse(req, distributionID, "failed to parse payload")
	}

	// Process the sync request
	resp := h.ProcessUpdate(syncReq)

	// Send confirmation response
	return h.sendConfirmResponse(req, resp)
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
func (h *CombinerChunkHandler) handlePing(req *DnsNotifyRequest, distributionID string, payload []byte) error {
	var ping struct {
		Type      string `json:"type"`
		SenderID  string `json:"sender_id"`
		Nonce     string `json:"nonce"`
		Timestamp int64  `json:"timestamp"`
	}
	if err := json.Unmarshal(payload, &ping); err != nil {
		log.Printf("CombinerChunkHandler: Failed to parse ping payload: %v", err)
		return h.sendErrorResponse(req, distributionID, "invalid ping payload")
	}
	if ping.Type != "ping" || ping.Nonce == "" {
		log.Printf("CombinerChunkHandler: Invalid ping (type=%q nonce=%q)", ping.Type, ping.Nonce)
		return h.sendErrorResponse(req, distributionID, "invalid ping")
	}

	confirmPayload := struct {
		Type          string `json:"type"`
		SenderID      string `json:"sender_id"`
		Nonce         string `json:"nonce"`
		DistributionID string `json:"distribution_id"`
		Status        string `json:"status"`
		Timestamp     int64  `json:"timestamp"`
	}{
		Type:          "ping_confirm",
		SenderID:      "combiner",
		Nonce:         ping.Nonce,
		DistributionID: distributionID,
		Status:        "ok",
		Timestamp:     time.Now().Unix(),
	}
	payloadBytes, err := json.Marshal(confirmPayload)
	if err != nil {
		return h.sendErrorResponse(req, distributionID, "failed to build ping_confirm")
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
			Data: payloadBytes,
		})
	}
	if req.ResponseWriter != nil {
		return req.ResponseWriter.WriteMsg(resp)
	}
	return nil
}

// getChunkPayload returns the CHUNK payload from the NOTIFY. Receiver adapts: first try EDNS(0) CHUNK option;
// if none, fetch via CHUNK query to the sender. Query target is the CHUNK query endpoint from the NOTIFY (if present), else the connection peer (may fail for ephemeral ports).
func (h *CombinerChunkHandler) getChunkPayload(ctx context.Context, req *DnsNotifyRequest) ([]byte, error) {
	// Always try EDNS0 first; receiver adapts to sender's choice
	payload, err := h.extractChunkPayload(req.Msg)
	if err == nil {
		return payload, nil
	}

	// No EDNS0 payload: fetch via CHUNK query. Use CHUNK_QUERY_ENDPOINT from NOTIFY if present, else static config (combiner.agent.address).
	queryTarget := extractChunkQueryEndpoint(req.Msg)
	if queryTarget == "" && Conf.Combiner != nil && Conf.Combiner.Agent != nil && Conf.Combiner.Agent.Address != "" {
		queryTarget = strings.TrimSpace(Conf.Combiner.Agent.Address)
	}
	if queryTarget == "" {
		return nil, fmt.Errorf("no CHUNK payload in EDNS0 and no CHUNK query endpoint (no EDNS0 option, no combiner.agent.address)")
	}
	return fetchChunkPayloadViaQuery(ctx, queryTarget, req.Qname)
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
		return nil, fmt.Errorf("CHUNK query to %s failed: %w", serverAddr, err)
	}
	if in == nil || in.Rcode != dns.RcodeSuccess {
		rcode := dns.RcodeSuccess
		if in != nil {
			rcode = in.Rcode
		}
		return nil, fmt.Errorf("CHUNK query to %s returned rcode %s", serverAddr, dns.RcodeToString[rcode])
	}
	for _, rr := range in.Answer {
		if prr, ok := rr.(*dns.PrivateRR); ok && prr.Hdr.Rrtype == core.TypeCHUNK {
			if chunk, ok := prr.Data.(*core.CHUNK); ok && chunk != nil {
				return chunk.Data, nil
			}
		}
	}
	return nil, fmt.Errorf("no CHUNK RR in response from %s", serverAddr)
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

// parseSyncPayload parses the JSON sync payload.
func (h *CombinerChunkHandler) parseSyncPayload(data []byte, distributionID string) (*CombinerSyncRequest, error) {
	// The payload format matches DnsSyncPayload from transport package
	var payload struct {
		Type          string   `json:"type"`
		SenderID      string   `json:"sender_id"`
		Zone          string   `json:"zone"`
		SyncType      string   `json:"sync_type"`
		Records       []string `json:"records"`
		Serial        uint32   `json:"serial,omitempty"`
		DistributionID string   `json:"distribution_id,omitempty"`
		Timestamp     int64    `json:"timestamp"`
	}

	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	if payload.Type != "sync" {
		return nil, fmt.Errorf("expected type 'sync', got '%s'", payload.Type)
	}

	// Use distribution ID from payload if present, otherwise from QNAME
	corrID := payload.DistributionID
	if corrID == "" {
		corrID = distributionID
	}

	return &CombinerSyncRequest{
		SenderID:      payload.SenderID,
		Zone:          payload.Zone,
		SyncType:      payload.SyncType,
		Records:       payload.Records,
		Serial:        payload.Serial,
		DistributionID: corrID,
		Timestamp:     time.Unix(payload.Timestamp, 0),
	}, nil
}

// ProcessUpdate handles a sync request and returns a response.
// This is the main entry point for CHUNK-based updates to the combiner.
func (h *CombinerChunkHandler) ProcessUpdate(req *CombinerSyncRequest) *CombinerSyncResponse {
	log.Printf("CombinerChunkHandler: Processing sync from %q for zone %q (%d records)",
		req.SenderID, req.Zone, len(req.Records))

	resp := &CombinerSyncResponse{
		DistributionID: req.DistributionID,
		Zone:          req.Zone,
		Timestamp:     time.Now(),
	}

	// Get the zone data
	zonename := dns.Fqdn(req.Zone)
	zd, exists := Zones.Get(zonename)
	if !exists {
		resp.Status = "error"
		resp.Message = fmt.Sprintf("zone %q not found", req.Zone)
		return resp
	}

	// Parse RRs and group by owner
	ownerRRs := make(map[string][]string)
	var appliedRecords []string
	var rejectedItems []RejectedItem

	for _, rrStr := range req.Records {
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
		owner := rr.Header().Name
		if owner != zonename {
			// For glue records, we might accept them - but current policy is apex only
			// This could be extended later
			rejectedItems = append(rejectedItems, RejectedItem{
				Record: rrStr,
				Reason: fmt.Sprintf("owner %q is not at zone apex %q", owner, zonename),
			})
			continue
		}

		// Group by owner for AddCombinerDataNG
		ownerRRs[owner] = append(ownerRRs[owner], rrStr)
		appliedRecords = append(appliedRecords, rrStr)
	}

	// Apply the updates if we have any valid records
	if len(ownerRRs) > 0 {
		err := zd.AddCombinerDataNG(ownerRRs)
		if err != nil {
			resp.Status = "error"
			resp.Message = fmt.Sprintf("failed to apply updates: %v", err)
			return resp
		}
	}

	// Build response
	resp.AppliedRecords = appliedRecords
	resp.RejectedItems = rejectedItems

	if len(rejectedItems) == 0 {
		resp.Status = "ok"
		resp.Message = fmt.Sprintf("applied %d records to zone %q", len(appliedRecords), req.Zone)
	} else if len(appliedRecords) > 0 {
		resp.Status = "partial"
		resp.Message = fmt.Sprintf("applied %d records, rejected %d records for zone %q",
			len(appliedRecords), len(rejectedItems), req.Zone)
	} else {
		resp.Status = "error"
		resp.Message = fmt.Sprintf("all %d records were rejected for zone %q",
			len(rejectedItems), req.Zone)
	}

	log.Printf("CombinerChunkHandler: %s - %s", resp.Status, resp.Message)

	return resp
}

// sendConfirmResponse sends a DNS response with confirmation in EDNS0.
func (h *CombinerChunkHandler) sendConfirmResponse(req *DnsNotifyRequest, resp *CombinerSyncResponse) error {
	if req.ResponseWriter == nil {
		return nil // No response writer, can't send response
	}

	// Build confirmation payload
	confirmPayload := struct {
		Type          string `json:"type"`
		DistributionID string `json:"distribution_id"`
		Zone          string `json:"zone"`
		Status        string `json:"status"`
		Message       string `json:"message"`
		AppliedCount  int    `json:"applied_count"`
		RejectedCount int    `json:"rejected_count"`
		Timestamp     int64  `json:"timestamp"`
	}{
		Type:          "confirm",
		DistributionID: resp.DistributionID,
		Zone:          resp.Zone,
		Status:        resp.Status,
		Message:       resp.Message,
		AppliedCount:  len(resp.AppliedRecords),
		RejectedCount: len(resp.RejectedItems),
		Timestamp:     resp.Timestamp.Unix(),
	}

	payloadBytes, err := json.Marshal(confirmPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal confirm payload: %w", err)
	}

	// Build response message
	response := new(dns.Msg)
	response.SetReply(req.Msg)
	response.Authoritative = true

	// Add EDNS0 with CHUNK option containing the confirmation
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
		Code: edns0.EDNS0_CHUNK_OPTION_CODE,
		Data: payloadBytes,
	})
	response.Extra = append(response.Extra, opt)

	return req.ResponseWriter.WriteMsg(response)
}

// sendErrorResponse sends a DNS error response.
func (h *CombinerChunkHandler) sendErrorResponse(req *DnsNotifyRequest, distributionID, errMsg string) error {
	resp := &CombinerSyncResponse{
		DistributionID: distributionID,
		Status:        "error",
		Message:       errMsg,
		Timestamp:     time.Now(),
	}
	return h.sendConfirmResponse(req, resp)
}

// RegisterCombinerChunkHandler registers the combiner's CHUNK handler.
// Control zone is derived per NOTIFY from qname (qname minus leftmost label); no static config.
// If secureWrapper is provided, the handler will decrypt incoming JWT payloads from the agent.
func RegisterCombinerChunkHandler(secureWrapper *transport.SecurePayloadWrapper) error {
	handler := NewCombinerChunkHandler()
	handler.SecureWrapper = secureWrapper
	if secureWrapper != nil && secureWrapper.IsEnabled() {
		log.Printf("RegisterCombinerChunkHandler: Registering CHUNK handler with crypto enabled")
	} else {
		log.Printf("RegisterCombinerChunkHandler: Registering CHUNK handler (control zone derived from qname)")
	}
	return RegisterNotifyHandler(core.TypeCHUNK, handler.CreateNotifyHandlerFunc())
}

// SendToCombiner is a helper function that sends a sync request to the combiner
// and waits for a response. This is called from SynchedDataEngine.
// For in-process communication, this calls the handler directly.
func SendToCombiner(handler *CombinerChunkHandler, req *CombinerSyncRequest) *CombinerSyncResponse {
	if handler == nil {
		log.Printf("SendToCombiner: handler is nil, cannot send update")
		return &CombinerSyncResponse{
			DistributionID: req.DistributionID,
			Zone:          req.Zone,
			Status:        "error",
			Message:       "combiner handler not initialized",
			Timestamp:     time.Now(),
		}
	}

	// For in-process communication, we can call directly
	return handler.ProcessUpdate(req)
}

// ConvertZoneUpdateToSyncRequest converts a ZoneUpdate to a CombinerSyncRequest.
func ConvertZoneUpdateToSyncRequest(update *ZoneUpdate, senderID string, distributionID string) *CombinerSyncRequest {
	var records []string

	// First, add RRs if present (these are individual RRs to add)
	for _, rr := range update.RRs {
		records = append(records, rr.String())
	}

	// Also add from RRsets (for backwards compatibility)
	for _, rrset := range update.RRsets {
		for _, rr := range rrset.RRs {
			records = append(records, rr.String())
		}
	}

	// Determine sync type from the RRs
	syncType := determineSyncType(update)

	return &CombinerSyncRequest{
		SenderID:      senderID,
		Zone:          string(update.Zone),
		SyncType:      syncType,
		Records:       records,
		DistributionID: distributionID,
		Timestamp:     time.Now(),
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
