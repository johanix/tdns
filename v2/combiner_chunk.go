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
	"time"

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
	CorrelationID string    // Correlation ID for tracking
	Timestamp     time.Time // When the request was created
}

// CombinerSyncResponse represents a confirmation from the combiner.
type CombinerSyncResponse struct {
	CorrelationID  string         // Echoed from request
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
	// ControlZone for QNAME parsing
	ControlZone string

	// RequestChan receives sync requests (for async processing if needed)
	RequestChan chan *CombinerSyncRequestPlus

	// Debug enables verbose logging
	Debug bool
}

// CombinerSyncRequestPlus includes a response channel for async processing.
type CombinerSyncRequestPlus struct {
	Request  *CombinerSyncRequest
	Response chan *CombinerSyncResponse
}

// NewCombinerChunkHandler creates a new combiner CHUNK handler.
func NewCombinerChunkHandler(controlZone string) *CombinerChunkHandler {
	return &CombinerChunkHandler{
		ControlZone: dns.Fqdn(controlZone),
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

	// Extract correlation ID from QNAME
	correlationID, err := h.extractCorrelationID(req.Qname)
	if err != nil {
		log.Printf("CombinerChunkHandler: Failed to extract correlation ID from %s: %v", req.Qname, err)
		return ErrNotHandled // Let other handlers try
	}

	log.Printf("CombinerChunkHandler: Received CHUNK NOTIFY correlation=%s qname=%s", correlationID, req.Qname)

	// Extract CHUNK payload from EDNS0
	payload, err := h.extractChunkPayload(req.Msg)
	if err != nil {
		log.Printf("CombinerChunkHandler: Failed to extract CHUNK payload: %v", err)
		return h.sendErrorResponse(req, correlationID, "failed to extract payload")
	}

	// Parse the sync payload
	syncReq, err := h.parseSyncPayload(payload, correlationID)
	if err != nil {
		log.Printf("CombinerChunkHandler: Failed to parse sync payload: %v", err)
		return h.sendErrorResponse(req, correlationID, "failed to parse payload")
	}

	// Process the sync request
	resp := h.ProcessUpdate(syncReq)

	// Send confirmation response
	return h.sendConfirmResponse(req, resp)
}

// extractCorrelationID extracts the correlation ID from the QNAME.
// QNAME format: <correlationID>.<controlZone>
func (h *CombinerChunkHandler) extractCorrelationID(qname string) (string, error) {
	qname = dns.Fqdn(qname)

	// Check if qname ends with control zone
	if len(qname) <= len(h.ControlZone) {
		return "", fmt.Errorf("qname %s too short for control zone %s", qname, h.ControlZone)
	}

	// Extract the prefix (correlation ID)
	if qname[len(qname)-len(h.ControlZone):] != h.ControlZone {
		return "", fmt.Errorf("qname %s does not end with control zone %s", qname, h.ControlZone)
	}

	correlationID := qname[:len(qname)-len(h.ControlZone)-1] // -1 for the dot
	if correlationID == "" {
		return "", fmt.Errorf("empty correlation ID in qname %s", qname)
	}

	return correlationID, nil
}

// extractChunkPayload extracts the CHUNK data from EDNS0 option.
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
func (h *CombinerChunkHandler) parseSyncPayload(data []byte, correlationID string) (*CombinerSyncRequest, error) {
	// The payload format matches DnsSyncPayload from transport package
	var payload struct {
		Type          string   `json:"type"`
		SenderID      string   `json:"sender_id"`
		Zone          string   `json:"zone"`
		SyncType      string   `json:"sync_type"`
		Records       []string `json:"records"`
		Serial        uint32   `json:"serial,omitempty"`
		CorrelationID string   `json:"correlation_id,omitempty"`
		Timestamp     int64    `json:"timestamp"`
	}

	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	if payload.Type != "sync" {
		return nil, fmt.Errorf("expected type 'sync', got '%s'", payload.Type)
	}

	// Use correlation ID from payload if present, otherwise from QNAME
	corrID := payload.CorrelationID
	if corrID == "" {
		corrID = correlationID
	}

	return &CombinerSyncRequest{
		SenderID:      payload.SenderID,
		Zone:          payload.Zone,
		SyncType:      payload.SyncType,
		Records:       payload.Records,
		Serial:        payload.Serial,
		CorrelationID: corrID,
		Timestamp:     time.Unix(payload.Timestamp, 0),
	}, nil
}

// ProcessUpdate handles a sync request and returns a response.
// This is the main entry point for CHUNK-based updates to the combiner.
func (h *CombinerChunkHandler) ProcessUpdate(req *CombinerSyncRequest) *CombinerSyncResponse {
	log.Printf("CombinerChunkHandler: Processing sync from %q for zone %q (%d records)",
		req.SenderID, req.Zone, len(req.Records))

	resp := &CombinerSyncResponse{
		CorrelationID: req.CorrelationID,
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
		CorrelationID string `json:"correlation_id"`
		Zone          string `json:"zone"`
		Status        string `json:"status"`
		Message       string `json:"message"`
		AppliedCount  int    `json:"applied_count"`
		RejectedCount int    `json:"rejected_count"`
		Timestamp     int64  `json:"timestamp"`
	}{
		Type:          "confirm",
		CorrelationID: resp.CorrelationID,
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
func (h *CombinerChunkHandler) sendErrorResponse(req *DnsNotifyRequest, correlationID, errMsg string) error {
	resp := &CombinerSyncResponse{
		CorrelationID: correlationID,
		Status:        "error",
		Message:       errMsg,
		Timestamp:     time.Now(),
	}
	return h.sendConfirmResponse(req, resp)
}

// RegisterCombinerChunkHandler registers the combiner's CHUNK handler.
// This should be called during combiner initialization.
func RegisterCombinerChunkHandler(controlZone string) error {
	handler := NewCombinerChunkHandler(controlZone)
	log.Printf("RegisterCombinerChunkHandler: Registering CHUNK handler for combiner (control zone: %s)", controlZone)
	return RegisterNotifyHandler(core.TypeCHUNK, handler.CreateNotifyHandlerFunc())
}

// SendToCombiner is a helper function that sends a sync request to the combiner
// and waits for a response. This is called from SynchedDataEngine.
// For in-process communication, this calls the handler directly.
func SendToCombiner(handler *CombinerChunkHandler, req *CombinerSyncRequest) *CombinerSyncResponse {
	if handler == nil {
		log.Printf("SendToCombiner: handler is nil, cannot send update")
		return &CombinerSyncResponse{
			CorrelationID: req.CorrelationID,
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
func ConvertZoneUpdateToSyncRequest(update *ZoneUpdate, senderID string, correlationID string) *CombinerSyncRequest {
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
		CorrelationID: correlationID,
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
