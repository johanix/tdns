/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Combiner business logic for multi-provider DNSSEC coordination (HSYNC).
 * Receives sync updates from agents and applies them to zones.
 *
 * Transport handling (CHUNK NOTIFY routing, EDNS0 extraction, decryption) is
 * handled by the unified ChunkNotifyHandler in agent/transport/. This file
 * contains only combiner-specific business logic: sync parsing, update
 * processing (ClassINET/ClassNONE/ClassANY), policy checks, and the
 * registration functions that wire ChunkNotifyHandler for combiner/signer roles.
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
	"github.com/miekg/dns"
)

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

// CombinerSyncRequestPlus includes a response channel for async processing.
type CombinerSyncRequestPlus struct {
	Request  *CombinerSyncRequest
	Response chan *CombinerSyncResponse
}

// CombinerState holds combiner-specific state that outlives individual CHUNK messages.
// Used by CLI commands (error journal queries) and in-process SendToCombiner.
// Transport routing is handled by the unified ChunkNotifyHandler.
type CombinerState struct {
	// ErrorJournal records errors during CHUNK NOTIFY processing for operational diagnostics.
	// Queried via "transaction errors" CLI commands. If nil, errors are only logged.
	ErrorJournal *ErrorJournal

	// ProtectedNamespaces: domain suffixes belonging to this provider.
	// NS records from remote agents whose targets fall within these namespaces are rejected.
	ProtectedNamespaces []string

	// chunkHandler is the underlying ChunkNotifyHandler (internal wiring).
	// Access is via SetRouter/SetGetPeerAddress/SetSecureWrapper.
	chunkHandler *transport.ChunkNotifyHandler
}

// ChunkHandler returns the underlying ChunkNotifyHandler for wiring into TransportManager.
func (cs *CombinerState) ChunkHandler() *transport.ChunkNotifyHandler {
	return cs.chunkHandler
}

// ProcessUpdate delegates to the standalone CombinerProcessUpdate.
func (cs *CombinerState) ProcessUpdate(req *CombinerSyncRequest) *CombinerSyncResponse {
	return CombinerProcessUpdate(req, cs.ProtectedNamespaces)
}

// --- Standalone business logic functions ---

// recordCombinerError records an error in the ErrorJournal if available.
func recordCombinerError(journal *ErrorJournal, distID, sender, messageType, errMsg, qname string) {
	if journal == nil {
		return
	}
	journal.Record(ErrorJournalEntry{
		DistributionID: distID,
		Sender:         sender,
		MessageType:    messageType,
		ErrorMsg:       errMsg,
		QNAME:          qname,
		Timestamp:      time.Now(),
	})
}

// ParseAgentMsgNotify parses a sync payload into a CombinerSyncRequest.
// Expects the standard AgentMsgPost format (MyIdentity/Zone/Records).
func ParseAgentMsgNotify(data []byte, distributionID string) (*CombinerSyncRequest, error) {
	var msg struct {
		MyIdentity string              `json:"MyIdentity"`
		Zone       string              `json:"Zone"`
		Records    map[string][]string `json:"Records"`
		Time       time.Time           `json:"Time"`
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	if msg.MyIdentity == "" {
		return nil, fmt.Errorf("missing MyIdentity")
	}
	if msg.Zone == "" {
		return nil, fmt.Errorf("missing Zone")
	}

	records := msg.Records
	if records == nil {
		records = make(map[string][]string)
	}

	rrCount := 0
	for _, rrs := range records {
		rrCount += len(rrs)
	}
	log.Printf("ParseAgentMsgNotify: Parsed sync from %q for zone %q (%d RRs, %d owners)",
		msg.MyIdentity, msg.Zone, rrCount, len(records))

	return &CombinerSyncRequest{
		SenderID:       msg.MyIdentity,
		Zone:           msg.Zone,
		Records:        records,
		DistributionID: distributionID,
		Timestamp:      msg.Time,
	}, nil
}

// CombinerProcessUpdate handles a sync request and returns a response.
// This is the main entry point for CHUNK-based and API-based updates to the combiner.
// Both transports use the same data structure (map[string][]string) for transport neutrality.
//
// RR class determines the operation:
//   - ClassINET: add/update the RR (existing behavior)
//   - ClassNONE: delete this specific RR from the agent's contributions
//   - ClassANY:  delete the entire RRset for the RR's type from the agent's contributions
func CombinerProcessUpdate(req *CombinerSyncRequest, protectedNamespaces []string) *CombinerSyncResponse {
	// Count total records for logging
	totalRecords := 0
	for _, rrs := range req.Records {
		totalRecords += len(rrs)
	}
	log.Printf("CombinerProcessUpdate: Processing sync from %q for zone %q (%d owners, %d records)",
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

			// Checkpoint 5: Content-based policy checks
			if reason := checkContentPolicy(rr, protectedNamespaces); reason != "" {
				rejectedItems = append(rejectedItems, RejectedItem{
					Record: rrStr,
					Reason: reason,
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
			log.Printf("CombinerProcessUpdate: Error removing records: %v", err)
			// Don't fail the whole request — report partial success
		}
		removedRecords = append(removedRecords, removed...)
	}

	// Apply ClassANY deletes (entire RRset removal by type)
	for owner, rrtypes := range bulkDeleteOwner {
		for _, rrtype := range rrtypes {
			removed, err := zd.RemoveCombinerDataByRRtype(req.SenderID, owner, rrtype)
			if err != nil {
				log.Printf("CombinerProcessUpdate: Error removing RRset %s for owner %s: %v",
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

	log.Printf("CombinerProcessUpdate: %s - %s", resp.Status, resp.Message)

	if totalActions > 0 {
		bumperResp, err := zd.BumpSerialOnly()
		if err != nil {
			log.Printf("CombinerProcessUpdate: BumpSerialOnly failed for zone %q: %v", req.Zone, err)
		} else {
			log.Printf("CombinerProcessUpdate: BumpSerial %s: %d -> %d",
				req.Zone, bumperResp.OldSerial, bumperResp.NewSerial)
		}
	}

	return resp
}

// NewCombinerSyncHandler creates a transport.MessageHandlerFunc for combiner UPDATE processing.
// The handler returns an immediate "pending" ACK in the DNS response and routes the update
// to MsgQs for async processing by CombinerMsgHandler. The actual CombinerProcessUpdate()
// runs asynchronously, and the detailed confirmation is sent back as a separate CONFIRM NOTIFY.
func NewCombinerSyncHandler() transport.MessageHandlerFunc {
	return func(ctx *transport.MessageContext) error {
		log.Printf("CombinerHandleUpdate: Received update from %s (distrib=%s), sending pending ACK",
			ctx.PeerID, ctx.DistributionID)

		// Build pending ACK for DNS response
		ack := struct {
			Type           string `json:"type"`
			Status         string `json:"status"`
			DistributionID string `json:"distribution_id"`
			Message        string `json:"message"`
			Timestamp      int64  `json:"timestamp"`
		}{
			Type:           "confirm",
			Status:         "pending",
			DistributionID: ctx.DistributionID,
			Message:        "update received, processing asynchronously",
			Timestamp:      time.Now().Unix(),
		}
		ackPayload, err := json.Marshal(ack)
		if err != nil {
			return fmt.Errorf("failed to marshal pending ack: %w", err)
		}
		ctx.Data["response"] = ackPayload

		// Route to MsgQs for async processing via RouteToMsgHandler middleware.
		// incoming_message is already set by ChunkNotifyHandler.parsePayload before the router runs.
		ctx.Data["message_type"] = "update"

		return nil
	}
}

// --- Registration functions ---

// RegisterCombinerChunkHandler registers the combiner's CHUNK handler using ChunkNotifyHandler.
// Creates a ChunkNotifyHandler with combiner-appropriate settings and registers it as a
// NotifyHandlerFunc. Returns CombinerState for error journal access and in-process updates.
func RegisterCombinerChunkHandler(localID string, secureWrapper *transport.SecurePayloadWrapper) (*CombinerState, error) {
	state := &CombinerState{
		ErrorJournal: NewErrorJournal(1000, 24*time.Hour),
	}

	handler := &transport.ChunkNotifyHandler{
		LocalID:       localID,
		Router:        nil, // Set after router initialization
		SecureWrapper: secureWrapper,
		IncomingChan:  make(chan *transport.IncomingMessage, 100),
	}

	if secureWrapper != nil && secureWrapper.IsEnabled() {
		log.Printf("RegisterCombinerChunkHandler: Registering CHUNK handler for %s with crypto enabled", localID)
	} else {
		log.Printf("RegisterCombinerChunkHandler: Registering CHUNK handler for %s", localID)
	}

	// Wire FetchChunkQuery for chunk_mode=query (combiner has no DNSTransport)
	handler.FetchChunkQuery = fetchChunkPayloadViaQuery

	err := RegisterNotifyHandler(core.TypeCHUNK, func(ctx context.Context, req *DnsNotifyRequest) error {
		return handler.RouteViaRouter(ctx, req.Qname, req.Msg, req.ResponseWriter)
	})
	if err != nil {
		return nil, err
	}

	// Store handler reference in state so main_initfuncs can set Router after initialization
	state.chunkHandler = handler

	return state, nil
}

// RegisterSignerChunkHandler registers a CHUNK NOTIFY handler for the signer (tdns-auth).
// Uses ChunkNotifyHandler — the signer only routes messages through the signer router
// which handles ping and KEYSTATE.
func RegisterSignerChunkHandler(localID string, secureWrapper *transport.SecurePayloadWrapper) (*CombinerState, error) {
	state := &CombinerState{
		ErrorJournal: NewErrorJournal(100, 24*time.Hour),
	}

	handler := &transport.ChunkNotifyHandler{
		LocalID:       localID,
		Router:        nil, // Set after router initialization via SetRouter()
		SecureWrapper: secureWrapper,
		IncomingChan:  make(chan *transport.IncomingMessage, 100),
	}

	// Wire FetchChunkQuery for chunk_mode=query (signer has no DNSTransport)
	handler.FetchChunkQuery = fetchChunkPayloadViaQuery

	if secureWrapper != nil && secureWrapper.IsEnabled() {
		log.Printf("RegisterSignerChunkHandler: Registering CHUNK handler for %s with crypto enabled", localID)
	} else {
		log.Printf("RegisterSignerChunkHandler: XX Registering CHUNK handler for %s", localID)
	}
	err := RegisterNotifyHandler(core.TypeCHUNK, func(ctx context.Context, req *DnsNotifyRequest) error {
		return handler.RouteViaRouter(ctx, req.Qname, req.Msg, req.ResponseWriter)
	})
	if err != nil {
		return nil, err
	}

	state.chunkHandler = handler

	return state, nil
}

// SetRouter sets the router on the underlying ChunkNotifyHandler.
// Called from main_initfuncs.go after the router is initialized.
func (cs *CombinerState) SetRouter(router *transport.DNSMessageRouter) {
	if cs.chunkHandler != nil {
		cs.chunkHandler.Router = router
	}
}

// SetSecureWrapper sets the secure wrapper on the underlying ChunkNotifyHandler.
func (cs *CombinerState) SetSecureWrapper(sw *transport.SecurePayloadWrapper) {
	if cs.chunkHandler != nil {
		cs.chunkHandler.SecureWrapper = sw
	}
}

// SetGetPeerAddress sets the GetPeerAddress callback on the underlying ChunkNotifyHandler.
func (cs *CombinerState) SetGetPeerAddress(fn func(senderID string) (address string, ok bool)) {
	if cs.chunkHandler != nil {
		cs.chunkHandler.GetPeerAddress = fn
	}
}

// fetchChunkPayloadViaQuery queries the given DNS server for qname CHUNK and returns the first CHUNK RR's Data.
// Used as the FetchChunkQuery callback for combiner/signer ChunkNotifyHandlers.
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

// --- Helper functions ---

// SendToCombiner is a helper function that sends a sync request to the combiner
// and waits for a response. This is called from SynchedDataEngine.
// For in-process communication, this calls CombinerProcessUpdate directly.
func SendToCombiner(state *CombinerState, req *CombinerSyncRequest) *CombinerSyncResponse {
	if state == nil {
		log.Printf("SendToCombiner: state is nil, cannot send update")
		return &CombinerSyncResponse{
			DistributionID: req.DistributionID,
			Zone:           req.Zone,
			Status:         "error",
			Message:        "combiner state not initialized",
			Timestamp:      time.Now(),
		}
	}

	return state.ProcessUpdate(req)
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

// --- Policy check functions ---

// checkContentPolicy applies content-based policy checks to a parsed RR.
// Returns empty string if accepted, or a rejection reason.
func checkContentPolicy(rr dns.RR, protectedNamespaces []string) string {
	if rr.Header().Rrtype == dns.TypeNS && rr.Header().Class == dns.ClassINET {
		return checkNSNamespacePolicy(rr, protectedNamespaces)
	}
	return ""
}

// checkNSNamespacePolicy rejects NS records whose targets fall within any of
// our protected namespaces. This prevents remote agents from claiming
// nameservers inside our provider's domains.
//
// Example: if protected-namespaces contains "echo.dnslab.", then an NS record
// targeting "ns7.echo.dnslab." from any remote agent is rejected. But
// "ns12.cooldns.com." from the same agent is accepted (not our namespace).
func checkNSNamespacePolicy(rr dns.RR, protectedNamespaces []string) string {
	if len(protectedNamespaces) == 0 {
		return ""
	}

	nsRR, ok := rr.(*dns.NS)
	if !ok {
		return ""
	}

	target := strings.ToLower(nsRR.Ns)
	for _, ns := range protectedNamespaces {
		ns = strings.ToLower(ns)
		if strings.HasSuffix(target, "."+ns) || target == ns {
			return fmt.Sprintf("NS target %s intrudes on protected namespace %s",
				nsRR.Ns, ns)
		}
	}
	return ""
}
