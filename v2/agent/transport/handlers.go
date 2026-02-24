/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Refactored message handlers using the DNS message router.
 * Replaces the monolithic chunk_notify_handler.go with modular handlers.
 */

package transport

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
)

// HandleConfirmation processes confirmation messages.
// Routes the confirmation to the transport's reliable message queue and
// forwards per-RR detail to the SynchedDataEngine via OnConfirmationReceived.
func HandleConfirmation(ctx *MessageContext) error {
	log.Printf("HandleConfirmation: Processing confirmation from %s (distrib=%s)",
		ctx.PeerID, ctx.DistributionID)

	// Parse the confirmation message
	var confirm DnsConfirmPayload
	if err := json.Unmarshal(ctx.ChunkPayload, &confirm); err != nil {
		return fmt.Errorf("failed to parse confirmation: %w", err)
	}

	status := parseConfirmStatus(confirm.Status)

	// Forward to transport's reliable message queue (marks distribution as confirmed)
	if transport, ok := ctx.Data["transport"].(*DNSTransport); ok && transport != nil {
		transport.HandleIncomingConfirmation(&IncomingConfirmation{
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

	// Forward confirmation detail to SynchedDataEngine
	type confirmCallback = func(distributionID string, senderID string, status ConfirmStatus,
		zone string, applied []string, removed []string, rejected []RejectedItemDTO, truncated bool)
	if cb, ok := ctx.Data["on_confirmation_received"].(confirmCallback); ok && cb != nil && confirm.DistributionID != "" {
		cb(confirm.DistributionID, confirm.SenderID, status,
			confirm.Zone, confirm.AppliedRecords, confirm.RemovedRecords, confirm.RejectedItems, confirm.Truncated)
	}

	log.Printf("HandleConfirmation: Confirmation processed from %s (status=%s)", ctx.PeerID, confirm.Status)
	return nil
}

// HandlePing processes ping messages and sends immediate response.
func HandlePing(ctx *MessageContext) error {
	log.Printf("HandlePing: Processing ping from %s (distrib=%s)",
		ctx.PeerID, ctx.DistributionID)

	// Get the pre-parsed message from context (set by RouteViaRouter)
	incomingMsg, ok := ctx.Data["incoming_message"].(*IncomingMessage)
	if ok {
		// Use pre-parsed message for type check
		if incomingMsg.Type != "ping" {
			return fmt.Errorf("invalid message type for ping handler: %s", incomingMsg.Type)
		}
	}

	// Parse the ping message using DnsPingPayload (handles both standard and legacy field names)
	var ping DnsPingPayload
	if err := json.Unmarshal(ctx.ChunkPayload, &ping); err != nil {
		return fmt.Errorf("failed to parse ping: %w", err)
	}

	if !ok && ping.Type != "ping" && ping.MessageType != "ping" {
		return fmt.Errorf("invalid message type for ping handler: type=%s MessageType=%s", ping.Type, ping.MessageType)
	}

	if ping.Nonce == "" {
		return fmt.Errorf("ping has empty nonce")
	}

	// Get local identity from context (set by RouteViaRouter)
	localID, _ := ctx.Data["local_id"].(string)

	// Create confirmation response matching DnsPingConfirmPayload format
	confirmation := &DnsPingConfirmPayload{
		Type:           "ping_confirm",
		SenderID:       localID,
		Nonce:          ping.Nonce,
		DistributionID: ctx.DistributionID,
		Status:         "ok",
		Timestamp:      time.Now().Unix(),
	}

	confirmPayload, err := json.Marshal(confirmation)
	if err != nil {
		return fmt.Errorf("failed to marshal ping confirmation: %w", err)
	}

	// Store confirmation in context for response middleware
	ctx.Data["ping_response"] = confirmPayload
	ctx.Data["ping_nonce"] = ping.Nonce

	log.Printf("HandlePing: Ping processed from %s, nonce=%s", ctx.PeerID, ping.Nonce)
	return nil
}

// HandleHello processes hello messages for peer introduction.
func HandleHello(ctx *MessageContext) error {
	log.Printf("HandleHello: Processing hello from %s (distrib=%s)",
		ctx.PeerID, ctx.DistributionID)

	// Get the pre-parsed message from context (set by agent RouteViaRouter)
	helloMsg, ok := ctx.Data["incoming_message"].(*IncomingMessage)
	if !ok {
		// Not pre-parsed: parse from raw payload (handles both standard and legacy field names)
		helloMsg = parseIncomingMessage(ctx.ChunkPayload)
		if helloMsg == nil {
			return fmt.Errorf("failed to parse hello payload")
		}
	}

	if helloMsg.Type != "hello" {
		return fmt.Errorf("invalid message type for hello handler: %s", helloMsg.Type)
	}

	// Store for routing to hsyncengine
	ctx.Data["message_type"] = "hello"
	ctx.Data["incoming_message"] = helloMsg

	log.Printf("HandleHello: Hello processed from %s", ctx.PeerID)
	return nil
}

// HandleBeat processes heartbeat messages.
// Works for both agent and combiner — the confirm response is always constructed,
// and the RouteToHsyncEngine middleware (agent only) picks up the message for further processing.
func HandleBeat(ctx *MessageContext) error {
	log.Printf("HandleBeat: Processing beat from %s (distrib=%s)",
		ctx.PeerID, ctx.DistributionID)

	// Get the pre-parsed message from context (set by agent RouteViaRouter)
	beatMsg, ok := ctx.Data["incoming_message"].(*IncomingMessage)
	if !ok {
		// Not pre-parsed: parse from raw payload (handles both standard and legacy field names)
		beatMsg = parseIncomingMessage(ctx.ChunkPayload)
		if beatMsg == nil {
			return fmt.Errorf("failed to parse beat payload")
		}
	}

	if beatMsg.Type != "beat" {
		return fmt.Errorf("invalid message type for beat handler: %s", beatMsg.Type)
	}

	// Store for routing to hsyncengine (agent middleware picks this up; combiner ignores it)
	ctx.Data["message_type"] = "beat"
	ctx.Data["incoming_message"] = beatMsg

	// Construct confirm response (used by both agent and combiner)
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
		log.Printf("HandleBeat: Failed to marshal beat confirm: %v", err)
	} else {
		ctx.Data["sync_response"] = payloadBytes
	}

	log.Printf("HandleBeat: Beat processed from %s", ctx.PeerID)
	return nil
}

// HandleSync processes sync messages and sends acknowledgment.
func HandleSync(ctx *MessageContext) error {
	log.Printf("HandleSync: Processing sync from %s (distrib=%s)",
		ctx.PeerID, ctx.DistributionID)

	// Check if sender has zero shared zones (LEGACY state)
	// LEGACY agents should not send sync messages (only beats)
	if ctx.Peer != nil && len(ctx.Peer.GetSharedZones()) == 0 {
		// Agent is LEGACY (zero shared zones) - reject sync
		log.Printf("HandleSync: Rejecting sync from LEGACY agent %s (zero shared zones)", ctx.PeerID)
		return fmt.Errorf("LEGACY agent %s cannot send sync messages (zero shared zones)", ctx.PeerID)
	}

	// Get the pre-parsed message from context (set by agent RouteViaRouter)
	syncMsg, ok := ctx.Data["incoming_message"].(*IncomingMessage)
	if !ok {
		syncMsg = parseIncomingMessage(ctx.ChunkPayload)
		if syncMsg == nil {
			return fmt.Errorf("failed to parse sync payload")
		}
	}

	if syncMsg.Type != "sync" {
		return fmt.Errorf("invalid message type for sync handler: %s", syncMsg.Type)
	}

	// Store for routing to hsyncengine
	ctx.Data["message_type"] = "sync"
	ctx.Data["incoming_message"] = syncMsg

	// Create sync acknowledgment response — format must match extractConfirmFromResponse
	ack := map[string]interface{}{
		"type":            "confirm",
		"status":          "ok",
		"distribution_id": ctx.DistributionID,
		"message":         fmt.Sprintf("sync received from %s", ctx.PeerID),
	}

	ackPayload, err := json.Marshal(ack)
	if err != nil {
		log.Printf("HandleSync: Failed to marshal sync acknowledgment: %v", err)
		// Don't return error - ack failure shouldn't prevent sync processing
	} else {
		// Store acknowledgment in context for response middleware
		ctx.Data["sync_response"] = ackPayload
		log.Printf("HandleSync: Sync acknowledgment prepared for %s (distrib=%s)", ctx.PeerID, ctx.DistributionID)
	}

	log.Printf("HandleSync: Sync processed from %s", ctx.PeerID)
	return nil
}

// HandleRfi processes RFI (Request For Information) messages.
func HandleRfi(ctx *MessageContext) error {
	log.Printf("HandleRfi: Processing RFI from %s (distrib=%s)",
		ctx.PeerID, ctx.DistributionID)

	// Get the pre-parsed message from context (set by agent RouteViaRouter)
	rfiMsg, ok := ctx.Data["incoming_message"].(*IncomingMessage)
	if !ok {
		rfiMsg = parseIncomingMessage(ctx.ChunkPayload)
		if rfiMsg == nil {
			return fmt.Errorf("failed to parse rfi payload")
		}
	}

	if rfiMsg.Type != "rfi" {
		return fmt.Errorf("invalid message type for rfi handler: %s", rfiMsg.Type)
	}

	// Store for routing to hsyncengine
	ctx.Data["message_type"] = "rfi"
	ctx.Data["incoming_message"] = rfiMsg

	// Create RFI acknowledgment response — format must match extractConfirmFromResponse
	ack := map[string]interface{}{
		"type":            "confirm",
		"status":          "ok",
		"distribution_id": ctx.DistributionID,
		"message":         fmt.Sprintf("rfi received from %s", ctx.PeerID),
	}

	ackPayload, err := json.Marshal(ack)
	if err != nil {
		log.Printf("HandleRfi: Failed to marshal rfi acknowledgment: %v", err)
	} else {
		ctx.Data["sync_response"] = ackPayload
		log.Printf("HandleRfi: RFI acknowledgment prepared for %s (distrib=%s)", ctx.PeerID, ctx.DistributionID)
	}

	log.Printf("HandleRfi: RFI processed from %s", ctx.PeerID)
	return nil
}

// HandleKeystate processes KEYSTATE messages for key lifecycle signaling.
// Used for agent↔signer communication about DNSKEY propagation status.
// Signals: propagated, rejected, removed (agent→signer), published, retired (signer→agent).
func HandleKeystate(ctx *MessageContext) error {
	log.Printf("HandleKeystate: Processing keystate from %s (distrib=%s)",
		ctx.PeerID, ctx.DistributionID)

	// Parse the keystate message
	var keystate DnsKeystatePayload
	if err := json.Unmarshal(ctx.ChunkPayload, &keystate); err != nil {
		return fmt.Errorf("failed to parse keystate: %w", err)
	}

	// Validate message type
	msgType := keystate.MessageType
	if msgType == "" {
		msgType = keystate.Type
	}
	if msgType != "keystate" {
		return fmt.Errorf("invalid message type for keystate handler: %s", msgType)
	}

	// Validate signal
	switch keystate.Signal {
	case "propagated", "rejected", "removed", "published", "retired":
		// valid signals
	default:
		return fmt.Errorf("unknown keystate signal: %q", keystate.Signal)
	}

	if keystate.Zone == "" {
		return fmt.Errorf("keystate message missing zone")
	}
	if keystate.KeyTag == 0 {
		return fmt.Errorf("keystate message missing key tag")
	}

	// Store for processing by the recipient (signer or agent)
	ctx.Data["message_type"] = "keystate"
	ctx.Data["incoming_message"] = &IncomingMessage{
		Type:     "keystate",
		SenderID: keystate.GetSenderID(),
		Zone:     keystate.Zone,
		Payload:  ctx.ChunkPayload,
	}

	// Create confirmation response using standard "confirm" type so sendNotifyWithPayload
	// can extract it via extractConfirmFromResponse
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
		Message:        fmt.Sprintf("keystate %s received for key %d in %s", keystate.Signal, keystate.KeyTag, keystate.Zone),
		Timestamp:      time.Now().Unix(),
	}

	payloadBytes, err := json.Marshal(confirmPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal keystate confirmation: %w", err)
	}

	// Store confirmation in context for response middleware
	ctx.Data["sync_response"] = payloadBytes

	log.Printf("HandleKeystate: keystate %s processed from %s for key %d in zone %s",
		keystate.Signal, ctx.PeerID, keystate.KeyTag, keystate.Zone)
	return nil
}

// HandleRelocate processes relocate messages for DDoS mitigation.
func HandleRelocate(ctx *MessageContext) error {
	log.Printf("HandleRelocate: Processing relocate from %s (distrib=%s)",
		ctx.PeerID, ctx.DistributionID)

	// Get the pre-parsed message from context (set by agent RouteViaRouter)
	relocateMsg, ok := ctx.Data["incoming_message"].(*IncomingMessage)
	if !ok {
		relocateMsg = parseIncomingMessage(ctx.ChunkPayload)
		if relocateMsg == nil {
			return fmt.Errorf("failed to parse relocate payload")
		}
	}

	if relocateMsg.Type != "relocate" {
		return fmt.Errorf("invalid message type for relocate handler: %s", relocateMsg.Type)
	}

	// Store for routing to hsyncengine
	ctx.Data["message_type"] = "relocate"
	ctx.Data["incoming_message"] = relocateMsg

	log.Printf("HandleRelocate: Relocate processed from %s", ctx.PeerID)
	return nil
}

// parseIncomingMessage parses a raw JSON payload into an IncomingMessage.
// Handles both standard format (MessageType/MyIdentity) and legacy format (type/sender_id).
// Returns nil if parsing fails.
func parseIncomingMessage(payload []byte) *IncomingMessage {
	var fields struct {
		MessageType string `json:"MessageType"`
		Type        string `json:"type"`
		MyIdentity  string `json:"MyIdentity"`
		SenderID    string `json:"sender_id"`
		Zone        string `json:"Zone"`
		LegacyZone  string `json:"zone"`
	}
	if err := json.Unmarshal(payload, &fields); err != nil {
		return nil
	}
	msgType := fields.MessageType
	if msgType == "" {
		msgType = fields.Type
	}
	senderID := fields.MyIdentity
	if senderID == "" {
		senderID = fields.SenderID
	}
	zone := fields.Zone
	if zone == "" {
		zone = fields.LegacyZone
	}
	return &IncomingMessage{
		Type:     msgType,
		SenderID: senderID,
		Zone:     zone,
		Payload:  payload,
	}
}

// SendResponseMiddleware sends the DNS response after all handlers complete.
// This middleware should be the outermost one (last to wrap, first to execute on return).
func SendResponseMiddleware(w dns.ResponseWriter, msg *dns.Msg) MiddlewareFunc {
	return func(ctx *MessageContext, next MessageHandlerFunc) error {
		// Execute the handler chain
		err := next(ctx)

		// Determine response code
		rcode := dns.RcodeSuccess
		if err != nil {
			log.Printf("SendResponseMiddleware: Handler error: %v", err)
			rcode = dns.RcodeServerFailure
		}

		// Check for ping response
		if pingResponse, ok := ctx.Data["ping_response"]; ok {
			if payload, ok := pingResponse.([]byte); ok {
				// Send response with CHUNK payload
				return sendChunkResponse(w, msg, payload, rcode)
			}
		}

		// Check for sync response
		if syncResponse, ok := ctx.Data["sync_response"]; ok {
			if payload, ok := syncResponse.([]byte); ok {
				// Send response with CHUNK payload
				return sendChunkResponse(w, msg, payload, rcode)
			}
		}

		// Build a generic EDNS0 confirmation for all other message types (hello, beat, etc).
		// The sender requires an EDNS0 CHUNK confirmation to distinguish "message received
		// and processed" from a bare DNS ACK (which could come from any DNS server).
		if rcode == dns.RcodeSuccess {
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
				Message:        "received",
				Timestamp:      time.Now().Unix(),
			}
			payloadBytes, marshalErr := json.Marshal(confirmPayload)
			if marshalErr == nil {
				return sendChunkResponse(w, msg, payloadBytes, rcode)
			}
		}
		return sendStandardResponse(w, msg, rcode)
	}
}

// sendChunkResponse sends a DNS response with CHUNK payload in EDNS0.
func sendChunkResponse(w dns.ResponseWriter, req *dns.Msg, payload []byte, rcode int) error {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = rcode

	// Add EDNS0 with CHUNK option
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)

	// Create CHUNK option (code 65004)
	chunkOpt := &dns.EDNS0_LOCAL{
		Code: 65004,
		Data: payload,
	}
	opt.Option = append(opt.Option, chunkOpt)
	resp.Extra = append(resp.Extra, opt)

	return w.WriteMsg(resp)
}

// sendStandardResponse sends a standard DNS response without CHUNK.
func sendStandardResponse(w dns.ResponseWriter, req *dns.Msg, rcode int) error {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = rcode
	return w.WriteMsg(resp)
}

// RouteToHsyncEngine is a middleware that routes processed messages to hsyncengine.
func RouteToHsyncEngine(incomingChan chan<- *IncomingMessage) MiddlewareFunc {
	return func(ctx *MessageContext, next MessageHandlerFunc) error {
		// Execute handler
		err := next(ctx)
		if err != nil {
			return err
		}

		// Check if message should be routed to hsyncengine
		if msgType, ok := ctx.Data["message_type"]; ok {
			if incomingMsg, ok := ctx.Data["incoming_message"].(*IncomingMessage); ok {
				select {
				case incomingChan <- incomingMsg:
					log.Printf("RouteToHsyncEngine: Routed %s message from %s to hsyncengine",
						msgType, ctx.PeerID)
				default:
					log.Printf("RouteToHsyncEngine: Incoming channel full, dropping %s message", msgType)
					return fmt.Errorf("hsyncengine channel full")
				}
			}
		}

		return nil
	}
}
