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
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// HandleConfirmation processes confirmation messages.
// Routes the confirmation to the transport's reliable message queue and
// forwards per-RR detail to the SynchedDataEngine via OnConfirmationReceived.
func HandleConfirmation(ctx *MessageContext) error {
	lgTransport().Debug("processing confirmation", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

	// Parse the confirmation message.
	// Size bounded: ctx.ChunkPayload originates from a DNS message (max ~65535 bytes over TCP).
	var confirm DnsConfirmPayload
	if err := json.Unmarshal(ctx.ChunkPayload, &confirm); err != nil {
		return fmt.Errorf("failed to parse confirmation: %w", err)
	}

	status := parseConfirmStatus(confirm.Status)

	// Forward to transport's reliable message queue (marks distribution as confirmed).
	// Two-value type assertion: ok is false if "transport" key is missing or wrong type.
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
			Nonce:          confirm.Nonce,
		})
	}

	// Forward confirmation detail to SynchedDataEngine
	type confirmCallback = func(distributionID string, senderID string, status ConfirmStatus,
		zone string, applied []string, removed []string, rejected []RejectedItemDTO, truncated bool, nonce string)
	if cb, ok := ctx.Data["on_confirmation_received"].(confirmCallback); ok && cb != nil && confirm.DistributionID != "" {
		cb(confirm.DistributionID, confirm.SenderID, status,
			confirm.Zone, confirm.AppliedRecords, confirm.RemovedRecords, confirm.RejectedItems, confirm.Truncated, confirm.Nonce)
	}

	lgTransport().Debug("confirmation processed", "peer", ctx.PeerID, "status", confirm.Status)
	return nil
}

// HandlePing processes ping messages and sends immediate response.
func HandlePing(ctx *MessageContext) error {
	lgTransport().Debug("processing ping", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

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

	// Get local identity from context (set by RouteViaRouter).
	// Two-value form: localID defaults to "" if key missing or wrong type.
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
	ctx.Data["response"] = confirmPayload
	ctx.Data["ping_nonce"] = ping.Nonce

	// Route to MsgQs for peer liveness tracking (response already sent synchronously)
	ctx.Data["message_type"] = "ping"

	lgTransport().Debug("ping processed", "peer", ctx.PeerID, "nonce", ping.Nonce)
	return nil
}

// HandleHello processes hello messages for peer introduction.
func HandleHello(ctx *MessageContext) error {
	lgTransport().Debug("processing hello", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

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

	lgTransport().Debug("hello processed", "peer", ctx.PeerID)
	return nil
}

// HandleBeat processes heartbeat messages.
// Works for both agent and combiner — the confirm response is always constructed,
// and the RouteToMsgHandler middleware (agent only) picks up the message for further processing.
func HandleBeat(ctx *MessageContext) error {
	lgTransport().Debug("processing beat", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

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
		lgTransport().Error("failed to marshal beat confirm", "err", err)
	} else {
		ctx.Data["response"] = payloadBytes
	}

	lgTransport().Debug("beat processed", "peer", ctx.PeerID)
	return nil
}

// HandleSync processes sync messages and sends acknowledgment.
func HandleSync(ctx *MessageContext) error {
	lgTransport().Debug("processing sync", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

	// Check if sender has zero shared zones (LEGACY state)
	// LEGACY agents should not send sync messages (only beats)
	if ctx.Peer != nil && len(ctx.Peer.GetSharedZones()) == 0 {
		// Agent is LEGACY (zero shared zones) - reject sync with informative error payload
		lgTransport().Warn("rejecting sync from LEGACY agent (zero shared zones)", "peer", ctx.PeerID)
		errorPayload := struct {
			Type           string `json:"type"`
			DistributionID string `json:"distribution_id"`
			Status         string `json:"status"`
			Message        string `json:"message"`
			Timestamp      int64  `json:"timestamp"`
		}{
			Type:           "error",
			DistributionID: ctx.DistributionID,
			Status:         "rejected",
			Message:        fmt.Sprintf("LEGACY agent %s cannot send sync messages (zero shared zones); re-introduce via HELLO with updated HSYNC zones", ctx.PeerID),
			Timestamp:      time.Now().Unix(),
		}
		payloadBytes, err := json.Marshal(errorPayload)
		if err == nil {
			ctx.Data["response"] = payloadBytes
			ctx.Data["response_rcode"] = dns.RcodeRefused
		}
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
		lgTransport().Error("failed to marshal sync acknowledgment", "err", err)
		// Don't return error - ack failure shouldn't prevent sync processing
	} else {
		// Store acknowledgment in context for response middleware
		ctx.Data["response"] = ackPayload
		lgTransport().Debug("sync acknowledgment prepared", "peer", ctx.PeerID, "distrib", ctx.DistributionID)
	}

	lgTransport().Debug("sync processed", "peer", ctx.PeerID)
	return nil
}

// HandleRfi processes RFI (Request For Information) messages.
func HandleRfi(ctx *MessageContext) error {
	lgTransport().Debug("processing RFI", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

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
		lgTransport().Error("failed to marshal rfi acknowledgment", "err", err)
	} else {
		ctx.Data["response"] = ackPayload
		lgTransport().Debug("RFI acknowledgment prepared", "peer", ctx.PeerID, "distrib", ctx.DistributionID)
	}

	lgTransport().Debug("RFI processed", "peer", ctx.PeerID)
	return nil
}

// HandleKeystate processes KEYSTATE messages for key lifecycle signaling.
// Used for agent↔signer communication about DNSKEY propagation status.
// Signals: propagated, rejected, removed (agent→signer), published, retired (signer→agent).
func HandleKeystate(ctx *MessageContext) error {
	lgTransport().Debug("processing keystate", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

	// Parse the keystate message.
	// Size bounded: ctx.ChunkPayload originates from a DNS message (max ~65535 bytes over TCP).
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
		// per-key signals
	case "inventory":
		// full inventory signal — KeyInventory carries the data, KeyTag not required
	default:
		return fmt.Errorf("unknown keystate signal: %q", keystate.Signal)
	}

	if keystate.Zone == "" {
		return fmt.Errorf("keystate message missing zone")
	}
	if keystate.Signal == "inventory" {
		if len(keystate.KeyInventory) == 0 {
			return fmt.Errorf("keystate inventory message has empty key inventory")
		}
	} else if keystate.KeyTag == 0 {
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
		Message:        fmt.Sprintf("keystate %s received for zone %s", keystate.Signal, keystate.Zone),
		Timestamp:      time.Now().Unix(),
	}

	payloadBytes, err := json.Marshal(confirmPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal keystate confirmation: %w", err)
	}

	// Store confirmation in context for response middleware
	ctx.Data["response"] = payloadBytes

	if keystate.Signal == "inventory" {
		lgTransport().Info("keystate inventory received", "peer", ctx.PeerID, "zone", keystate.Zone, "keys", len(keystate.KeyInventory))
	} else {
		lgTransport().Info("keystate processed", "signal", keystate.Signal, "peer", ctx.PeerID, "keytag", keystate.KeyTag, "zone", keystate.Zone)
	}
	return nil
}

// HandleEdits processes EDITS messages carrying an agent's current contributions
// from the combiner. Modeled on HandleKeystate.
// Sent by the combiner in response to an RFI EDITS request.
func HandleEdits(ctx *MessageContext) error {
	lgTransport().Debug("processing edits", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

	// Parse the edits message.
	// Size bounded: ctx.ChunkPayload originates from a DNS message (max ~65535 bytes over TCP).
	var edits DnsEditsPayload
	if err := json.Unmarshal(ctx.ChunkPayload, &edits); err != nil {
		return fmt.Errorf("failed to parse edits: %w", err)
	}

	// Validate message type
	msgType := edits.MessageType
	if msgType == "" {
		msgType = edits.Type
	}
	if msgType != "edits" {
		return fmt.Errorf("invalid message type for edits handler: %s", msgType)
	}

	if edits.Zone == "" {
		return fmt.Errorf("edits message missing zone")
	}

	// Store for processing by the agent
	ctx.Data["message_type"] = "edits"
	ctx.Data["incoming_message"] = &IncomingMessage{
		Type:     "edits",
		SenderID: edits.GetSenderID(),
		Zone:     edits.Zone,
		Payload:  ctx.ChunkPayload,
	}

	// Create confirmation response using standard "confirm" type
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
		Message:        fmt.Sprintf("edits received for zone %s (%d owners)", edits.Zone, len(edits.Records)),
		Timestamp:      time.Now().Unix(),
	}

	payloadBytes, err := json.Marshal(confirmPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal edits confirmation: %w", err)
	}

	ctx.Data["response"] = payloadBytes

	lgTransport().Info("edits received", "peer", ctx.PeerID, "zone", edits.Zone, "owners", len(edits.Records))
	return nil
}

// HandleRelocate processes relocate messages for DDoS mitigation.
func HandleRelocate(ctx *MessageContext) error {
	lgTransport().Debug("processing relocate", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

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

	lgTransport().Debug("relocate processed", "peer", ctx.PeerID)
	return nil
}

// parseIncomingMessage parses a raw JSON payload into an IncomingMessage.
// Handles both standard format (MessageType/OriginatorID) and legacy format (type/sender_id).
// Returns nil if parsing fails.
func parseIncomingMessage(payload []byte) *IncomingMessage {
	var fields struct {
		MessageType  string `json:"MessageType"`
		Type         string `json:"type"`
		OriginatorID string `json:"OriginatorID"` // Sync/update messages
		MyIdentity   string `json:"MyIdentity"`   // Hello/beat/ping messages
		SenderID     string `json:"sender_id"`
		Zone         string `json:"Zone"`
		LegacyZone   string `json:"zone"`
	}
	if err := json.Unmarshal(payload, &fields); err != nil {
		return nil
	}
	msgType := fields.MessageType
	if msgType == "" {
		msgType = fields.Type
	}
	senderID := fields.OriginatorID
	if senderID == "" {
		senderID = fields.MyIdentity
	}
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

// DefaultUnsupportedHandler returns a handler for message types that have no
// registered handler. Instead of returning an error (which causes SERVFAIL),
// it sends a clean REFUSED response with an error payload explaining that the
// message type is not supported.
func DefaultUnsupportedHandler(ctx *MessageContext) error {
	msgType := "unknown"
	if mt, ok := ctx.Data["unhandled_message_type"].(string); ok {
		msgType = mt
	}

	lgTransport().Warn("unsupported message type", "type", msgType, "peer", ctx.PeerID)

	errorPayload := struct {
		Type           string `json:"type"`
		DistributionID string `json:"distribution_id"`
		Status         string `json:"status"`
		Message        string `json:"message"`
		Timestamp      int64  `json:"timestamp"`
	}{
		Type:           "error",
		DistributionID: ctx.DistributionID,
		Status:         "unsupported",
		Message:        fmt.Sprintf("message type %q not supported", msgType),
		Timestamp:      time.Now().Unix(),
	}

	payloadBytes, err := json.Marshal(errorPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal unsupported-type error response: %w", err)
	}

	ctx.Data["response"] = payloadBytes
	ctx.Data["response_rcode"] = dns.RcodeRefused
	return nil
}

// encryptResponsePayload encrypts a response payload if SecureWrapper is available in ctx.Data.
// Returns the (possibly encrypted) payload and the appropriate format byte.
func encryptResponsePayload(ctx *MessageContext, payload []byte) ([]byte, uint8) {
	if sw, ok := ctx.Data["secure_wrapper"].(*SecurePayloadWrapper); ok && sw != nil && sw.IsEnabled() {
		if peerID, ok := ctx.Data["response_peer_id"].(string); ok && peerID != "" {
			if encrypted, err := sw.WrapOutgoing(peerID, payload); err == nil {
				return encrypted, core.FormatJWT
			} else {
				lgTransport().Error("response encryption failed", "peer", peerID, "err", err)
			}
		}
	}
	return payload, core.FormatJSON
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
			lgTransport().Error("handler error", "err", err)
			rcode = dns.RcodeServerFailure
		}

		// Check for explicit response_rcode (set by default handler, etc.)
		if rc, ok := ctx.Data["response_rcode"].(int); ok {
			rcode = rc
		}

		// Check for response payload (unified key for all message types)
		if response, ok := ctx.Data["response"]; ok {
			if payload, ok := response.([]byte); ok {
				payload, format := encryptResponsePayload(ctx, payload)
				return sendChunkResponse(w, msg, payload, format, rcode)
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
				payloadBytes, format := encryptResponsePayload(ctx, payloadBytes)
				return sendChunkResponse(w, msg, payloadBytes, format, rcode)
			}
		}
		return sendStandardResponse(w, msg, rcode)
	}
}

// sendChunkResponse sends a DNS response with CHUNK payload in EDNS0.
func sendChunkResponse(w dns.ResponseWriter, req *dns.Msg, payload []byte, format uint8, rcode int) error {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = rcode

	// Add EDNS0 with CHUNK option using proper framing
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)

	opt.Option = append(opt.Option, edns0.CreateChunkOption(format, nil, payload))
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

// RouteToMsgHandler is a middleware that routes processed messages to a handler goroutine.
// After the handler executes, if it set "message_type" and "incoming_message" in ctx.Data,
// the IncomingMessage is forwarded to the incomingChan for async processing.
// Used by all roles (agent, combiner, signer).
func RouteToMsgHandler(incomingChan chan<- *IncomingMessage) MiddlewareFunc {
	return func(ctx *MessageContext, next MessageHandlerFunc) error {
		// Execute handler
		err := next(ctx)
		if err != nil {
			return err
		}

		// Route message to handler goroutine if handler stored it for routing
		if msgType, ok := ctx.Data["message_type"]; ok {
			if incomingMsg, ok := ctx.Data["incoming_message"].(*IncomingMessage); ok {
				select {
				case incomingChan <- incomingMsg:
					lgTransport().Debug("routed message to handler", "type", msgType, "peer", ctx.PeerID)
				default:
					lgTransport().Warn("message dropped: channel full",
						"type", msgType, "peer", ctx.PeerID, "distrib", ctx.DistributionID)
					return fmt.Errorf("message handler channel full")
				}
			}
		}

		return nil
	}
}
