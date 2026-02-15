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
func HandleConfirmation(ctx *MessageContext) error {
	log.Printf("HandleConfirmation: Processing confirmation from %s (distrib=%s)",
		ctx.PeerID, ctx.DistributionID)

	// Parse the confirmation message
	var confirmMsg map[string]interface{}
	if err := json.Unmarshal(ctx.ChunkPayload, &confirmMsg); err != nil {
		return fmt.Errorf("failed to parse confirmation: %w", err)
	}

	// Route to transport's confirmation handler
	// This needs access to the transport's pending confirmation map
	// For now, we'll add the confirmation to the context data
	ctx.Data["confirmation"] = confirmMsg
	ctx.Data["confirmation_type"] = "confirm"

	log.Printf("HandleConfirmation: Confirmation processed from %s", ctx.PeerID)
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

	// Parse the ping message to get nonce field
	var pingMsg struct {
		Type  string `json:"type"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(ctx.ChunkPayload, &pingMsg); err != nil {
		return fmt.Errorf("failed to parse ping: %w", err)
	}

	if !ok && pingMsg.Type != "ping" {
		return fmt.Errorf("invalid message type for ping handler: %s", pingMsg.Type)
	}

	// Create confirmation response with echoed nonce
	confirmation := map[string]interface{}{
		"type":        "confirm",
		"ok":          true,
		"original_id": ctx.DistributionID,
		"nonce":       pingMsg.Nonce,
	}

	confirmPayload, err := json.Marshal(confirmation)
	if err != nil {
		return fmt.Errorf("failed to marshal ping confirmation: %w", err)
	}

	// Store confirmation in context for response middleware
	ctx.Data["ping_response"] = confirmPayload
	ctx.Data["ping_nonce"] = pingMsg.Nonce

	log.Printf("HandlePing: Ping processed from %s, nonce=%s", ctx.PeerID, pingMsg.Nonce)
	return nil
}

// HandleHello processes hello messages for peer introduction.
func HandleHello(ctx *MessageContext) error {
	log.Printf("HandleHello: Processing hello from %s (distrib=%s)",
		ctx.PeerID, ctx.DistributionID)

	// Get the pre-parsed message from context (set by RouteViaRouter)
	helloMsg, ok := ctx.Data["incoming_message"].(*IncomingMessage)
	if !ok {
		// Fallback: parse the payload if not pre-parsed
		var msg IncomingMessage
		if err := json.Unmarshal(ctx.ChunkPayload, &msg); err != nil {
			return fmt.Errorf("failed to parse hello: %w", err)
		}
		helloMsg = &msg
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
func HandleBeat(ctx *MessageContext) error {
	log.Printf("HandleBeat: Processing beat from %s (distrib=%s)",
		ctx.PeerID, ctx.DistributionID)

	// Get the pre-parsed message from context (set by RouteViaRouter)
	beatMsg, ok := ctx.Data["incoming_message"].(*IncomingMessage)
	if !ok {
		// Fallback: parse the payload if not pre-parsed
		var msg IncomingMessage
		if err := json.Unmarshal(ctx.ChunkPayload, &msg); err != nil {
			return fmt.Errorf("failed to parse beat: %w", err)
		}
		beatMsg = &msg
	}

	if beatMsg.Type != "beat" {
		return fmt.Errorf("invalid message type for beat handler: %s", beatMsg.Type)
	}

	// Store for routing to hsyncengine
	ctx.Data["message_type"] = "beat"
	ctx.Data["incoming_message"] = beatMsg

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

	// Get the pre-parsed message from context (set by RouteViaRouter)
	syncMsg, ok := ctx.Data["incoming_message"].(*IncomingMessage)
	if !ok {
		// Fallback: parse the payload if not pre-parsed
		var msg IncomingMessage
		if err := json.Unmarshal(ctx.ChunkPayload, &msg); err != nil {
			return fmt.Errorf("failed to parse sync: %w", err)
		}
		syncMsg = &msg
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

// HandleRelocate processes relocate messages for DDoS mitigation.
func HandleRelocate(ctx *MessageContext) error {
	log.Printf("HandleRelocate: Processing relocate from %s (distrib=%s)",
		ctx.PeerID, ctx.DistributionID)

	// Parse the relocate message
	var relocateMsg IncomingMessage
	if err := json.Unmarshal(ctx.ChunkPayload, &relocateMsg); err != nil {
		return fmt.Errorf("failed to parse relocate: %w", err)
	}

	if relocateMsg.Type != "relocate" {
		return fmt.Errorf("invalid message type for relocate handler: %s", relocateMsg.Type)
	}

	// Store for routing to hsyncengine
	ctx.Data["message_type"] = "relocate"
	ctx.Data["incoming_message"] = &relocateMsg

	log.Printf("HandleRelocate: Relocate processed from %s", ctx.PeerID)
	return nil
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
