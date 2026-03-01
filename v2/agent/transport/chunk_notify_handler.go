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

	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/distrib"
	"github.com/johanix/tdns/v2/edns0"
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

	// IsPeerAuthorized checks if a sender is authorized to send us messages.
	// This is called BEFORE expensive operations (decryption, query fetch) to prevent DoS attacks.
	// If nil, no authorization check is performed (not recommended for production).
	IsPeerAuthorized func(senderID string, zone string) (authorized bool, reason string)

	// OnPeerDiscoveryNeeded is called when we receive a message from an authorized peer
	// but don't have their verification key yet. Handler should trigger discovery asynchronously.
	OnPeerDiscoveryNeeded func(peerID string)

	// OnConfirmationReceived is called when a confirmation is received for a distribution ID.
	// Used by TransportManager to mark messages as confirmed in the ReliableMessageQueue
	// and to forward per-RR detail to the SynchedDataEngine.
	OnConfirmationReceived func(distributionID string, senderID string, status ConfirmStatus,
		zone string, applied []string, removed []string, rejected []RejectedItemDTO, truncated bool)

	// FetchChunkQuery performs a CHUNK query to the given server for the given qname.
	// Used when Transport is nil (combiner/signer mode) for chunk_mode=query fallback.
	// If nil and Transport is nil, query mode is not supported.
	FetchChunkQuery func(ctx context.Context, serverAddr, qname string) ([]byte, error)

	// unsolicitedCount tracks rejected messages from unauthorized senders (DoS mitigation)
	// Use atomic operations to increment (accessed from multiple NOTIFY handler goroutines)
	unsolicitedCount uint64
}

// NewChunkNotifyHandler creates a new ChunkNotifyHandler.
func NewChunkNotifyHandler(controlZone, localID string, transport *DNSTransport) *ChunkNotifyHandler {
	h := &ChunkNotifyHandler{
		ControlZone:  dns.Fqdn(controlZone),
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

// extractDistributionIDAndSender extracts the distribution ID and sender identity from a QNAME.
// QNAME format: <distributionID>.<sender-identity> e.g. "6981284f.agent.alpha.dnslab."
// The first label is the distribution ID; the rest is the sender's identity (FQDN).
// Returns (distributionID, senderID, error). senderID may be empty if QNAME has only one label.
func (h *ChunkNotifyHandler) extractDistributionIDAndSender(qname string) (distributionID, senderID string, err error) {
	qname = dns.Fqdn(qname)
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	if len(labels) == 0 {
		return "", "", fmt.Errorf("empty QNAME")
	}
	distributionID = labels[0]
	if distributionID == "" {
		return "", "", fmt.Errorf("no distribution ID in QNAME %s", qname)
	}
	if len(labels) > 1 {
		senderID = dns.Fqdn(strings.Join(labels[1:], "."))
	}
	return distributionID, senderID, nil
}

// extractChunkPayload extracts the CHUNK payload from the EDNS0 option using ChunkOption framing.
// Returns the payload data, the format byte (FormatJSON or FormatJWT), and any error.
func (h *ChunkNotifyHandler) extractChunkPayload(msg *dns.Msg) ([]byte, uint8, error) {
	if msg == nil {
		return nil, 0, fmt.Errorf("message is nil")
	}

	opt := msg.IsEdns0()
	if opt == nil {
		return nil, 0, fmt.Errorf("no EDNS0 OPT record")
	}

	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == edns0.EDNS0_CHUNK_OPTION_CODE {
				chunkOpt, err := edns0.ParseChunkOption(localOpt)
				if err != nil {
					return nil, 0, fmt.Errorf("invalid CHUNK option: %w", err)
				}
				return chunkOpt.Data, chunkOpt.Format, nil
			}
		}
	}

	return nil, 0, fmt.Errorf("no CHUNK EDNS0 option found")
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
// Uses manifest-first fetch: fetches manifest (sequence 0), checks if inline, otherwise fetches data chunks 1..N.
// Builds base qname as {receiver}.{distid}.{sender} and queries the sender.
func (h *ChunkNotifyHandler) fetchChunkViaQuery(ctx context.Context, senderID, distributionID string, msg *dns.Msg, w dns.ResponseWriter) ([]byte, error) {
	if h.Transport == nil && h.FetchChunkQuery == nil {
		return nil, fmt.Errorf("no transport or FetchChunkQuery callback for CHUNK query")
	}
	if senderID == "" {
		return nil, fmt.Errorf("cannot derive sender for query mode (empty senderID)")
	}

	baseQname := buildChunkQueryQname(h.LocalID, distributionID, senderID)
	queryTarget := extractChunkQueryEndpointFromMsg(msg)
	if queryTarget == "" && h.GetPeerAddress != nil {
		if addr, ok := h.GetPeerAddress(senderID); ok && addr != "" {
			queryTarget = addr
		}
	}
	if queryTarget == "" && w != nil {
		queryTarget = w.RemoteAddr().String()
		if host, _, err := net.SplitHostPort(queryTarget); err == nil && host != "" {
			queryTarget = net.JoinHostPort(host, "53")
		}
	}
	if queryTarget == "" {
		return nil, fmt.Errorf("no CHUNK payload in EDNS0 and no CHUNK query endpoint (no EDNS0 option 65005, no peer address for %q)", senderID)
	}

	// Phase 1: Fetch manifest (sequence 0)
	if h.Transport == nil {
		// Combiner/signer fallback: no Transport, use legacy single-fetch callback
		return h.FetchChunkQuery(ctx, queryTarget, baseQname)
	}

	manifestQname := buildChunkQueryQnameWithSeq(0, baseQname)
	manifestChunk, err := h.Transport.FetchChunkRR(ctx, queryTarget, manifestQname)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest (seq 0): %w", err)
	}

	// Phase 2: Extract manifest data — check if payload is inline
	manifestData, err := core.ExtractManifestData(manifestChunk)
	if err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}
	if manifestData.ChunkCount == 0 {
		// Payload is inline in the manifest
		return manifestData.Payload, nil
	}

	// Phase 3: Fetch data chunks 1..N and reassemble
	dataChunks := make([]*core.CHUNK, 0, manifestData.ChunkCount)
	for i := uint16(1); i <= manifestData.ChunkCount; i++ {
		chunkQname := buildChunkQueryQnameWithSeq(i, baseQname)
		chunk, err := h.Transport.FetchChunkRR(ctx, queryTarget, chunkQname)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch chunk %d/%d: %w", i, manifestData.ChunkCount, err)
		}
		dataChunks = append(dataChunks, chunk)
	}
	return distrib.ReassembleCHUNKs(dataChunks)
}

// parsePayload parses the JSON payload to determine message type and content.
func (h *ChunkNotifyHandler) parsePayload(distributionID string, payload []byte, sourceAddr string) (*IncomingMessage, error) {
	var fields struct {
		MessageType string `json:"MessageType"` // Standard format (string: "sync", "update", "beat", etc.)
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
func (h *ChunkNotifyHandler) sendConfirmResponse(w dns.ResponseWriter, req *dns.Msg, distributionID, msgType, senderID string) error {
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

	// Encrypt response when SecureWrapper is configured
	var payloadFormat uint8 = core.FormatJSON
	if h.SecureWrapper != nil && h.SecureWrapper.IsEnabled() && senderID != "" {
		if encrypted, err := h.SecureWrapper.WrapOutgoing(senderID, payloadBytes); err == nil {
			payloadBytes = encrypted
			payloadFormat = core.FormatJWT
		} else {
			log.Printf("sendConfirmResponse: encryption failed for peer %s: %v", senderID, err)
		}
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.Rcode = dns.RcodeSuccess
	resp.SetEdns0(4096, true)
	opt := resp.IsEdns0()
	if opt != nil {
		opt.Option = append(opt.Option, edns0.CreateChunkOption(payloadFormat, nil, payloadBytes))
	}
	return w.WriteMsg(resp)
}

// CreateNotifyHandlerFunc creates a function compatible with tdns.NotifyHandlerFunc.
// This is a helper that wraps RouteViaRouter for use with tdns.RegisterNotifyHandler.
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
		return h.RouteViaRouter(ctx, qname, msg, w)
	}
}

// UnsolicitedMessageCount returns the number of rejected messages from unauthorized senders.
// This counter is used for DoS attack monitoring and should be exported via metrics/monitoring.
func (h *ChunkNotifyHandler) UnsolicitedMessageCount() uint64 {
	return atomic.LoadUint64(&h.unsolicitedCount)
}

// RouteViaRouter routes a message through the DNS message router with middleware.
// This is the only routing path — the router must be configured.
func (h *ChunkNotifyHandler) RouteViaRouter(ctx context.Context, qname string, msg *dns.Msg, w dns.ResponseWriter) error {
	if h.Router == nil {
		log.Printf("RouteViaRouter: ERROR: Router is nil — cannot route message for %s", qname)
		return fmt.Errorf("router not configured")
	}

	sourceAddr := ""
	if w != nil {
		sourceAddr = w.RemoteAddr().String()
	}

	log.Printf("RouteViaRouter: Received NOTIFY(CHUNK) for %s from %s", qname, sourceAddr)

	// Extract distribution ID and sender identity from QNAME
	distributionID, senderHint, err := h.extractDistributionIDAndSender(qname)
	if err != nil {
		log.Printf("RouteViaRouter: Failed to extract distribution ID from %s: %v", qname, err)
		return h.sendResponse(w, msg, dns.RcodeFormatError)
	}

	// Extract CHUNK payload: first try EDNS0 (edns0 mode); if absent, fetch via CHUNK query (query mode)
	payload, _, err := h.extractChunkPayload(msg)
	if err != nil {
		// Query mode: NOTIFY has no EDNS0 payload; fetch using {receiver}.{distid}.{sender} from sender
		payload, err = h.fetchChunkViaQuery(ctx, senderHint, distributionID, msg, w)
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
	// Store local identity so handlers (e.g. ping) can include it in responses
	msgCtx.Data["local_id"] = h.LocalID
	// Store transport for confirmation handling
	if h.Transport != nil {
		msgCtx.Data["transport"] = h.Transport
	}
	// Store SecureWrapper + peer ID so SendResponseMiddleware can encrypt responses
	if h.SecureWrapper != nil {
		msgCtx.Data["secure_wrapper"] = h.SecureWrapper
	}
	msgCtx.Data["response_peer_id"] = senderHint
	if h.OnConfirmationReceived != nil {
		msgCtx.Data["on_confirmation_received"] = h.OnConfirmationReceived
	}
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
