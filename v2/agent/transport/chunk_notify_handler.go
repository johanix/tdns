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
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/distrib"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

const (
	// unsolicitedWarnThreshold is the number of unsolicited messages from unauthorized
	// senders before escalating log level from Debug to Warn. This helps detect sustained
	// DoS attempts without flooding the log with individual Debug entries.
	unsolicitedWarnThreshold uint64 = 100
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
		zone string, applied []string, removed []string, rejected []RejectedItemDTO, truncated bool, nonce string)

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
	// M16: Reject empty senderID — every CHUNK NOTIFY must identify its sender
	if senderID == "" || senderID == "." {
		return "", "", fmt.Errorf("missing sender identity in QNAME %s", qname)
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
// M11: The payload is bounded by DNS message size (max 65535 bytes for TCP, ~4096 for UDP)
// or by the CHUNK query reassembly limit. No additional size limit is needed here because
// the input is always sourced from DNS wire data, never from unbounded HTTP or file input.
func (h *ChunkNotifyHandler) parsePayload(distributionID string, payload []byte, sourceAddr string) (*IncomingMessage, error) {
	var fields struct {
		MessageType  string `json:"MessageType"`  // Standard format (string: "sync", "update", "beat", etc.)
		Type         string `json:"type"`         // Legacy format (fallback)
		OriginatorID string `json:"OriginatorID"` // Sync/update messages
		MyIdentity   string `json:"MyIdentity"`   // Hello/beat/ping messages
		SenderID     string `json:"sender_id"`    // Legacy
		Zone         string `json:"Zone"`
		LegacyZone   string `json:"zone"`  // Legacy
		Nonce        string `json:"nonce"` // Nonce for replay protection
	}
	if err := json.Unmarshal(payload, &fields); err != nil {
		return nil, fmt.Errorf("failed to parse message: %w", err)
	}

	// M21: Reject messages that set both standard and legacy fields to different values.
	// This prevents ambiguity where an attacker could set conflicting field values
	// to bypass routing or authorization logic.
	if fields.MessageType != "" && fields.Type != "" && fields.MessageType != fields.Type {
		return nil, fmt.Errorf("conflicting message type fields: MessageType=%q vs type=%q", fields.MessageType, fields.Type)
	}
	if fields.Zone != "" && fields.LegacyZone != "" && fields.Zone != fields.LegacyZone {
		return nil, fmt.Errorf("conflicting zone fields: Zone=%q vs zone=%q", fields.Zone, fields.LegacyZone)
	}

	// Determine message type: prefer MessageType, fall back to legacy "type"
	msgType := fields.MessageType
	if msgType == "" {
		msgType = fields.Type
	}
	if msgType == "" {
		return nil, fmt.Errorf("no message type found in payload")
	}

	// Get sender ID: OriginatorID (sync/update), MyIdentity (hello/beat/ping), sender_id (legacy)
	senderID := fields.OriginatorID
	if senderID == "" {
		senderID = fields.MyIdentity
	}
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
		Nonce:          fields.Nonce,
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

	// Encrypt response when SecureWrapper is configured.
	// H6: If encryption is enabled but fails, return SERVFAIL rather than sending plaintext.
	// Sending an unencrypted response when encryption is expected would leak information.
	var payloadFormat uint8 = core.FormatJSON
	if h.SecureWrapper != nil && h.SecureWrapper.IsEnabled() && senderID != "" {
		encrypted, encErr := h.SecureWrapper.WrapOutgoing(senderID, payloadBytes)
		if encErr != nil {
			lgTransport().Error("confirm response encryption failed, refusing to send plaintext", "peer", senderID, "err", encErr)
			return h.sendResponse(w, req, dns.RcodeServerFailure)
		}
		payloadBytes = encrypted
		payloadFormat = core.FormatJWT
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
		lgTransport().Error("router is nil, cannot route message", "qname", qname)
		return fmt.Errorf("router not configured")
	}

	sourceAddr := ""
	if w != nil {
		sourceAddr = w.RemoteAddr().String()
	}

	lgTransport().Debug("received NOTIFY(CHUNK)", "qname", qname, "source", sourceAddr)

	// Extract distribution ID and sender identity from QNAME
	distributionID, senderHint, err := h.extractDistributionIDAndSender(qname)
	if err != nil {
		lgTransport().Error("failed to extract distribution ID", "qname", qname, "err", err)
		return h.sendResponse(w, msg, dns.RcodeFormatError)
	}

	// H8: Pre-crypto authorization check. Reject unknown senders BEFORE doing any expensive
	// crypto or query operations. This prevents DoS attacks where an attacker sends messages
	// with forged sender identities to force expensive decryption attempts.
	// Note: zone is not yet known at this point (it's inside the encrypted payload), so we
	// pass "" — the callback should check if the sender is known at all.
	if h.IsPeerAuthorized != nil {
		authorized, reason := h.IsPeerAuthorized(senderHint, "")
		if !authorized {
			count := atomic.AddUint64(&h.unsolicitedCount, 1)
			// M18: Escalate log level when unsolicited count exceeds threshold
			if count%unsolicitedWarnThreshold == 0 {
				lgTransport().Warn("sustained unsolicited messages from unauthorized senders",
					"total_count", count, "latest_peer", senderHint, "source", sourceAddr, "reason", reason)
			} else {
				lgTransport().Debug("rejected message from unauthorized sender",
					"peer", senderHint, "source", sourceAddr, "reason", reason)
			}
			return h.sendResponse(w, msg, dns.RcodeRefused)
		}
	}

	// Extract CHUNK payload: first try EDNS0 (edns0 mode); if absent, fetch via CHUNK query (query mode)
	payload, _, err := h.extractChunkPayload(msg)
	if err != nil {
		// Query mode: NOTIFY has no EDNS0 payload; fetch using {receiver}.{distid}.{sender} from sender
		payload, err = h.fetchChunkViaQuery(ctx, senderHint, distributionID, msg, w)
		if err != nil {
			lgTransport().Error("failed to get CHUNK payload (EDNS0 and query mode)", "err", err)
			return h.sendResponse(w, msg, dns.RcodeFormatError)
		}
	}

	// Decrypt the payload if it is encrypted.
	// SECURITY: Use strict decryption — ONLY try the claimed sender's key.
	// H7: No combiner key fallback. If decryption fails with the sender's key, reject.
	if h.SecureWrapper != nil {
		lgTransport().Debug("attempting to decrypt payload", "source", sourceAddr, "key_for", senderHint)

		decrypted, err := h.SecureWrapper.UnwrapIncomingFromPeer(payload, senderHint)
		if err != nil {
			// H5: Use sentinel error instead of string matching
			if errors.Is(err, ErrNoVerificationKey) {
				lgTransport().Info("missing verification key, triggering discovery", "peer", senderHint, "source", sourceAddr)
				if h.OnPeerDiscoveryNeeded != nil {
					go h.OnPeerDiscoveryNeeded(senderHint)
				}
				// Drop this message — sender will retry and we'll have the key by then
				return nil
			}

			// Decryption failed with the claimed sender's key — possible forgery
			lgTransport().Warn("SECURITY: decryption failed for NOTIFY, possible forgery",
				"source", sourceAddr, "claimed_peer", senderHint, "err", err)
			return h.sendResponse(w, msg, dns.RcodeRefused)
		}
		payload = decrypted
		lgTransport().Debug("successfully decrypted payload", "source", sourceAddr, "key_for", senderHint)
	}

	// Parse payload to normalize message format (converts numeric MessageType to string Type)
	incomingMsg, err := h.parsePayload(distributionID, payload, sourceAddr)
	if err != nil {
		lgTransport().Error("failed to parse payload", "err", err)
		return h.sendResponse(w, msg, dns.RcodeFormatError)
	}
	// Set the transport-level sender (from QNAME) — distinct from SenderID (payload OriginatorID).
	// For forwarded messages, SenderID is the original author while TransportSender is the relay agent.
	incomingMsg.TransportSender = senderHint

	msgType := MessageType(incomingMsg.Type)
	lgTransport().Debug("determined message type", "type", msgType, "sender", incomingMsg.SenderID, "transport_sender", senderHint)

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
		lgTransport().Debug("extracted zone for authorization", "zone", incomingMsg.Zone)
	} else if msgType == MessageType("beat") {
		// For beat messages, extract zones from the Zones array
		// Parse the raw payload to get the Zones field from AgentBeatPost
		var beatPayload struct {
			Zones []string `json:"Zones"`
		}
		// M11: payload is DNS-sourced (bounded by wire size), safe to unmarshal without size limit
		if err := json.Unmarshal(payload, &beatPayload); err == nil && len(beatPayload.Zones) > 0 {
			// Use first shared zone for authorization
			msgCtx.Data["zone"] = beatPayload.Zones[0]
			lgTransport().Debug("extracted zone from beat for authorization", "zone", beatPayload.Zones[0])
		}
	}

	// M20: Zone-peer authorization check. Now that we have the zone from the (decrypted) payload,
	// verify that this peer is authorized for this specific zone. The pre-crypto check (H8 above)
	// only verified the peer is known at all (zone=""); this check validates the zone-peer binding.
	if h.IsPeerAuthorized != nil {
		zone := ""
		if zoneVal, ok := msgCtx.Data["zone"]; ok {
			if zoneStr, ok := zoneVal.(string); ok {
				zone = zoneStr
			}
		}
		if zone != "" {
			authorized, reason := h.IsPeerAuthorized(senderHint, zone)
			if !authorized {
				lgTransport().Warn("peer not authorized for zone", "peer", senderHint, "zone", zone, "reason", reason)
				return h.sendResponse(w, msg, dns.RcodeRefused)
			}
		}
	}

	// Route through router (middleware + handlers)
	// The SendResponseMiddleware will send the DNS response
	responseMiddleware := SendResponseMiddleware(w, msg)
	err = responseMiddleware(msgCtx, func(ctx *MessageContext) error {
		return h.Router.Route(ctx, msgType)
	})

	if err != nil {
		lgTransport().Error("routing failed", "err", err)
		return h.sendResponse(w, msg, dns.RcodeServerFailure)
	}

	return nil
}
