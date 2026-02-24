/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * DNS transport implementation for multi-provider DNSSEC coordination (HSYNC).
 * Uses NOTIFY(CHUNK) + Query pattern for communication.
 */

package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// DNSTransport implements the Transport interface using DNS NOTIFY and queries.
// Communication pattern:
// - Outbound: Send NOTIFY(CHUNK) with distribution ID in QNAME
// - Inbound: Receive queries for CHUNK RRtype, respond with data
// - Confirmation: Send NOTIFY(CHUNK) back with status in EDNS0
type DNSTransport struct {
	// LocalID is our own identity
	LocalID string

	// ControlZone is the zone used for NOTIFY QNAMEs (e.g., "agent.example.com.")
	ControlZone string

	// ListenAddr is where we listen for incoming DNS queries
	ListenAddr string

	// DNSClient for sending DNS messages
	DNSClient *dns.Client

	// Timeout for DNS operations
	Timeout time.Duration

	// PendingConfirmations tracks operations waiting for confirmation
	pendingConfirmations map[string]*pendingOperation
	pendingMu            sync.RWMutex

	// ConfirmationChan receives confirmations from the DNS responder
	ConfirmationChan chan *IncomingConfirmation

	// SecureWrapper handles optional JWS/JWE encryption for payloads
	SecureWrapper *SecurePayloadWrapper

	// chunkMode: "edns0" or "query"; when "query", payload is stored and NOTIFY sent without EDNS0
	chunkMode string
	chunkGet  func(qname string) ([]byte, uint8, bool)
	chunkSet  func(qname string, payload []byte, format uint8)
	// chunkQueryEndpoint: for query mode, address (host:port) where we answer CHUNK queries
	chunkQueryEndpoint string
	// chunkQueryEndpointInNotify: when true, include endpoint in NOTIFY (EDNS0); when false, receiver uses static config
	chunkQueryEndpointInNotify bool

	distributionAdd           func(qname string, senderID string, receiverID string, operation string, distributionID string)
	distributionMarkCompleted func(qname string)
}

// pendingOperation tracks an operation awaiting confirmation
type pendingOperation struct {
	DistributionID string
	PeerID         string
	OperationType  string // "hello", "beat", "sync", "relocate"
	SentAt         time.Time
	ResponseChan   chan *operationResponse
}

// operationResponse represents a response to a pending operation
type operationResponse struct {
	Status         ConfirmStatus
	Message        string
	Error          error
	AppliedRecords []string
	RemovedRecords []string
	RejectedItems  []RejectedItemDTO
	Truncated      bool
}

// IncomingConfirmation represents a confirmation received via DNS
type IncomingConfirmation struct {
	DistributionID string
	PeerID         string
	Status         ConfirmStatus
	Message        string
	Timestamp      time.Time
	Zone           string
	AppliedRecords []string
	RemovedRecords []string
	RejectedItems  []RejectedItemDTO
	Truncated      bool
}

// DNSTransportConfig holds configuration for creating a DNSTransport.
type DNSTransportConfig struct {
	LocalID     string
	ControlZone string
	ListenAddr  string
	Timeout     time.Duration

	// PayloadCrypto is optional - if set, enables JWS/JWE encryption for payloads
	PayloadCrypto *PayloadCrypto

	// ChunkMode: "edns0" (default) = payload in EDNS0 option; "query" = store payload, send NOTIFY without EDNS0; receiver fetches via CHUNK query
	ChunkMode string
	// For ChunkMode "query": optional get/set for payload store (keyed by qname). If nil, query mode is effectively disabled.
	// Format: FormatJSON=1, FormatJWT=2 (from core package)
	ChunkPayloadGet func(qname string) ([]byte, uint8, bool)
	ChunkPayloadSet func(qname string, payload []byte, format uint8)
	// ChunkQueryEndpoint: for query mode, the address (host:port) where this agent answers CHUNK queries
	ChunkQueryEndpoint string
	// ChunkQueryEndpointInNotify: when true, include ChunkQueryEndpoint in NOTIFY via EDNS0 option 65005; when false, receiver uses static config (e.g. combiner.agents[].address)
	ChunkQueryEndpointInNotify bool

	// Optional: register distributions for "agent distrib list". Called when sending; MarkCompleted when response is success.
	DistributionAdd           func(qname string, senderID string, receiverID string, operation string, distributionID string)
	DistributionMarkCompleted func(qname string)
}

// NewDNSTransport creates a new DNSTransport with the given configuration.
func NewDNSTransport(cfg *DNSTransportConfig) *DNSTransport {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	t := &DNSTransport{
		LocalID:                    cfg.LocalID,
		ControlZone:                ensureFQDN(cfg.ControlZone),
		ListenAddr:                 cfg.ListenAddr,
		Timeout:                    timeout,
		DNSClient:                  &dns.Client{Timeout: timeout, Net: "udp"},
		pendingConfirmations:       make(map[string]*pendingOperation),
		ConfirmationChan:           make(chan *IncomingConfirmation, 100),
		chunkMode:                  cfg.ChunkMode,
		chunkGet:                   cfg.ChunkPayloadGet,
		chunkSet:                   cfg.ChunkPayloadSet,
		chunkQueryEndpoint:         cfg.ChunkQueryEndpoint,
		chunkQueryEndpointInNotify: cfg.ChunkQueryEndpointInNotify,
		distributionAdd:            cfg.DistributionAdd,
		distributionMarkCompleted:  cfg.DistributionMarkCompleted,
	}

	// Set up secure payload wrapper if crypto is configured
	if cfg.PayloadCrypto != nil {
		t.SecureWrapper = NewSecurePayloadWrapper(cfg.PayloadCrypto)
	}

	return t
}

// Name returns the transport name for logging.
func (t *DNSTransport) Name() string {
	return "DNS"
}

// Distribution ID: 8 hex chars = epoch (when transport first used) + per-operation counter (tdns-kdc style).
var (
	distributionEpochOnce sync.Once
	distributionEpoch     int64
	distributionCounter   uint64
)

// GenerateDistributionID returns a unique 8-character (hex) ID: base = unix epoch when first used, then +1 per call.
func GenerateDistributionID() string {
	distributionEpochOnce.Do(func() { distributionEpoch = time.Now().Unix() })
	n := atomic.AddUint64(&distributionCounter, 1)
	return fmt.Sprintf("%08x", uint32(distributionEpoch+int64(n-1)))
}

// ensureFQDN ensures a domain name ends with a dot.
func ensureFQDN(name string) string {
	if name == "" {
		return name
	}
	if name[len(name)-1] != '.' {
		return name + "."
	}
	return name
}

// buildNotifyQNAME constructs a NOTIFY QNAME from distribution ID and control zone.
// NOTIFY qname = {distid}.{sender} e.g. "69812b15.agent.alpha.dnslab."
func (t *DNSTransport) buildNotifyQNAME(distributionID string) string {
	return distributionID + "." + t.ControlZone
}

// buildChunkQueryQname constructs the CHUNK query/store qname: {receiver}.{distid}.{sender}.
// Used when chunk_mode=query: sender stores under this key; receiver fetches with this qname.
func buildChunkQueryQname(receiverID, distID, senderID string) string {
	r := strings.TrimSuffix(ensureFQDN(receiverID), ".")
	s := strings.TrimSuffix(ensureFQDN(senderID), ".")
	return ensureFQDN(r + "." + distID + "." + s)
}

// Hello sends a hello handshake request to a peer via DNS.
func (t *DNSTransport) Hello(ctx context.Context, peer *Peer, req *HelloRequest) (*HelloResponse, error) {
	addr := peer.CurrentAddress()
	if addr == nil {
		return nil, NewTransportError("DNS", "Hello", peer.ID, fmt.Errorf("no address available"), false)
	}

	distributionID := GenerateDistributionID()
	qname := t.buildNotifyQNAME(distributionID)

	// Create hello payload using typed struct from core package
	var zone string
	if len(req.SharedZones) > 0 {
		zone = req.SharedZones[0] // Use first shared zone
	}

	payload := &core.AgentHelloPost{
		MessageType:  core.AgentMsgHello,
		MyIdentity:   req.SenderID,
		YourIdentity: peer.ID,
		Zone:         zone,
		Time:         req.Timestamp,
		// Deprecated fields not set (omitempty)
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, NewTransportError("DNS", "Hello", peer.ID,
			fmt.Errorf("failed to marshal hello payload: %w", err), false)
	}

	// Create and send NOTIFY(CHUNK) - force endpoint for discovery (receiver may not know our address yet)
	resp, err := t.sendNotifyWithPayload(ctx, peer, qname, "hello", distributionID, payloadJSON, true)
	if err != nil {
		return nil, err
	}

	// Parse response
	if resp.Status != ConfirmSuccess {
		return &HelloResponse{
			ResponderID:  peer.ID,
			Accepted:     false,
			RejectReason: resp.Message,
			Timestamp:    time.Now(),
		}, nil
	}

	return &HelloResponse{
		ResponderID: peer.ID,
		Accepted:    true,
		Timestamp:   time.Now(),
		Nonce:       req.Nonce,
	}, nil
}

// Beat sends a heartbeat to a peer via DNS.
func (t *DNSTransport) Beat(ctx context.Context, peer *Peer, req *BeatRequest) (*BeatResponse, error) {
	addr := peer.CurrentAddress()
	if addr == nil {
		return nil, NewTransportError("DNS", "Beat", peer.ID, fmt.Errorf("no address available"), false)
	}

	distributionID := GenerateDistributionID()
	qname := t.buildNotifyQNAME(distributionID)

	// Create beat payload using typed struct from core package
	// Get shared zones from peer
	sharedZones := peer.GetSharedZones()

	if len(sharedZones) == 0 {
		log.Printf("DNS Beat: WARNING: No shared zones found for peer %s", peer.ID)
	} else {
		log.Printf("DNS Beat: Including %d shared zone(s) for peer %s: %v", len(sharedZones), peer.ID, sharedZones)
	}

	payload := &core.AgentBeatPost{
		MessageType:  core.AgentMsgBeat,
		MyIdentity:   req.SenderID,
		YourIdentity: peer.ID,
		Time:         req.Timestamp,
		Zones:        sharedZones, // Include shared zones for authorization
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, NewTransportError("DNS", "Beat", peer.ID,
			fmt.Errorf("failed to marshal beat payload: %w", err), false)
	}

	// Create and send NOTIFY(CHUNK) - beats can be fire-and-forget
	resp, err := t.sendNotifyWithPayload(ctx, peer, qname, "beat", distributionID, payloadJSON, false)
	if err != nil {
		// For beats, we might want to be more lenient with errors
		log.Printf("DNS Beat to %s failed: %v", peer.ID, err)
		return &BeatResponse{
			ResponderID: peer.ID,
			Timestamp:   time.Now(),
			Sequence:    req.Sequence,
			Ack:         false,
		}, nil
	}

	return &BeatResponse{
		ResponderID: peer.ID,
		Timestamp:   time.Now(),
		Sequence:    req.Sequence,
		State:       resp.Message,
		Ack:         resp.Status == ConfirmSuccess,
	}, nil
}

// Sync sends a data synchronization request to a peer via DNS.
// This is the primary DNS mode operation using NOTIFY(CHUNK) + Query.
func (t *DNSTransport) Sync(ctx context.Context, peer *Peer, req *SyncRequest) (*SyncResponse, error) {
	addr := peer.CurrentAddress()
	if addr == nil {
		return nil, NewTransportError("DNS", "Sync", peer.ID, fmt.Errorf("no address available"), false)
	}

	distributionID := req.DistributionID
	if distributionID == "" {
		distributionID = GenerateDistributionID()
	}
	qname := t.buildNotifyQNAME(distributionID)

	// Create sync payload using typed struct from core package
	messageType := core.AgentMsg(req.MessageType)
	if messageType == "" {
		messageType = core.AgentMsgNotify // backward compat safety net
	}
	payload := &core.AgentMsgPost{
		MessageType:  messageType,
		MyIdentity:   req.SenderID,
		YourIdentity: peer.ID,
		Zone:         req.Zone,
		Records:      req.Records,
		Time:         req.Timestamp,
		RfiType:      req.RfiType,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, NewTransportError("DNS", "Sync", peer.ID,
			fmt.Errorf("failed to marshal sync payload: %w", err), false)
	}

	// Create and send NOTIFY(CHUNK)
	resp, err := t.sendNotifyWithPayload(ctx, peer, qname, "sync", distributionID, payloadJSON, false)
	if err != nil {
		return nil, err
	}

	syncResp := &SyncResponse{
		ResponderID:    peer.ID,
		Zone:           req.Zone,
		DistributionID: distributionID,
		Status:         resp.Status,
		Message:        resp.Message,
		Timestamp:      time.Now(),
		AppliedRecords: resp.AppliedRecords,
		RemovedRecords: resp.RemovedRecords,
		RejectedItems:  resp.RejectedItems,
		Truncated:      resp.Truncated,
	}

	// A non-ok confirmation is an application-level rejection — return as error
	// so the queue knows to retry.
	if resp.Status == ConfirmFailed {
		return syncResp, NewTransportError("DNS", "Sync", peer.ID,
			fmt.Errorf("recipient rejected sync: %s", resp.Message), true)
	}

	return syncResp, nil
}

// Relocate requests a peer to use a different address via DNS.
func (t *DNSTransport) Relocate(ctx context.Context, peer *Peer, req *RelocateRequest) (*RelocateResponse, error) {
	addr := peer.CurrentAddress()
	if addr == nil {
		return nil, NewTransportError("DNS", "Relocate", peer.ID, fmt.Errorf("no address available"), false)
	}

	distributionID := GenerateDistributionID()
	qname := t.buildNotifyQNAME(distributionID)

	// Create relocate payload
	payload := &DnsRelocatePayload{
		Type:     "relocate",
		SenderID: req.SenderID,
		NewAddress: DnsAddress{
			Host:      req.NewAddress.Host,
			Port:      req.NewAddress.Port,
			Transport: req.NewAddress.Transport,
			Path:      req.NewAddress.Path,
		},
		Reason:     req.Reason,
		ValidUntil: req.ValidUntil.Unix(),
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, NewTransportError("DNS", "Relocate", peer.ID,
			fmt.Errorf("failed to marshal relocate payload: %w", err), false)
	}

	// Create and send NOTIFY(CHUNK)
	resp, err := t.sendNotifyWithPayload(ctx, peer, qname, "relocate", distributionID, payloadJSON, false)
	if err != nil {
		return nil, err
	}

	return &RelocateResponse{
		ResponderID: peer.ID,
		Accepted:    resp.Status == ConfirmSuccess,
		Message:     resp.Message,
		Timestamp:   time.Now(),
	}, nil
}

// Ping sends a liveness probe via DNS NOTIFY(CHUNK); response carries ping_confirm in EDNS0.
func (t *DNSTransport) Ping(ctx context.Context, peer *Peer, req *PingRequest) (*PingResponse, error) {
	addr := peer.CurrentAddress()
	if addr == nil {
		return nil, NewTransportError("DNS", "Ping", peer.ID, fmt.Errorf("no address available"), false)
	}

	distributionID := GenerateDistributionID()
	qname := t.buildNotifyQNAME(distributionID)

	if t.distributionAdd != nil {
		t.distributionAdd(qname, t.LocalID, peer.ID, "ping", distributionID)
	}

	// Create ping payload using typed struct from core package
	payload := &core.AgentPingPost{
		MessageType:  core.AgentMsgPing,
		MyIdentity:   req.SenderID,
		YourIdentity: peer.ID,
		Nonce:        req.Nonce,
		Time:         req.Timestamp,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, NewTransportError("DNS", "Ping", peer.ID,
			fmt.Errorf("failed to marshal ping payload: %w", err), false)
	}

	// Encrypt the payload when secure wrapper is configured; do not fall back to cleartext
	finalPayload := payloadJSON
	var payloadFormat uint8 = core.FormatJSON
	if t.SecureWrapper != nil && t.SecureWrapper.IsEnabled() {
		encrypted, err := t.SecureWrapper.WrapOutgoing(peer.ID, payloadJSON)
		if err != nil {
			return nil, NewTransportError("DNS", "Ping", peer.ID,
				fmt.Errorf("encryption required but failed: %w", err), false)
		}
		finalPayload = encrypted
		payloadFormat = core.FormatJWT
	}

	useQueryMode := t.chunkMode == "query" && t.chunkSet != nil
	if useQueryMode {
		// Store under CHUNK query qname so receiver can fetch: {receiver}.{distid}.{sender}
		chunkQueryQname := buildChunkQueryQname(peer.ID, distributionID, t.ControlZone)
		t.chunkSet(chunkQueryQname, finalPayload, payloadFormat)
	}

	m := new(dns.Msg)
	m.SetNotify(qname)
	m.Question = []dns.Question{
		{Name: qname, Qtype: TypeCHUNK, Qclass: dns.ClassINET},
	}
	if !useQueryMode {
		m.SetEdns0(4096, true)
		opt := m.IsEdns0()
		if opt != nil {
			opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
				Code: edns0.EDNS0_CHUNK_OPTION_CODE,
				Data: finalPayload,
			})
		}
	} else if t.chunkQueryEndpoint != "" && t.chunkQueryEndpointInNotify {
		m.SetEdns0(4096, true)
		opt := m.IsEdns0()
		if opt != nil {
			opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
				Code: edns0.EDNS0_CHUNK_QUERY_ENDPOINT_CODE,
				Data: []byte(t.chunkQueryEndpoint),
			})
		}
	}

	dnsAddr := fmt.Sprintf("%s:%d", addr.Host, addr.Port)
	res, _, err := t.DNSClient.ExchangeContext(ctx, m, dnsAddr)
	if err != nil {
		return nil, NewTransportError("DNS", "Ping", peer.ID,
			fmt.Errorf("NOTIFY exchange failed: %w", err), true)
	}
	if res.Rcode != dns.RcodeSuccess {
		return nil, NewTransportError("DNS", "Ping", peer.ID,
			fmt.Errorf("NOTIFY returned rcode %s (e.g. decryption/verification failed)", dns.RcodeToString[res.Rcode]), true)
	}

	// Parse EDNS0 CHUNK from response for ping_confirm
	confirm, err := extractPingConfirmFromResponse(res)
	if err != nil {
		return nil, NewTransportError("DNS", "Ping", peer.ID,
			fmt.Errorf("invalid ping response: %w", err), true)
	}
	// Check status before nonce: if the combiner sent an error response, the nonce
	// will be empty. Checking nonce first would produce a misleading "nonce mismatch"
	// instead of the actual error message.
	if confirm.Status != "ok" {
		return nil, NewTransportError("DNS", "Ping", peer.ID,
			fmt.Errorf("peer responded with status %q: %s", confirm.Status, confirm.Message), true)
	}
	if confirm.Nonce != req.Nonce {
		return nil, NewTransportError("DNS", "Ping", peer.ID,
			fmt.Errorf("ping response nonce mismatch"), true)
	}

	if t.distributionMarkCompleted != nil {
		t.distributionMarkCompleted(qname)
	}

	return &PingResponse{
		ResponderID: confirm.SenderID,
		Nonce:       confirm.Nonce,
		OK:          confirm.Status == "ok",
		Timestamp:   time.Unix(confirm.Timestamp, 0),
	}, nil
}

// extractPingConfirmFromResponse extracts DnsPingConfirmPayload from response EDNS0 CHUNK.
func extractPingConfirmFromResponse(res *dns.Msg) (*DnsPingConfirmPayload, error) {
	opt := res.IsEdns0()
	if opt == nil {
		return nil, fmt.Errorf("no EDNS0 in response")
	}
	for _, o := range opt.Option {
		if local, ok := o.(*dns.EDNS0_LOCAL); ok && local.Code == edns0.EDNS0_CHUNK_OPTION_CODE {
			var confirm DnsPingConfirmPayload
			if err := json.Unmarshal(local.Data, &confirm); err != nil {
				return nil, err
			}
			// Accept both "ping_confirm" (new format) and "confirm" (legacy format from older combiners)
			if confirm.Type != "ping_confirm" && confirm.Type != "confirm" {
				return nil, fmt.Errorf("expected ping_confirm or confirm, got %s", confirm.Type)
			}
			return &confirm, nil
		}
	}
	return nil, fmt.Errorf("no CHUNK option in response")
}

// Keystate sends a key lifecycle signal to a peer via DNS NOTIFY(CHUNK).
// Used for agent↔signer DNSKEY propagation signaling.
func (t *DNSTransport) Keystate(ctx context.Context, peer *Peer, req *KeystateRequest) (*KeystateResponse, error) {
	addr := peer.CurrentAddress()
	if addr == nil {
		return nil, NewTransportError("DNS", "Keystate", peer.ID, fmt.Errorf("no address available"), false)
	}

	distributionID := GenerateDistributionID()
	qname := t.buildNotifyQNAME(distributionID)

	// Create keystate payload using typed struct from core package
	payload := &core.AgentKeystatePost{
		MessageType:  core.AgentMsgKeystate,
		MyIdentity:   req.SenderID,
		YourIdentity: peer.ID,
		Zone:         req.Zone,
		KeyTag:       req.KeyTag,
		Algorithm:    req.Algorithm,
		Signal:       req.Signal,
		Message:      req.Message,
		Time:         req.Timestamp,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, NewTransportError("DNS", "Keystate", peer.ID,
			fmt.Errorf("failed to marshal keystate payload: %w", err), false)
	}

	// Send via sendNotifyWithPayload (reuses standard NOTIFY+confirm flow)
	resp, err := t.sendNotifyWithPayload(ctx, peer, qname, "keystate", distributionID, payloadJSON, false)
	if err != nil {
		return nil, err
	}

	return &KeystateResponse{
		ResponderID: peer.ID,
		Zone:        req.Zone,
		KeyTag:      req.KeyTag,
		Signal:      req.Signal,
		Accepted:    resp.Status == ConfirmSuccess,
		Message:     resp.Message,
		Timestamp:   time.Now(),
	}, nil
}

// extractKeystateConfirmFromResponse extracts DnsKeystateConfirmPayload from response EDNS0 CHUNK.
func extractKeystateConfirmFromResponse(res *dns.Msg) (*DnsKeystateConfirmPayload, error) {
	opt := res.IsEdns0()
	if opt == nil {
		return nil, fmt.Errorf("no EDNS0 in response")
	}
	for _, o := range opt.Option {
		if local, ok := o.(*dns.EDNS0_LOCAL); ok && local.Code == edns0.EDNS0_CHUNK_OPTION_CODE {
			var confirm DnsKeystateConfirmPayload
			if err := json.Unmarshal(local.Data, &confirm); err != nil {
				return nil, err
			}
			if confirm.Type != "keystate_confirm" && confirm.Type != "confirm" {
				return nil, fmt.Errorf("expected keystate_confirm or confirm, got %s", confirm.Type)
			}
			return &confirm, nil
		}
	}
	return nil, fmt.Errorf("no CHUNK option in response")
}

// Confirm sends an acknowledgment of a sync operation via DNS.
// Uses NOTIFY(CHUNK) with status in EDNS0 option.
func (t *DNSTransport) Confirm(ctx context.Context, peer *Peer, req *ConfirmRequest) error {
	addr := peer.CurrentAddress()
	if addr == nil {
		return NewTransportError("DNS", "Confirm", peer.ID, fmt.Errorf("no address available"), false)
	}

	// Use the distribution ID from the original request
	qname := t.buildNotifyQNAME(req.DistributionID)

	// Create confirmation payload with per-RR detail
	payload := &DnsConfirmPayload{
		Type:           "confirm",
		SenderID:       req.SenderID,
		Zone:           req.Zone,
		DistributionID: req.DistributionID,
		Status:         req.Status.String(),
		Message:        req.Message,
		AppliedCount:   len(req.AppliedRecords),
		RemovedCount:   len(req.RemovedRecords),
		RejectedCount:  len(req.RejectedItems),
		AppliedRecords: req.AppliedRecords,
		RemovedRecords: req.RemovedRecords,
		RejectedItems:  req.RejectedItems,
		Truncated:      req.Truncated,
		Timestamp:      req.Timestamp.Unix(),
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return NewTransportError("DNS", "Confirm", peer.ID,
			fmt.Errorf("failed to marshal confirm payload: %w", err), false)
	}

	// Size guard: EDNS0 payload must fit in UDP. If too large, drop per-RR detail
	// and set Truncated so the receiver knows full detail was not included.
	if len(payloadJSON) > 3500 {
		payload.AppliedRecords = nil
		payload.RemovedRecords = nil
		payload.Truncated = true
		payloadJSON, err = json.Marshal(payload)
	}
	if err != nil {
		return NewTransportError("DNS", "Confirm", peer.ID,
			fmt.Errorf("failed to marshal confirm payload: %w", err), false)
	}

	// Encrypt the payload when secure wrapper is configured; do not fall back to cleartext
	finalPayload := payloadJSON
	if t.SecureWrapper != nil && t.SecureWrapper.IsEnabled() {
		encrypted, err := t.SecureWrapper.WrapOutgoing(peer.ID, payloadJSON)
		if err != nil {
			return NewTransportError("DNS", "Confirm", peer.ID,
				fmt.Errorf("encryption required but failed: %w", err), false)
		}
		finalPayload = encrypted
	}

	// Create NOTIFY message
	m := new(dns.Msg)
	m.SetNotify(qname)
	m.Question = []dns.Question{
		{Name: qname, Qtype: TypeCHUNK, Qclass: dns.ClassINET},
	}

	// Add payload as CHUNK EDNS0 option
	m.SetEdns0(4096, true)
	opt := m.IsEdns0()
	if opt != nil {
		chunkOpt := &dns.EDNS0_LOCAL{
			Code: edns0.EDNS0_CHUNK_OPTION_CODE,
			Data: finalPayload,
		}
		opt.Option = append(opt.Option, chunkOpt)
	}

	// Send NOTIFY to peer
	dnsAddr := fmt.Sprintf("%s:%d", addr.Host, addr.Port)
	_, _, err = t.DNSClient.ExchangeContext(ctx, m, dnsAddr)
	if err != nil {
		return NewTransportError("DNS", "Confirm", peer.ID,
			fmt.Errorf("NOTIFY exchange failed: %w", err), true)
	}

	return nil
}

// sendNotifyWithPayload sends a NOTIFY(CHUNK) with payload and waits for confirmation.
func (t *DNSTransport) sendNotifyWithPayload(ctx context.Context, peer *Peer, qname, opType, distributionID string, payload []byte, forceEndpoint bool) (*operationResponse, error) {
	addr := peer.CurrentAddress()

	if t.distributionAdd != nil {
		t.distributionAdd(qname, t.LocalID, peer.ID, opType, distributionID)
	}

	// Encrypt the payload when secure wrapper is configured; do not fall back to cleartext
	finalPayload := payload
	var payloadFormat uint8 = core.FormatJSON
	if t.SecureWrapper != nil && t.SecureWrapper.IsEnabled() {
		encrypted, err := t.SecureWrapper.WrapOutgoing(peer.ID, payload)
		if err != nil {
			return nil, NewTransportError("DNS", "sendNotifyWithPayload", peer.ID,
				fmt.Errorf("encryption required but failed: %w", err), false)
		}
		finalPayload = encrypted
		payloadFormat = core.FormatJWT
	}

	useQueryMode := t.chunkMode == "query" && t.chunkSet != nil
	if useQueryMode {
		// Store under CHUNK query qname: {receiver}.{distid}.{sender}
		chunkQueryQname := buildChunkQueryQname(peer.ID, distributionID, t.ControlZone)
		t.chunkSet(chunkQueryQname, finalPayload, payloadFormat)
	}

	// Create NOTIFY message
	m := new(dns.Msg)
	m.SetNotify(qname)
	m.Question = []dns.Question{
		{Name: qname, Qtype: TypeCHUNK, Qclass: dns.ClassINET},
	}

	// EDNS0: payload in edns0 mode; in query mode include CHUNK query endpoint so receiver knows where to send CHUNK query
	if !useQueryMode {
		m.SetEdns0(4096, true)
		opt := m.IsEdns0()
		if opt != nil {
			opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
				Code: edns0.EDNS0_CHUNK_OPTION_CODE,
				Data: finalPayload,
			})
		}
	} else if t.chunkQueryEndpoint != "" && (t.chunkQueryEndpointInNotify || forceEndpoint) {
		// Include endpoint if configured OR if forced (discovery messages need it)
		m.SetEdns0(4096, true)
		opt := m.IsEdns0()
		if opt != nil {
			opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
				Code: edns0.EDNS0_CHUNK_QUERY_ENDPOINT_CODE,
				Data: []byte(t.chunkQueryEndpoint),
			})
		}
	}

	// Register pending operation
	responseChan := make(chan *operationResponse, 1)
	pending := &pendingOperation{
		DistributionID: distributionID,
		PeerID:         peer.ID,
		OperationType:  opType,
		SentAt:         time.Now(),
		ResponseChan:   responseChan,
	}

	t.pendingMu.Lock()
	t.pendingConfirmations[distributionID] = pending
	t.pendingMu.Unlock()

	defer func() {
		t.pendingMu.Lock()
		delete(t.pendingConfirmations, distributionID)
		t.pendingMu.Unlock()
	}()

	// Send NOTIFY to peer
	dnsAddr := fmt.Sprintf("%s:%d", addr.Host, addr.Port)
	res, _, err := t.DNSClient.ExchangeContext(ctx, m, dnsAddr)
	if err != nil {
		return nil, NewTransportError("DNS", opType, peer.ID,
			fmt.Errorf("NOTIFY exchange failed: %w", err), true)
	}

	// Check immediate response (NOTIFY acknowledgment)
	if res.Rcode != dns.RcodeSuccess {
		return nil, NewTransportError("DNS", opType, peer.ID,
			fmt.Errorf("NOTIFY returned rcode %s", dns.RcodeToString[res.Rcode]), true)
	}

	if t.distributionMarkCompleted != nil {
		t.distributionMarkCompleted(qname)
	}

	// Try to extract application-level confirmation from the DNS response EDNS0.
	// The combiner embeds a JSON confirmation in an EDNS0 CHUNK option.
	if confirm := extractConfirmFromResponse(res); confirm != nil {
		log.Printf("DNS: Received confirmation for %s %s to %s: status=%s message=%q applied=%d removed=%d rejected=%d",
			opType, distributionID, peer.ID, confirm.Status, confirm.Message,
			len(confirm.AppliedRecords), len(confirm.RemovedRecords), len(confirm.RejectedItems))
		status := parseConfirmStatus(confirm.Status)
		return &operationResponse{
			Status:         status,
			Message:        confirm.Message,
			AppliedRecords: confirm.AppliedRecords,
			RemovedRecords: confirm.RemovedRecords,
			RejectedItems:  confirm.RejectedItems,
			Truncated:      confirm.Truncated,
		}, nil
	}

	// No EDNS0 confirmation payload — DNS-level ACK (NOERROR) is NOT sufficient.
	// The recipient must include an explicit EDNS0 CHUNK confirmation to prove
	// it received and processed the message.
	log.Printf("DNS: NOTIFY %s %s to %s: DNS ACK received but no EDNS0 confirmation payload — treating as unconfirmed",
		opType, distributionID, peer.ID)
	return nil, NewTransportError("DNS", opType, peer.ID,
		fmt.Errorf("no EDNS0 confirmation in response (DNS-level ACK only)"), true)
}

// inlineConfirm holds the parsed confirmation from an EDNS0 CHUNK response.
type inlineConfirm struct {
	Type           string            `json:"type"`
	Status         string            `json:"status"`
	Message        string            `json:"message"`
	DistributionID string            `json:"distribution_id"`
	Zone           string            `json:"zone"`
	AppliedCount   int               `json:"applied_count,omitempty"`
	RemovedCount   int               `json:"removed_count,omitempty"`
	RejectedCount  int               `json:"rejected_count,omitempty"`
	AppliedRecords []string          `json:"applied_records,omitempty"`
	RemovedRecords []string          `json:"removed_records,omitempty"`
	RejectedItems  []RejectedItemDTO `json:"rejected_items,omitempty"`
	Truncated      bool              `json:"truncated,omitempty"`
}

// extractConfirmFromResponse extracts a JSON confirmation from the EDNS0 CHUNK option in a DNS response.
// Returns nil if no confirmation is present.
func extractConfirmFromResponse(res *dns.Msg) *inlineConfirm {
	opt := res.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		if local, ok := o.(*dns.EDNS0_LOCAL); ok && local.Code == edns0.EDNS0_CHUNK_OPTION_CODE {
			var confirm inlineConfirm
			if err := json.Unmarshal(local.Data, &confirm); err == nil && confirm.Type == "confirm" {
				return &confirm
			}
		}
	}
	return nil
}

// HandleIncomingConfirmation processes an incoming confirmation from the DNS responder.
// This should be called by the DNS message handler when a confirmation NOTIFY is received.
func (t *DNSTransport) HandleIncomingConfirmation(confirm *IncomingConfirmation) {
	t.pendingMu.RLock()
	pending, exists := t.pendingConfirmations[confirm.DistributionID]
	t.pendingMu.RUnlock()

	if !exists {
		log.Printf("DNS: Received confirmation for unknown distribution ID: %s", confirm.DistributionID)
		return
	}

	// Send response to waiting goroutine
	select {
	case pending.ResponseChan <- &operationResponse{
		Status:  confirm.Status,
		Message: confirm.Message,
	}:
	default:
		log.Printf("DNS: Response channel full for distribution ID: %s", confirm.DistributionID)
	}
}

// DNS payload types for JSON serialization
// These are exported so hsync_transport.go can access parsed payload fields.

// DnsHelloPayload represents a hello message payload.
// Parses both standard (MessageType/MyIdentity) and legacy (type/sender_id) fields.
type DnsHelloPayload struct {
	// Legacy fields (fallback)
	Type         string   `json:"type"`
	SenderID     string   `json:"sender_id"`
	Capabilities []string `json:"capabilities,omitempty"`
	SharedZones  []string `json:"shared_zones,omitempty"`
	Timestamp    int64    `json:"timestamp"`
	Nonce        string   `json:"nonce,omitempty"`

	// Standard fields
	MessageType  string `json:"MessageType"` // "hello"
	MyIdentity   string `json:"MyIdentity"`
	YourIdentity string `json:"YourIdentity"`
	Zone         string `json:"Zone"`
	Time         string `json:"Time"` // RFC3339 timestamp
}

// GetSenderID returns the sender ID from either old or new format.
func (d *DnsHelloPayload) GetSenderID() string {
	if d.MyIdentity != "" {
		return d.MyIdentity // New format
	}
	return d.SenderID // Old format
}

// GetSharedZones returns shared zones from either old or new format.
func (d *DnsHelloPayload) GetSharedZones() []string {
	if d.Zone != "" {
		return []string{d.Zone} // New format (single zone)
	}
	return d.SharedZones // Old format (array)
}

// DnsBeatPayload represents a beat/heartbeat message payload.
// Parses both standard (MessageType/MyIdentity) and legacy (type/sender_id) fields.
type DnsBeatPayload struct {
	// Legacy fields (fallback)
	Type      string `json:"type"`
	SenderID  string `json:"sender_id"`
	Timestamp int64  `json:"timestamp"`
	Sequence  uint64 `json:"sequence"`
	State     string `json:"state,omitempty"`

	// Standard fields
	MessageType    string   `json:"MessageType"` // "beat"
	MyIdentity     string   `json:"MyIdentity"`
	YourIdentity   string   `json:"YourIdentity"`
	MyBeatInterval uint32   `json:"MyBeatInterval"`
	Zones          []string `json:"Zones"`
	Time           string   `json:"Time"` // RFC3339
}

// GetSenderID returns the sender ID from either old or new format.
func (d *DnsBeatPayload) GetSenderID() string {
	if d.MyIdentity != "" {
		return d.MyIdentity // New format
	}
	return d.SenderID // Old format
}

// DnsSyncPayload represents a sync message payload.
type DnsSyncPayload struct {
	MessageType    string              `json:"MessageType"`
	MyIdentity     string              `json:"MyIdentity"`
	YourIdentity   string              `json:"YourIdentity"`
	Zone           string              `json:"Zone"`
	Records        map[string][]string `json:"Records"` // RRs grouped by owner name
	Time           string              `json:"Time"`    // RFC3339 timestamp
	RfiType        string              `json:"RfiType"`
	Timestamp      int64               `json:"timestamp"` // Unix timestamp (legacy compat)
	DistributionID string              `json:"distribution_id"`
}

// DnsAddress represents an address in DNS payloads.
type DnsAddress struct {
	Host      string `json:"host"`
	Port      uint16 `json:"port"`
	Transport string `json:"transport"`
	Path      string `json:"path,omitempty"`
}

// DnsRelocatePayload represents a relocate message payload.
type DnsRelocatePayload struct {
	Type       string     `json:"type"`
	SenderID   string     `json:"sender_id"`
	NewAddress DnsAddress `json:"new_address"`
	Reason     string     `json:"reason"`
	ValidUntil int64      `json:"valid_until"`
}

// RejectedItemDTO describes an RR that was rejected by the combiner and why.
type RejectedItemDTO struct {
	Record string `json:"record"`
	Reason string `json:"reason"`
}

// DnsConfirmPayload represents a confirmation message payload.
type DnsConfirmPayload struct {
	Type           string            `json:"type"`
	SenderID       string            `json:"sender_id"`
	Zone           string            `json:"zone"`
	DistributionID string            `json:"distribution_id"`
	Status         string            `json:"status"`
	Message        string            `json:"message,omitempty"`
	AppliedCount   int               `json:"applied_count,omitempty"`
	RemovedCount   int               `json:"removed_count,omitempty"`
	RejectedCount  int               `json:"rejected_count,omitempty"`
	AppliedRecords []string          `json:"applied_records,omitempty"`
	RemovedRecords []string          `json:"removed_records,omitempty"`
	RejectedItems  []RejectedItemDTO `json:"rejected_items,omitempty"`
	Truncated      bool              `json:"truncated,omitempty"`
	Timestamp      int64             `json:"timestamp"`
}

// GetSenderID returns the sender ID.
func (d *DnsSyncPayload) GetSenderID() string {
	return d.MyIdentity
}

// GetRecords returns records grouped by owner name.
func (d *DnsSyncPayload) GetRecords() map[string][]string {
	return d.Records
}

// DnsPingPayload represents a ping (liveness) message payload.
// Parses both standard (MessageType/MyIdentity) and legacy (type/sender_id) fields.
type DnsPingPayload struct {
	// Legacy fields (fallback)
	Type      string `json:"type"`
	SenderID  string `json:"sender_id"`
	Nonce     string `json:"nonce"` // Common to both formats
	Timestamp int64  `json:"timestamp"`

	// Standard fields
	MessageType  string `json:"MessageType"` // "ping"
	MyIdentity   string `json:"MyIdentity"`
	YourIdentity string `json:"YourIdentity"`
	Time         string `json:"Time"` // RFC3339
}

// GetSenderID returns the sender ID from either old or new format.
func (d *DnsPingPayload) GetSenderID() string {
	if d.MyIdentity != "" {
		return d.MyIdentity // New format
	}
	return d.SenderID // Old format
}

// DnsKeystatePayload represents a KEYSTATE message payload.
// Used for agent↔signer key lifecycle signaling.
type DnsKeystatePayload struct {
	// Standard fields
	MessageType  string `json:"MessageType"`  // "keystate"
	MyIdentity   string `json:"MyIdentity"`   // Sender identity
	YourIdentity string `json:"YourIdentity"` // Recipient identity

	// KEYSTATE-specific fields
	Zone      string `json:"Zone"`              // Zone this key belongs to (FQDN)
	KeyTag    uint16 `json:"KeyTag"`            // DNSKEY key tag
	Algorithm uint8  `json:"Algorithm"`         // DNSKEY algorithm number
	Signal    string `json:"Signal"`            // "propagated", "rejected", "removed", "published", "retired"
	Message   string `json:"Message,omitempty"` // Optional detail (e.g. rejection reason)
	Timestamp int64  `json:"timestamp"`         // Unix timestamp

	// Legacy fields (fallback)
	Type     string `json:"type"`      // "keystate"
	SenderID string `json:"sender_id"` // Sender identity (legacy)
}

// GetSenderID returns the sender ID from either standard or legacy format.
func (d *DnsKeystatePayload) GetSenderID() string {
	if d.MyIdentity != "" {
		return d.MyIdentity
	}
	return d.SenderID
}

// DnsKeystateConfirmPayload is the response to a KEYSTATE message.
type DnsKeystateConfirmPayload struct {
	Type      string `json:"type"`              // "keystate_confirm"
	SenderID  string `json:"sender_id"`         // Responder identity
	Zone      string `json:"zone"`              // Echoed zone
	KeyTag    uint16 `json:"key_tag"`           // Echoed key tag
	Signal    string `json:"signal"`            // Echoed signal
	Status    string `json:"status"`            // "ok" or "error"
	Message   string `json:"message,omitempty"` // Optional detail
	Timestamp int64  `json:"timestamp"`
}

// DnsPingConfirmPayload is the response to a ping; echoes the nonce.
type DnsPingConfirmPayload struct {
	Type           string `json:"type"`
	SenderID       string `json:"sender_id"`
	Nonce          string `json:"nonce"`
	DistributionID string `json:"distribution_id"`
	Status         string `json:"status"`
	Message        string `json:"message,omitempty"` // Error detail from combiner
	Timestamp      int64  `json:"timestamp"`
}

// FetchChunkViaQuery queries the given DNS server for qname CHUNK and returns the first CHUNK RR's Data and Format.
// Used by the receiver in chunk_mode=query when NOTIFY has no EDNS0 payload.
func (t *DNSTransport) FetchChunkViaQuery(ctx context.Context, serverAddr, qname string) ([]byte, uint8, error) {
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
	m.SetQuestion(dns.Fqdn(qname), TypeCHUNK)
	m.RecursionDesired = false

	c := &dns.Client{Timeout: t.Timeout, Net: "tcp"}
	in, _, err := c.ExchangeContext(ctx, m, serverAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("CHUNK query to %s failed: %w", serverAddr, err)
	}
	if in == nil || in.Rcode != dns.RcodeSuccess {
		rcode := dns.RcodeSuccess
		if in != nil {
			rcode = in.Rcode
		}
		return nil, 0, fmt.Errorf("CHUNK query to %s returned rcode %s", serverAddr, dns.RcodeToString[rcode])
	}
	for _, rr := range in.Answer {
		if prr, ok := rr.(*dns.PrivateRR); ok && prr.Hdr.Rrtype == TypeCHUNK {
			if chunk, ok := prr.Data.(*core.CHUNK); ok && chunk != nil {
				return chunk.Data, chunk.Format, nil
			}
		}
	}
	return nil, 0, fmt.Errorf("no CHUNK RR in response from %s", serverAddr)
}

// Constants for DNS transport
// TypeCHUNK is the DNS RRtype for CHUNK records (should match core.TypeCHUNK).
// EDNS0 CHUNK option code is edns0.EDNS0_CHUNK_OPTION_CODE (65004); do not use RR type as option code.
const (
	TypeCHUNK = 65015 // 0xFDF7 - matches core.TypeCHUNK
)
