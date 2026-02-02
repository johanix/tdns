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
// - Outbound: Send NOTIFY(CHUNK) with correlation ID in QNAME
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

	distributionAdd           func(qname string, senderID string, receiverID string, operation string, correlationID string)
	distributionMarkCompleted func(qname string)
}

// pendingOperation tracks an operation awaiting confirmation
type pendingOperation struct {
	CorrelationID string
	PeerID        string
	OperationType string // "hello", "beat", "sync", "relocate"
	SentAt        time.Time
	ResponseChan  chan *operationResponse
}

// operationResponse represents a response to a pending operation
type operationResponse struct {
	Status  ConfirmStatus
	Message string
	Error   error
}

// IncomingConfirmation represents a confirmation received via DNS
type IncomingConfirmation struct {
	CorrelationID string
	PeerID        string
	Status        ConfirmStatus
	Message       string
	Timestamp     time.Time
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
	// ChunkQueryEndpointInNotify: when true, include ChunkQueryEndpoint in NOTIFY via EDNS0 option 65005; when false, receiver uses static config (e.g. combiner.agent.address)
	ChunkQueryEndpointInNotify bool

	// Optional: register distributions for "agent distrib list". Called when sending; MarkCompleted when response is success.
	DistributionAdd          func(qname string, senderID string, receiverID string, operation string, correlationID string)
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

// Correlation ID: 8 hex chars = epoch (when transport first used) + per-operation counter (tdns-kdc style).
var (
	correlationEpochOnce sync.Once
	correlationEpoch     int64
	correlationCounter   uint64
)

// generateCorrelationID returns a unique 8-character (hex) ID: base = unix epoch when first used, then +1 per call.
func generateCorrelationID() string {
	correlationEpochOnce.Do(func() { correlationEpoch = time.Now().Unix() })
	n := atomic.AddUint64(&correlationCounter, 1)
	return fmt.Sprintf("%08x", uint32(correlationEpoch+int64(n-1)))
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

// buildNotifyQNAME constructs a NOTIFY QNAME from correlation ID and control zone.
// NOTIFY qname = {distid}.{sender} e.g. "69812b15.agent.alpha.dnslab."
func (t *DNSTransport) buildNotifyQNAME(correlationID string) string {
	return correlationID + "." + t.ControlZone
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

	correlationID := generateCorrelationID()
	qname := t.buildNotifyQNAME(correlationID)

	// Create hello payload
	payload := &DnsHelloPayload{
		Type:         "hello",
		SenderID:     req.SenderID,
		Capabilities: req.Capabilities,
		SharedZones:  req.SharedZones,
		Timestamp:    req.Timestamp.Unix(),
		Nonce:        req.Nonce,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, NewTransportError("DNS", "Hello", peer.ID,
			fmt.Errorf("failed to marshal hello payload: %w", err), false)
	}

	// Create and send NOTIFY(CHUNK)
	resp, err := t.sendNotifyWithPayload(ctx, peer, qname, "hello", correlationID, payloadJSON)
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

	correlationID := generateCorrelationID()
	qname := t.buildNotifyQNAME(correlationID)

	// Create beat payload
	payload := &DnsBeatPayload{
		Type:      "beat",
		SenderID:  req.SenderID,
		Timestamp: req.Timestamp.Unix(),
		Sequence:  req.Sequence,
		State:     req.State,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, NewTransportError("DNS", "Beat", peer.ID,
			fmt.Errorf("failed to marshal beat payload: %w", err), false)
	}

	// Create and send NOTIFY(CHUNK) - beats can be fire-and-forget
	resp, err := t.sendNotifyWithPayload(ctx, peer, qname, "beat", correlationID, payloadJSON)
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

	correlationID := req.CorrelationID
	if correlationID == "" {
		correlationID = generateCorrelationID()
	}
	qname := t.buildNotifyQNAME(correlationID)

	// Create sync payload
	payload := &DnsSyncPayload{
		Type:          "sync",
		SenderID:      req.SenderID,
		Zone:          req.Zone,
		SyncType:      req.SyncType.String(),
		Records:       req.Records,
		Serial:        req.Serial,
		CorrelationID: correlationID,
		Timestamp:     req.Timestamp.Unix(),
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, NewTransportError("DNS", "Sync", peer.ID,
			fmt.Errorf("failed to marshal sync payload: %w", err), false)
	}

	// Create and send NOTIFY(CHUNK)
	resp, err := t.sendNotifyWithPayload(ctx, peer, qname, "sync", correlationID, payloadJSON)
	if err != nil {
		return nil, err
	}

	return &SyncResponse{
		ResponderID:   peer.ID,
		Zone:          req.Zone,
		CorrelationID: correlationID,
		Status:        resp.Status,
		Message:       resp.Message,
		Timestamp:     time.Now(),
	}, nil
}

// Relocate requests a peer to use a different address via DNS.
func (t *DNSTransport) Relocate(ctx context.Context, peer *Peer, req *RelocateRequest) (*RelocateResponse, error) {
	addr := peer.CurrentAddress()
	if addr == nil {
		return nil, NewTransportError("DNS", "Relocate", peer.ID, fmt.Errorf("no address available"), false)
	}

	correlationID := generateCorrelationID()
	qname := t.buildNotifyQNAME(correlationID)

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
	resp, err := t.sendNotifyWithPayload(ctx, peer, qname, "relocate", correlationID, payloadJSON)
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

	correlationID := generateCorrelationID()
	qname := t.buildNotifyQNAME(correlationID)

	if t.distributionAdd != nil {
		t.distributionAdd(qname, t.LocalID, peer.ID, "ping", correlationID)
	}

	payload := &DnsPingPayload{
		Type:      "ping",
		SenderID:  req.SenderID,
		Nonce:     req.Nonce,
		Timestamp: req.Timestamp.Unix(),
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
		chunkQueryQname := buildChunkQueryQname(peer.ID, correlationID, t.ControlZone)
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
	if confirm.Nonce != req.Nonce {
		return nil, NewTransportError("DNS", "Ping", peer.ID,
			fmt.Errorf("ping response nonce mismatch"), true)
	}
	if confirm.Status != "ok" {
		return nil, NewTransportError("DNS", "Ping", peer.ID,
			fmt.Errorf("peer responded with status %q", confirm.Status), true)
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
			if confirm.Type != "ping_confirm" {
				return nil, fmt.Errorf("expected ping_confirm, got %s", confirm.Type)
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

	// Use the correlation ID from the original request
	qname := t.buildNotifyQNAME(req.CorrelationID)

	// Create confirmation payload
	payload := &DnsConfirmPayload{
		Type:          "confirm",
		SenderID:      req.SenderID,
		Zone:          req.Zone,
		CorrelationID: req.CorrelationID,
		Status:        req.Status.String(),
		Message:       req.Message,
		Timestamp:     req.Timestamp.Unix(),
	}

	payloadJSON, err := json.Marshal(payload)
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
func (t *DNSTransport) sendNotifyWithPayload(ctx context.Context, peer *Peer, qname, opType, correlationID string, payload []byte) (*operationResponse, error) {
	addr := peer.CurrentAddress()

	if t.distributionAdd != nil {
		t.distributionAdd(qname, t.LocalID, peer.ID, opType, correlationID)
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
		chunkQueryQname := buildChunkQueryQname(peer.ID, correlationID, t.ControlZone)
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

	// Register pending operation
	responseChan := make(chan *operationResponse, 1)
	pending := &pendingOperation{
		CorrelationID: correlationID,
		PeerID:        peer.ID,
		OperationType: opType,
		SentAt:        time.Now(),
		ResponseChan:  responseChan,
	}

	t.pendingMu.Lock()
	t.pendingConfirmations[correlationID] = pending
	t.pendingMu.Unlock()

	defer func() {
		t.pendingMu.Lock()
		delete(t.pendingConfirmations, correlationID)
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

	// For confirmation-based operations, wait for async confirmation
	// For now, treat NOTIFY ACK as success
	// TODO: Implement async confirmation waiting when needed
	return &operationResponse{
		Status:  ConfirmSuccess,
		Message: "NOTIFY acknowledged",
		Error:   nil,
	}, nil
}

// HandleIncomingConfirmation processes an incoming confirmation from the DNS responder.
// This should be called by the DNS message handler when a confirmation NOTIFY is received.
func (t *DNSTransport) HandleIncomingConfirmation(confirm *IncomingConfirmation) {
	t.pendingMu.RLock()
	pending, exists := t.pendingConfirmations[confirm.CorrelationID]
	t.pendingMu.RUnlock()

	if !exists {
		log.Printf("DNS: Received confirmation for unknown correlation ID: %s", confirm.CorrelationID)
		return
	}

	// Send response to waiting goroutine
	select {
	case pending.ResponseChan <- &operationResponse{
		Status:  confirm.Status,
		Message: confirm.Message,
	}:
	default:
		log.Printf("DNS: Response channel full for correlation ID: %s", confirm.CorrelationID)
	}
}

// DNS payload types for JSON serialization
// These are exported so hsync_transport.go can access parsed payload fields.

// DnsHelloPayload represents a hello message payload.
type DnsHelloPayload struct {
	Type         string   `json:"type"`
	SenderID     string   `json:"sender_id"`
	Capabilities []string `json:"capabilities,omitempty"`
	SharedZones  []string `json:"shared_zones,omitempty"`
	Timestamp    int64    `json:"timestamp"`
	Nonce        string   `json:"nonce,omitempty"`
}

// DnsBeatPayload represents a beat/heartbeat message payload.
type DnsBeatPayload struct {
	Type      string `json:"type"`
	SenderID  string `json:"sender_id"`
	Timestamp int64  `json:"timestamp"`
	Sequence  uint64 `json:"sequence"`
	State     string `json:"state,omitempty"`
}

// DnsSyncPayload represents a sync message payload.
type DnsSyncPayload struct {
	Type          string   `json:"type"`
	SenderID      string   `json:"sender_id"`
	Zone          string   `json:"zone"`
	SyncType      string   `json:"sync_type"`
	Records       []string `json:"records"`
	Serial        uint32   `json:"serial"`
	CorrelationID string   `json:"correlation_id"`
	Timestamp     int64    `json:"timestamp"`
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

// DnsConfirmPayload represents a confirmation message payload.
type DnsConfirmPayload struct {
	Type          string `json:"type"`
	SenderID      string `json:"sender_id"`
	Zone          string `json:"zone"`
	CorrelationID string `json:"correlation_id"`
	Status        string `json:"status"`
	Message       string `json:"message,omitempty"`
	Timestamp     int64  `json:"timestamp"`
}

// DnsPingPayload represents a ping (liveness) message payload.
type DnsPingPayload struct {
	Type      string `json:"type"`
	SenderID  string `json:"sender_id"`
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
}

// DnsPingConfirmPayload is the response to a ping; echoes the nonce.
type DnsPingConfirmPayload struct {
	Type          string `json:"type"`
	SenderID      string `json:"sender_id"`
	Nonce         string `json:"nonce"`
	CorrelationID string `json:"correlation_id"`
	Status        string `json:"status"`
	Timestamp     int64  `json:"timestamp"`
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
