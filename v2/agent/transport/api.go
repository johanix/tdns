/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * API transport implementation for multi-provider DNSSEC coordination (HSYNC).
 * Wraps the existing HTTPS-based API communication in tdns/v2.
 */

package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// APITransport implements the Transport interface using HTTPS REST API.
type APITransport struct {
	// LocalID is our own identity
	LocalID string

	// DefaultTimeout for API calls
	DefaultTimeout time.Duration

	// HTTPClient is the shared HTTP client (can be configured for TLS)
	HTTPClient *http.Client
}

// APITransportConfig holds configuration for creating an APITransport.
type APITransportConfig struct {
	LocalID        string
	DefaultTimeout time.Duration
	TLSConfig      *tls.Config
}

// NewAPITransport creates a new APITransport with the given configuration.
func NewAPITransport(cfg *APITransportConfig) *APITransport {
	timeout := cfg.DefaultTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	tlsConfig := cfg.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}

	return &APITransport{
		LocalID:        cfg.LocalID,
		DefaultTimeout: timeout,
		HTTPClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	}
}

// Name returns the transport name for logging.
func (t *APITransport) Name() string {
	return "API"
}

// Hello sends a hello handshake request to a peer via HTTPS API.
func (t *APITransport) Hello(ctx context.Context, peer *Peer, req *HelloRequest) (*HelloResponse, error) {
	addr := peer.CurrentAddress()
	if addr == nil {
		return nil, NewTransportError("API", "Hello", peer.ID, fmt.Errorf("no address available"), false)
	}

	// Build the API request payload
	apiReq := &apiHelloRequest{
		MessageType:  "HELLO",
		MyIdentity:   req.SenderID,
		YourIdentity: peer.ID,
		Capabilities: req.Capabilities,
		SharedZones:  req.SharedZones,
		Timestamp:    req.Timestamp.Unix(),
		Nonce:        req.Nonce,
	}

	url := buildURL(addr, "/hello")
	respBody, err := t.doRequest(ctx, "POST", url, apiReq)
	if err != nil {
		return nil, NewTransportError("API", "Hello", peer.ID, err, true)
	}

	var apiResp apiHelloResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, NewTransportError("API", "Hello", peer.ID,
			fmt.Errorf("failed to unmarshal response: %w", err), false)
	}

	if apiResp.Error {
		return &HelloResponse{
			ResponderID:  peer.ID,
			Accepted:     false,
			RejectReason: apiResp.ErrorMsg,
			Timestamp:    time.Now(),
		}, nil
	}

	return &HelloResponse{
		ResponderID:  apiResp.Identity,
		Capabilities: apiResp.Capabilities,
		SharedZones:  apiResp.SharedZones,
		Accepted:     true,
		Timestamp:    time.Now(),
		Nonce:        req.Nonce,
	}, nil
}

// Beat sends a heartbeat to a peer via HTTPS API.
func (t *APITransport) Beat(ctx context.Context, peer *Peer, req *BeatRequest) (*BeatResponse, error) {
	addr := peer.CurrentAddress()
	if addr == nil {
		return nil, NewTransportError("API", "Beat", peer.ID, fmt.Errorf("no address available"), false)
	}

	apiReq := &apiBeatRequest{
		MessageType:  "BEAT",
		MyIdentity:   req.SenderID,
		YourIdentity: peer.ID,
		Timestamp:    req.Timestamp.Unix(),
		Sequence:     req.Sequence,
		State:        req.State,
	}

	url := buildURL(addr, "/beat")
	respBody, err := t.doRequest(ctx, "POST", url, apiReq)
	if err != nil {
		return nil, NewTransportError("API", "Beat", peer.ID, err, true)
	}

	var apiResp apiBeatResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, NewTransportError("API", "Beat", peer.ID,
			fmt.Errorf("failed to unmarshal response: %w", err), false)
	}

	return &BeatResponse{
		ResponderID: apiResp.Identity,
		Timestamp:   time.Now(),
		Sequence:    req.Sequence,
		State:       apiResp.State,
		Ack:         !apiResp.Error,
	}, nil
}

// Sync sends a data synchronization request to a peer via HTTPS API.
func (t *APITransport) Sync(ctx context.Context, peer *Peer, req *SyncRequest) (*SyncResponse, error) {
	addr := peer.CurrentAddress()
	if addr == nil {
		return nil, NewTransportError("API", "Sync", peer.ID, fmt.Errorf("no address available"), false)
	}

	apiReq := &apiSyncRequest{
		MessageType:   "SYNC",
		MyIdentity:    req.SenderID,
		YourIdentity:  peer.ID,
		Zone:          req.Zone,
		SyncType:      req.SyncType.String(),
		Records:       req.Records,
		Serial:        req.Serial,
		CorrelationID: req.CorrelationID,
		Timestamp:     req.Timestamp.Unix(),
	}

	url := buildURL(addr, "/sync")
	respBody, err := t.doRequest(ctx, "POST", url, apiReq)
	if err != nil {
		return nil, NewTransportError("API", "Sync", peer.ID, err, true)
	}

	var apiResp apiSyncResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, NewTransportError("API", "Sync", peer.ID,
			fmt.Errorf("failed to unmarshal response: %w", err), false)
	}

	status := ConfirmSuccess
	if apiResp.Error {
		status = ConfirmFailed
	}

	return &SyncResponse{
		ResponderID:   apiResp.Identity,
		Zone:          req.Zone,
		CorrelationID: req.CorrelationID,
		Status:        status,
		Message:       apiResp.Msg,
		Timestamp:     time.Now(),
	}, nil
}

// Relocate requests a peer to use a different address via HTTPS API.
func (t *APITransport) Relocate(ctx context.Context, peer *Peer, req *RelocateRequest) (*RelocateResponse, error) {
	addr := peer.CurrentAddress()
	if addr == nil {
		return nil, NewTransportError("API", "Relocate", peer.ID, fmt.Errorf("no address available"), false)
	}

	apiReq := &apiRelocateRequest{
		MessageType: "RELOCATE",
		MyIdentity:  req.SenderID,
		NewAddress: apiAddress{
			Host:      req.NewAddress.Host,
			Port:      req.NewAddress.Port,
			Transport: req.NewAddress.Transport,
			Path:      req.NewAddress.Path,
		},
		Reason:     req.Reason,
		ValidUntil: req.ValidUntil.Unix(),
	}

	url := buildURL(addr, "/relocate")
	respBody, err := t.doRequest(ctx, "POST", url, apiReq)
	if err != nil {
		return nil, NewTransportError("API", "Relocate", peer.ID, err, true)
	}

	var apiResp apiRelocateResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, NewTransportError("API", "Relocate", peer.ID,
			fmt.Errorf("failed to unmarshal response: %w", err), false)
	}

	return &RelocateResponse{
		ResponderID: apiResp.Identity,
		Accepted:    apiResp.Accepted,
		Message:     apiResp.Msg,
		Timestamp:   time.Now(),
	}, nil
}

// Confirm sends an acknowledgment of a sync operation via HTTPS API.
func (t *APITransport) Confirm(ctx context.Context, peer *Peer, req *ConfirmRequest) error {
	addr := peer.CurrentAddress()
	if addr == nil {
		return NewTransportError("API", "Confirm", peer.ID, fmt.Errorf("no address available"), false)
	}

	apiReq := &apiConfirmRequest{
		MessageType:   "CONFIRM",
		MyIdentity:    req.SenderID,
		Zone:          req.Zone,
		CorrelationID: req.CorrelationID,
		Status:        req.Status.String(),
		Message:       req.Message,
		Timestamp:     req.Timestamp.Unix(),
	}

	url := buildURL(addr, "/confirm")
	_, err := t.doRequest(ctx, "POST", url, apiReq)
	if err != nil {
		return NewTransportError("API", "Confirm", peer.ID, err, true)
	}

	return nil
}

// doRequest performs an HTTP request and returns the response body.
func (t *APITransport) doRequest(ctx context.Context, method, url string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := t.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// buildURL constructs a full URL from an address and path.
func buildURL(addr *Address, path string) string {
	scheme := addr.Transport
	if scheme == "" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, addr.Host, addr.Port, path)
}

// API request/response types for JSON serialization.
// These match the existing tdns API structures.

type apiHelloRequest struct {
	MessageType  string   `json:"message_type"`
	MyIdentity   string   `json:"my_identity"`
	YourIdentity string   `json:"your_identity"`
	Capabilities []string `json:"capabilities,omitempty"`
	SharedZones  []string `json:"shared_zones,omitempty"`
	Timestamp    int64    `json:"timestamp"`
	Nonce        string   `json:"nonce,omitempty"`
}

type apiHelloResponse struct {
	Identity     string   `json:"identity,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	SharedZones  []string `json:"shared_zones,omitempty"`
	Msg          string   `json:"msg,omitempty"`
	Error        bool     `json:"error"`
	ErrorMsg     string   `json:"error_msg,omitempty"`
}

type apiBeatRequest struct {
	MessageType  string `json:"message_type"`
	MyIdentity   string `json:"my_identity"`
	YourIdentity string `json:"your_identity"`
	Timestamp    int64  `json:"timestamp"`
	Sequence     uint64 `json:"sequence"`
	State        string `json:"state,omitempty"`
}

type apiBeatResponse struct {
	Identity string `json:"identity,omitempty"`
	State    string `json:"state,omitempty"`
	Msg      string `json:"msg,omitempty"`
	Error    bool   `json:"error"`
	ErrorMsg string `json:"error_msg,omitempty"`
}

type apiSyncRequest struct {
	MessageType   string   `json:"message_type"`
	MyIdentity    string   `json:"my_identity"`
	YourIdentity  string   `json:"your_identity"`
	Zone          string   `json:"zone"`
	SyncType      string   `json:"sync_type"`
	Records       []string `json:"records"`
	Serial        uint32   `json:"serial"`
	CorrelationID string   `json:"correlation_id"`
	Timestamp     int64    `json:"timestamp"`
}

type apiSyncResponse struct {
	Identity      string `json:"identity,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
	Msg           string `json:"msg,omitempty"`
	Error         bool   `json:"error"`
	ErrorMsg      string `json:"error_msg,omitempty"`
}

type apiAddress struct {
	Host      string `json:"host"`
	Port      uint16 `json:"port"`
	Transport string `json:"transport"`
	Path      string `json:"path,omitempty"`
}

type apiRelocateRequest struct {
	MessageType string     `json:"message_type"`
	MyIdentity  string     `json:"my_identity"`
	NewAddress  apiAddress `json:"new_address"`
	Reason      string     `json:"reason"`
	ValidUntil  int64      `json:"valid_until"`
}

type apiRelocateResponse struct {
	Identity string `json:"identity,omitempty"`
	Accepted bool   `json:"accepted"`
	Msg      string `json:"msg,omitempty"`
	Error    bool   `json:"error"`
	ErrorMsg string `json:"error_msg,omitempty"`
}

type apiConfirmRequest struct {
	MessageType   string `json:"message_type"`
	MyIdentity    string `json:"my_identity"`
	Zone          string `json:"zone"`
	CorrelationID string `json:"correlation_id"`
	Status        string `json:"status"`
	Message       string `json:"message,omitempty"`
	Timestamp     int64  `json:"timestamp"`
}
