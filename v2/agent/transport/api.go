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

	"github.com/johanix/tdns/v2/core"
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

// apiURL returns the full URL for an API operation on a peer.
// Uses peer.APIEndpoint (the discovered base URI) when available,
// falling back to constructing from CurrentAddress().
func apiURL(peer *Peer, path string) (string, error) {
	if peer.APIEndpoint != "" {
		return peer.APIEndpoint + path, nil
	}
	addr := peer.CurrentAddress()
	if addr == nil {
		return "", fmt.Errorf("no address available")
	}
	return buildURL(addr, path), nil
}

// Hello sends a hello handshake request to a peer via HTTPS API.
func (t *APITransport) Hello(ctx context.Context, peer *Peer, req *HelloRequest) (*HelloResponse, error) {
	url, err := apiURL(peer, "/hello")
	if err != nil {
		return nil, NewTransportError("API", "Hello", peer.ID, err, false)
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
	url, err := apiURL(peer, "/beat")
	if err != nil {
		return nil, NewTransportError("API", "Beat", peer.ID, err, false)
	}

	apiReq := &apiBeatRequest{
		MessageType:  "BEAT",
		MyIdentity:   req.SenderID,
		YourIdentity: peer.ID,
		Timestamp:    req.Timestamp.Unix(),
		Sequence:     req.Sequence,
		State:        req.State,
	}
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
	url, err := apiURL(peer, "/sync")
	if err != nil {
		return nil, NewTransportError("API", "Sync", peer.ID, err, false)
	}

	// Use req.MessageType if set (e.g. "rfi"), default to "sync"
	msgType := req.MessageType
	if msgType == "" {
		msgType = "sync"
	}

	apiReq := &apiSyncRequest{
		MessageType:    msgType,
		OriginatorID:   req.SenderID,
		YourIdentity:   peer.ID,
		Zone:           req.Zone,
		SyncType:       req.SyncType.String(),
		Records:        req.Records,
		Operations:     req.Operations,
		Serial:         req.Serial,
		DistributionID: req.DistributionID,
		RfiType:        req.RfiType,
		Timestamp:      req.Timestamp.Unix(),
	}
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
		ResponderID:    apiResp.Identity,
		Zone:           req.Zone,
		DistributionID: req.DistributionID,
		Status:         status,
		Message:        apiResp.Msg,
		Timestamp:      time.Now(),
	}, nil
}

// Relocate requests a peer to use a different address via HTTPS API.
func (t *APITransport) Relocate(ctx context.Context, peer *Peer, req *RelocateRequest) (*RelocateResponse, error) {
	url, err := apiURL(peer, "/relocate")
	if err != nil {
		return nil, NewTransportError("API", "Relocate", peer.ID, err, false)
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

// Ping sends a lightweight liveness probe to a peer via HTTPS API.
func (t *APITransport) Ping(ctx context.Context, peer *Peer, req *PingRequest) (*PingResponse, error) {
	url, err := apiURL(peer, "/sync/ping")
	if err != nil {
		return nil, NewTransportError("API", "Ping", peer.ID, err, false)
	}

	apiReq := &apiPingRequest{
		MessageType:  "PING",
		MyIdentity:   req.SenderID,
		YourIdentity: peer.ID,
		Nonce:        req.Nonce,
		Timestamp:    req.Timestamp.Unix(),
	}
	respBody, err := t.doRequest(ctx, "POST", url, apiReq)
	if err != nil {
		return nil, NewTransportError("API", "Ping", peer.ID, err, true)
	}

	var apiResp apiPingResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, NewTransportError("API", "Ping", peer.ID,
			fmt.Errorf("failed to unmarshal response: %w", err), false)
	}

	return &PingResponse{
		ResponderID: apiResp.Identity,
		Nonce:       apiResp.Nonce,
		OK:          !apiResp.Error,
		Timestamp:   time.Now(),
	}, nil
}

// Confirm sends an acknowledgment of a sync operation via HTTPS API.
func (t *APITransport) Confirm(ctx context.Context, peer *Peer, req *ConfirmRequest) error {
	url, err := apiURL(peer, "/confirm")
	if err != nil {
		return NewTransportError("API", "Confirm", peer.ID, err, false)
	}

	apiReq := &apiConfirmRequest{
		MessageType:    "CONFIRM",
		MyIdentity:     req.SenderID,
		Zone:           req.Zone,
		DistributionID: req.DistributionID,
		Status:         req.Status.String(),
		Message:        req.Message,
		Timestamp:      req.Timestamp.Unix(),
	}
	_, err = t.doRequest(ctx, "POST", url, apiReq)
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
		return nil, fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, url, string(respBody))
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
	MessageType    string              `json:"message_type"`
	OriginatorID   string              `json:"originator_id"`
	YourIdentity   string              `json:"your_identity"`
	Zone           string              `json:"zone"`
	SyncType       string              `json:"sync_type"`
	Records        map[string][]string `json:"records"`
	Operations     []core.RROperation  `json:"operations,omitempty"`
	Serial         uint32              `json:"serial"`
	DistributionID string              `json:"distribution_id"`
	RfiType        string              `json:"rfi_type,omitempty"`
	Timestamp      int64               `json:"timestamp"`
}

type apiSyncResponse struct {
	Identity       string `json:"identity,omitempty"`
	DistributionID string `json:"distribution_id,omitempty"`
	Msg            string `json:"msg,omitempty"`
	Error          bool   `json:"error"`
	ErrorMsg       string `json:"error_msg,omitempty"`
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

type apiPingRequest struct {
	MessageType  string `json:"message_type"`
	MyIdentity   string `json:"my_identity"`
	YourIdentity string `json:"your_identity"`
	Nonce        string `json:"nonce"`
	Timestamp    int64  `json:"timestamp"`
}

type apiPingResponse struct {
	Identity string `json:"identity,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
	Msg      string `json:"msg,omitempty"`
	Error    bool   `json:"error"`
	ErrorMsg string `json:"error_msg,omitempty"`
}

type apiConfirmRequest struct {
	MessageType    string `json:"message_type"`
	MyIdentity     string `json:"my_identity"`
	Zone           string `json:"zone"`
	DistributionID string `json:"distribution_id"`
	Status         string `json:"status"`
	Message        string `json:"message,omitempty"`
	Timestamp      int64  `json:"timestamp"`
}
