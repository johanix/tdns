/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Unit tests for crypto middleware.
 */

package transport

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/miekg/dns"
)

// Mock crypto backend for testing
type mockCryptoBackend struct {
	signShouldFail   bool
	verifyShouldFail bool
	decryptShouldFail bool
}

func (m *mockCryptoBackend) Sign(key interface{}, payload []byte) ([]byte, error) {
	if m.signShouldFail {
		return nil, errors.New("mock sign error")
	}
	// Return fake JWS
	return []byte("mock.jws.signature"), nil
}

func (m *mockCryptoBackend) Verify(key interface{}, data []byte, signature []byte) (bool, error) {
	if m.verifyShouldFail {
		return false, errors.New("mock verify error")
	}
	return true, nil
}

func (m *mockCryptoBackend) Encrypt(key interface{}, payload []byte) ([]byte, error) {
	return []byte("encrypted"), nil
}

func (m *mockCryptoBackend) Decrypt(key interface{}, ciphertext []byte) ([]byte, error) {
	if m.decryptShouldFail {
		return nil, errors.New("mock decrypt error")
	}
	return []byte("decrypted"), nil
}

func (m *mockCryptoBackend) EncryptMultiRecipient(recipients []interface{}, payload []byte, metadata map[string]interface{}) ([]byte, error) {
	return []byte("encrypted"), nil
}

func (m *mockCryptoBackend) DecryptMultiRecipient(key interface{}, ciphertext []byte) ([]byte, error) {
	if m.decryptShouldFail {
		return nil, errors.New("mock decrypt error")
	}
	return []byte("decrypted"), nil
}

func (m *mockCryptoBackend) GenerateKeypair() (interface{}, interface{}, error) {
	return "private", "public", nil
}

// Mock security event logger for testing
type mockSecurityLogger struct {
	events []SecurityEvent
}

func (m *mockSecurityLogger) LogSecurityEvent(event SecurityEvent) {
	m.events = append(m.events, event)
}

func (m *mockSecurityLogger) HasEventType(eventType string) bool {
	for _, e := range m.events {
		if e.Type == eventType {
			return true
		}
	}
	return false
}

func (m *mockSecurityLogger) GetEventCount(eventType string) int {
	count := 0
	for _, e := range m.events {
		if e.Type == eventType {
			count++
		}
	}
	return count
}

// Mock transport manager for authorization
type mockTransportManager struct {
	authorizedPeers map[string]bool
}

func (m *mockTransportManager) IsAgentAuthorized(senderID string, zone string) (bool, string) {
	if m.authorizedPeers == nil {
		return false, "no authorized peers configured"
	}
	if m.authorizedPeers[senderID] {
		return true, "authorized via config (agent.authorized_peers)"
	}
	return false, "not authorized"
}

// Test helper to create a test crypto config
func newTestCryptoConfig() *CryptoMiddlewareConfig {
	backend := &mockCryptoBackend{}
	pc, _ := NewPayloadCrypto(&PayloadCryptoConfig{
		Backend: backend,
		Enabled: true,
	})
	pc.SetLocalKeys("local-private", "local-public")
	pc.AddPeerVerificationKey("peer1", "peer1-public")

	logger := &mockSecurityLogger{}

	return &CryptoMiddlewareConfig{
		PayloadCrypto:  pc,
		SecurityLogger: logger,
	}
}

func TestSignatureMiddleware_CryptoDisabled(t *testing.T) {
	cfg := &CryptoMiddlewareConfig{
		PayloadCrypto:  nil,
		SecurityLogger: &mockSecurityLogger{},
	}

	middleware := NewSignatureMiddleware(cfg)
	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	ctx.ChunkPayload = []byte(`{"test":"payload"}`)

	called := false
	err := middleware(ctx, func(ctx *MessageContext) error {
		called = true
		return nil
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if !called {
		t.Error("Next handler was not called")
	}
}

func TestSignatureMiddleware_NoPayload(t *testing.T) {
	cfg := newTestCryptoConfig()
	middleware := NewSignatureMiddleware(cfg)

	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	ctx.ChunkPayload = []byte{} // Empty payload

	called := false
	err := middleware(ctx, func(ctx *MessageContext) error {
		called = true
		return nil
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if !called {
		t.Error("Next handler was not called")
	}
}

func TestSignatureMiddleware_UnencryptedAllowed(t *testing.T) {
	cfg := newTestCryptoConfig()
	cfg.AllowUnencrypted = true

	middleware := NewSignatureMiddleware(cfg)
	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	ctx.PeerID = "peer1"
	ctx.ChunkPayload = []byte(`{"test":"unencrypted"}`)

	called := false
	err := middleware(ctx, func(ctx *MessageContext) error {
		called = true
		return nil
	})

	if err != nil {
		t.Fatalf("Expected no error with AllowUnencrypted=true, got: %v", err)
	}
	if !called {
		t.Error("Next handler was not called")
	}
}

func TestSignatureMiddleware_UnencryptedNotAllowed(t *testing.T) {
	cfg := newTestCryptoConfig()
	cfg.AllowUnencrypted = false

	middleware := NewSignatureMiddleware(cfg)
	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	ctx.PeerID = "peer1"
	ctx.ChunkPayload = []byte(`{"test":"unencrypted"}`)

	err := middleware(ctx, func(ctx *MessageContext) error {
		t.Error("Next handler should not be called")
		return nil
	})

	if err == nil {
		t.Fatal("Expected error for unencrypted payload, got nil")
	}
}

func TestSignatureMiddleware_MissingKeyWithDiscovery(t *testing.T) {
	cfg := newTestCryptoConfig()
	cfg.TriggerDiscoveryOnMissingKey = true
	logger := cfg.SecurityLogger.(*mockSecurityLogger)

	middleware := NewSignatureMiddleware(cfg)
	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	ctx.PeerID = "unknown-peer"
	ctx.ChunkPayload = []byte("YmFzZTY0ZW5jb2RlZA==") // base64 encoded

	called := false
	err := middleware(ctx, func(ctx *MessageContext) error {
		called = true
		return nil
	})

	if err != nil {
		t.Fatalf("Expected no error with TriggerDiscoveryOnMissingKey=true, got: %v", err)
	}
	if !called {
		t.Error("Next handler was not called")
	}
	if !logger.HasEventType("missing_verification_key") {
		t.Error("Expected missing_verification_key security event")
	}
	if ctx.SignatureValid {
		t.Error("Expected SignatureValid=false for missing key")
	}
}

func TestSignatureMiddleware_MissingKeyWithoutDiscovery(t *testing.T) {
	cfg := newTestCryptoConfig()
	cfg.TriggerDiscoveryOnMissingKey = false
	logger := cfg.SecurityLogger.(*mockSecurityLogger)

	middleware := NewSignatureMiddleware(cfg)
	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	ctx.PeerID = "unknown-peer"
	ctx.ChunkPayload = []byte("YmFzZTY0ZW5jb2RlZA==") // base64 encoded

	err := middleware(ctx, func(ctx *MessageContext) error {
		t.Error("Next handler should not be called")
		return nil
	})

	if err == nil {
		t.Fatal("Expected error for missing key, got nil")
	}
	if !logger.HasEventType("missing_verification_key") {
		t.Error("Expected missing_verification_key security event")
	}
}

func TestDecryptionMiddleware_CryptoDisabled(t *testing.T) {
	cfg := &CryptoMiddlewareConfig{
		PayloadCrypto:  nil,
		SecurityLogger: &mockSecurityLogger{},
	}

	middleware := NewDecryptionMiddleware(cfg)
	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	ctx.ChunkPayload = []byte(`{"test":"payload"}`)

	called := false
	err := middleware(ctx, func(ctx *MessageContext) error {
		called = true
		return nil
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if !called {
		t.Error("Next handler was not called")
	}
}

func TestDecryptionMiddleware_AlreadyDecrypted(t *testing.T) {
	cfg := newTestCryptoConfig()
	middleware := NewDecryptionMiddleware(cfg)

	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	ctx.ChunkPayload = []byte(`{"test":"payload"}`)
	ctx.ChunkCrypted = true
	ctx.SignatureValid = true

	called := false
	err := middleware(ctx, func(ctx *MessageContext) error {
		called = true
		return nil
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if !called {
		t.Error("Next handler was not called")
	}
}

func TestAuthorizationMiddleware_Authorized(t *testing.T) {
	tm := &mockTransportManager{
		authorizedPeers: map[string]bool{
			"peer1": true,
		},
	}

	middleware := NewAuthorizationMiddleware(tm)
	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	ctx.PeerID = "peer1"

	called := false
	err := middleware(ctx, func(ctx *MessageContext) error {
		called = true
		return nil
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if !called {
		t.Error("Next handler was not called")
	}
	if !ctx.Authorized {
		t.Error("Expected ctx.Authorized=true")
	}
	if ctx.AuthorizedVia != "explicit" {
		t.Errorf("Expected AuthorizedVia='explicit', got %q", ctx.AuthorizedVia)
	}
}

func TestAuthorizationMiddleware_NotAuthorized(t *testing.T) {
	tm := &mockTransportManager{
		authorizedPeers: map[string]bool{},
	}

	middleware := NewAuthorizationMiddleware(tm)
	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	ctx.PeerID = "unknown-peer"

	err := middleware(ctx, func(ctx *MessageContext) error {
		t.Error("Next handler should not be called")
		return nil
	})

	if err == nil {
		t.Fatal("Expected error for unauthorized peer, got nil")
	}
	if ctx.Authorized {
		t.Error("Expected ctx.Authorized=false")
	}
}

func TestLoggingMiddleware(t *testing.T) {
	middleware := NewLoggingMiddleware(false) // Non-verbose
	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	ctx.PeerID = "peer1"
	ctx.DistributionID = "test-123"

	called := false
	err := middleware(ctx, func(ctx *MessageContext) error {
		called = true
		return nil
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if !called {
		t.Error("Next handler was not called")
	}
}

func TestMetricsMiddleware(t *testing.T) {
	// Mock metrics collector
	metrics := make(map[string]float64)
	collector := &mockMetricsCollector{metrics: metrics}

	middleware := NewMetricsMiddleware(collector)
	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	ctx.Authorized = true
	ctx.SignatureValid = true

	err := middleware(ctx, func(ctx *MessageContext) error {
		return nil
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if metrics["message.success"] != 1 {
		t.Errorf("Expected message.success=1, got %v", metrics["message.success"])
	}
	if metrics["message.authorized"] != 1 {
		t.Errorf("Expected message.authorized=1, got %v", metrics["message.authorized"])
	}
	if metrics["message.signature_valid"] != 1 {
		t.Errorf("Expected message.signature_valid=1, got %v", metrics["message.signature_valid"])
	}
}

func TestSecurityEventLogger(t *testing.T) {
	logger := &mockSecurityLogger{}

	event := SecurityEvent{
		Type:     "test_event",
		PeerID:   "peer1",
		Reason:   "test reason",
		Severity: "info",
	}

	logger.LogSecurityEvent(event)

	if len(logger.events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(logger.events))
	}
	if logger.events[0].Type != "test_event" {
		t.Errorf("Expected event type 'test_event', got %q", logger.events[0].Type)
	}
}

func TestMiddlewareChain_AuthThenCrypto(t *testing.T) {
	// Test full middleware chain: Authorization -> Signature -> Decryption -> Handler
	tm := &mockTransportManager{
		authorizedPeers: map[string]bool{
			"peer1": true,
		},
	}

	cfg := newTestCryptoConfig()
	cfg.AllowUnencrypted = true

	authMW := NewAuthorizationMiddleware(tm)
	sigMW := NewSignatureMiddleware(cfg)
	decMW := NewDecryptionMiddleware(cfg)

	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")
	ctx.PeerID = "peer1"
	ctx.ChunkPayload = []byte(`{"test":"payload"}`)

	// Build chain: auth -> sig -> dec -> handler
	handler := func(ctx *MessageContext) error {
		if !ctx.Authorized {
			t.Error("Expected ctx.Authorized=true")
		}
		return nil
	}

	chain := authMW(ctx, func(ctx *MessageContext) error {
		return sigMW(ctx, func(ctx *MessageContext) error {
			return decMW(ctx, handler)
		})
	})

	if chain != nil {
		t.Fatalf("Expected no error, got: %v", chain)
	}
}

func TestIsPayloadEncrypted(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected bool
	}{
		{
			name:     "JSON payload",
			payload:  []byte(`{"test":"value"}`),
			expected: false,
		},
		{
			name:     "Empty payload",
			payload:  []byte{},
			expected: false,
		},
		{
			name:     "Base64 encrypted",
			payload:  []byte("YmFzZTY0ZW5jb2RlZA=="),
			expected: true,
		},
		{
			name:     "Invalid base64",
			payload:  []byte("not-base64!@#"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPayloadEncrypted(tt.payload)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for payload: %s", tt.expected, result, tt.payload)
			}
		})
	}
}

// Mock metrics collector
type mockMetricsCollector struct {
	metrics map[string]float64
}

func (m *mockMetricsCollector) RecordMetric(name string, value float64) {
	m.metrics[name] = value
}

func TestDefaultSecurityLogger(t *testing.T) {
	logger := &DefaultSecurityLogger{}
	event := SecurityEvent{
		Type:     "test_event",
		PeerID:   "peer1",
		Reason:   "test",
		Severity: "info",
	}

	// Should not panic
	logger.LogSecurityEvent(event)
}

func TestCryptoMiddlewareConfig_NilLogger(t *testing.T) {
	cfg := &CryptoMiddlewareConfig{
		PayloadCrypto:  nil,
		SecurityLogger: nil, // Will be replaced with default
	}

	middleware := NewSignatureMiddleware(cfg)
	ctx := NewMessageContext(&dns.Msg{}, "127.0.0.1:1234")

	// Should not panic with nil logger (gets replaced with default)
	err := middleware(ctx, func(ctx *MessageContext) error {
		return nil
	})

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
}

func TestSecurityEvent_JSONMarshaling(t *testing.T) {
	event := SecurityEvent{
		Type:      "test",
		PeerID:    "peer1",
		Reason:    "test reason",
		Severity:  "warning",
		Timestamp: "2025-01-01T00:00:00Z",
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Failed to marshal SecurityEvent: %v", err)
	}

	var decoded SecurityEvent
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal SecurityEvent: %v", err)
	}

	if decoded.Type != event.Type {
		t.Errorf("Expected Type=%q, got %q", event.Type, decoded.Type)
	}
}
