/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Unit tests for JWT manifest operations
 */

package distrib

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/core"
)

func TestJWTManifestClaims(t *testing.T) {
	claims := JWTManifestClaims{
		Issuer:          "kdc",
		Subject:         "distribution",
		IssuedAt:        time.Now().Unix(),
		DistributionID:  "dist-123",
		ReceiverID:      "node1.example.com.",
		Content:         "key_operations",
		Crypto:          "jose",
		ChunkCount:      3,
		ChunkSize:       25000,
		ChunkHash:       "sha256:abc123",
		KeyCount:        5,
		OperationCount:  5,
		ZoneCount:       2,
		DistributionTTL: "5m0s",
		RetireTime:      "2m0s",
	}

	// Verify fields
	if claims.Issuer != "kdc" {
		t.Errorf("Issuer = %v, want kdc", claims.Issuer)
	}
	if claims.ChunkCount != 3 {
		t.Errorf("ChunkCount = %v, want 3", claims.ChunkCount)
	}
	if claims.Content != "key_operations" {
		t.Errorf("Content = %v, want key_operations", claims.Content)
	}
}

func TestJWTManifestClaimsWithPayload(t *testing.T) {
	payload := []byte("inline test payload")
	encodedPayload := base64.StdEncoding.EncodeToString(payload)

	claims := JWTManifestClaims{
		Issuer:         "kdc",
		Subject:        "distribution",
		IssuedAt:       time.Now().Unix(),
		DistributionID: "dist-456",
		ReceiverID:     "node2.example.com.",
		Content:        "mgmt_operations",
		ChunkCount:     0, // Inline payload
		Payload:        encodedPayload,
	}

	// Verify inline payload
	if claims.ChunkCount != 0 {
		t.Errorf("ChunkCount = %v, want 0 for inline payload", claims.ChunkCount)
	}

	// Decode and verify payload
	decoded, err := base64.StdEncoding.DecodeString(claims.Payload)
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}
	if string(decoded) != string(payload) {
		t.Errorf("Payload = %q, want %q", decoded, payload)
	}
}

func TestConvertManifestDataToJWTClaims(t *testing.T) {
	md := &ManifestData{
		ChunkCount: 2,
		ChunkSize:  30000,
		Metadata: map[string]interface{}{
			"distribution_id":  "dist-789",
			"receiver_id":      "node3.example.com.",
			"content":          "key_operations",
			"crypto":           "jose",
			"timestamp":        float64(1234567890),
			"key_count":        float64(3),
			"operation_count":  float64(3),
			"zone_count":       float64(1),
			"distribution_ttl": "5m0s",
			"retire_time":      "2m0s",
		},
		Payload: []byte("test payload"),
	}

	claims := ConvertManifestDataToJWTClaims(md, "kdc")

	// Verify conversion
	if claims.Issuer != "kdc" {
		t.Errorf("Issuer = %v, want kdc", claims.Issuer)
	}
	if claims.DistributionID != "dist-789" {
		t.Errorf("DistributionID = %v, want dist-789", claims.DistributionID)
	}
	if claims.ReceiverID != "node3.example.com." {
		t.Errorf("ReceiverID = %v, want node3.example.com.", claims.ReceiverID)
	}
	if claims.Content != "key_operations" {
		t.Errorf("Content = %v, want key_operations", claims.Content)
	}
	if claims.Crypto != "jose" {
		t.Errorf("Crypto = %v, want jose", claims.Crypto)
	}
	if claims.ChunkCount != 2 {
		t.Errorf("ChunkCount = %v, want 2", claims.ChunkCount)
	}
	if claims.ChunkSize != 30000 {
		t.Errorf("ChunkSize = %v, want 30000", claims.ChunkSize)
	}
	if claims.KeyCount != 3 {
		t.Errorf("KeyCount = %v, want 3", claims.KeyCount)
	}
	if claims.OperationCount != 3 {
		t.Errorf("OperationCount = %v, want 3", claims.OperationCount)
	}
	if claims.ZoneCount != 1 {
		t.Errorf("ZoneCount = %v, want 1", claims.ZoneCount)
	}
	if claims.DistributionTTL != "5m0s" {
		t.Errorf("DistributionTTL = %v, want 5m0s", claims.DistributionTTL)
	}
	if claims.RetireTime != "2m0s" {
		t.Errorf("RetireTime = %v, want 2m0s", claims.RetireTime)
	}

	// Verify payload was base64 encoded
	if claims.Payload == "" {
		t.Error("Payload should be set")
	}
	decoded, err := base64.StdEncoding.DecodeString(claims.Payload)
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}
	if string(decoded) != "test payload" {
		t.Errorf("Decoded payload = %q, want 'test payload'", decoded)
	}
}

func TestConvertJWTClaimsToManifestData(t *testing.T) {
	payload := []byte("converted payload")
	claims := &JWTManifestClaims{
		Issuer:          "kdc",
		Subject:         "distribution",
		IssuedAt:        1234567890,
		DistributionID:  "dist-abc",
		ReceiverID:      "node4.example.com.",
		Content:         "mgmt_operations",
		Crypto:          "hpke",
		ChunkCount:      1,
		ChunkSize:       50000,
		ChunkHash:       "sha256:xyz789",
		KeyCount:        0,
		OperationCount:  1,
		ZoneCount:       0,
		DistributionTTL: "10m0s",
		RetireTime:      "5m0s",
	}

	md := ConvertJWTClaimsToManifestData(claims, payload)

	// Verify conversion
	if md.ChunkCount != 1 {
		t.Errorf("ChunkCount = %v, want 1", md.ChunkCount)
	}
	if md.ChunkSize != 50000 {
		t.Errorf("ChunkSize = %v, want 50000", md.ChunkSize)
	}
	if string(md.Payload) != string(payload) {
		t.Errorf("Payload = %q, want %q", md.Payload, payload)
	}

	// Verify metadata
	if md.Metadata["distribution_id"] != "dist-abc" {
		t.Errorf("Metadata[distribution_id] = %v, want dist-abc", md.Metadata["distribution_id"])
	}
	if md.Metadata["receiver_id"] != "node4.example.com." {
		t.Errorf("Metadata[receiver_id] = %v, want node4.example.com.", md.Metadata["receiver_id"])
	}
	if md.Metadata["content"] != "mgmt_operations" {
		t.Errorf("Metadata[content] = %v, want mgmt_operations", md.Metadata["content"])
	}
	if md.Metadata["crypto"] != "hpke" {
		t.Errorf("Metadata[crypto] = %v, want hpke", md.Metadata["crypto"])
	}
	if md.Metadata["timestamp"] != int64(1234567890) {
		t.Errorf("Metadata[timestamp] = %v, want 1234567890", md.Metadata["timestamp"])
	}
}

func TestEstimateJWTManifestSize(t *testing.T) {
	claims := &JWTManifestClaims{
		Issuer:         "kdc",
		Subject:        "distribution",
		IssuedAt:       time.Now().Unix(),
		DistributionID: "dist-size-test",
		ReceiverID:     "node.example.com.",
		Content:        "key_operations",
		ChunkCount:     0,
	}

	size := EstimateJWTManifestSize(claims)

	// Size should be reasonable
	if size < 100 || size > 1000 {
		t.Errorf("EstimateJWTManifestSize returned unexpected size: %d", size)
	}

	// Adding payload should increase size
	claims.Payload = base64.StdEncoding.EncodeToString(make([]byte, 100))
	sizeWithPayload := EstimateJWTManifestSize(claims)

	if sizeWithPayload <= size {
		t.Errorf("Size with payload (%d) should be greater than without (%d)", sizeWithPayload, size)
	}
}

func TestShouldIncludePayloadInlineJWT(t *testing.T) {
	baseClaims := &JWTManifestClaims{
		Issuer:         "kdc",
		Subject:        "distribution",
		IssuedAt:       time.Now().Unix(),
		DistributionID: "dist-inline-test",
		ReceiverID:     "node.example.com.",
		Content:        "mgmt_operations",
	}

	tests := []struct {
		name        string
		payloadSize int
		wantInline  bool
	}{
		{
			name:        "small payload should be inline",
			payloadSize: 100,
			wantInline:  true,
		},
		{
			name:        "medium payload should be inline",
			payloadSize: 400,
			wantInline:  true,
		},
		{
			name:        "large payload should not be inline",
			payloadSize: 600,
			wantInline:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldIncludePayloadInlineJWT(tt.payloadSize, baseClaims)
			if got != tt.wantInline {
				t.Errorf("ShouldIncludePayloadInlineJWT(%d) = %v, want %v", tt.payloadSize, got, tt.wantInline)
			}
		})
	}
}

func TestCreateJWTManifest_NilErrors(t *testing.T) {
	backend := &mockBackend{name: "mock"}
	privKey := &mockPrivateKey{}
	claims := &JWTManifestClaims{
		Issuer:         "kdc",
		DistributionID: "test",
		ReceiverID:     "node",
		Content:        "test",
	}

	// Nil claims
	_, err := CreateJWTManifest(nil, privKey, backend)
	if err == nil {
		t.Error("Expected error for nil claims")
	}

	// Nil signing key
	_, err = CreateJWTManifest(claims, nil, backend)
	if err == nil {
		t.Error("Expected error for nil signing key")
	}

	// Nil backend
	_, err = CreateJWTManifest(claims, privKey, nil)
	if err == nil {
		t.Error("Expected error for nil backend")
	}
}

func TestCreateJWTManifest_WithMockBackend(t *testing.T) {
	backend := &mockBackend{name: "mock"}
	privKey := &mockPrivateKey{}

	claims := &JWTManifestClaims{
		Issuer:         "kdc",
		DistributionID: "dist-jwt-test",
		ReceiverID:     "node.example.com.",
		Content:        "key_operations",
		Crypto:         "mock",
		ChunkCount:     2,
		ChunkSize:      25000,
	}

	chunk, err := CreateJWTManifest(claims, privKey, backend)
	if err != nil {
		t.Fatalf("CreateJWTManifest failed: %v", err)
	}

	// Verify chunk properties
	if chunk.Format != core.FormatJWT {
		t.Errorf("Format = %d, want %d (FormatJWT)", chunk.Format, core.FormatJWT)
	}
	if chunk.Sequence != 0 {
		t.Errorf("Sequence = %d, want 0", chunk.Sequence)
	}
	if chunk.Total != claims.ChunkCount {
		t.Errorf("Total = %d, want %d", chunk.Total, claims.ChunkCount)
	}
	if len(chunk.Data) == 0 {
		t.Error("Data should not be empty")
	}
	// JWT has no separate HMAC (signature is in the JWT itself)
	if chunk.HMACLen != 0 {
		t.Errorf("HMACLen = %d, want 0 for JWT", chunk.HMACLen)
	}
}

func TestCreateJWTManifest_SetsDefaultClaims(t *testing.T) {
	backend := &mockBackend{name: "mock"}
	privKey := &mockPrivateKey{}

	claims := &JWTManifestClaims{
		DistributionID: "dist-defaults",
		ReceiverID:     "node",
		Content:        "test",
		// Subject and IssuedAt not set
	}

	_, err := CreateJWTManifest(claims, privKey, backend)
	if err != nil {
		t.Fatalf("CreateJWTManifest failed: %v", err)
	}

	// Verify defaults were set
	if claims.Subject != "distribution" {
		t.Errorf("Subject = %v, want 'distribution'", claims.Subject)
	}
	if claims.IssuedAt == 0 {
		t.Error("IssuedAt should be set")
	}
}

func TestExtractJWTManifestData_Errors(t *testing.T) {
	backend := &mockBackend{name: "mock"}
	pubKey := &mockPublicKey{}

	tests := []struct {
		name    string
		chunk   *core.CHUNK
		wantErr bool
	}{
		{
			name: "non-manifest chunk",
			chunk: &core.CHUNK{
				Format:   core.FormatJWT,
				Sequence: 1, // Not a manifest
				Data:     []byte("test"),
			},
			wantErr: true,
		},
		{
			name: "wrong format",
			chunk: &core.CHUNK{
				Format:   core.FormatJSON,
				Sequence: 0,
				Data:     []byte("{}"),
			},
			wantErr: true,
		},
		{
			name: "invalid JWS format",
			chunk: &core.CHUNK{
				Format:   core.FormatJWT,
				Sequence: 0,
				Data:     []byte("not.a.valid.jws.format"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExtractJWTManifestData(tt.chunk, pubKey, backend)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractJWTManifestData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExtractJWTManifestData_NilErrors(t *testing.T) {
	backend := &mockBackend{name: "mock"}
	pubKey := &mockPublicKey{}
	chunk := &core.CHUNK{
		Format:   core.FormatJWT,
		Sequence: 0,
		Data:     []byte("header.payload.signature"),
	}

	// Nil verification key
	_, err := ExtractJWTManifestData(chunk, nil, backend)
	if err == nil {
		t.Error("Expected error for nil verification key")
	}

	// Nil backend
	_, err = ExtractJWTManifestData(chunk, pubKey, nil)
	if err == nil {
		t.Error("Expected error for nil backend")
	}
}

func TestRoundtripConversion(t *testing.T) {
	// Test that converting ManifestData -> JWTClaims -> ManifestData preserves data
	original := &ManifestData{
		ChunkCount: 5,
		ChunkSize:  20000,
		Metadata: map[string]interface{}{
			"distribution_id":  "roundtrip-test",
			"receiver_id":      "node.example.com.",
			"content":          "key_operations",
			"crypto":           "jose",
			"timestamp":        float64(1234567890),
			"key_count":        float64(10),
			"operation_count":  float64(10),
			"zone_count":       float64(3),
			"distribution_ttl": "5m0s",
			"retire_time":      "2m0s",
			"chunk_hash":       "sha256:abc",
		},
		Payload: []byte("roundtrip payload"),
	}

	// Convert to JWT claims
	claims := ConvertManifestDataToJWTClaims(original, "kdc")

	// Decode payload from claims
	payload, err := base64.StdEncoding.DecodeString(claims.Payload)
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	// Convert back to ManifestData
	converted := ConvertJWTClaimsToManifestData(claims, payload)

	// Verify key fields are preserved
	if converted.ChunkCount != original.ChunkCount {
		t.Errorf("ChunkCount = %v, want %v", converted.ChunkCount, original.ChunkCount)
	}
	if converted.ChunkSize != original.ChunkSize {
		t.Errorf("ChunkSize = %v, want %v", converted.ChunkSize, original.ChunkSize)
	}
	if string(converted.Payload) != string(original.Payload) {
		t.Errorf("Payload = %q, want %q", converted.Payload, original.Payload)
	}
	if converted.Metadata["distribution_id"] != original.Metadata["distribution_id"] {
		t.Errorf("distribution_id = %v, want %v", converted.Metadata["distribution_id"], original.Metadata["distribution_id"])
	}
	if converted.Metadata["content"] != original.Metadata["content"] {
		t.Errorf("content = %v, want %v", converted.Metadata["content"], original.Metadata["content"])
	}
}
