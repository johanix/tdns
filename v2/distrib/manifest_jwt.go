/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * JWT manifest format for CHUNK-based distribution framework.
 * Provides signed manifest with flattened claims structure.
 *
 * JWT Manifest Structure (flattened claims):
 *   - iss: Issuer (sender ID)
 *   - sub: Subject ("distribution")
 *   - iat: Issued at (Unix timestamp)
 *   - distribution_id: Unique distribution identifier
 *   - receiver_id: Intended recipient
 *   - content: Content type (e.g., "mgmt_operations")
 *   - crypto: Crypto backend used (e.g., "jose", "hpke")
 *   - chunk_count: Number of data chunks (0 = inline payload)
 *   - chunk_size: Size of each chunk
 *   - chunk_hash: SHA-256 hash of all chunk data
 *   - payload: Base64-encoded payload (only when inlined)
 *   - ... additional application-specific claims
 */

package distrib

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/crypto"
)

// DefaultJWTExpiration is the default JWT expiration duration (24 hours)
const DefaultJWTExpiration = 24 * time.Hour

// MaxJWTExpiration is the maximum allowed JWT expiration duration (7 days)
const MaxJWTExpiration = 7 * 24 * time.Hour

// AllowedJWTAlgorithms is the set of algorithms accepted for JWT verification.
// HMAC-based algorithms ("HS256", "HS384", "HS512") and "none" are rejected.
var AllowedJWTAlgorithms = map[string]bool{
	"EdDSA": true,
	"ES256": true,
	"ES384": true,
	"ES512": true,
}

// JWTManifestClaims represents the flattened JWT claims for a distribution manifest.
// All metadata fields are top-level claims rather than nested in a "metadata" object.
type JWTManifestClaims struct {
	// Standard JWT claims
	Issuer    string `json:"iss,omitempty"` // Sender ID
	Subject   string `json:"sub,omitempty"` // "distribution"
	IssuedAt  int64  `json:"iat,omitempty"` // Unix timestamp
	ExpiresAt int64  `json:"exp,omitempty"` // Expiration (Unix timestamp)

	// Distribution identification
	DistributionID string `json:"distribution_id"`
	ReceiverID     string `json:"receiver_id"`

	// Content description
	Content string `json:"content"`          // Content type (e.g., "mgmt_operations")
	Crypto  string `json:"crypto,omitempty"` // Crypto backend (e.g., "jose")

	// Chunk information
	ChunkCount uint16 `json:"chunk_count"`          // Number of data chunks (0 = inline)
	ChunkSize  uint16 `json:"chunk_size,omitempty"` // Size per chunk
	ChunkHash  string `json:"chunk_hash,omitempty"` // SHA-256 hash of chunk data

	// Optional inline payload (base64-encoded)
	// Present only when payload is small enough to fit in manifest
	Payload string `json:"payload,omitempty"`

	// Application-specific counts (flattened from metadata)
	KeyCount       int `json:"key_count,omitempty"`
	OperationCount int `json:"operation_count,omitempty"`
	ZoneCount      int `json:"zone_count,omitempty"`

	// TTL/timing
	DistributionTTL string `json:"distribution_ttl,omitempty"`
	RetireTime      string `json:"retire_time,omitempty"`
}

// JWTManifestData is the internal representation used for creating/extracting JWT manifests.
// It mirrors ManifestData but with the flattened structure.
type JWTManifestData struct {
	Claims  JWTManifestClaims
	Payload []byte // Decoded payload (if inlined)
}

// CreateJWTManifest creates a signed JWT manifest CHUNK record.
// The JWT is signed using the provided signing key.
//
// Parameters:
//   - claims: The manifest claims (flattened structure)
//   - signingKey: Key to sign the JWT
//   - backend: Crypto backend for signing
//
// Returns:
//   - A CHUNK record with Format=FormatJWT, or error
func CreateJWTManifest(claims *JWTManifestClaims, signingKey crypto.PrivateKey, backend crypto.Backend) (*core.CHUNK, error) {
	if claims == nil {
		return nil, fmt.Errorf("claims cannot be nil")
	}
	if signingKey == nil {
		return nil, fmt.Errorf("signing key cannot be nil")
	}
	if backend == nil {
		return nil, fmt.Errorf("backend cannot be nil")
	}

	// Set standard claims if not set
	if claims.Subject == "" {
		claims.Subject = "distribution"
	}
	now := time.Now()
	if claims.IssuedAt == 0 {
		claims.IssuedAt = now.Unix()
	}
	if claims.ExpiresAt == 0 {
		claims.ExpiresAt = now.Add(DefaultJWTExpiration).Unix()
	}

	// Marshal claims to JSON
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWT claims: %w", err)
	}

	// Sign the claims to create JWS
	jws, err := backend.Sign(signingKey, claimsJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWT: %w", err)
	}

	// Create CHUNK record
	chunk := &core.CHUNK{
		Format:     core.FormatJWT,
		HMACLen:    0, // JWT has its own signature, no separate HMAC needed
		HMAC:       nil,
		Sequence:   0,                 // Manifest is always sequence 0
		Total:      claims.ChunkCount, // Total data chunks
		DataLength: uint16(len(jws)),
		Data:       jws,
	}

	return chunk, nil
}

// ExtractJWTManifestData extracts and verifies a JWT manifest from a CHUNK record.
// The JWT signature is verified using the provided verification key.
//
// Parameters:
//   - chunk: The CHUNK record (must have Format=FormatJWT, Sequence=0)
//   - verificationKey: Public key to verify the JWT signature
//   - backend: Crypto backend for verification
//
// Returns:
//   - The extracted JWTManifestData, or error if verification fails
func ExtractJWTManifestData(chunk *core.CHUNK, verificationKey crypto.PublicKey, backend crypto.Backend) (*JWTManifestData, error) {
	if chunk.Sequence != 0 {
		return nil, fmt.Errorf("ExtractJWTManifestData can only be called for manifest chunks (Sequence=0), got Sequence=%d", chunk.Sequence)
	}

	if chunk.Format != core.FormatJWT {
		return nil, fmt.Errorf("expected FormatJWT (%d), got format %d", core.FormatJWT, chunk.Format)
	}

	if verificationKey == nil {
		return nil, fmt.Errorf("verification key cannot be nil")
	}
	if backend == nil {
		return nil, fmt.Errorf("backend cannot be nil")
	}

	// Parse JWS to extract payload
	jws := chunk.Data
	parts := strings.Split(string(jws), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWS format: expected 3 parts, got %d", len(parts))
	}

	// Decode and validate JWT header for allowed algorithm (M39)
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("failed to parse JWT header: %w", err)
	}
	if !AllowedJWTAlgorithms[header.Alg] {
		return nil, fmt.Errorf("JWT algorithm %q is not in the allowed list", header.Alg)
	}

	// Decode the payload (claims)
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Verify the signature
	valid, err := backend.Verify(verificationKey, claimsJSON, jws)
	if err != nil {
		return nil, fmt.Errorf("failed to verify JWT signature: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("JWT signature verification failed")
	}

	// Parse claims
	var claims JWTManifestClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// Validate expiration claim (H22)
	if claims.ExpiresAt > 0 {
		if time.Now().Unix() > claims.ExpiresAt {
			return nil, fmt.Errorf("JWT has expired (exp=%d, now=%d)", claims.ExpiresAt, time.Now().Unix())
		}
	}

	// Decode inline payload if present
	var payload []byte
	if claims.Payload != "" {
		payload, err = base64.StdEncoding.DecodeString(claims.Payload)
		if err != nil {
			return nil, fmt.Errorf("failed to decode inline payload: %w", err)
		}
	}

	return &JWTManifestData{
		Claims:  claims,
		Payload: payload,
	}, nil
}

// ConvertManifestDataToJWTClaims converts the legacy ManifestData structure to JWTManifestClaims.
// This is useful for migration from JSON format to JWT format.
func ConvertManifestDataToJWTClaims(md *ManifestData, senderID string) *JWTManifestClaims {
	claims := &JWTManifestClaims{
		Issuer:     senderID,
		Subject:    "distribution",
		IssuedAt:   time.Now().Unix(),
		ChunkCount: md.ChunkCount,
		ChunkSize:  md.ChunkSize,
	}

	// Extract fields from metadata map
	if md.Metadata != nil {
		if v, ok := md.Metadata["distribution_id"].(string); ok {
			claims.DistributionID = v
		}
		if v, ok := md.Metadata["receiver_id"].(string); ok {
			claims.ReceiverID = v
		}
		if v, ok := md.Metadata["content"].(string); ok {
			claims.Content = v
		}
		if v, ok := md.Metadata["crypto"].(string); ok {
			claims.Crypto = v
		}
		if v, ok := md.Metadata["chunk_hash"].(string); ok {
			claims.ChunkHash = v
		}
		// Handle counts - may be int or float64 from JSON
		if v, ok := md.Metadata["key_count"].(int); ok {
			claims.KeyCount = v
		} else if v, ok := md.Metadata["key_count"].(float64); ok {
			claims.KeyCount = int(v)
		}
		if v, ok := md.Metadata["operation_count"].(int); ok {
			claims.OperationCount = v
		} else if v, ok := md.Metadata["operation_count"].(float64); ok {
			claims.OperationCount = int(v)
		}
		if v, ok := md.Metadata["zone_count"].(int); ok {
			claims.ZoneCount = v
		} else if v, ok := md.Metadata["zone_count"].(float64); ok {
			claims.ZoneCount = int(v)
		}
		if v, ok := md.Metadata["distribution_ttl"].(string); ok {
			claims.DistributionTTL = v
		}
		if v, ok := md.Metadata["retire_time"].(string); ok {
			claims.RetireTime = v
		}
		// Timestamp -> iat
		if v, ok := md.Metadata["timestamp"].(int64); ok {
			claims.IssuedAt = v
		} else if v, ok := md.Metadata["timestamp"].(float64); ok {
			claims.IssuedAt = int64(v)
		}
	}

	// Handle inline payload
	if len(md.Payload) > 0 {
		claims.Payload = base64.StdEncoding.EncodeToString(md.Payload)
	}

	return claims
}

// ConvertJWTClaimsToManifestData converts JWTManifestClaims back to the legacy ManifestData structure.
// This is useful for backwards compatibility with code that expects ManifestData.
func ConvertJWTClaimsToManifestData(claims *JWTManifestClaims, payload []byte) *ManifestData {
	metadata := map[string]interface{}{
		"distribution_id": claims.DistributionID,
		"receiver_id":     claims.ReceiverID,
		"content":         claims.Content,
		"timestamp":       claims.IssuedAt,
	}

	if claims.Crypto != "" {
		metadata["crypto"] = claims.Crypto
	}
	if claims.ChunkHash != "" {
		metadata["chunk_hash"] = claims.ChunkHash
	}
	if claims.KeyCount > 0 {
		metadata["key_count"] = claims.KeyCount
	}
	if claims.OperationCount > 0 {
		metadata["operation_count"] = claims.OperationCount
	}
	if claims.ZoneCount > 0 {
		metadata["zone_count"] = claims.ZoneCount
	}
	if claims.DistributionTTL != "" {
		metadata["distribution_ttl"] = claims.DistributionTTL
	}
	if claims.RetireTime != "" {
		metadata["retire_time"] = claims.RetireTime
	}

	return &ManifestData{
		ChunkCount: claims.ChunkCount,
		ChunkSize:  claims.ChunkSize,
		Metadata:   metadata,
		Payload:    payload,
	}
}

// EstimateJWTManifestSize estimates the size of a JWT manifest with given claims.
// Used to determine if payload should be inlined.
func EstimateJWTManifestSize(claims *JWTManifestClaims) int {
	// Marshal claims to get base size
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return 1000 // Fallback estimate
	}

	// JWT overhead: header (~50 bytes) + signature (~100 bytes for ECDSA) + 2 dots
	// Plus base64 encoding overhead (~33%)
	jwtOverhead := 150
	base64Overhead := len(claimsJSON) / 3

	// CHUNK header: Format(1) + HMACLen(2) + Sequence(2) + Total(2) + DataLength(2)
	chunkHeaderSize := 9

	return chunkHeaderSize + len(claimsJSON) + jwtOverhead + base64Overhead
}

// ShouldIncludePayloadInlineJWT determines if payload should be inlined in JWT manifest.
// DEPRECATED: This function uses hardcoded UDP-era thresholds (500/1200 bytes).
// For TCP transport, use ShouldIncludePayloadInlineJWTWithLimit instead.
//
// Parameters:
//   - payloadSize: Size of the raw payload in bytes (will be base64-encoded in JWT)
//   - claims: The JWT claims (used to estimate total size)
//
// Returns:
//   - true if payload should be included inline, false if it should be chunked
func ShouldIncludePayloadInlineJWT(payloadSize int, claims *JWTManifestClaims) bool {
	const inlinePayloadThreshold = 500 // Max payload size for inline (legacy UDP limit)
	const maxTotalSize = 1200          // Max total manifest size (legacy UDP limit)

	// Create test claims with payload to estimate size
	testClaims := *claims
	testClaims.Payload = base64.StdEncoding.EncodeToString(make([]byte, payloadSize))

	estimatedSize := EstimateJWTManifestSize(&testClaims)

	return payloadSize <= inlinePayloadThreshold && estimatedSize < maxTotalSize
}

// ShouldIncludePayloadInlineJWTWithLimit determines if payload should be inlined in JWT manifest.
// Returns true if the estimated JWT manifest size (including payload) fits within maxSize.
//
// Parameters:
//   - payloadSize: Size of the raw payload in bytes (will be base64-encoded in JWT)
//   - claims: The JWT claims (used to estimate total size)
//   - maxSize: Maximum allowed manifest size (from config, typically up to 64KB for TCP)
//
// Returns:
//   - true if payload should be included inline, false if it should be chunked
func ShouldIncludePayloadInlineJWTWithLimit(payloadSize int, claims *JWTManifestClaims, maxSize int) bool {
	// Create test claims with payload to estimate size
	testClaims := *claims
	testClaims.Payload = base64.StdEncoding.EncodeToString(make([]byte, payloadSize))

	estimatedSize := EstimateJWTManifestSize(&testClaims)

	return estimatedSize <= maxSize
}

// String returns a human-readable representation of JWT manifest claims.
// Useful for logging and debugging.
func (c *JWTManifestClaims) String() string {
	var sb strings.Builder
	sb.WriteString("JWTManifest{\n")
	sb.WriteString(fmt.Sprintf("  iss: %s\n", c.Issuer))
	sb.WriteString(fmt.Sprintf("  sub: %s\n", c.Subject))
	sb.WriteString(fmt.Sprintf("  iat: %d (%s)\n", c.IssuedAt, time.Unix(c.IssuedAt, 0).Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("  distribution_id: %s\n", c.DistributionID))
	sb.WriteString(fmt.Sprintf("  receiver_id: %s\n", c.ReceiverID))
	sb.WriteString(fmt.Sprintf("  content: %s\n", c.Content))
	if c.Crypto != "" {
		sb.WriteString(fmt.Sprintf("  crypto: %s\n", c.Crypto))
	}
	sb.WriteString(fmt.Sprintf("  chunk_count: %d\n", c.ChunkCount))
	if c.ChunkSize > 0 {
		sb.WriteString(fmt.Sprintf("  chunk_size: %d\n", c.ChunkSize))
	}
	if c.ChunkHash != "" {
		sb.WriteString(fmt.Sprintf("  chunk_hash: %s\n", c.ChunkHash))
	}
	if c.KeyCount > 0 {
		sb.WriteString(fmt.Sprintf("  key_count: %d\n", c.KeyCount))
	}
	if c.OperationCount > 0 {
		sb.WriteString(fmt.Sprintf("  operation_count: %d\n", c.OperationCount))
	}
	if c.ZoneCount > 0 {
		sb.WriteString(fmt.Sprintf("  zone_count: %d\n", c.ZoneCount))
	}
	if c.DistributionTTL != "" {
		sb.WriteString(fmt.Sprintf("  distribution_ttl: %s\n", c.DistributionTTL))
	}
	if c.RetireTime != "" {
		sb.WriteString(fmt.Sprintf("  retire_time: %s\n", c.RetireTime))
	}
	if c.Payload != "" {
		sb.WriteString(fmt.Sprintf("  payload: <%d bytes base64>\n", len(c.Payload)))
	}
	sb.WriteString("}")
	return sb.String()
}

// Summary returns a single-line summary of JWT manifest claims for logging.
func (c *JWTManifestClaims) Summary() string {
	return fmt.Sprintf("dist=%s receiver=%s content=%s crypto=%s chunks=%d ops=%d",
		c.DistributionID, c.ReceiverID, c.Content, c.Crypto, c.ChunkCount, c.OperationCount)
}

// DecodeJWTManifestForDisplay decodes a JWT manifest from a CHUNK record WITHOUT verification.
// This is intended ONLY for display/debugging purposes - never use this for processing!
// For actual manifest extraction with signature verification, use ExtractJWTManifestData.
//
// Parameters:
//   - chunk: The CHUNK record (must have Format=FormatJWT, Sequence=0)
//
// Returns:
//   - The decoded JWTManifestClaims (unverified!), or error if decoding fails
func DecodeJWTManifestForDisplay(chunk *core.CHUNK) (*JWTManifestClaims, error) {
	if chunk.Sequence != 0 {
		return nil, fmt.Errorf("not a manifest chunk (Sequence=%d)", chunk.Sequence)
	}

	if chunk.Format != core.FormatJWT {
		return nil, fmt.Errorf("not a JWT manifest (Format=%d)", chunk.Format)
	}

	// Parse JWS to extract payload (without verification)
	jws := chunk.Data
	parts := strings.Split(string(jws), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWS format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (claims)
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse claims
	var claims JWTManifestClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	return &claims, nil
}

// FormatJWTManifestForDisplay formats a JWT manifest CHUNK for human-readable display.
// This decodes the JWT WITHOUT verification - for display only!
func FormatJWTManifestForDisplay(chunk *core.CHUNK) string {
	claims, err := DecodeJWTManifestForDisplay(chunk)
	if err != nil {
		return fmt.Sprintf("<error decoding JWT: %v>", err)
	}
	return claims.String()
}
