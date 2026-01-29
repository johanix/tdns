/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Cryptographic integration for DNS transport payloads.
 * Provides JWS/JWE encryption and signing for secure agent-to-agent communication.
 *
 * This module wraps the tdns/v2/crypto backend to provide:
 * - Payload encryption using JWE (confidentiality)
 * - Payload signing using JWS (authenticity)
 * - Combined JWS(JWE) for authenticated encryption
 *
 * The encrypted payloads are base64-encoded for embedding in DNS EDNS0 CHUNK options.
 */

package transport

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/johanix/tdns/v2/crypto"
)

// PayloadCrypto handles encryption and signing of DNS transport payloads.
// It wraps a crypto.Backend to provide a simple interface for the DNS transport.
type PayloadCrypto struct {
	// Backend is the cryptographic backend (e.g., JOSE, HPKE)
	Backend crypto.Backend

	// LocalPrivateKey is our private key for decryption and signing
	LocalPrivateKey crypto.PrivateKey

	// LocalPublicKey is our public key (for key exchange)
	LocalPublicKey crypto.PublicKey

	// SigningKey is the key used for signing (may be same as LocalPrivateKey for JOSE)
	SigningKey crypto.PrivateKey

	// VerificationKey is our public key for signature verification
	VerificationKey crypto.PublicKey

	// PeerKeys maps peer IDs to their public keys for encryption
	PeerKeys map[string]crypto.PublicKey

	// PeerVerificationKeys maps peer IDs to their verification keys for signature verification
	PeerVerificationKeys map[string]crypto.PublicKey

	// Enabled indicates if encryption is enabled
	Enabled bool
}

// PayloadCryptoConfig holds configuration for creating a PayloadCrypto instance.
type PayloadCryptoConfig struct {
	Backend      crypto.Backend
	Enabled      bool
	AutoGenerate bool // If true, generate keypair if not provided
}

// NewPayloadCrypto creates a new PayloadCrypto instance.
func NewPayloadCrypto(cfg *PayloadCryptoConfig) (*PayloadCrypto, error) {
	if cfg.Backend == nil && cfg.Enabled {
		return nil, fmt.Errorf("crypto backend is required when encryption is enabled")
	}

	pc := &PayloadCrypto{
		Backend:              cfg.Backend,
		Enabled:              cfg.Enabled,
		PeerKeys:             make(map[string]crypto.PublicKey),
		PeerVerificationKeys: make(map[string]crypto.PublicKey),
	}

	// Generate keypair if enabled and requested
	if cfg.Enabled && cfg.AutoGenerate && cfg.Backend != nil {
		privKey, pubKey, err := cfg.Backend.GenerateKeypair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate keypair: %w", err)
		}
		pc.LocalPrivateKey = privKey
		pc.LocalPublicKey = pubKey
		pc.SigningKey = privKey
		pc.VerificationKey = pubKey
	}

	return pc, nil
}

// SetLocalKeys sets the local private and public keys.
func (pc *PayloadCrypto) SetLocalKeys(privKey crypto.PrivateKey, pubKey crypto.PublicKey) {
	pc.LocalPrivateKey = privKey
	pc.LocalPublicKey = pubKey
	pc.SigningKey = privKey
	pc.VerificationKey = pubKey
}

// AddPeerKey adds a peer's public key for encryption.
func (pc *PayloadCrypto) AddPeerKey(peerID string, pubKey crypto.PublicKey) {
	pc.PeerKeys[peerID] = pubKey
}

// AddPeerVerificationKey adds a peer's public key for signature verification.
func (pc *PayloadCrypto) AddPeerVerificationKey(peerID string, pubKey crypto.PublicKey) {
	pc.PeerVerificationKeys[peerID] = pubKey
}

// GetPeerKey retrieves a peer's public key for encryption.
func (pc *PayloadCrypto) GetPeerKey(peerID string) (crypto.PublicKey, bool) {
	key, exists := pc.PeerKeys[peerID]
	return key, exists
}

// GetPeerVerificationKey retrieves a peer's public key for signature verification.
func (pc *PayloadCrypto) GetPeerVerificationKey(peerID string) (crypto.PublicKey, bool) {
	key, exists := pc.PeerVerificationKeys[peerID]
	return key, exists
}

// EncryptPayload encrypts a payload for a specific peer.
// Returns base64-encoded ciphertext.
// If encryption is disabled, returns the original payload as-is.
func (pc *PayloadCrypto) EncryptPayload(peerID string, payload []byte) ([]byte, error) {
	if !pc.Enabled {
		return payload, nil
	}

	peerKey, exists := pc.PeerKeys[peerID]
	if !exists {
		return nil, fmt.Errorf("no encryption key for peer %s", peerID)
	}

	ciphertext, err := pc.Backend.Encrypt(peerKey, payload)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	return []byte(base64.StdEncoding.EncodeToString(ciphertext)), nil
}

// DecryptPayload decrypts a payload received from a peer.
// Expects base64-encoded ciphertext.
// If encryption is disabled, returns the original payload as-is.
func (pc *PayloadCrypto) DecryptPayload(payload []byte) ([]byte, error) {
	if !pc.Enabled {
		return payload, nil
	}

	if pc.LocalPrivateKey == nil {
		return nil, fmt.Errorf("no private key configured for decryption")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(string(payload))
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	plaintext, err := pc.Backend.Decrypt(pc.LocalPrivateKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// SignPayload signs a payload and returns JWS format.
// Returns base64-encoded JWS.
// If encryption is disabled, returns the original payload as-is.
func (pc *PayloadCrypto) SignPayload(payload []byte) ([]byte, error) {
	if !pc.Enabled {
		return payload, nil
	}

	if pc.SigningKey == nil {
		return nil, fmt.Errorf("no signing key configured")
	}

	jws, err := pc.Backend.Sign(pc.SigningKey, payload)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return []byte(base64.StdEncoding.EncodeToString(jws)), nil
}

// VerifyPayload verifies a signed payload from a peer.
// Expects base64-encoded JWS.
// If encryption is disabled, returns the original payload as-is.
func (pc *PayloadCrypto) VerifyPayload(peerID string, signedPayload []byte, originalData []byte) (bool, error) {
	if !pc.Enabled {
		return true, nil
	}

	verifyKey, exists := pc.PeerVerificationKeys[peerID]
	if !exists {
		return false, fmt.Errorf("no verification key for peer %s", peerID)
	}

	jws, err := base64.StdEncoding.DecodeString(string(signedPayload))
	if err != nil {
		return false, fmt.Errorf("base64 decode failed: %w", err)
	}

	valid, err := pc.Backend.Verify(verifyKey, originalData, jws)
	if err != nil {
		return false, fmt.Errorf("verification failed: %w", err)
	}

	return valid, nil
}

// EncryptAndSignPayload creates authenticated encrypted payload: JWS(JWE(payload)).
// Returns base64-encoded JWS.
// If encryption is disabled, returns the original payload as-is.
func (pc *PayloadCrypto) EncryptAndSignPayload(peerID string, payload []byte, metadata map[string]interface{}) ([]byte, error) {
	if !pc.Enabled {
		return payload, nil
	}

	peerKey, exists := pc.PeerKeys[peerID]
	if !exists {
		return nil, fmt.Errorf("no encryption key for peer %s", peerID)
	}

	if pc.SigningKey == nil {
		return nil, fmt.Errorf("no signing key configured")
	}

	// Add default metadata if not provided
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	if _, exists := metadata["timestamp"]; !exists {
		metadata["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	}

	// Step 1: Encrypt with JWE (multi-recipient capable)
	recipients := []crypto.PublicKey{peerKey}
	jwe, err := pc.Backend.EncryptMultiRecipient(recipients, payload, metadata)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Step 2: Sign the JWE with JWS
	jws, err := pc.Backend.Sign(pc.SigningKey, jwe)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return []byte(base64.StdEncoding.EncodeToString(jws)), nil
}

// DecryptAndVerifyPayload verifies and decrypts JWS(JWE(payload)).
// Expects base64-encoded JWS.
// Returns the decrypted plaintext payload.
// If encryption is disabled, returns the original payload as-is.
func (pc *PayloadCrypto) DecryptAndVerifyPayload(peerID string, encodedPayload []byte) ([]byte, error) {
	if !pc.Enabled {
		return encodedPayload, nil
	}

	if pc.LocalPrivateKey == nil {
		return nil, fmt.Errorf("no private key configured for decryption")
	}

	verifyKey, exists := pc.PeerVerificationKeys[peerID]
	if !exists {
		return nil, fmt.Errorf("no verification key for peer %s", peerID)
	}

	// Decode base64 to get JWS
	jws, err := base64.StdEncoding.DecodeString(string(encodedPayload))
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	// Parse JWS to extract JWE payload
	parts := splitJWS(jws)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWS format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (which is the JWE)
	jwe, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWS payload: %w", err)
	}

	// Verify the JWS signature
	valid, err := pc.Backend.Verify(verifyKey, jwe, jws)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("signature verification failed: invalid signature from peer %s", peerID)
	}

	// Decrypt the JWE
	plaintext, err := pc.Backend.DecryptMultiRecipient(pc.LocalPrivateKey, jwe)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// splitJWS splits a JWS Compact Serialization into its three parts.
// JWS format: <header>.<payload>.<signature>
func splitJWS(jws []byte) [][]byte {
	var parts [][]byte
	start := 0
	for i := 0; i < len(jws); i++ {
		if jws[i] == '.' {
			parts = append(parts, jws[start:i])
			start = i + 1
		}
	}
	if start < len(jws) {
		parts = append(parts, jws[start:])
	}
	return parts
}

// base64URLDecode decodes base64url (RFC 4648) data.
// JWS uses base64url encoding without padding.
func base64URLDecode(data []byte) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

// IsPayloadEncrypted checks if a payload appears to be encrypted (base64-encoded).
// This is a heuristic check - encrypted payloads won't start with '{' after decode attempt.
func IsPayloadEncrypted(payload []byte) bool {
	// Try to parse as JSON first - if it works, it's not encrypted
	var test interface{}
	if err := json.Unmarshal(payload, &test); err == nil {
		return false
	}

	// Check if it looks like base64
	if len(payload) == 0 {
		return false
	}

	// Try to decode as base64 - if successful and result isn't JSON, it's encrypted
	decoded, err := base64.StdEncoding.DecodeString(string(payload))
	if err != nil {
		return false
	}

	// If decoded bytes don't look like JSON, assume encrypted
	return len(decoded) > 0 && decoded[0] != '{'
}

// SecurePayloadWrapper wraps the payload crypto operations for use with DNS transport.
type SecurePayloadWrapper struct {
	crypto *PayloadCrypto
}

// NewSecurePayloadWrapper creates a new wrapper for secure payload handling.
func NewSecurePayloadWrapper(crypto *PayloadCrypto) *SecurePayloadWrapper {
	return &SecurePayloadWrapper{crypto: crypto}
}

// WrapOutgoing prepares an outgoing payload for a specific peer.
// If encryption is enabled, returns encrypted and signed payload.
// Otherwise returns the original payload.
func (w *SecurePayloadWrapper) WrapOutgoing(peerID string, payload []byte) ([]byte, error) {
	if w.crypto == nil || !w.crypto.Enabled {
		return payload, nil
	}

	metadata := map[string]interface{}{
		"peer_id":   peerID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	encrypted, err := w.crypto.EncryptAndSignPayload(peerID, payload, metadata)
	if err != nil {
		log.Printf("SecurePayloadWrapper: Encryption failed for peer %s: %v", peerID, err)
		return nil, err
	}

	return encrypted, nil
}

// UnwrapIncoming processes an incoming payload from a specific peer.
// If encryption is enabled, verifies and decrypts the payload.
// Otherwise returns the original payload.
func (w *SecurePayloadWrapper) UnwrapIncoming(peerID string, payload []byte) ([]byte, error) {
	if w.crypto == nil || !w.crypto.Enabled {
		return payload, nil
	}

	// Check if payload is encrypted
	if !IsPayloadEncrypted(payload) {
		log.Printf("SecurePayloadWrapper: Received unencrypted payload from peer %s when encryption is enabled", peerID)
		// For backward compatibility, we might accept unencrypted payloads
		// but this should be configurable
		return payload, nil
	}

	decrypted, err := w.crypto.DecryptAndVerifyPayload(peerID, payload)
	if err != nil {
		log.Printf("SecurePayloadWrapper: Decryption failed for peer %s: %v", peerID, err)
		return nil, err
	}

	return decrypted, nil
}

// IsEnabled returns true if encryption is enabled.
func (w *SecurePayloadWrapper) IsEnabled() bool {
	return w.crypto != nil && w.crypto.Enabled
}
