/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Transport layer for CHUNK-based distribution framework.
 * Provides encrypt/sign/encode functions for secure transport over DNS.
 *
 * Supports two transport modes:
 * - Simple encryption: Encrypt(plaintext) -> base64(ciphertext)
 * - Signed encryption: JWS(JWE(plaintext)) -> base64(JWS)
 *
 * The transport format uses base64 encoding for DNS-safe transmission.
 */

package distrib

import (
	"encoding/base64"
	"fmt"

	"github.com/johanix/tdns/v2/crypto"
)

// TransportEncoder defines the interface for encoding/decoding distribution payloads.
// This allows different transport mechanisms to be used (direct HPKE, JOSE, etc.)
type TransportEncoder interface {
	// Encode encrypts and encodes a payload for transport.
	// Returns base64-encoded ciphertext.
	Encode(recipientPubKey crypto.PublicKey, plaintext []byte) ([]byte, error)

	// Decode decodes and decrypts a transport-encoded payload.
	// Expects base64-encoded ciphertext.
	Decode(privateKey crypto.PrivateKey, encoded []byte) ([]byte, error)

	// EncodeWithSignature encrypts, signs, and encodes a payload.
	// Creates JWS(JWE(plaintext)) structure for authenticated encryption.
	// Returns base64-encoded JWS.
	EncodeWithSignature(recipientPubKey crypto.PublicKey, plaintext []byte, signingKey crypto.PrivateKey, metadata map[string]interface{}) ([]byte, error)

	// DecodeWithSignature decodes, verifies, and decrypts a signed payload.
	// Expects base64-encoded JWS(JWE) structure.
	DecodeWithSignature(privateKey crypto.PrivateKey, verificationKey crypto.PublicKey, encoded []byte) ([]byte, error)
}

// BackendTransportEncoder implements TransportEncoder using a crypto.Backend.
type BackendTransportEncoder struct {
	backend crypto.Backend
}

// NewTransportEncoder creates a new TransportEncoder using the specified crypto backend.
func NewTransportEncoder(backend crypto.Backend) TransportEncoder {
	return &BackendTransportEncoder{backend: backend}
}

// Encode encrypts plaintext and encodes it for transport.
// The transport format is: base64(<backend-specific ciphertext>)
func (e *BackendTransportEncoder) Encode(recipientPubKey crypto.PublicKey, plaintext []byte) ([]byte, error) {
	if e.backend == nil {
		return nil, fmt.Errorf("backend is nil")
	}

	ciphertext, err := e.backend.Encrypt(recipientPubKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt with %s backend: %w", e.backend.Name(), err)
	}

	return []byte(base64.StdEncoding.EncodeToString(ciphertext)), nil
}

// Decode decodes and decrypts a transport-encoded payload.
// Expects base64-encoded ciphertext in backend-specific format.
func (e *BackendTransportEncoder) Decode(privateKey crypto.PrivateKey, encoded []byte) ([]byte, error) {
	if e.backend == nil {
		return nil, fmt.Errorf("backend is nil")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	plaintext, err := e.backend.Decrypt(privateKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with %s backend: %w", e.backend.Name(), err)
	}

	return plaintext, nil
}

// EncodeWithSignature encrypts, signs, and encodes a payload.
// Creates JWS(JWE(plaintext)) structure:
// - Step 1: JWE encrypts the payload for the recipient(s)
// - Step 2: JWS signs the JWE structure with the sender's signing key
// This provides both confidentiality (JWE) and authenticity (JWS).
func (e *BackendTransportEncoder) EncodeWithSignature(recipientPubKey crypto.PublicKey, plaintext []byte, signingKey crypto.PrivateKey, metadata map[string]interface{}) ([]byte, error) {
	if e.backend == nil {
		return nil, fmt.Errorf("backend is nil")
	}
	if signingKey == nil {
		return nil, fmt.Errorf("signing key is nil")
	}

	// Step 1: Encrypt using EncryptMultiRecipient (creates JWE)
	recipients := []crypto.PublicKey{recipientPubKey}
	jwe, err := e.backend.EncryptMultiRecipient(recipients, plaintext, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt with %s backend: %w", e.backend.Name(), err)
	}

	// Step 2: Sign the JWE (creates JWS(JWE))
	jws, err := e.backend.Sign(signingKey, jwe)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with %s backend: %w", e.backend.Name(), err)
	}

	return []byte(base64.StdEncoding.EncodeToString(jws)), nil
}

// DecodeWithSignature decodes, verifies signature, and decrypts JWS(JWE(payload)).
// - Step 1: Verifies the JWS signature using the sender's public key
// - Step 2: Decrypts the JWE content using the recipient's private key
// Returns an error if signature verification fails.
func (e *BackendTransportEncoder) DecodeWithSignature(privateKey crypto.PrivateKey, verificationKey crypto.PublicKey, encoded []byte) ([]byte, error) {
	if e.backend == nil {
		return nil, fmt.Errorf("backend is nil")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}
	if verificationKey == nil {
		return nil, fmt.Errorf("verification key is nil")
	}

	// Decode base64 to get JWS
	jws, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 JWS: %w", err)
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
	valid, err := e.backend.Verify(verificationKey, jwe, jws)
	if err != nil {
		return nil, fmt.Errorf("failed to verify signature with %s backend: %w", e.backend.Name(), err)
	}
	if !valid {
		return nil, fmt.Errorf("signature verification failed: invalid signature")
	}

	// Decrypt the JWE using the recipient's private key
	plaintext, err := e.backend.DecryptMultiRecipient(privateKey, jwe)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with %s backend: %w", e.backend.Name(), err)
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

// Convenience functions that don't require creating a TransportEncoder instance.
// These use the provided backend directly.

// EncryptAndEncode encrypts plaintext using the specified crypto backend and encodes for transport.
// Returns base64-encoded ciphertext.
func EncryptAndEncode(backend crypto.Backend, recipientPubKey crypto.PublicKey, plaintext []byte) ([]byte, error) {
	encoder := NewTransportEncoder(backend)
	return encoder.Encode(recipientPubKey, plaintext)
}

// DecodeAndDecrypt decodes and decrypts transport-encoded data.
// Expects base64-encoded ciphertext.
func DecodeAndDecrypt(backend crypto.Backend, privateKey crypto.PrivateKey, encoded []byte) ([]byte, error) {
	encoder := NewTransportEncoder(backend)
	return encoder.Decode(privateKey, encoded)
}

// EncryptSignAndEncode creates authenticated encrypted transport data.
// Creates JWS(JWE(plaintext)) structure for confidentiality and authenticity.
func EncryptSignAndEncode(backend crypto.Backend, recipientPubKey crypto.PublicKey, plaintext []byte, signingKey crypto.PrivateKey, metadata map[string]interface{}) ([]byte, error) {
	encoder := NewTransportEncoder(backend)
	return encoder.EncodeWithSignature(recipientPubKey, plaintext, signingKey, metadata)
}

// DecodeDecryptAndVerify decodes, verifies, and decrypts authenticated transport data.
// Expects JWS(JWE) structure.
func DecodeDecryptAndVerify(backend crypto.Backend, privateKey crypto.PrivateKey, verificationKey crypto.PublicKey, encoded []byte) ([]byte, error) {
	encoder := NewTransportEncoder(backend)
	return encoder.DecodeWithSignature(privateKey, verificationKey, encoded)
}
