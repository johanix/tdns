/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Crypto backend abstraction layer for TDNS
 * Supports multiple cryptographic backends (HPKE, JOSE) for key distribution
 */

package crypto

// Backend defines the interface that all cryptographic backends must implement.
// This allows TDNS to support multiple encryption mechanisms (HPKE, JOSE)
// while keeping the distribution logic crypto-agnostic.
type Backend interface {
	// Name returns the backend identifier (e.g., "hpke", "jose")
	Name() string

	// GenerateKeypair generates a new key pair suitable for this backend
	GenerateKeypair() (PrivateKey, PublicKey, error)

	// ParsePublicKey deserializes a public key from bytes
	// The format is backend-specific (e.g., raw bytes for HPKE, JWK JSON for JOSE)
	ParsePublicKey(data []byte) (PublicKey, error)

	// ParsePrivateKey deserializes a private key from bytes
	// The format is backend-specific
	ParsePrivateKey(data []byte) (PrivateKey, error)

	// SerializePublicKey serializes a public key to bytes
	// The format is backend-specific
	SerializePublicKey(key PublicKey) ([]byte, error)

	// SerializePrivateKey serializes a private key to bytes
	// The format is backend-specific
	SerializePrivateKey(key PrivateKey) ([]byte, error)

	// Encrypt encrypts plaintext for the specified recipient public key
	// Returns ciphertext in backend-specific format (may include ephemeral key, etc.)
	Encrypt(recipientPubKey PublicKey, plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext using the private key
	// Expects ciphertext in backend-specific format
	Decrypt(privateKey PrivateKey, ciphertext []byte) ([]byte, error)

	// GetEphemeralKey extracts the ephemeral public key from ciphertext
	// Returns the ephemeral public key bytes, or nil/empty if the backend
	// embeds the ephemeral key within the ciphertext format (e.g., JWE header)
	// This allows the encryption layer to be truly backend-agnostic
	GetEphemeralKey(ciphertext []byte) ([]byte, error)

	// EncryptMultiRecipient encrypts plaintext for multiple recipients.
	// Returns JWE-formatted ciphertext (JSON Serialization) containing:
	// - Single encrypted payload (CEK-encrypted with AES-256-GCM)
	// - Multiple recipient entries, each with encrypted CEK
	// - Protected headers with metadata (distribution_id, timestamp, etc.)
	//
	// For backends that don't support native multi-recipient (e.g., HPKE),
	// this may use multiple single-recipient encryptions in JWE recipients array.
	//
	// The metadata map should contain JWE protected header fields:
	//   - "distribution_id": string - Distribution identifier
	//   - "content_type": string - Content type (e.g., "key_operations")
	//   - "timestamp": string - ISO8601 timestamp for replay protection
	//   - "distribution_ttl": string - TTL for replay protection
	//   - "sender": string - Sender identity
	//   - Other custom fields as needed
	EncryptMultiRecipient(recipients []PublicKey, plaintext []byte, metadata map[string]interface{}) ([]byte, error)

	// DecryptMultiRecipient decrypts JWE-formatted multi-recipient ciphertext.
	// Finds the recipient entry matching the provided private key and decrypts.
	// Returns plaintext and metadata from protected headers.
	//
	// This method handles both:
	// - JWE JSON Serialization (standard multi-recipient format)
	// - JWE Compact Serialization (single-recipient, for backward compatibility)
	DecryptMultiRecipient(privKey PrivateKey, ciphertext []byte) ([]byte, error)

	// Sign signs data using the private key, returning a JWS structure.
	// The signature format depends on the backend:
	// - JOSE backend: ES256 (P-256 ECDSA)
	// - HPKE backend: Ed25519 or separate signing keypair
	//
	// Returns JWS Compact Serialization: <header>.<payload>.<signature>
	// where payload is base64url(data).
	Sign(privKey PrivateKey, data []byte) ([]byte, error)

	// Verify verifies a JWS signature using the public key.
	// Returns true if signature is valid, false otherwise.
	// The signature algorithm is detected from the JWS protected header.
	Verify(pubKey PublicKey, data []byte, signature []byte) (bool, error)
}

// PrivateKey represents a private key (backend-specific implementation)
type PrivateKey interface {
	// Backend returns the name of the backend this key belongs to
	Backend() string
}

// PublicKey represents a public key (backend-specific implementation)
type PublicKey interface {
	// Backend returns the name of the backend this key belongs to
	Backend() string
}
