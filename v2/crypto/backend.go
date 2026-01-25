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
