/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * HPKE backend implementation for crypto abstraction layer
 * Wraps existing tdns/v2/hpke implementation
 */

package hpke

import (
	"fmt"

	"github.com/johanix/tdns/v2/crypto"
	hpkelib "github.com/johanix/tdns/v2/hpke"
)

// Backend implements crypto.Backend for HPKE
type Backend struct{}

// NewBackend creates a new HPKE backend
func NewBackend() crypto.Backend {
	return &Backend{}
}

// Ensure Backend implements crypto.Backend interface
var _ crypto.Backend = (*Backend)(nil)

// Name returns the backend identifier
func (b *Backend) Name() string {
	return "hpke"
}

// GenerateKeypair generates a new HPKE keypair (X25519)
func (b *Backend) GenerateKeypair() (crypto.PrivateKey, crypto.PublicKey, error) {
	pubBytes, privBytes, err := hpkelib.GenerateKeyPair()
	if err != nil {
		return nil, nil, crypto.NewBackendError("hpke", "generate_keypair", err)
	}

	return &privateKey{data: privBytes}, &publicKey{data: pubBytes}, nil
}

// ParsePublicKey deserializes an HPKE public key from bytes
func (b *Backend) ParsePublicKey(data []byte) (crypto.PublicKey, error) {
	if len(data) != 32 {
		return nil, crypto.NewBackendError("hpke", "parse_public_key",
			crypto.ErrInvalidKey)
	}

	// For HPKE/X25519, the key is just raw bytes
	// Make a copy to avoid any aliasing issues
	keyData := make([]byte, 32)
	copy(keyData, data)

	return &publicKey{data: keyData}, nil
}

// ParsePrivateKey deserializes an HPKE private key from bytes
func (b *Backend) ParsePrivateKey(data []byte) (crypto.PrivateKey, error) {
	if len(data) != 32 {
		return nil, crypto.NewBackendError("hpke", "parse_private_key",
			crypto.ErrInvalidKey)
	}

	// For HPKE/X25519, the key is just raw bytes
	// Make a copy to avoid any aliasing issues
	keyData := make([]byte, 32)
	copy(keyData, data)

	return &privateKey{data: keyData}, nil
}

// SerializePublicKey serializes an HPKE public key to bytes
func (b *Backend) SerializePublicKey(key crypto.PublicKey) ([]byte, error) {
	hpkeKey, ok := key.(*publicKey)
	if !ok {
		return nil, crypto.ErrBackendMismatch
	}

	// Make a copy to avoid any aliasing issues
	data := make([]byte, len(hpkeKey.data))
	copy(data, hpkeKey.data)
	return data, nil
}

// SerializePrivateKey serializes an HPKE private key to bytes
func (b *Backend) SerializePrivateKey(key crypto.PrivateKey) ([]byte, error) {
	hpkeKey, ok := key.(*privateKey)
	if !ok {
		return nil, crypto.ErrBackendMismatch
	}

	// Make a copy to avoid any aliasing issues
	data := make([]byte, len(hpkeKey.data))
	copy(data, hpkeKey.data)
	return data, nil
}

// Encrypt encrypts plaintext for the recipient using HPKE Base mode
func (b *Backend) Encrypt(recipientPubKey crypto.PublicKey, plaintext []byte) ([]byte, error) {
	hpkeKey, ok := recipientPubKey.(*publicKey)
	if !ok {
		return nil, crypto.ErrBackendMismatch
	}

	// Call existing HPKE Encrypt function
	// Note: ephemeralPubKey parameter is nil (HPKE generates its own)
	ciphertext, _, err := hpkelib.Encrypt(hpkeKey.data, nil, plaintext)
	if err != nil {
		return nil, crypto.NewBackendError("hpke", "encrypt", err)
	}

	return ciphertext, nil
}

// Decrypt decrypts ciphertext using the recipient's private key
func (b *Backend) Decrypt(privKey crypto.PrivateKey, ciphertext []byte) ([]byte, error) {
	hpkeKey, ok := privKey.(*privateKey)
	if !ok {
		return nil, crypto.ErrBackendMismatch
	}

	// Call existing HPKE Decrypt function
	// Note: ephemeralPubKey parameter is nil (extracted from ciphertext)
	plaintext, err := hpkelib.Decrypt(hpkeKey.data, nil, ciphertext)
	if err != nil {
		return nil, crypto.NewBackendError("hpke", "decrypt", err)
	}

	return plaintext, nil
}

// GetEphemeralKey extracts the ephemeral public key from HPKE ciphertext
// For HPKE, the first 32 bytes of ciphertext is the encapsulated key (ephemeral public key)
func (b *Backend) GetEphemeralKey(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 32 {
		return nil, crypto.NewBackendError("hpke", "get_ephemeral_key",
			fmt.Errorf("ciphertext too short: %d bytes (expected at least 32)", len(ciphertext)))
	}

	// Extract first 32 bytes (encapsulated key)
	ephemeralPub := make([]byte, 32)
	copy(ephemeralPub, ciphertext[:32])
	return ephemeralPub, nil
}

// privateKey implements crypto.PrivateKey for HPKE
type privateKey struct {
	data []byte // X25519 private key (32 bytes)
}

// Backend returns "hpke"
func (k *privateKey) Backend() string {
	return "hpke"
}

// publicKey implements crypto.PublicKey for HPKE
type publicKey struct {
	data []byte // X25519 public key (32 bytes)
}

// Backend returns "hpke"
func (k *publicKey) Backend() string {
	return "hpke"
}

// Auto-register backend on package import
func init() {
	crypto.RegisterBackend(NewBackend())
}
