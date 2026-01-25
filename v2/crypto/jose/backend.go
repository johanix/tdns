/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * JOSE backend implementation for crypto abstraction layer
 * Uses go-jose library for JWE operations
 */

package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/johanix/tdns/v2/crypto"
)

// Backend implements crypto.Backend for JOSE
type Backend struct{}

// NewBackend creates a new JOSE backend
func NewBackend() crypto.Backend {
	return &Backend{}
}

// Ensure Backend implements crypto.Backend interface
var _ crypto.Backend = (*Backend)(nil)

// Name returns the backend identifier
func (b *Backend) Name() string {
	return "jose"
}

// GenerateKeypair generates a new JOSE keypair (P-256 ECDSA)
func (b *Backend) GenerateKeypair() (crypto.PrivateKey, crypto.PublicKey, error) {
	// Generate P-256 ECDSA key
	privECDSA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, crypto.NewBackendError("jose", "generate_keypair", err)
	}

	// Create JWK from ECDSA key
	jwk := jose.JSONWebKey{
		Key:       privECDSA,
		KeyID:     "", // No key ID for now
		Algorithm: string(jose.ECDH_ES),
		Use:       "enc",
	}

	// Create public JWK
	pubJWK := jwk.Public()

	return &privateKey{jwk: jwk}, &publicKey{jwk: pubJWK}, nil
}

// ParsePublicKey deserializes a JOSE public key from JWK JSON
func (b *Backend) ParsePublicKey(data []byte) (crypto.PublicKey, error) {
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, crypto.NewBackendError("jose", "parse_public_key", err)
	}

	// Verify it's a public key
	if !jwk.IsPublic() {
		return nil, crypto.NewBackendError("jose", "parse_public_key",
			fmt.Errorf("not a public key"))
	}

	// Verify it's an ECDSA key suitable for ECDH-ES (this backend only supports ECDSA P-256)
	if _, ok := jwk.Key.(*ecdsa.PublicKey); !ok {
		return nil, crypto.NewBackendError("jose", "parse_public_key",
			fmt.Errorf("unsupported key type: expected ECDSA public key (P-256)"))
	}

	return &publicKey{jwk: jwk}, nil
}

// ParsePrivateKey deserializes a JOSE private key from JWK JSON
func (b *Backend) ParsePrivateKey(data []byte) (crypto.PrivateKey, error) {
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, crypto.NewBackendError("jose", "parse_private_key", err)
	}

	// Verify it's a private key (has private key material)
	if jwk.IsPublic() {
		return nil, crypto.NewBackendError("jose", "parse_private_key",
			fmt.Errorf("not a private key (missing private key material)"))
	}

	// Verify it's an ECDSA key suitable for ECDH-ES (this backend only supports ECDSA P-256)
	if _, ok := jwk.Key.(*ecdsa.PrivateKey); !ok {
		return nil, crypto.NewBackendError("jose", "parse_private_key",
			fmt.Errorf("unsupported key type: expected ECDSA private key (P-256)"))
	}

	return &privateKey{jwk: jwk}, nil
}

// SerializePublicKey serializes a JOSE public key to JWK JSON
func (b *Backend) SerializePublicKey(key crypto.PublicKey) ([]byte, error) {
	joseKey, ok := key.(*publicKey)
	if !ok {
		return nil, crypto.ErrBackendMismatch
	}

	data, err := json.Marshal(joseKey.jwk)
	if err != nil {
		return nil, crypto.NewBackendError("jose", "serialize_public_key", err)
	}

	return data, nil
}

// SerializePrivateKey serializes a JOSE private key to JWK JSON
func (b *Backend) SerializePrivateKey(key crypto.PrivateKey) ([]byte, error) {
	joseKey, ok := key.(*privateKey)
	if !ok {
		return nil, crypto.ErrBackendMismatch
	}

	data, err := json.Marshal(joseKey.jwk)
	if err != nil {
		return nil, crypto.NewBackendError("jose", "serialize_private_key", err)
	}

	return data, nil
}

// Encrypt encrypts plaintext for the recipient using JWE (ECDH-ES+A256GCM)
func (b *Backend) Encrypt(recipientPubKey crypto.PublicKey, plaintext []byte) ([]byte, error) {
	joseKey, ok := recipientPubKey.(*publicKey)
	if !ok {
		return nil, crypto.ErrBackendMismatch
	}

	// Create encrypter with ECDH-ES and A256GCM
	// ECDH-ES: Elliptic Curve Diffie-Hellman Ephemeral Static
	// A256GCM: AES-256 in Galois/Counter Mode
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.ECDH_ES,
			Key:       joseKey.jwk.Key,
		},
		nil, // No additional options
	)
	if err != nil {
		return nil, crypto.NewBackendError("jose", "encrypt", err)
	}

	// Encrypt plaintext
	jwe, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return nil, crypto.NewBackendError("jose", "encrypt", err)
	}

	// Serialize to compact format
	// Format: header.encrypted_key.iv.ciphertext.tag
	serialized, err := jwe.CompactSerialize()
	if err != nil {
		return nil, crypto.NewBackendError("jose", "encrypt", err)
	}

	return []byte(serialized), nil
}

// Decrypt decrypts JWE ciphertext using the recipient's private key
func (b *Backend) Decrypt(privKey crypto.PrivateKey, ciphertext []byte) ([]byte, error) {
	joseKey, ok := privKey.(*privateKey)
	if !ok {
		return nil, crypto.ErrBackendMismatch
	}

	// Parse JWE compact serialization
	// v4 requires explicit algorithm specification for security
	jwe, err := jose.ParseEncrypted(
		string(ciphertext),
		[]jose.KeyAlgorithm{jose.ECDH_ES},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	if err != nil {
		return nil, crypto.NewBackendError("jose", "decrypt", err)
	}

	// Decrypt using private key
	plaintext, err := jwe.Decrypt(joseKey.jwk.Key)
	if err != nil {
		return nil, crypto.NewBackendError("jose", "decrypt", err)
	}

	return plaintext, nil
}

// privateKey implements crypto.PrivateKey for JOSE
type privateKey struct {
	jwk jose.JSONWebKey // JWK with private key material
}

// Backend returns "jose"
func (k *privateKey) Backend() string {
	return "jose"
}

// publicKey implements crypto.PublicKey for JOSE
type publicKey struct {
	jwk jose.JSONWebKey // JWK (public key only)
}

// Backend returns "jose"
func (k *publicKey) Backend() string {
	return "jose"
}

// Auto-register backend on package import
func init() {
	crypto.RegisterBackend(NewBackend())
}
