/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * HPKE backend implementation for crypto abstraction layer
 * Wraps existing tdns/v2/hpke implementation
 */

package hpke

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
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

// EncryptMultiRecipient encrypts plaintext for multiple recipients using HPKE.
//
// CURRENT LIMITATION (Phase 3):
// Similar to JOSE backend, this implementation currently encrypts for the FIRST
// recipient only using raw HPKE ciphertext format.
//
// FUTURE (Phase 4):
// Will implement JWE JSON Serialization with multiple HPKE encryptions where
// each recipient gets their own HPKE-encrypted CEK (Content Encryption Key).
// Format will be our interpretation of HPKE-in-JWE (not RFC-standardized).
//
// For now, callers should encrypt multiple times (once per recipient) if they
// need to distribute to multiple recipients.
func (b *Backend) EncryptMultiRecipient(recipients []crypto.PublicKey, plaintext []byte, metadata map[string]interface{}) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, crypto.NewBackendError("hpke", "encrypt_multi_recipient",
			fmt.Errorf("no recipients provided"))
	}

	// TODO Phase 4: Implement JWE JSON Serialization with multiple HPKE encryptions
	// For now, encrypt for first recipient only using raw HPKE format
	firstRecipient := recipients[0]

	hpkeKey, ok := firstRecipient.(*publicKey)
	if !ok {
		return nil, crypto.ErrBackendMismatch
	}

	// Encrypt with HPKE
	ciphertext, _, err := hpkelib.Encrypt(hpkeKey.data, nil, plaintext)
	if err != nil {
		return nil, crypto.NewBackendError("hpke", "encrypt_multi_recipient", err)
	}

	// TODO Phase 4: Wrap in JWE JSON Serialization with metadata
	// For now, return raw HPKE ciphertext (backward compatible with old Encrypt)
	return ciphertext, nil
}

// DecryptMultiRecipient decrypts HPKE-formatted ciphertext.
//
// CURRENT LIMITATION (Phase 3):
// Since EncryptMultiRecipient currently only encrypts for the first recipient,
// this method simply decrypts raw HPKE ciphertext format.
//
// FUTURE (Phase 4):
// Will support JWE JSON Serialization with multiple HPKE-encrypted recipients,
// automatically finding and using the correct recipient entry.
func (b *Backend) DecryptMultiRecipient(privKey crypto.PrivateKey, ciphertext []byte) ([]byte, error) {
	hpkeKey, ok := privKey.(*privateKey)
	if !ok {
		return nil, crypto.ErrBackendMismatch
	}

	// Decrypt raw HPKE ciphertext (currently only format supported)
	plaintext, err := hpkelib.Decrypt(hpkeKey.data, nil, ciphertext)
	if err != nil {
		return nil, crypto.NewBackendError("hpke", "decrypt_multi_recipient", err)
	}

	return plaintext, nil
}

// Sign signs data using a P-256 ECDSA signing key and returns JWS Compact Serialization.
//
// IMPORTANT: The HPKE backend uses X25519 keys for encryption but P-256 keys for signing.
// This maintains consistency with the JOSE backend (both use ES256 signatures).
//
// The privKey parameter should be a P-256 signing key (created separately from HPKE keys).
// For signing, use a P-256 keypair generated via crypto/ecdsa, not the HPKE X25519 keys.
//
// Returns JWS Compact Serialization: <header>.<payload>.<signature>
func (b *Backend) Sign(privKey crypto.PrivateKey, data []byte) ([]byte, error) {
	// For HPKE backend signing, we expect a P-256 ECDSA key wrapped in signingKey type
	// (not the HPKE privateKey type which is X25519)

	// Try to extract ECDSA private key
	// The caller should pass a signingKey, not an HPKE privateKey
	var ecdsaKey *ecdsa.PrivateKey

	// Check if it's a signingKey (will be implemented below)
	if sigKey, ok := privKey.(*signingKey); ok {
		ecdsaKey = sigKey.key
	} else {
		return nil, crypto.NewBackendError("hpke", "sign",
			fmt.Errorf("signing requires P-256 signing key, not HPKE encryption key"))
	}

	// Create signer with ES256 (ECDSA using P-256 and SHA-256)
	signingJoseKey := jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       ecdsaKey,
	}

	opts := &jose.SignerOptions{}
	opts = opts.WithType("JWS")
	opts = opts.WithContentType("application/octet-stream")

	signer, err := jose.NewSigner(signingJoseKey, opts)
	if err != nil {
		return nil, crypto.NewBackendError("hpke", "sign", err)
	}

	// Sign the data
	jws, err := signer.Sign(data)
	if err != nil {
		return nil, crypto.NewBackendError("hpke", "sign", err)
	}

	// Serialize to compact format
	serialized, err := jws.CompactSerialize()
	if err != nil {
		return nil, crypto.NewBackendError("hpke", "sign", err)
	}

	return []byte(serialized), nil
}

// Verify verifies a JWS signature using a P-256 ECDSA public key.
//
// IMPORTANT: The pubKey parameter should be a P-256 verification key (verifyKey type),
// not an HPKE X25519 public key.
//
// The signature parameter should be JWS Compact Serialization format.
func (b *Backend) Verify(pubKey crypto.PublicKey, data []byte, signature []byte) (bool, error) {
	// Extract P-256 ECDSA public key
	var ecdsaPubKey *ecdsa.PublicKey

	// Check if it's a verifyKey (will be implemented below)
	if verKey, ok := pubKey.(*verifyKey); ok {
		ecdsaPubKey = verKey.key
	} else {
		return false, crypto.NewBackendError("hpke", "verify",
			fmt.Errorf("verification requires P-256 public key, not HPKE encryption key"))
	}

	// Parse JWS
	jws, err := jose.ParseSigned(
		string(signature),
		[]jose.SignatureAlgorithm{jose.ES256},
	)
	if err != nil {
		return false, crypto.NewBackendError("hpke", "verify", err)
	}

	// Verify signature and extract payload
	payload, err := jws.Verify(ecdsaPubKey)
	if err != nil {
		// Signature verification failed
		return false, nil
	}

	// Verify that the payload matches the original data
	if len(payload) != len(data) {
		return false, nil
	}
	for i := range payload {
		if payload[i] != data[i] {
			return false, nil
		}
	}

	return true, nil
}

// privateKey implements crypto.PrivateKey for HPKE encryption keys (X25519)
type privateKey struct {
	data []byte // X25519 private key (32 bytes)
}

// Backend returns "hpke"
func (k *privateKey) Backend() string {
	return "hpke"
}

// publicKey implements crypto.PublicKey for HPKE encryption keys (X25519)
type publicKey struct {
	data []byte // X25519 public key (32 bytes)
}

// Backend returns "hpke"
func (k *publicKey) Backend() string {
	return "hpke"
}

// signingKey implements crypto.PrivateKey for HPKE signing keys (P-256 ECDSA)
// HPKE backend uses separate keys for encryption (X25519) and signing (P-256)
type signingKey struct {
	key *ecdsa.PrivateKey // P-256 ECDSA private key
}

// Backend returns "hpke"
func (k *signingKey) Backend() string {
	return "hpke"
}

// verifyKey implements crypto.PublicKey for HPKE signature verification (P-256 ECDSA)
type verifyKey struct {
	key *ecdsa.PublicKey // P-256 ECDSA public key
}

// Backend returns "hpke"
func (k *verifyKey) Backend() string {
	return "hpke"
}

// GenerateSigningKeypair generates a P-256 ECDSA signing keypair for use with HPKE backend.
// These are separate from HPKE encryption keys (X25519).
// Use these keys for Sign() and Verify() operations.
func (b *Backend) GenerateSigningKeypair() (crypto.PrivateKey, crypto.PublicKey, error) {
	// Generate P-256 ECDSA key
	privECDSA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, crypto.NewBackendError("hpke", "generate_signing_keypair", err)
	}

	return &signingKey{key: privECDSA}, &verifyKey{key: &privECDSA.PublicKey}, nil
}

// ParseSigningKey deserializes a P-256 ECDSA signing private key from JWK JSON.
func (b *Backend) ParseSigningKey(data []byte) (crypto.PrivateKey, error) {
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, crypto.NewBackendError("hpke", "parse_signing_key", err)
	}

	// Verify it's a private key
	if jwk.IsPublic() {
		return nil, crypto.NewBackendError("hpke", "parse_signing_key",
			fmt.Errorf("not a private key"))
	}

	// Verify it's an ECDSA key (P-256)
	ecdsaKey, ok := jwk.Key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, crypto.NewBackendError("hpke", "parse_signing_key",
			fmt.Errorf("expected ECDSA private key"))
	}

	if ecdsaKey.Curve != elliptic.P256() {
		return nil, crypto.NewBackendError("hpke", "parse_signing_key",
			fmt.Errorf("expected P-256 curve, got %s", ecdsaKey.Curve.Params().Name))
	}

	return &signingKey{key: ecdsaKey}, nil
}

// ParseVerifyKey deserializes a P-256 ECDSA verification public key from JWK JSON.
func (b *Backend) ParseVerifyKey(data []byte) (crypto.PublicKey, error) {
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, crypto.NewBackendError("hpke", "parse_verify_key", err)
	}

	// Verify it's a public key
	if !jwk.IsPublic() {
		return nil, crypto.NewBackendError("hpke", "parse_verify_key",
			fmt.Errorf("not a public key"))
	}

	// Verify it's an ECDSA key (P-256)
	ecdsaPubKey, ok := jwk.Key.(*ecdsa.PublicKey)
	if !ok {
		return nil, crypto.NewBackendError("hpke", "parse_verify_key",
			fmt.Errorf("expected ECDSA public key"))
	}

	if ecdsaPubKey.Curve != elliptic.P256() {
		return nil, crypto.NewBackendError("hpke", "parse_verify_key",
			fmt.Errorf("expected P-256 curve, got %s", ecdsaPubKey.Curve.Params().Name))
	}

	return &verifyKey{key: ecdsaPubKey}, nil
}

// SerializeSigningKey serializes a P-256 ECDSA signing private key to JWK JSON.
func (b *Backend) SerializeSigningKey(key crypto.PrivateKey) ([]byte, error) {
	sigKey, ok := key.(*signingKey)
	if !ok {
		return nil, crypto.NewBackendError("hpke", "serialize_signing_key",
			fmt.Errorf("not a signing key"))
	}

	jwk := jose.JSONWebKey{
		Key:       sigKey.key,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}

	data, err := json.Marshal(jwk)
	if err != nil {
		return nil, crypto.NewBackendError("hpke", "serialize_signing_key", err)
	}

	return data, nil
}

// SerializeVerifyKey serializes a P-256 ECDSA verification public key to JWK JSON.
func (b *Backend) SerializeVerifyKey(key crypto.PublicKey) ([]byte, error) {
	verKey, ok := key.(*verifyKey)
	if !ok {
		return nil, crypto.NewBackendError("hpke", "serialize_verify_key",
			fmt.Errorf("not a verify key"))
	}

	jwk := jose.JSONWebKey{
		Key:       verKey.key,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}

	data, err := json.Marshal(jwk)
	if err != nil {
		return nil, crypto.NewBackendError("hpke", "serialize_verify_key", err)
	}

	return data, nil
}

// EncryptAndSign is a convenience method that creates JWS(HPKE(...)).
// This wraps HPKE encryption with a JWS signature for authenticated distributions.
// Returns JWS Compact Serialization containing the HPKE ciphertext as payload.
//
// IMPORTANT: signingKey must be a P-256 signing key (created via GenerateSigningKeypair),
// not an HPKE X25519 encryption key.
func (b *Backend) EncryptAndSign(recipients []crypto.PublicKey, plaintext []byte, signingKey crypto.PrivateKey, metadata map[string]interface{}) ([]byte, error) {
	// Step 1: Encrypt with HPKE (currently single-recipient)
	hpkeCiphertext, err := b.EncryptMultiRecipient(recipients, plaintext, metadata)
	if err != nil {
		return nil, err
	}

	// Step 2: Sign the HPKE ciphertext
	jws, err := b.Sign(signingKey, hpkeCiphertext)
	if err != nil {
		return nil, err
	}

	// Return JWS(HPKE(...))
	return jws, nil
}

// DecryptAndVerify is a convenience method that verifies JWS and decrypts HPKE ciphertext.
// This is the inverse of EncryptAndSign, verifying the signature before decrypting.
// Returns plaintext if signature is valid and decryption succeeds.
//
// IMPORTANT: verificationKey must be a P-256 verification key (created via GenerateSigningKeypair),
// not an HPKE X25519 public key.
func (b *Backend) DecryptAndVerify(privKey crypto.PrivateKey, verificationKey crypto.PublicKey, ciphertext []byte) ([]byte, error) {
	// Step 1: Parse and verify JWS
	jws, err := jose.ParseSigned(
		string(ciphertext),
		[]jose.SignatureAlgorithm{jose.ES256},
	)
	if err != nil {
		return nil, crypto.NewBackendError("hpke", "decrypt_and_verify",
			fmt.Errorf("failed to parse JWS: %w", err))
	}

	verKey, ok := verificationKey.(*verifyKey)
	if !ok {
		return nil, crypto.NewBackendError("hpke", "decrypt_and_verify",
			fmt.Errorf("verify key must be P-256 verification key"))
	}

	// Step 2: Verify signature and extract HPKE ciphertext payload
	hpkeCiphertext, err := jws.Verify(verKey.key)
	if err != nil {
		return nil, crypto.NewBackendError("hpke", "decrypt_and_verify",
			fmt.Errorf("signature verification failed: %w", err))
	}

	// Step 3: Decrypt HPKE ciphertext
	plaintext, err := b.DecryptMultiRecipient(privKey, hpkeCiphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Auto-register backend on package import
func init() {
	crypto.RegisterBackend(NewBackend())
}
