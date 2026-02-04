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
	ecdsaKey, ok := jwk.Key.(*ecdsa.PublicKey)
	if !ok {
		return nil, crypto.NewBackendError("jose", "parse_public_key",
			fmt.Errorf("unsupported key type: expected ECDSA public key (P-256)"))
	}
	// Verify the curve is P-256
	if ecdsaKey.Curve != elliptic.P256() {
		return nil, crypto.NewBackendError("jose", "parse_public_key",
			fmt.Errorf("unsupported curve: expected P-256, got %s", ecdsaKey.Curve.Params().Name))
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
	ecdsaKey, ok := jwk.Key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, crypto.NewBackendError("jose", "parse_private_key",
			fmt.Errorf("unsupported key type: expected ECDSA private key (P-256)"))
	}
	// Verify the curve is P-256
	if ecdsaKey.Curve != elliptic.P256() {
		return nil, crypto.NewBackendError("jose", "parse_private_key",
			fmt.Errorf("unsupported curve: expected P-256, got %s", ecdsaKey.Curve.Params().Name))
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

// PublicKeyFromStdlib wraps a stdlib crypto.PublicKey in a JOSE backend wrapper.
// This allows converting discovered keys (from JWK records, etc.) to JOSE publicKey type.
// Supports ECDSA P-256 public keys from stdlib.
func (b *Backend) PublicKeyFromStdlib(stdlibKey interface{}) (crypto.PublicKey, error) {
	// Type assert to ECDSA public key
	ecdsaKey, ok := stdlibKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, crypto.NewBackendError("jose", "public_key_from_stdlib",
			fmt.Errorf("unsupported stdlib key type: expected *ecdsa.PublicKey, got %T", stdlibKey))
	}

	// Verify the curve is P-256
	if ecdsaKey.Curve != elliptic.P256() {
		return nil, crypto.NewBackendError("jose", "public_key_from_stdlib",
			fmt.Errorf("unsupported curve: expected P-256, got %s", ecdsaKey.Curve.Params().Name))
	}

	// Create JWK wrapper
	jwk := jose.JSONWebKey{
		Key:       ecdsaKey,
		KeyID:     "", // No key ID for discovered keys
		Algorithm: string(jose.ECDH_ES),
		Use:       "enc",
	}

	return &publicKey{jwk: jwk}, nil
}

// PublicFromPrivate returns the public key corresponding to the given private key.
// Used by CLI "keys show" to derive public JWK from configured private key file.
func (b *Backend) PublicFromPrivate(priv crypto.PrivateKey) (crypto.PublicKey, error) {
	josePriv, ok := priv.(*privateKey)
	if !ok {
		return nil, crypto.ErrBackendMismatch
	}
	pubJWK := josePriv.jwk.Public()
	return &publicKey{jwk: pubJWK}, nil
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

// GetEphemeralKey extracts the ephemeral public key from JOSE ciphertext
// For JOSE (JWE), the ephemeral key is embedded in the JWE header and cannot
// be extracted without parsing the full JWE structure. Since the recipient
// extracts it during decryption, we return nil to indicate no separate
// ephemeral key field is needed.
func (b *Backend) GetEphemeralKey(ciphertext []byte) ([]byte, error) {
	// JOSE (JWE) wraps the ephemeral key exchange within the ciphertext itself:
	// The JWE header contains the ephemeral public key used for ECDH-ES key agreement,
	// so there's no separate ephemeralPubKey field needed. The recipient extracts it
	// from the JWE header during decryption.
	return nil, nil
}

// EncryptMultiRecipient encrypts plaintext for multiple recipients using JWE.
//
// CURRENT LIMITATION (Phase 2):
// The go-jose v4 library does not support multi-recipient JWE decryption.
// This implementation currently encrypts for the FIRST recipient only using
// standard JWE Compact Serialization (ECDH-ES+A256GCM).
//
// FUTURE (Phase 4):
// Will implement manual JWE JSON Serialization with ECDH-ES+A256KW to support
// true multi-recipient encryption where a single ciphertext can be decrypted
// by any of N recipients.
//
// For now, callers should encrypt multiple times (once per recipient) if they
// need to distribute to multiple recipients. This is less efficient but functionally
// equivalent.
func (b *Backend) EncryptMultiRecipient(recipients []crypto.PublicKey, plaintext []byte, metadata map[string]interface{}) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, crypto.NewBackendError("jose", "encrypt_multi_recipient",
			fmt.Errorf("no recipients provided"))
	}

	// TODO Phase 4: Implement true multi-recipient JWE JSON Serialization
	// For now, encrypt for first recipient only using single-recipient JWE
	firstRecipient := recipients[0]

	joseKey, ok := firstRecipient.(*publicKey)
	if !ok {
		return nil, crypto.ErrBackendMismatch
	}

	// Build encrypter options with protected headers
	opts := &jose.EncrypterOptions{}
	opts = opts.WithContentType("application/octet-stream")

	// Add custom protected headers from metadata
	if metadata != nil {
		for key, value := range metadata {
			opts = opts.WithHeader(jose.HeaderKey(key), value)
		}
	}

	// Add TDNS-specific headers
	opts = opts.WithType("tdns-distribution")
	opts = opts.WithHeader("crypto_backend", "jose")

	// Add recipient count to metadata (informational)
	opts = opts.WithHeader("recipients_count", len(recipients))

	// Create single-recipient encrypter
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.ECDH_ES,
			Key:       joseKey.jwk.Key,
			KeyID:     joseKey.jwk.KeyID,
		},
		opts,
	)
	if err != nil {
		return nil, crypto.NewBackendError("jose", "encrypt_multi_recipient", err)
	}

	// Encrypt plaintext
	jwe, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return nil, crypto.NewBackendError("jose", "encrypt_multi_recipient", err)
	}

	// Serialize to compact format
	serialized, err := jwe.CompactSerialize()
	if err != nil {
		return nil, crypto.NewBackendError("jose", "encrypt_multi_recipient", err)
	}

	return []byte(serialized), nil
}

// DecryptMultiRecipient decrypts JWE-formatted ciphertext.
//
// CURRENT LIMITATION (Phase 2):
// Since EncryptMultiRecipient currently only encrypts for the first recipient,
// this method simply decrypts standard JWE Compact Serialization.
//
// FUTURE (Phase 4):
// Will support true multi-recipient JWE JSON Serialization decryption,
// automatically finding and using the correct recipient entry.
func (b *Backend) DecryptMultiRecipient(privKey crypto.PrivateKey, ciphertext []byte) ([]byte, error) {
	joseKey, ok := privKey.(*privateKey)
	if !ok {
		return nil, crypto.ErrBackendMismatch
	}

	// Parse JWE (currently only handles compact serialization)
	jwe, err := jose.ParseEncrypted(
		string(ciphertext),
		[]jose.KeyAlgorithm{jose.ECDH_ES, jose.ECDH_ES_A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	if err != nil {
		return nil, crypto.NewBackendError("jose", "decrypt_multi_recipient", err)
	}

	// Decrypt using private key
	plaintext, err := jwe.Decrypt(joseKey.jwk.Key)
	if err != nil {
		return nil, crypto.NewBackendError("jose", "decrypt_multi_recipient", err)
	}

	return plaintext, nil
}

// Sign signs data using ECDSA (ES256) and returns JWS Compact Serialization.
// The signature format is: <header>.<payload>.<signature>
func (b *Backend) Sign(privKey crypto.PrivateKey, data []byte) ([]byte, error) {
	joseKey, ok := privKey.(*privateKey)
	if !ok {
		return nil, crypto.ErrBackendMismatch
	}

	// Create signer with ES256 (ECDSA using P-256 and SHA-256)
	signingKey := jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       joseKey.jwk.Key,
	}

	opts := &jose.SignerOptions{}
	opts = opts.WithType("JWS")
	opts = opts.WithContentType("application/octet-stream")

	signer, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		return nil, crypto.NewBackendError("jose", "sign", err)
	}

	// Sign the data
	jws, err := signer.Sign(data)
	if err != nil {
		return nil, crypto.NewBackendError("jose", "sign", err)
	}

	// Serialize to compact format
	serialized, err := jws.CompactSerialize()
	if err != nil {
		return nil, crypto.NewBackendError("jose", "sign", err)
	}

	return []byte(serialized), nil
}

// Verify verifies a JWS signature using ECDSA public key.
// The signature parameter should be JWS Compact Serialization format.
func (b *Backend) Verify(pubKey crypto.PublicKey, data []byte, signature []byte) (bool, error) {
	joseKey, ok := pubKey.(*publicKey)
	if !ok {
		return false, crypto.ErrBackendMismatch
	}

	// Parse JWS
	jws, err := jose.ParseSigned(
		string(signature),
		[]jose.SignatureAlgorithm{jose.ES256},
	)
	if err != nil {
		return false, crypto.NewBackendError("jose", "verify", err)
	}

	// Verify signature and extract payload
	payload, err := jws.Verify(joseKey.jwk.Key)
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

// EncryptAndSign is a convenience method that creates JWS(JWE(...)).
// This wraps multi-recipient JWE encryption with a JWS signature for authenticated distributions.
// Returns JWS Compact Serialization containing the JWE as payload.
func (b *Backend) EncryptAndSign(recipients []crypto.PublicKey, plaintext []byte, signingKey crypto.PrivateKey, metadata map[string]interface{}) ([]byte, error) {
	// Step 1: Create multi-recipient JWE
	jwe, err := b.EncryptMultiRecipient(recipients, plaintext, metadata)
	if err != nil {
		return nil, err
	}

	// Step 2: Sign the JWE structure
	jws, err := b.Sign(signingKey, jwe)
	if err != nil {
		return nil, err
	}

	// Return JWS(JWE(...))
	return jws, nil
}

// DecryptAndVerify is a convenience method that verifies JWS and decrypts JWE.
// This is the inverse of EncryptAndSign, verifying the signature before decrypting.
// Returns plaintext if signature is valid and decryption succeeds.
func (b *Backend) DecryptAndVerify(privKey crypto.PrivateKey, verifyKey crypto.PublicKey, ciphertext []byte) ([]byte, error) {
	// Step 1: Parse and verify JWS
	jws, err := jose.ParseSigned(
		string(ciphertext),
		[]jose.SignatureAlgorithm{jose.ES256},
	)
	if err != nil {
		return nil, crypto.NewBackendError("jose", "decrypt_and_verify",
			fmt.Errorf("failed to parse JWS: %w", err))
	}

	joseVerifyKey, ok := verifyKey.(*publicKey)
	if !ok {
		return nil, crypto.ErrBackendMismatch
	}

	// Step 2: Verify signature and extract JWE payload
	jweBytes, err := jws.Verify(joseVerifyKey.jwk.Key)
	if err != nil {
		return nil, crypto.NewBackendError("jose", "decrypt_and_verify",
			fmt.Errorf("signature verification failed: %w", err))
	}

	// Step 3: Decrypt JWE
	plaintext, err := b.DecryptMultiRecipient(privKey, jweBytes)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Auto-register backend on package import
func init() {
	crypto.RegisterBackend(NewBackend())
}
