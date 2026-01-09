/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * HPKE wrapper functions using Cloudflare CIRCL library
 * Configuration: Base mode, X25519 KEM, HKDF-SHA256 KDF, AES-256-GCM AEAD
 */

package hpke

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/hpke"
)

// getHPKESuite returns the HPKE suite for X25519 + HKDF-SHA256 + AES-256-GCM
func getHPKESuite() hpke.Suite {
	return hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
}

// Encrypt encrypts plaintext using HPKE Base mode
// recipientPubKey: X25519 public key of the recipient (32 bytes)
// ephemeralPubKey: Optional ephemeral public key from recipient (for forward secrecy)
// If ephemeralPubKey is nil, a new ephemeral keypair is generated
// Returns: encrypted ciphertext (with encapsulated key prepended), ephemeral public key used, error
func Encrypt(recipientPubKey []byte, ephemeralPubKey []byte, plaintext []byte) (ciphertext []byte, ephemeralPub []byte, err error) {
	if len(recipientPubKey) != 32 {
		return nil, nil, fmt.Errorf("recipient public key must be 32 bytes (got %d)", len(recipientPubKey))
	}

	// Get HPKE suite
	suite := getHPKESuite()

	// Get KEM scheme
	kemScheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()

	// Unmarshal recipient's public key
	recipientKey, err := kemScheme.UnmarshalBinaryPublicKey(recipientPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal recipient public key: %v", err)
	}

	// Note: The ephemeralPubKey parameter is for future use with forward secrecy.
	// For now, HPKE Base mode generates its own ephemeral key during Setup().
	// The ephemeralPubKey parameter is ignored in this implementation.

	// Create sender context (Base mode: no PSK, no sender authentication)
	sender, err := suite.NewSender(recipientKey, nil) // nil = no info
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create sender: %v", err)
	}

	// Setup encryption (generates ephemeral keypair internally)
	encapsulatedKey, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup encryption: %v", err)
	}

	// Verify encapsulated key size matches expected ciphertext size
	// For X25519, CiphertextSize() should equal PublicKeySize() (32 bytes)
	expectedSize := kemScheme.CiphertextSize()
	publicKeySize := kemScheme.PublicKeySize()
	if len(encapsulatedKey) != expectedSize {
		return nil, nil, fmt.Errorf("encapsulated key size mismatch: got %d, expected %d (PublicKeySize=%d)", len(encapsulatedKey), expectedSize, publicKeySize)
	}

	// Encrypt plaintext
	encryptedData, err := sealer.Seal(plaintext, nil) // nil = no associated data
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt: %v", err)
	}

	// Prepend encapsulated key to ciphertext
	// For X25519, the encapsulated key should be exactly CiphertextSize() bytes
	encLen := len(encapsulatedKey)
	expectedEncLen := kemScheme.CiphertextSize()
	if encLen != expectedEncLen {
		return nil, nil, fmt.Errorf("encapsulated key length mismatch: got %d, expected %d", encLen, expectedEncLen)
	}

	fullCiphertext := make([]byte, encLen+len(encryptedData))
	copy(fullCiphertext[:encLen], encapsulatedKey)
	copy(fullCiphertext[encLen:], encryptedData)

	// Extract ephemeral public key from encapsulated key
	// For X25519, the encapsulated key IS the ephemeral public key
	ephemeralPub = make([]byte, len(encapsulatedKey))
	copy(ephemeralPub, encapsulatedKey)

	return fullCiphertext, ephemeralPub, nil
}

// Decrypt decrypts ciphertext using HPKE Base mode
// recipientPrivKey: X25519 private key of the recipient (32 bytes)
// ephemeralPubKey: Ephemeral public key from sender (32 bytes) - currently unused, extracted from ciphertext
// ciphertext: HPKE-encrypted data (encapsulated key + encrypted data)
// Returns: decrypted plaintext, error
func Decrypt(recipientPrivKey []byte, ephemeralPubKey []byte, ciphertext []byte) (plaintext []byte, err error) {
	if len(recipientPrivKey) != 32 {
		return nil, fmt.Errorf("recipient private key must be 32 bytes (got %d)", len(recipientPrivKey))
	}

	// Get HPKE suite
	suite := getHPKESuite()

	// Get KEM scheme
	kemScheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()

	// Unmarshal recipient's private key
	recipientKey, err := kemScheme.UnmarshalBinaryPrivateKey(recipientPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal recipient private key: %v", err)
	}

	// Extract encapsulated key from ciphertext
	// For X25519, the encapsulated key is the ephemeral public key
	// Use PublicKeySize() which should equal CiphertextSize() for X25519 (32 bytes)
	encLen := kemScheme.PublicKeySize()
	ciphertextSize := kemScheme.CiphertextSize()
	if encLen != ciphertextSize {
		// This shouldn't happen for X25519, but if it does, use CiphertextSize()
		encLen = ciphertextSize
	}
	if len(ciphertext) < encLen {
		return nil, fmt.Errorf("ciphertext too short (got %d, need at least %d)", len(ciphertext), encLen)
	}

	// Extract encapsulated key (first encLen bytes)
	encapsulatedKey := make([]byte, encLen)
	copy(encapsulatedKey, ciphertext[:encLen])

	// Extract encrypted data (remaining bytes after encapsulated key)
	// Create a proper copy to avoid any potential slice sharing issues
	encryptedDataLen := len(ciphertext) - encLen
	encryptedData := make([]byte, encryptedDataLen)
	copy(encryptedData, ciphertext[encLen:])

	// Create receiver context (Base mode: no PSK, no sender authentication)
	receiver, err := suite.NewReceiver(recipientKey, nil) // nil = no info
	if err != nil {
		return nil, fmt.Errorf("failed to create receiver: %v", err)
	}

	// Setup decryption (takes encapsulated key)
	opener, err := receiver.Setup(encapsulatedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to setup decryption: %v", err)
	}

	// Decrypt
	plaintext, err = opener.Open(encryptedData, nil) // nil = no associated data
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil
}

// GenerateKeyPair generates a new HPKE keypair (X25519)
// Returns: public key (32 bytes), private key (32 bytes), error
func GenerateKeyPair() (publicKey []byte, privateKey []byte, err error) {
	// Get KEM scheme
	kemScheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()

	// Generate keypair
	// Note: kemScheme.GenerateKeyPair() returns (pubKey, privKey, error) - public key first!
	pubKey, privKey, err := kemScheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate keypair: %v", err)
	}

	// Marshal keys to bytes (PublicKey and PrivateKey implement encoding.BinaryMarshaler)
	pubBytes, err := pubKey.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %v", err)
	}

	privBytes, err := privKey.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %v", err)
	}

	return pubBytes, privBytes, nil
}

// DerivePublicKey derives the public key from a private key (X25519)
// privateKey: X25519 private key (32 bytes)
// Returns: public key (32 bytes), error
func DerivePublicKey(privateKey []byte) (publicKey []byte, err error) {
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes (got %d)", len(privateKey))
	}

	// Use X25519 package directly to derive public key
	var privKey, pubKey x25519.Key
	copy(privKey[:], privateKey)

	// Derive public key by scalar multiplication with base point
	x25519.KeyGen(&pubKey, &privKey)

	// Return public key as bytes
	return pubKey[:], nil
}

// EncryptAuth encrypts plaintext using HPKE Auth mode (sender authentication)
// senderPrivKey: X25519 private key of the sender (32 bytes) - for authentication
// recipientPubKey: X25519 public key of the recipient (32 bytes)
// plaintext: Data to encrypt
// Returns: encrypted ciphertext (with encapsulated key prepended), error
func EncryptAuth(senderPrivKey []byte, recipientPubKey []byte, plaintext []byte) (ciphertext []byte, err error) {
	if len(senderPrivKey) != 32 {
		return nil, fmt.Errorf("sender private key must be 32 bytes (got %d)", len(senderPrivKey))
	}
	if len(recipientPubKey) != 32 {
		return nil, fmt.Errorf("recipient public key must be 32 bytes (got %d)", len(recipientPubKey))
	}

	// Get HPKE suite
	suite := getHPKESuite()

	// Get KEM scheme
	kemScheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()

	// Unmarshal sender's private key
	senderKey, err := kemScheme.UnmarshalBinaryPrivateKey(senderPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal sender private key: %v", err)
	}

	// Unmarshal recipient's public key
	recipientKey, err := kemScheme.UnmarshalBinaryPublicKey(recipientPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal recipient public key: %v", err)
	}

	// Create sender context (Auth mode requires sender's private key)
	// Note: CIRCL HPKE Auth mode uses NewSender with sender's private key parameter
	// The SetupAuth method is called on the sender object
	sender, err := suite.NewSender(recipientKey, nil) // nil = no info
	if err != nil {
		return nil, fmt.Errorf("failed to create sender: %v", err)
	}

	// Setup encryption with authentication (generates ephemeral keypair internally)
	// SetupAuth takes the sender's private key for authentication
	encapsulatedKey, sealer, err := sender.SetupAuth(rand.Reader, senderKey)
	if err != nil {
		return nil, fmt.Errorf("failed to setup authenticated encryption: %v", err)
	}

	// Verify encapsulated key size matches expected ciphertext size
	expectedSize := kemScheme.CiphertextSize()
	if len(encapsulatedKey) != expectedSize {
		return nil, fmt.Errorf("encapsulated key size mismatch: got %d, expected %d", len(encapsulatedKey), expectedSize)
	}

	// Encrypt plaintext
	encryptedData, err := sealer.Seal(plaintext, nil) // nil = no associated data
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %v", err)
	}

	// Prepend encapsulated key to ciphertext
	encLen := len(encapsulatedKey)
	fullCiphertext := make([]byte, encLen+len(encryptedData))
	copy(fullCiphertext[:encLen], encapsulatedKey)
	copy(fullCiphertext[encLen:], encryptedData)

	return fullCiphertext, nil
}

// DecryptAuth decrypts ciphertext using HPKE Auth mode (sender authentication)
// recipientPrivKey: X25519 private key of the recipient (32 bytes)
// senderPubKey: X25519 public key of the sender (32 bytes) - for authentication verification
// ciphertext: HPKE-encrypted data (encapsulated key + encrypted data)
// Returns: decrypted plaintext, error
func DecryptAuth(recipientPrivKey []byte, senderPubKey []byte, ciphertext []byte) (plaintext []byte, err error) {
	if len(recipientPrivKey) != 32 {
		return nil, fmt.Errorf("recipient private key must be 32 bytes (got %d)", len(recipientPrivKey))
	}
	if len(senderPubKey) != 32 {
		return nil, fmt.Errorf("sender public key must be 32 bytes (got %d)", len(senderPubKey))
	}

	// Get HPKE suite
	suite := getHPKESuite()

	// Get KEM scheme
	kemScheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()

	// Unmarshal recipient's private key
	recipientKey, err := kemScheme.UnmarshalBinaryPrivateKey(recipientPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal recipient private key: %v", err)
	}

	// Unmarshal sender's public key
	senderKey, err := kemScheme.UnmarshalBinaryPublicKey(senderPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal sender public key: %v", err)
	}

	// Extract encapsulated key from ciphertext
	encLen := kemScheme.PublicKeySize()
	ciphertextSize := kemScheme.CiphertextSize()
	if encLen != ciphertextSize {
		encLen = ciphertextSize
	}
	if len(ciphertext) < encLen {
		return nil, fmt.Errorf("ciphertext too short (got %d, need at least %d)", len(ciphertext), encLen)
	}

	// Extract encapsulated key (first encLen bytes)
	encapsulatedKey := make([]byte, encLen)
	copy(encapsulatedKey, ciphertext[:encLen])

	// Extract encrypted data (remaining bytes after encapsulated key)
	encryptedDataLen := len(ciphertext) - encLen
	encryptedData := make([]byte, encryptedDataLen)
	copy(encryptedData, ciphertext[encLen:])

	// Create receiver context (Auth mode requires sender's public key)
	// Note: CIRCL HPKE Auth mode uses NewReceiver with sender's public key parameter
	// The SetupAuth method is called on the receiver object
	receiver, err := suite.NewReceiver(recipientKey, nil) // nil = no info
	if err != nil {
		return nil, fmt.Errorf("failed to create receiver: %v", err)
	}

	// Setup decryption with authentication (takes encapsulated key and sender's public key)
	// SetupAuth takes the sender's public key for authentication verification
	opener, err := receiver.SetupAuth(encapsulatedKey, senderKey)
	if err != nil {
		return nil, fmt.Errorf("failed to setup authenticated decryption: %v", err)
	}

	// Decrypt
	plaintext, err = opener.Open(encryptedData, nil) // nil = no associated data
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil
}
