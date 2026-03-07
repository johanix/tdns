/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Tests for HPKE backend wrapper
 */

package hpke

import (
	"bytes"
	"testing"

	"github.com/johanix/tdns/v2/crypto"
)

// TestBackendInterface verifies that Backend implements crypto.Backend
func TestBackendInterface(t *testing.T) {
	var _ crypto.Backend = (*Backend)(nil)
}

// TestBackendName verifies the backend name
func TestBackendName(t *testing.T) {
	backend := NewBackend()
	if backend.Name() != "hpke" {
		t.Errorf("expected backend name 'hpke', got '%s'", backend.Name())
	}
}

// TestGenerateKeypair tests keypair generation
func TestGenerateKeypair(t *testing.T) {
	backend := NewBackend()

	privKey, pubKey, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	if privKey == nil {
		t.Error("private key is nil")
	}
	if pubKey == nil {
		t.Error("public key is nil")
	}

	if privKey.Backend() != "hpke" {
		t.Errorf("private key backend expected 'hpke', got '%s'", privKey.Backend())
	}
	if pubKey.Backend() != "hpke" {
		t.Errorf("public key backend expected 'hpke', got '%s'", pubKey.Backend())
	}
}

// TestSerializeParsePublicKey tests public key serialization and parsing
func TestSerializeParsePublicKey(t *testing.T) {
	backend := NewBackend()

	// Generate a keypair
	_, pubKey, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	// Serialize
	data, err := backend.SerializePublicKey(pubKey)
	if err != nil {
		t.Fatalf("SerializePublicKey failed: %v", err)
	}

	if len(data) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(data))
	}

	// Parse
	parsedKey, err := backend.ParsePublicKey(data)
	if err != nil {
		t.Fatalf("ParsePublicKey failed: %v", err)
	}

	if parsedKey == nil {
		t.Fatal("parsed key is nil")
	}

	if parsedKey.Backend() != "hpke" {
		t.Errorf("parsed key backend expected 'hpke', got '%s'", parsedKey.Backend())
	}

	// Serialize again and compare
	data2, err := backend.SerializePublicKey(parsedKey)
	if err != nil {
		t.Fatalf("SerializePublicKey (2nd) failed: %v", err)
	}

	if !bytes.Equal(data, data2) {
		t.Error("serialized keys don't match")
	}
}

// TestSerializeParsePrivateKey tests private key serialization and parsing
func TestSerializeParsePrivateKey(t *testing.T) {
	backend := NewBackend()

	// Generate a keypair
	privKey, _, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	// Serialize
	data, err := backend.SerializePrivateKey(privKey)
	if err != nil {
		t.Fatalf("SerializePrivateKey failed: %v", err)
	}

	if len(data) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(data))
	}

	// Parse
	parsedKey, err := backend.ParsePrivateKey(data)
	if err != nil {
		t.Fatalf("ParsePrivateKey failed: %v", err)
	}

	if parsedKey == nil {
		t.Fatal("parsed key is nil")
	}

	if parsedKey.Backend() != "hpke" {
		t.Errorf("parsed key backend expected 'hpke', got '%s'", parsedKey.Backend())
	}

	// Serialize again and compare
	data2, err := backend.SerializePrivateKey(parsedKey)
	if err != nil {
		t.Fatalf("SerializePrivateKey (2nd) failed: %v", err)
	}

	if !bytes.Equal(data, data2) {
		t.Error("serialized keys don't match")
	}
}

// TestEncryptDecrypt tests encryption and decryption
func TestEncryptDecrypt(t *testing.T) {
	backend := NewBackend()

	// Generate keypair
	privKey, pubKey, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	// Plaintext to encrypt
	plaintext := []byte("Hello, HPKE world! This is a test message.")

	// Encrypt
	ciphertext, err := backend.Encrypt(pubKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatal("ciphertext is empty")
	}

	// Verify ciphertext is different from plaintext
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should be different from plaintext")
	}

	// Decrypt
	decrypted, err := backend.Decrypt(privKey, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify decrypted matches original
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted text doesn't match original.\nOriginal:  %s\nDecrypted: %s", plaintext, decrypted)
	}
}

// TestEncryptDecryptMultiple tests multiple encrypt/decrypt operations
func TestEncryptDecryptMultiple(t *testing.T) {
	backend := NewBackend()

	// Generate keypair
	privKey, pubKey, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	testMessages := []string{
		"Short",
		"Medium length message for testing",
		"A longer message that contains more data to ensure HPKE handles various sizes correctly. " +
			"This should be more than enough bytes to test the encryption and decryption pipeline thoroughly.",
		"",         // Empty message
		"\x00\x01", // Binary data
	}

	for i, msg := range testMessages {
		plaintext := []byte(msg)

		// Encrypt
		ciphertext, err := backend.Encrypt(pubKey, plaintext)
		if err != nil {
			t.Fatalf("Test %d: Encrypt failed: %v", i, err)
		}

		// Decrypt
		decrypted, err := backend.Decrypt(privKey, ciphertext)
		if err != nil {
			t.Fatalf("Test %d: Decrypt failed: %v", i, err)
		}

		// Verify
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("Test %d: decrypted text doesn't match original", i)
		}
	}
}

// TestDecryptWithWrongKey tests that decryption fails with wrong private key
func TestDecryptWithWrongKey(t *testing.T) {
	backend := NewBackend()

	// Generate two keypairs
	_, pubKey1, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (1) failed: %v", err)
	}

	privKey2, _, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (2) failed: %v", err)
	}

	// Encrypt with first keypair's public key
	plaintext := []byte("Secret message")
	ciphertext, err := backend.Encrypt(pubKey1, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to decrypt with second keypair's private key (should fail)
	_, err = backend.Decrypt(privKey2, ciphertext)
	if err == nil {
		t.Error("Decrypt with wrong key should fail, but succeeded")
	}
}

// TestParseInvalidPublicKey tests parsing of invalid public keys
func TestParseInvalidPublicKey(t *testing.T) {
	backend := NewBackend()

	tests := []struct {
		name string
		data []byte
	}{
		{"too short", []byte{1, 2, 3}},
		{"too long", make([]byte, 64)},
		{"empty", []byte{}},
		{"nil", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := backend.ParsePublicKey(tt.data)
			if err == nil {
				t.Error("expected error for invalid key, got nil")
			}
		})
	}
}

// TestParseInvalidPrivateKey tests parsing of invalid private keys
func TestParseInvalidPrivateKey(t *testing.T) {
	backend := NewBackend()

	tests := []struct {
		name string
		data []byte
	}{
		{"too short", []byte{1, 2, 3}},
		{"too long", make([]byte, 64)},
		{"empty", []byte{}},
		{"nil", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := backend.ParsePrivateKey(tt.data)
			if err == nil {
				t.Error("expected error for invalid key, got nil")
			}
		})
	}
}

// mockKey is a mock key type from a different backend
type mockKey struct{}

func (m mockKey) Backend() string { return "mock" }

// TestBackendMismatch tests that operations with wrong key type fail
func TestBackendMismatch(t *testing.T) {
	backend := NewBackend()

	// Create mock keys from a different backend
	var mockPub mockKey
	var mockPriv mockKey

	// Try to serialize mock keys
	_, err := backend.SerializePublicKey(mockPub)
	if err != crypto.ErrBackendMismatch {
		t.Errorf("expected ErrBackendMismatch, got %v", err)
	}

	_, err = backend.SerializePrivateKey(mockPriv)
	if err != crypto.ErrBackendMismatch {
		t.Errorf("expected ErrBackendMismatch, got %v", err)
	}

	// Try to encrypt with mock public key
	_, err = backend.Encrypt(mockPub, []byte("test"))
	if err != crypto.ErrBackendMismatch {
		t.Errorf("expected ErrBackendMismatch, got %v", err)
	}

	// Try to decrypt with mock private key
	_, err = backend.Decrypt(mockPriv, []byte("test"))
	if err != crypto.ErrBackendMismatch {
		t.Errorf("expected ErrBackendMismatch, got %v", err)
	}
}

// TestRegistration tests that the backend auto-registers
func TestRegistration(t *testing.T) {
	// The backend should be auto-registered via init()
	backend, err := crypto.GetBackend("hpke")
	if err != nil {
		t.Fatalf("GetBackend failed: %v", err)
	}

	if backend == nil {
		t.Fatal("backend is nil")
	}

	if backend.Name() != "hpke" {
		t.Errorf("expected name 'hpke', got '%s'", backend.Name())
	}
}

// TestGenerateSigningKeypair tests signing keypair generation (P-256)
func TestGenerateSigningKeypair(t *testing.T) {
	backend := NewBackend().(*Backend)

	signingKey, verifyKey, err := backend.GenerateSigningKeypair()
	if err != nil {
		t.Fatalf("GenerateSigningKeypair failed: %v", err)
	}

	if signingKey == nil {
		t.Error("signing key is nil")
	}
	if verifyKey == nil {
		t.Error("verify key is nil")
	}

	if signingKey.Backend() != "hpke" {
		t.Errorf("signing key backend expected 'hpke', got '%s'", signingKey.Backend())
	}
	if verifyKey.Backend() != "hpke" {
		t.Errorf("verify key backend expected 'hpke', got '%s'", verifyKey.Backend())
	}
}

// TestSignVerify tests signing and verification with P-256
func TestSignVerify(t *testing.T) {
	backend := NewBackend().(*Backend)

	signingKey, verifyKey, err := backend.GenerateSigningKeypair()
	if err != nil {
		t.Fatalf("GenerateSigningKeypair failed: %v", err)
	}

	data := []byte("Data to sign with HPKE backend")

	// Sign
	signature, err := backend.Sign(signingKey, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("signature is empty")
	}

	// Verify
	valid, err := backend.Verify(verifyKey, data, signature)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !valid {
		t.Error("signature verification failed, expected valid")
	}
}

// TestSignWithWrongKeyType tests that signing with encryption key fails
func TestSignWithWrongKeyType(t *testing.T) {
	backend := NewBackend().(*Backend)

	// Generate HPKE encryption key (X25519)
	encryptKey, _, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	data := []byte("Data to sign")

	// Try to sign with encryption key (should fail)
	_, err = backend.Sign(encryptKey, data)
	if err == nil {
		t.Error("Sign with encryption key should fail")
	}
}

// TestVerifyWithWrongKey tests signature verification with wrong key
func TestVerifyWithWrongKey(t *testing.T) {
	backend := NewBackend().(*Backend)

	signingKey1, _, err := backend.GenerateSigningKeypair()
	if err != nil {
		t.Fatalf("GenerateSigningKeypair (1) failed: %v", err)
	}

	_, verifyKey2, err := backend.GenerateSigningKeypair()
	if err != nil {
		t.Fatalf("GenerateSigningKeypair (2) failed: %v", err)
	}

	data := []byte("Data to sign")

	// Sign with key 1
	signature, err := backend.Sign(signingKey1, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Try to verify with key 2 (should fail)
	valid, err := backend.Verify(verifyKey2, data, signature)
	if err != nil {
		// Verification can fail with error or return false
		return
	}

	if valid {
		t.Error("signature verification should fail with wrong key")
	}
}

// TestVerifyModifiedData tests signature verification with modified data
func TestVerifyModifiedData(t *testing.T) {
	backend := NewBackend().(*Backend)

	signingKey, verifyKey, err := backend.GenerateSigningKeypair()
	if err != nil {
		t.Fatalf("GenerateSigningKeypair failed: %v", err)
	}

	originalData := []byte("Original data")
	modifiedData := []byte("Modified data")

	// Sign original data
	signature, err := backend.Sign(signingKey, originalData)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Try to verify modified data (should fail)
	valid, err := backend.Verify(verifyKey, modifiedData, signature)
	if err != nil {
		// Verification can fail with error or return false
		return
	}

	if valid {
		t.Error("signature verification should fail with modified data")
	}
}

// TestEncryptMultiRecipient tests multi-recipient API (single-recipient for Phase 3)
func TestEncryptMultiRecipient(t *testing.T) {
	backend := NewBackend()

	// Generate 3 keypairs
	privKeys := make([]crypto.PrivateKey, 3)
	pubKeys := make([]crypto.PublicKey, 3)
	for i := 0; i < 3; i++ {
		priv, pub, err := backend.GenerateKeypair()
		if err != nil {
			t.Fatalf("GenerateKeypair(%d) failed: %v", i, err)
		}
		privKeys[i] = priv
		pubKeys[i] = pub
	}

	plaintext := []byte("Multi-recipient test message for HPKE")

	// Test with metadata (currently not used, but API accepts it)
	metadata := map[string]interface{}{
		"distribution_id": "test-dist-789",
		"timestamp":       "2025-01-26T14:00:00Z",
	}

	// Encrypt for all 3 recipients (currently only encrypts for first)
	ciphertext, err := backend.EncryptMultiRecipient(pubKeys, plaintext, metadata)
	if err != nil {
		t.Fatalf("EncryptMultiRecipient failed: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatal("ciphertext is empty")
	}

	// PHASE 3 LIMITATION: Only first recipient can decrypt
	decrypted, err := backend.DecryptMultiRecipient(privKeys[0], ciphertext)
	if err != nil {
		t.Fatalf("Recipient 0 (first): DecryptMultiRecipient failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Recipient 0: decrypted text doesn't match original")
	}

	// Other recipients cannot decrypt (expected limitation)
	for i := 1; i < len(privKeys); i++ {
		_, err := backend.DecryptMultiRecipient(privKeys[i], ciphertext)
		if err == nil {
			t.Logf("Recipient %d: Unexpectedly succeeded (Phase 3 limitation means only first recipient should work)", i)
		}
	}
}

// TestEncryptMultiRecipientSingle tests single recipient via multi-recipient API
func TestEncryptMultiRecipientSingle(t *testing.T) {
	backend := NewBackend()

	privKey, pubKey, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	plaintext := []byte("Single recipient via multi-recipient API for HPKE")

	// Encrypt for single recipient
	ciphertext, err := backend.EncryptMultiRecipient([]crypto.PublicKey{pubKey}, plaintext, nil)
	if err != nil {
		t.Fatalf("EncryptMultiRecipient failed: %v", err)
	}

	// Decrypt
	decrypted, err := backend.DecryptMultiRecipient(privKey, ciphertext)
	if err != nil {
		t.Fatalf("DecryptMultiRecipient failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted text doesn't match original")
	}
}

// TestEncryptAndSign tests full JWS(HPKE(...)) creation
func TestEncryptAndSign(t *testing.T) {
	backend := NewBackend().(*Backend)

	// Generate signing keypair
	signingKey, verifyKey, err := backend.GenerateSigningKeypair()
	if err != nil {
		t.Fatalf("GenerateSigningKeypair failed: %v", err)
	}

	// Generate 2 recipient keypairs
	privKeys := make([]crypto.PrivateKey, 2)
	pubKeys := make([]crypto.PublicKey, 2)
	for i := 0; i < 2; i++ {
		priv, pub, err := backend.GenerateKeypair()
		if err != nil {
			t.Fatalf("GenerateKeypair (recipient %d) failed: %v", i, err)
		}
		privKeys[i] = priv
		pubKeys[i] = pub
	}

	plaintext := []byte("Authenticated and encrypted HPKE distribution")

	metadata := map[string]interface{}{
		"distribution_id": "dist-hpke-123",
		"timestamp":       "2025-01-26T14:30:00Z",
	}

	// Encrypt and sign (currently only encrypts for first recipient)
	jws, err := backend.EncryptAndSign(pubKeys, plaintext, signingKey, metadata)
	if err != nil {
		t.Fatalf("EncryptAndSign failed: %v", err)
	}

	if len(jws) == 0 {
		t.Fatal("JWS output is empty")
	}

	// PHASE 3 LIMITATION: Only first recipient can decrypt and verify
	decrypted, err := backend.DecryptAndVerify(privKeys[0], verifyKey, jws)
	if err != nil {
		t.Fatalf("Recipient 0: DecryptAndVerify failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Recipient 0: decrypted text doesn't match")
	}
}

// TestDecryptAndVerifyInvalidSignature tests that DecryptAndVerify fails with wrong verify key
func TestDecryptAndVerifyInvalidSignature(t *testing.T) {
	backend := NewBackend().(*Backend)

	// Generate two signing keypairs
	signingKey1, _, err := backend.GenerateSigningKeypair()
	if err != nil {
		t.Fatalf("GenerateSigningKeypair (1) failed: %v", err)
	}

	_, verifyKey2, err := backend.GenerateSigningKeypair()
	if err != nil {
		t.Fatalf("GenerateSigningKeypair (2) failed: %v", err)
	}

	// Generate recipient keypair
	recipientPriv, recipientPub, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (recipient) failed: %v", err)
	}

	plaintext := []byte("Test message for HPKE")

	// Encrypt and sign with key 1
	jws, err := backend.EncryptAndSign([]crypto.PublicKey{recipientPub}, plaintext, signingKey1, nil)
	if err != nil {
		t.Fatalf("EncryptAndSign failed: %v", err)
	}

	// Try to decrypt and verify with key 2 (should fail)
	_, err = backend.DecryptAndVerify(recipientPriv, verifyKey2, jws)
	if err == nil {
		t.Error("DecryptAndVerify should fail with wrong verify key")
	}
}

// TestEncryptMultiRecipientNoRecipients tests error handling for empty recipients
func TestEncryptMultiRecipientNoRecipients(t *testing.T) {
	backend := NewBackend()

	plaintext := []byte("test")

	// Try to encrypt with no recipients (should fail)
	_, err := backend.EncryptMultiRecipient([]crypto.PublicKey{}, plaintext, nil)
	if err == nil {
		t.Error("EncryptMultiRecipient with no recipients should fail")
	}
}

// TestBackwardCompatibility tests that DecryptMultiRecipient can decrypt old Encrypt output
func TestBackwardCompatibility(t *testing.T) {
	backend := NewBackend()

	privKey, pubKey, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	plaintext := []byte("Backward compatibility test for HPKE")

	// Encrypt with old single-recipient Encrypt method (raw HPKE format)
	oldCiphertext, err := backend.Encrypt(pubKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt with new DecryptMultiRecipient method (should handle raw HPKE format)
	decrypted, err := backend.DecryptMultiRecipient(privKey, oldCiphertext)
	if err != nil {
		t.Fatalf("DecryptMultiRecipient failed on raw HPKE format: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("backward compatibility: decrypted text doesn't match")
	}
}

// TestSerializeParseSigningKey tests signing key serialization
func TestSerializeParseSigningKey(t *testing.T) {
	backend := NewBackend().(*Backend)

	signingKey, _, err := backend.GenerateSigningKeypair()
	if err != nil {
		t.Fatalf("GenerateSigningKeypair failed: %v", err)
	}

	// Serialize
	data, err := backend.SerializeSigningKey(signingKey)
	if err != nil {
		t.Fatalf("SerializeSigningKey failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("serialized data is empty")
	}

	// Parse
	parsedKey, err := backend.ParseSigningKey(data)
	if err != nil {
		t.Fatalf("ParseSigningKey failed: %v", err)
	}

	if parsedKey == nil {
		t.Fatal("parsed key is nil")
	}

	// Use parsed key to sign and verify it works
	testData := []byte("test signing with parsed key")
	signature, err := backend.Sign(parsedKey, testData)
	if err != nil {
		t.Fatalf("Sign with parsed key failed: %v", err)
	}

	if len(signature) == 0 {
		t.Error("signature is empty")
	}
}

// TestSerializeParseVerifyKey tests verify key serialization
func TestSerializeParseVerifyKey(t *testing.T) {
	backend := NewBackend().(*Backend)

	signingKey, verifyKey, err := backend.GenerateSigningKeypair()
	if err != nil {
		t.Fatalf("GenerateSigningKeypair failed: %v", err)
	}

	// Serialize verify key
	data, err := backend.SerializeVerifyKey(verifyKey)
	if err != nil {
		t.Fatalf("SerializeVerifyKey failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("serialized data is empty")
	}

	// Parse
	parsedKey, err := backend.ParseVerifyKey(data)
	if err != nil {
		t.Fatalf("ParseVerifyKey failed: %v", err)
	}

	if parsedKey == nil {
		t.Fatal("parsed key is nil")
	}

	// Use parsed key to verify a signature
	testData := []byte("test verification with parsed key")
	signature, err := backend.Sign(signingKey, testData)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	valid, err := backend.Verify(parsedKey, testData, signature)
	if err != nil {
		t.Fatalf("Verify with parsed key failed: %v", err)
	}

	if !valid {
		t.Error("verification with parsed key failed")
	}
}
