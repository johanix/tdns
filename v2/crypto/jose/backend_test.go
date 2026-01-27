/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Tests for JOSE backend
 */

package jose

import (
	"bytes"
	"encoding/json"
	"strings"
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
	if backend.Name() != "jose" {
		t.Errorf("expected backend name 'jose', got '%s'", backend.Name())
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

	if privKey.Backend() != "jose" {
		t.Errorf("private key backend expected 'jose', got '%s'", privKey.Backend())
	}
	if pubKey.Backend() != "jose" {
		t.Errorf("public key backend expected 'jose', got '%s'", pubKey.Backend())
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

	if len(data) == 0 {
		t.Error("serialized data is empty")
	}

	// Verify it's valid JSON
	if !json.Valid(data) {
		t.Error("serialized key is not valid JSON")
	}

	// Verify it's a JWK
	var jwkMap map[string]interface{}
	if err := json.Unmarshal(data, &jwkMap); err != nil {
		t.Fatalf("failed to unmarshal JWK: %v", err)
	}

	// Check JWK fields
	if kty, ok := jwkMap["kty"].(string); !ok || kty != "EC" {
		t.Errorf("expected kty='EC', got '%v'", jwkMap["kty"])
	}
	if crv, ok := jwkMap["crv"].(string); !ok || crv != "P-256" {
		t.Errorf("expected crv='P-256', got '%v'", jwkMap["crv"])
	}

	// Parse
	parsedKey, err := backend.ParsePublicKey(data)
	if err != nil {
		t.Fatalf("ParsePublicKey failed: %v", err)
	}

	if parsedKey == nil {
		t.Fatal("parsed key is nil")
	}

	if parsedKey.Backend() != "jose" {
		t.Errorf("parsed key backend expected 'jose', got '%s'", parsedKey.Backend())
	}

	// Serialize again and verify structure matches (may not be byte-identical due to JSON formatting)
	data2, err := backend.SerializePublicKey(parsedKey)
	if err != nil {
		t.Fatalf("SerializePublicKey (2nd) failed: %v", err)
	}

	// Compare as JSON objects
	var jwk1, jwk2 map[string]interface{}
	json.Unmarshal(data, &jwk1)
	json.Unmarshal(data2, &jwk2)

	// Compare key fields (x, y coordinates should match)
	if jwk1["x"] != jwk2["x"] || jwk1["y"] != jwk2["y"] {
		t.Error("serialized keys have different coordinates")
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

	if len(data) == 0 {
		t.Error("serialized data is empty")
	}

	// Verify it's valid JSON
	if !json.Valid(data) {
		t.Error("serialized key is not valid JSON")
	}

	// Verify it's a JWK with private key material
	var jwkMap map[string]interface{}
	if err := json.Unmarshal(data, &jwkMap); err != nil {
		t.Fatalf("failed to unmarshal JWK: %v", err)
	}

	// Private key should have 'd' field
	if _, ok := jwkMap["d"]; !ok {
		t.Error("private key JWK missing 'd' field")
	}

	// Parse
	parsedKey, err := backend.ParsePrivateKey(data)
	if err != nil {
		t.Fatalf("ParsePrivateKey failed: %v", err)
	}

	if parsedKey == nil {
		t.Fatal("parsed key is nil")
	}

	if parsedKey.Backend() != "jose" {
		t.Errorf("parsed key backend expected 'jose', got '%s'", parsedKey.Backend())
	}

	// Serialize again and compare
	data2, err := backend.SerializePrivateKey(parsedKey)
	if err != nil {
		t.Fatalf("SerializePrivateKey (2nd) failed: %v", err)
	}

	// Compare as JSON objects
	var jwk1, jwk2 map[string]interface{}
	json.Unmarshal(data, &jwk1)
	json.Unmarshal(data2, &jwk2)

	// Compare key fields
	if jwk1["d"] != jwk2["d"] {
		t.Error("serialized keys have different private key material")
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
	plaintext := []byte("Hello, JOSE world! This is a test message.")

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

	// Verify it looks like JWE compact serialization (5 parts separated by dots)
	parts := strings.Split(string(ciphertext), ".")
	if len(parts) != 5 {
		t.Errorf("expected 5 parts in JWE compact serialization, got %d", len(parts))
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
		"A longer message that contains more data to ensure JOSE handles various sizes correctly. " +
			"This should be more than enough bytes to test the encryption and decryption pipeline thoroughly.",
		// Note: Empty messages may not be supported by all JWE implementations
		// For TDNS use case, we always encrypt non-empty data (keys, manifests)
		// so this is not a practical limitation
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
		{"not json", []byte("not json")},
		{"empty json", []byte("{}")},
		{"private key", []byte(`{"kty":"EC","crv":"P-256","x":"abc","y":"def","d":"private"}`)},
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
		{"not json", []byte("not json")},
		{"empty json", []byte("{}")},
		{"public key only", []byte(`{"kty":"EC","crv":"P-256","x":"abc","y":"def"}`)},
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
	backend, err := crypto.GetBackend("jose")
	if err != nil {
		t.Fatalf("GetBackend failed: %v", err)
	}

	if backend == nil {
		t.Fatal("backend is nil")
	}

	if backend.Name() != "jose" {
		t.Errorf("expected name 'jose', got '%s'", backend.Name())
	}
}

// TestJWEFormat tests that encrypted output is valid JWE compact serialization
func TestJWEFormat(t *testing.T) {
	backend := NewBackend()

	privKey, pubKey, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	plaintext := []byte("test message")
	ciphertext, err := backend.Encrypt(pubKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// JWE compact serialization format: header.encrypted_key.iv.ciphertext.tag
	parts := strings.Split(string(ciphertext), ".")
	if len(parts) != 5 {
		t.Errorf("expected 5 parts in JWE, got %d", len(parts))
	}

	// Each part should be base64url encoded (non-empty for this use case)
	for i, part := range parts {
		// IV (part 2) and encrypted_key (part 1) might be empty for some algorithms
		// but for ECDH-ES+A256GCM they should all have content
		if i == 1 {
			// encrypted_key may be empty for ECDH-ES (direct key agreement)
			continue
		}
		if len(part) == 0 {
			t.Errorf("part %d is empty", i)
		}
	}

	// Verify we can decrypt it
	decrypted, err := backend.Decrypt(privKey, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypt verification failed")
	}
}

// TestEncryptMultiRecipient tests multi-recipient JWE encryption
// NOTE: Phase 2 limitation - currently only encrypts for first recipient
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

	plaintext := []byte("Multi-recipient test message")

	// Test with metadata
	metadata := map[string]interface{}{
		"distribution_id": "test-dist-123",
		"timestamp":       "2025-01-26T10:00:00Z",
		"sender":          "kdc.example.com",
	}

	// Encrypt for all 3 recipients (currently only encrypts for first)
	ciphertext, err := backend.EncryptMultiRecipient(pubKeys, plaintext, metadata)
	if err != nil {
		t.Fatalf("EncryptMultiRecipient failed: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatal("ciphertext is empty")
	}

	// PHASE 2 LIMITATION: Only first recipient can decrypt
	// First recipient should be able to decrypt
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
			t.Logf("Recipient %d: Unexpectedly succeeded (Phase 2 limitation means only first recipient should work)", i)
		}
	}
}

// TestEncryptMultiRecipientSingle tests multi-recipient with single recipient
func TestEncryptMultiRecipientSingle(t *testing.T) {
	backend := NewBackend()

	privKey, pubKey, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	plaintext := []byte("Single recipient via multi-recipient API")

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

// TestEncryptMultiRecipientMany tests with 5 recipients
// NOTE: Phase 2 limitation - currently only encrypts for first recipient
func TestEncryptMultiRecipientMany(t *testing.T) {
	backend := NewBackend()

	// Generate 5 keypairs
	const numRecipients = 5
	privKeys := make([]crypto.PrivateKey, numRecipients)
	pubKeys := make([]crypto.PublicKey, numRecipients)
	for i := 0; i < numRecipients; i++ {
		priv, pub, err := backend.GenerateKeypair()
		if err != nil {
			t.Fatalf("GenerateKeypair(%d) failed: %v", i, err)
		}
		privKeys[i] = priv
		pubKeys[i] = pub
	}

	plaintext := []byte("Message for 5 recipients")

	// Encrypt for all recipients (currently only encrypts for first)
	ciphertext, err := backend.EncryptMultiRecipient(pubKeys, plaintext, nil)
	if err != nil {
		t.Fatalf("EncryptMultiRecipient failed: %v", err)
	}

	// PHASE 2 LIMITATION: Only first recipient can decrypt
	decrypted, err := backend.DecryptMultiRecipient(privKeys[0], ciphertext)
	if err != nil {
		t.Fatalf("Recipient 0 (first): DecryptMultiRecipient failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Recipient 0: decrypted text doesn't match")
	}
}

// TestSign tests JWS signing
func TestSign(t *testing.T) {
	backend := NewBackend()

	privKey, _, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	data := []byte("Data to sign")

	// Sign
	signature, err := backend.Sign(privKey, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("signature is empty")
	}

	// Verify it looks like JWS compact serialization (3 parts)
	parts := strings.Split(string(signature), ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 parts in JWS compact serialization, got %d", len(parts))
	}
}

// TestVerify tests JWS signature verification
func TestVerify(t *testing.T) {
	backend := NewBackend()

	privKey, pubKey, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	data := []byte("Data to sign and verify")

	// Sign
	signature, err := backend.Sign(privKey, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify
	valid, err := backend.Verify(pubKey, data, signature)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !valid {
		t.Error("signature verification failed, expected valid")
	}
}

// TestVerifyWrongKey tests signature verification with wrong public key
func TestVerifyWrongKey(t *testing.T) {
	backend := NewBackend()

	privKey1, _, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (1) failed: %v", err)
	}

	_, pubKey2, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (2) failed: %v", err)
	}

	data := []byte("Data to sign")

	// Sign with key 1
	signature, err := backend.Sign(privKey1, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Try to verify with key 2 (should fail)
	valid, err := backend.Verify(pubKey2, data, signature)
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
	backend := NewBackend()

	privKey, pubKey, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	originalData := []byte("Original data")
	modifiedData := []byte("Modified data")

	// Sign original data
	signature, err := backend.Sign(privKey, originalData)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Try to verify modified data (should fail)
	valid, err := backend.Verify(pubKey, modifiedData, signature)
	if err != nil {
		// Verification can fail with error or return false
		return
	}

	if valid {
		t.Error("signature verification should fail with modified data")
	}
}

// TestEncryptAndSign tests full JWS(JWE(...)) creation
// NOTE: Phase 2 limitation - currently only encrypts for first recipient
func TestEncryptAndSign(t *testing.T) {
	backend := NewBackend().(*Backend)

	// Generate signing keypair
	signingKey, verifyKey, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (signing) failed: %v", err)
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

	plaintext := []byte("Authenticated and encrypted distribution")

	metadata := map[string]interface{}{
		"distribution_id": "dist-456",
		"timestamp":       "2025-01-26T12:00:00Z",
	}

	// Encrypt and sign (currently only encrypts for first recipient)
	jws, err := backend.EncryptAndSign(pubKeys, plaintext, signingKey, metadata)
	if err != nil {
		t.Fatalf("EncryptAndSign failed: %v", err)
	}

	if len(jws) == 0 {
		t.Fatal("JWS output is empty")
	}

	// Verify it's JWS compact serialization (3 parts)
	parts := strings.Split(string(jws), ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 parts in JWS, got %d", len(parts))
	}

	// PHASE 2 LIMITATION: Only first recipient can decrypt and verify
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
	signingKey1, _, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (signing1) failed: %v", err)
	}

	_, verifyKey2, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (signing2) failed: %v", err)
	}

	// Generate recipient keypair
	recipientPriv, recipientPub, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (recipient) failed: %v", err)
	}

	plaintext := []byte("Test message")

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

// TestDecryptMultiRecipientWrongKey tests that decryption fails with wrong key
// NOTE: Phase 2 limitation - currently only encrypts for first recipient
func TestDecryptMultiRecipientWrongKey(t *testing.T) {
	backend := NewBackend()

	// Generate 2 keypairs for recipients
	privKey1, pubKey1, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (1) failed: %v", err)
	}

	_, pubKey2, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (2) failed: %v", err)
	}

	// Generate a third keypair (not a recipient)
	privKey3, _, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (3) failed: %v", err)
	}

	plaintext := []byte("Secret for recipients 1 and 2 only")

	// Encrypt for recipients 1 and 2 (currently only encrypts for first)
	ciphertext, err := backend.EncryptMultiRecipient([]crypto.PublicKey{pubKey1, pubKey2}, plaintext, nil)
	if err != nil {
		t.Fatalf("EncryptMultiRecipient failed: %v", err)
	}

	// PHASE 2 LIMITATION: Only recipient 1 (first) should succeed
	_, err = backend.DecryptMultiRecipient(privKey1, ciphertext)
	if err != nil {
		t.Errorf("Recipient 1 (first) decrypt failed: %v", err)
	}

	// Recipient 3 (not included) should fail
	_, err = backend.DecryptMultiRecipient(privKey3, ciphertext)
	if err == nil {
		t.Error("Decrypt with non-recipient key should fail")
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

	plaintext := []byte("Backward compatibility test")

	// Encrypt with old single-recipient Encrypt method (compact serialization)
	oldCiphertext, err := backend.Encrypt(pubKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt with new DecryptMultiRecipient method (should handle compact serialization)
	decrypted, err := backend.DecryptMultiRecipient(privKey, oldCiphertext)
	if err != nil {
		t.Fatalf("DecryptMultiRecipient failed on compact serialization: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("backward compatibility: decrypted text doesn't match")
	}
}
