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
