/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Tests for HPKE wrapper functions
 */

package hpke

import (
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	pubKey, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if len(pubKey) != 32 {
		t.Errorf("Public key length is %d, expected 32", len(pubKey))
	}

	if len(privKey) != 32 {
		t.Errorf("Private key length is %d, expected 32", len(privKey))
	}

	t.Logf("Generated keypair: pub=%x priv=%x", pubKey[:8], privKey[:8])
}

func TestEncryptDecrypt(t *testing.T) {
	// Generate recipient keypair
	recipientPub, recipientPriv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate recipient keypair: %v", err)
	}

	// Test plaintext
	plaintext := []byte("This is a test message for HPKE encryption")

	// Encrypt without ephemeral key (will generate one)
	ciphertext, ephemeralPub, err := Encrypt(recipientPub, nil, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatal("Ciphertext is empty")
	}

	if len(ephemeralPub) != 32 {
		t.Errorf("Ephemeral public key length is %d, expected 32", len(ephemeralPub))
	}

	t.Logf("Encrypted %d bytes to %d bytes (ephemeral pub: %x)", len(plaintext), len(ciphertext), ephemeralPub[:8])

	// Decrypt
	decrypted, err := Decrypt(recipientPriv, ephemeralPub, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text doesn't match: got %q, want %q", string(decrypted), string(plaintext))
	}

	t.Logf("Successfully decrypted: %q", string(decrypted))
}

func TestEncryptDecryptWithEphemeralKey(t *testing.T) {
	// Generate recipient keypair
	recipientPub, recipientPriv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate recipient keypair: %v", err)
	}

	// Generate ephemeral keypair for forward secrecy
	ephemeralPub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate ephemeral keypair: %v", err)
	}

	// Test plaintext
	plaintext := []byte("Test message with ephemeral key for forward secrecy")

	// Encrypt with provided ephemeral public key
	ciphertext, senderEphemeralPub, err := Encrypt(recipientPub, ephemeralPub, plaintext)
	if err != nil {
		t.Fatalf("Encrypt with ephemeral key failed: %v", err)
	}

	t.Logf("Encrypted with ephemeral key: %d bytes (sender ephemeral: %x)", len(ciphertext), senderEphemeralPub[:8])

	// Note: In a real scenario, the recipient would use their ephemeral private key
	// For this test, we're using the recipient's long-term key
	// The actual implementation would need to handle ephemeral keys differently
	decrypted, err := Decrypt(recipientPriv, senderEphemeralPub, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text doesn't match: got %q, want %q", string(decrypted), string(plaintext))
	}

	t.Logf("Successfully decrypted with ephemeral key: %q", string(decrypted))
}

func TestEncryptDecryptLargeData(t *testing.T) {
	// Generate recipient keypair
	recipientPub, recipientPriv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate recipient keypair: %v", err)
	}

	// Create larger test data (simulating a DNSSEC private key)
	plaintext := make([]byte, 4096)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	// Encrypt
	ciphertext, ephemeralPub, err := Encrypt(recipientPub, nil, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	t.Logf("Encrypted %d bytes to %d bytes", len(plaintext), len(ciphertext))

	// Decrypt
	decrypted, err := Decrypt(recipientPriv, ephemeralPub, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if len(decrypted) != len(plaintext) {
		t.Errorf("Decrypted length %d doesn't match plaintext length %d", len(decrypted), len(plaintext))
	}

	for i := range plaintext {
		if decrypted[i] != plaintext[i] {
			t.Errorf("Mismatch at byte %d: got %d, want %d", i, decrypted[i], plaintext[i])
			break
		}
	}

	t.Logf("Successfully encrypted and decrypted %d bytes", len(plaintext))
}
