/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Cross-backend compatibility tests
 */

package crypto_test

import (
	"bytes"
	"testing"

	"github.com/johanix/tdns/v2/crypto"
	_ "github.com/johanix/tdns/v2/crypto/hpke" // Register HPKE backend
	_ "github.com/johanix/tdns/v2/crypto/jose" // Register JOSE backend
)

// TestBothBackendsRegistered verifies both backends auto-registered
func TestBothBackendsRegistered(t *testing.T) {
	backends := crypto.ListBackends()

	if len(backends) < 2 {
		t.Fatalf("expected at least 2 backends, got %d: %v", len(backends), backends)
	}

	// Check for HPKE
	hpkeFound := false
	joseFound := false
	for _, name := range backends {
		if name == "hpke" {
			hpkeFound = true
		}
		if name == "jose" {
			joseFound = true
		}
	}

	if !hpkeFound {
		t.Error("HPKE backend not registered")
	}
	if !joseFound {
		t.Error("JOSE backend not registered")
	}
}

// TestGetBackend tests backend retrieval
func TestGetBackend(t *testing.T) {
	tests := []struct {
		name      string
		expectErr bool
	}{
		{"hpke", false},
		{"jose", false},
		{"unknown", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, err := crypto.GetBackend(tt.name)
			if tt.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if backend == nil {
					t.Error("backend is nil")
				}
				if backend.Name() != tt.name {
					t.Errorf("expected name '%s', got '%s'", tt.name, backend.Name())
				}
			}
		})
	}
}

// TestBackendInterface tests that both backends implement the interface identically
func TestBackendInterface(t *testing.T) {
	backends := []string{"hpke", "jose"}

	for _, backendName := range backends {
		t.Run(backendName, func(t *testing.T) {
			backend, err := crypto.GetBackend(backendName)
			if err != nil {
				t.Fatalf("GetBackend(%s) failed: %v", backendName, err)
			}

			// Test key generation
			privKey, pubKey, err := backend.GenerateKeypair()
			if err != nil {
				t.Fatalf("GenerateKeypair failed: %v", err)
			}

			if privKey.Backend() != backendName {
				t.Errorf("private key backend mismatch: expected %s, got %s", backendName, privKey.Backend())
			}
			if pubKey.Backend() != backendName {
				t.Errorf("public key backend mismatch: expected %s, got %s", backendName, pubKey.Backend())
			}

			// Test encryption/decryption
			plaintext := []byte("Test message for backend: " + backendName)
			ciphertext, err := backend.Encrypt(pubKey, plaintext)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			if len(ciphertext) == 0 {
				t.Error("ciphertext is empty")
			}

			decrypted, err := backend.Decrypt(privKey, ciphertext)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Error("decrypted text doesn't match original")
			}

			// Test serialization
			pubData, err := backend.SerializePublicKey(pubKey)
			if err != nil {
				t.Fatalf("SerializePublicKey failed: %v", err)
			}

			privData, err := backend.SerializePrivateKey(privKey)
			if err != nil {
				t.Fatalf("SerializePrivateKey failed: %v", err)
			}

			// Test parsing
			parsedPub, err := backend.ParsePublicKey(pubData)
			if err != nil {
				t.Fatalf("ParsePublicKey failed: %v", err)
			}

			parsedPriv, err := backend.ParsePrivateKey(privData)
			if err != nil {
				t.Fatalf("ParsePrivateKey failed: %v", err)
			}

			// Test that parsed keys work
			ciphertext2, err := backend.Encrypt(parsedPub, plaintext)
			if err != nil {
				t.Fatalf("Encrypt with parsed public key failed: %v", err)
			}

			decrypted2, err := backend.Decrypt(parsedPriv, ciphertext2)
			if err != nil {
				t.Fatalf("Decrypt with parsed private key failed: %v", err)
			}

			if !bytes.Equal(decrypted2, plaintext) {
				t.Error("decrypted text with parsed keys doesn't match original")
			}
		})
	}
}

// TestCrossBackendIncompatibility verifies that keys from one backend don't work with another
func TestCrossBackendIncompatibility(t *testing.T) {
	hpke, _ := crypto.GetBackend("hpke")
	jose, _ := crypto.GetBackend("jose")

	// Generate keys with HPKE
	hpkePriv, hpkePub, err := hpke.GenerateKeypair()
	if err != nil {
		t.Fatalf("HPKE GenerateKeypair failed: %v", err)
	}

	// Try to use HPKE keys with JOSE backend (should fail with ErrBackendMismatch)
	_, err = jose.SerializePublicKey(hpkePub)
	if err != crypto.ErrBackendMismatch {
		t.Errorf("expected ErrBackendMismatch, got %v", err)
	}

	_, err = jose.SerializePrivateKey(hpkePriv)
	if err != crypto.ErrBackendMismatch {
		t.Errorf("expected ErrBackendMismatch, got %v", err)
	}

	_, err = jose.Encrypt(hpkePub, []byte("test"))
	if err != crypto.ErrBackendMismatch {
		t.Errorf("expected ErrBackendMismatch, got %v", err)
	}

	_, err = jose.Decrypt(hpkePriv, []byte("test"))
	if err != crypto.ErrBackendMismatch {
		t.Errorf("expected ErrBackendMismatch, got %v", err)
	}
}

// TestIsBackendRegistered tests the helper function
func TestIsBackendRegistered(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"hpke", true},
		{"jose", true},
		{"unknown", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := crypto.IsBackendRegistered(tt.name)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestBackendsSorted tests that ListBackends returns sorted results
func TestBackendsSorted(t *testing.T) {
	backends := crypto.ListBackends()

	// Should be in alphabetical order: hpke, jose
	if len(backends) >= 2 {
		if backends[0] != "hpke" {
			t.Errorf("expected first backend to be 'hpke', got '%s'", backends[0])
		}
		if backends[1] != "jose" {
			t.Errorf("expected second backend to be 'jose', got '%s'", backends[1])
		}
	}
}

// BenchmarkHPKEEncrypt benchmarks HPKE encryption
func BenchmarkHPKEEncrypt(b *testing.B) {
	backend, _ := crypto.GetBackend("hpke")
	_, pubKey, _ := backend.GenerateKeypair()
	plaintext := make([]byte, 1024) // 1KB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		backend.Encrypt(pubKey, plaintext)
	}
}

// BenchmarkJOSEEncrypt benchmarks JOSE encryption
func BenchmarkJOSEEncrypt(b *testing.B) {
	backend, _ := crypto.GetBackend("jose")
	_, pubKey, _ := backend.GenerateKeypair()
	plaintext := make([]byte, 1024) // 1KB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		backend.Encrypt(pubKey, plaintext)
	}
}

// BenchmarkHPKEDecrypt benchmarks HPKE decryption
func BenchmarkHPKEDecrypt(b *testing.B) {
	backend, _ := crypto.GetBackend("hpke")
	privKey, pubKey, _ := backend.GenerateKeypair()
	plaintext := make([]byte, 1024) // 1KB
	ciphertext, _ := backend.Encrypt(pubKey, plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		backend.Decrypt(privKey, ciphertext)
	}
}

// BenchmarkJOSEDecrypt benchmarks JOSE decryption
func BenchmarkJOSEDecrypt(b *testing.B) {
	backend, _ := crypto.GetBackend("jose")
	privKey, pubKey, _ := backend.GenerateKeypair()
	plaintext := make([]byte, 1024) // 1KB
	ciphertext, _ := backend.Encrypt(pubKey, plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		backend.Decrypt(privKey, ciphertext)
	}
}
