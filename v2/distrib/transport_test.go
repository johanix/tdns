package distrib

import (
	"testing"

	"github.com/johanix/tdns/v2/crypto"
)

// mockBackend implements crypto.Backend for testing
type mockBackend struct {
	name string
}

func (m *mockBackend) Name() string { return m.name }

func (m *mockBackend) GenerateKeypair() (crypto.PrivateKey, crypto.PublicKey, error) {
	return &mockPrivateKey{}, &mockPublicKey{}, nil
}

func (m *mockBackend) ParsePublicKey(data []byte) (crypto.PublicKey, error) {
	return &mockPublicKey{}, nil
}

func (m *mockBackend) ParsePrivateKey(data []byte) (crypto.PrivateKey, error) {
	return &mockPrivateKey{}, nil
}

func (m *mockBackend) SerializePublicKey(key crypto.PublicKey) ([]byte, error) {
	return []byte("pubkey"), nil
}

func (m *mockBackend) SerializePrivateKey(key crypto.PrivateKey) ([]byte, error) {
	return []byte("privkey"), nil
}

func (m *mockBackend) Encrypt(recipientPubKey crypto.PublicKey, plaintext []byte) ([]byte, error) {
	// Simple XOR "encryption" for testing (NOT secure, just for testing)
	result := make([]byte, len(plaintext))
	for i, b := range plaintext {
		result[i] = b ^ 0x42
	}
	return result, nil
}

func (m *mockBackend) Decrypt(privateKey crypto.PrivateKey, ciphertext []byte) ([]byte, error) {
	// Reverse the XOR "encryption"
	result := make([]byte, len(ciphertext))
	for i, b := range ciphertext {
		result[i] = b ^ 0x42
	}
	return result, nil
}

func (m *mockBackend) GetEphemeralKey(ciphertext []byte) ([]byte, error) {
	return nil, nil
}

func (m *mockBackend) EncryptMultiRecipient(recipients []crypto.PublicKey, plaintext []byte, metadata map[string]interface{}) ([]byte, error) {
	return m.Encrypt(recipients[0], plaintext)
}

func (m *mockBackend) DecryptMultiRecipient(privKey crypto.PrivateKey, ciphertext []byte) ([]byte, error) {
	return m.Decrypt(privKey, ciphertext)
}

func (m *mockBackend) Sign(privKey crypto.PrivateKey, data []byte) ([]byte, error) {
	// Mock JWS format: header.payload.signature
	return append([]byte("eyJhbGciOiJtb2NrIn0."), append(data, []byte(".mocksig")...)...), nil
}

func (m *mockBackend) Verify(pubKey crypto.PublicKey, data []byte, signature []byte) (bool, error) {
	return true, nil
}

type mockPrivateKey struct{}

func (k *mockPrivateKey) Backend() string { return "mock" }

type mockPublicKey struct{}

func (k *mockPublicKey) Backend() string { return "mock" }

func TestNewTransportEncoder(t *testing.T) {
	backend := &mockBackend{name: "mock"}
	encoder := NewTransportEncoder(backend)
	if encoder == nil {
		t.Error("NewTransportEncoder returned nil")
	}
}

func TestEncodeAndDecode(t *testing.T) {
	backend := &mockBackend{name: "mock"}
	encoder := NewTransportEncoder(backend)

	plaintext := []byte("Hello, World!")
	pubKey := &mockPublicKey{}
	privKey := &mockPrivateKey{}

	// Encode
	encoded, err := encoder.Encode(pubKey, plaintext)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	// Decode
	decoded, err := encoder.Decode(privKey, encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if string(decoded) != string(plaintext) {
		t.Errorf("Decoded text %q doesn't match original %q", decoded, plaintext)
	}
}

func TestConvenienceFunctions(t *testing.T) {
	backend := &mockBackend{name: "mock"}
	plaintext := []byte("Test message")
	pubKey := &mockPublicKey{}
	privKey := &mockPrivateKey{}

	// Test EncryptAndEncode / DecodeAndDecrypt
	encoded, err := EncryptAndEncode(backend, pubKey, plaintext)
	if err != nil {
		t.Fatalf("EncryptAndEncode failed: %v", err)
	}

	decoded, err := DecodeAndDecrypt(backend, privKey, encoded)
	if err != nil {
		t.Fatalf("DecodeAndDecrypt failed: %v", err)
	}

	if string(decoded) != string(plaintext) {
		t.Errorf("Decoded text %q doesn't match original %q", decoded, plaintext)
	}
}

func TestSplitJWS(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"header.payload.signature", 3},
		{"a.b.c", 3},
		{"no.dots", 2},
		{"single", 1},
	}

	for _, tt := range tests {
		parts := splitJWS([]byte(tt.input))
		if len(parts) != tt.expected {
			t.Errorf("splitJWS(%q): expected %d parts, got %d", tt.input, tt.expected, len(parts))
		}
	}
}

func TestBase64URLDecode(t *testing.T) {
	// "Hello" in base64url encoding (no padding)
	encoded := []byte("SGVsbG8")
	decoded, err := base64URLDecode(encoded)
	if err != nil {
		t.Fatalf("base64URLDecode failed: %v", err)
	}
	if string(decoded) != "Hello" {
		t.Errorf("Expected 'Hello', got %q", decoded)
	}
}

func TestNilBackendErrors(t *testing.T) {
	encoder := &BackendTransportEncoder{backend: nil}
	pubKey := &mockPublicKey{}
	privKey := &mockPrivateKey{}

	_, err := encoder.Encode(pubKey, []byte("test"))
	if err == nil {
		t.Error("Expected error for nil backend in Encode")
	}

	_, err = encoder.Decode(privKey, []byte("dGVzdA=="))
	if err == nil {
		t.Error("Expected error for nil backend in Decode")
	}
}
