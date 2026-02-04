/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Unit tests for JWK RRtype and helper functions.
 */

package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// TestJWKTypeRegistration verifies that the JWK type is registered with miekg/dns
func TestJWKTypeRegistration(t *testing.T) {
	// Check type to string mapping
	if dns.TypeToString[TypeJWK] != "JWK" {
		t.Errorf("TypeToString[TypeJWK] = %q, want %q", dns.TypeToString[TypeJWK], "JWK")
	}

	// Check string to type mapping
	if dns.StringToType["JWK"] != TypeJWK {
		t.Errorf("StringToType[\"JWK\"] = %d, want %d", dns.StringToType["JWK"], TypeJWK)
	}
}

// TestEncodeDecodeP256 tests encoding and decoding of P-256 ECDSA keys
func TestEncodeDecodeP256(t *testing.T) {
	// Generate a test P-256 key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate P-256 key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Encode to JWK
	jwkData, algorithm, err := EncodePublicKeyToJWK(publicKey)
	if err != nil {
		t.Fatalf("EncodePublicKeyToJWK failed: %v", err)
	}

	// Check algorithm
	if algorithm != "ES256" {
		t.Errorf("algorithm = %q, want %q", algorithm, "ES256")
	}

	// Check that it's valid base64url
	_, err = base64.RawURLEncoding.DecodeString(jwkData)
	if err != nil {
		t.Errorf("JWK data is not valid base64url: %v", err)
	}

	// Validate JWK
	if err := ValidateJWK(jwkData); err != nil {
		t.Errorf("ValidateJWK failed: %v", err)
	}

	// Decode back to public key
	decodedKey, decodedAlg, err := DecodeJWKToPublicKey(jwkData)
	if err != nil {
		t.Fatalf("DecodeJWKToPublicKey failed: %v", err)
	}

	// Check algorithm
	if decodedAlg != "ES256" {
		t.Errorf("decoded algorithm = %q, want %q", decodedAlg, "ES256")
	}

	// Verify decoded key matches original
	decodedECKey, ok := decodedKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("decoded key is not *ecdsa.PublicKey, got %T", decodedKey)
	}

	if decodedECKey.Curve != elliptic.P256() {
		t.Errorf("decoded key curve = %v, want P-256", decodedECKey.Curve)
	}

	if decodedECKey.X.Cmp(publicKey.X) != 0 {
		t.Errorf("decoded X coordinate does not match original")
	}

	if decodedECKey.Y.Cmp(publicKey.Y) != 0 {
		t.Errorf("decoded Y coordinate does not match original")
	}
}

// TestJWKRRString tests the String() method for zone file format
func TestJWKRRString(t *testing.T) {
	// Create a JWK RDATA
	jwk := &JWK{
		JWKData: "eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2In0",
	}

	// Get string representation
	s := jwk.String()

	// Verify format (should be quoted string)
	if !strings.Contains(s, "eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2In0") {
		t.Errorf("String() missing JWK data: %s", s)
	}
}

// TestJWKRRPackUnpack tests wire format encoding/decoding
func TestJWKRRPackUnpack(t *testing.T) {
	// Create original JWK RDATA
	original := &JWK{
		JWKData: "eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2In0",
	}

	// Pack to wire format
	buf := make([]byte, 512)
	n, err := original.Pack(buf)
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	// Unpack from wire format
	unpacked := &JWK{}
	n2, err := unpacked.Unpack(buf[:n])
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}

	if n != n2 {
		t.Errorf("pack length %d != unpack length %d", n, n2)
	}

	// Verify unpacked data matches
	if unpacked.JWKData != original.JWKData {
		t.Errorf("unpacked JWK data = %q, want %q", unpacked.JWKData, original.JWKData)
	}
}

// TestValidateJWKErrors tests error cases for ValidateJWK
func TestValidateJWKErrors(t *testing.T) {
	tests := []struct {
		name    string
		jwkData string
		wantErr string
	}{
		{
			name:    "empty data",
			jwkData: "",
			wantErr: "empty",
		},
		{
			name:    "invalid base64",
			jwkData: "not-base64!!!",
			wantErr: "base64url",
		},
		{
			name:    "invalid JSON",
			jwkData: base64.RawURLEncoding.EncodeToString([]byte("not json")),
			wantErr: "JSON",
		},
		{
			name:    "missing kty",
			jwkData: base64.RawURLEncoding.EncodeToString([]byte(`{"crv":"P-256"}`)),
			wantErr: "kty",
		},
		{
			name:    "EC missing crv",
			jwkData: base64.RawURLEncoding.EncodeToString([]byte(`{"kty":"EC","x":"..","y":".."}`)),
			wantErr: "crv",
		},
		{
			name:    "EC missing coordinates",
			jwkData: base64.RawURLEncoding.EncodeToString([]byte(`{"kty":"EC","crv":"P-256"}`)),
			wantErr: "coordinate",
		},
		{
			name:    "unsupported curve",
			jwkData: base64.RawURLEncoding.EncodeToString([]byte(`{"kty":"EC","crv":"P-521","x":"..","y":".."}`)),
			wantErr: "unsupported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateJWK(tt.jwkData)
			if err == nil {
				t.Errorf("ValidateJWK() succeeded, want error containing %q", tt.wantErr)
				return
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErr)) {
				t.Errorf("ValidateJWK() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestGetJWKKeyType tests extracting key type without full decode
func TestGetJWKKeyType(t *testing.T) {
	// Create a test P-256 key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate P-256 key: %v", err)
	}

	// Encode to JWK
	jwkData, _, err := EncodePublicKeyToJWK(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("EncodePublicKeyToJWK failed: %v", err)
	}

	// Get key type
	kty, crv, err := GetJWKKeyType(jwkData)
	if err != nil {
		t.Fatalf("GetJWKKeyType failed: %v", err)
	}

	if kty != "EC" {
		t.Errorf("kty = %q, want %q", kty, "EC")
	}

	if crv != "P-256" {
		t.Errorf("crv = %q, want %q", crv, "P-256")
	}
}

// TestJWKSizeEstimates verifies that JWK sizes are within expected ranges
func TestJWKSizeEstimates(t *testing.T) {
	// Generate P-256 key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate P-256 key: %v", err)
	}

	// Encode to JWK
	jwkData, _, err := EncodePublicKeyToJWK(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("EncodePublicKeyToJWK failed: %v", err)
	}

	// Check size is within expected range (210-240 bytes per design doc)
	size := len(jwkData)
	if size < 150 || size > 300 {
		t.Errorf("P-256 JWK size = %d bytes, expected 150-300 bytes", size)
	}

	t.Logf("P-256 JWK size: %d bytes (base64url)", size)

	// Decode to get JSON size
	jsonBytes, err := base64.RawURLEncoding.DecodeString(jwkData)
	if err != nil {
		t.Fatalf("Failed to decode base64url: %v", err)
	}

	jsonSize := len(jsonBytes)
	t.Logf("P-256 JWK JSON size: %d bytes", jsonSize)

	if jsonSize < 120 || jsonSize > 220 {
		t.Errorf("P-256 JWK JSON size = %d bytes, expected 120-220 bytes", jsonSize)
	}
}

// TestJWKRRCopy tests the Copy() method
func TestJWKRRCopy(t *testing.T) {
	original := &JWK{
		JWKData: "test-jwk-data",
	}

	// Copy the RDATA
	dest := &JWK{}
	err := original.Copy(dest)
	if err != nil {
		t.Fatalf("Copy failed: %v", err)
	}

	// Verify copy matches original
	if dest.JWKData != original.JWKData {
		t.Errorf("copied JWK data = %q, want %q", dest.JWKData, original.JWKData)
	}

	// Modify copy and verify original unchanged
	dest.JWKData = "modified"
	if original.JWKData == "modified" {
		t.Error("modifying copy affected original")
	}
}

// TestEncodeNilKey tests error handling for nil keys
func TestEncodeNilKey(t *testing.T) {
	_, _, err := EncodePublicKeyToJWK(nil)
	if err == nil {
		t.Error("EncodePublicKeyToJWK(nil) succeeded, want error")
	}
}

// TestUnsupportedKeyType tests error handling for unsupported key types
func TestUnsupportedKeyType(t *testing.T) {
	// Try to encode a string (not a valid key type)
	_, _, err := EncodePublicKeyToJWK("not a key")
	if err == nil {
		t.Error("EncodePublicKeyToJWK(string) succeeded, want error")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("error = %v, want error containing 'unsupported'", err)
	}
}

// TestJWKParse tests the Parse() method
func TestJWKParse(t *testing.T) {
	jwk := &JWK{}

	// Valid parse
	err := jwk.Parse([]string{`"eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2In0"`})
	if err != nil {
		t.Errorf("Parse() failed: %v", err)
	}

	if jwk.JWKData != "eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2In0" {
		t.Errorf("Parse() data = %q, want %q", jwk.JWKData, "eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2In0")
	}

	// Invalid parse (wrong number of arguments)
	jwk2 := &JWK{}
	err = jwk2.Parse([]string{"arg1", "arg2"})
	if err == nil {
		t.Error("Parse() with 2 args succeeded, want error")
	}
}
