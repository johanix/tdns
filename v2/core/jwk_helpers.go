/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * JWK encoding/decoding helpers for converting between Go crypto types
 * and base64url-encoded JWK JSON format (RFC 7517).
 */

package core

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// JWK represents a JSON Web Key structure per RFC 7517
type JWKKey struct {
	Kty string `json:"kty"`           // Key Type (e.g., "EC", "OKP")
	Crv string `json:"crv,omitempty"` // Curve (e.g., "P-256", "X25519")
	X   string `json:"x,omitempty"`   // X coordinate (base64url)
	Y   string `json:"y,omitempty"`   // Y coordinate (base64url, EC only)
	Alg string `json:"alg,omitempty"` // Algorithm (optional)
	Use string `json:"use,omitempty"` // Public Key Use (optional)
}

// EncodePublicKeyToJWK converts a Go crypto.PublicKey to base64url-encoded JWK JSON.
// Returns: (base64url-jwk, key-algorithm, error)
//
// Supported key types:
//   - *ecdsa.PublicKey (P-256 curve)
//   - ed25519.PublicKey (for X25519, converted from Ed25519)
//
// The returned algorithm string is one of: "ES256" (P-256), "X25519"
//
// The use parameter specifies the intended use: "" (omit), "sig" (signing), "enc" (encryption)
func EncodePublicKeyToJWK(key crypto.PublicKey, use string) (string, string, error) {
	if key == nil {
		return "", "", fmt.Errorf("public key is nil")
	}

	var jwk JWKKey
	var algorithm string

	switch k := key.(type) {
	case *ecdsa.PublicKey:
		// Only P-256 supported for now
		if k.Curve != elliptic.P256() {
			return "", "", fmt.Errorf("unsupported ECDSA curve: %s (only P-256 supported)", k.Curve.Params().Name)
		}

		// Encode coordinates as base64url
		xBytes := k.X.Bytes()
		yBytes := k.Y.Bytes()

		// Pad to 32 bytes for P-256
		xPadded := make([]byte, 32)
		yPadded := make([]byte, 32)
		copy(xPadded[32-len(xBytes):], xBytes)
		copy(yPadded[32-len(yBytes):], yBytes)

		jwk = JWKKey{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(xPadded),
			Y:   base64.RawURLEncoding.EncodeToString(yPadded),
			Use: use, // Set the "use" field
		}
		algorithm = "ES256"

	// Note: X25519 support would go here
	// case ed25519.PublicKey:
	//     jwk = JWKKey{
	//         Kty: "OKP",
	//         Crv: "X25519",
	//         X:   base64.RawURLEncoding.EncodeToString(k),
	//         Use: use,
	//     }
	//     algorithm = "X25519"

	default:
		return "", "", fmt.Errorf("unsupported public key type: %T", key)
	}

	// Marshal to JSON
	jsonBytes, err := json.Marshal(jwk)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal JWK to JSON: %w", err)
	}

	// Encode JSON to base64url
	base64urlJWK := base64.RawURLEncoding.EncodeToString(jsonBytes)

	return base64urlJWK, algorithm, nil
}

// DecodeJWKToPublicKey parses base64url-encoded JWK JSON to Go crypto.PublicKey.
// Returns: (public-key, key-algorithm, error)
//
// The returned algorithm string is one of: "ES256" (P-256), "X25519"
func DecodeJWKToPublicKey(jwkData string) (crypto.PublicKey, string, error) {
	if jwkData == "" {
		return nil, "", fmt.Errorf("JWK data is empty")
	}

	// Decode base64url to JSON
	jsonBytes, err := base64.RawURLEncoding.DecodeString(jwkData)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode base64url: %w", err)
	}

	// Unmarshal JSON to JWK struct
	var jwk JWKKey
	if err := json.Unmarshal(jsonBytes, &jwk); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal JWK JSON: %w", err)
	}

	// Validate required fields
	if jwk.Kty == "" {
		return nil, "", fmt.Errorf("JWK missing required 'kty' field")
	}

	var publicKey crypto.PublicKey
	var algorithm string

	switch jwk.Kty {
	case "EC":
		// Elliptic Curve key
		if jwk.Crv == "" {
			return nil, "", fmt.Errorf("EC JWK missing 'crv' field")
		}
		if jwk.X == "" || jwk.Y == "" {
			return nil, "", fmt.Errorf("EC JWK missing 'x' or 'y' coordinate")
		}

		switch jwk.Crv {
		case "P-256":
			// Decode coordinates
			xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
			if err != nil {
				return nil, "", fmt.Errorf("failed to decode 'x' coordinate: %w", err)
			}
			yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
			if err != nil {
				return nil, "", fmt.Errorf("failed to decode 'y' coordinate: %w", err)
			}

			// Construct ECDSA public key
			x := new(big.Int).SetBytes(xBytes)
			y := new(big.Int).SetBytes(yBytes)

			publicKey = &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     x,
				Y:     y,
			}
			algorithm = "ES256"

		default:
			return nil, "", fmt.Errorf("unsupported EC curve: %s", jwk.Crv)
		}

	case "OKP":
		// Octet Key Pair (X25519, Ed25519)
		if jwk.Crv == "" {
			return nil, "", fmt.Errorf("OKP JWK missing 'crv' field")
		}
		if jwk.X == "" {
			return nil, "", fmt.Errorf("OKP JWK missing 'x' field")
		}

		switch jwk.Crv {
		case "X25519":
			// Decode public key bytes
			xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
			if err != nil {
				return nil, "", fmt.Errorf("failed to decode 'x' coordinate: %w", err)
			}

			if len(xBytes) != 32 {
				return nil, "", fmt.Errorf("X25519 public key must be 32 bytes, got %d", len(xBytes))
			}

			// Note: Go's crypto library doesn't have a standard X25519 public key type
			// Return the raw bytes for now; caller can use crypto/ecdh or golang.org/x/crypto/curve25519
			publicKey = xBytes // This is a workaround; proper type would be better
			algorithm = "X25519"

		default:
			return nil, "", fmt.Errorf("unsupported OKP curve: %s", jwk.Crv)
		}

	default:
		return nil, "", fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}

	return publicKey, algorithm, nil
}

// ValidateJWK checks if base64url-encoded JWK data is well-formed.
// This does basic validation without converting to crypto.PublicKey.
func ValidateJWK(jwkData string) error {
	if jwkData == "" {
		return fmt.Errorf("JWK data is empty")
	}

	// Decode base64url
	jsonBytes, err := base64.RawURLEncoding.DecodeString(jwkData)
	if err != nil {
		return fmt.Errorf("invalid base64url encoding: %w", err)
	}

	// Unmarshal JSON
	var jwk JWKKey
	if err := json.Unmarshal(jsonBytes, &jwk); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	// Validate required fields
	if jwk.Kty == "" {
		return fmt.Errorf("missing required 'kty' field")
	}

	switch jwk.Kty {
	case "EC":
		if jwk.Crv == "" {
			return fmt.Errorf("EC key missing 'crv' field")
		}
		if jwk.X == "" || jwk.Y == "" {
			return fmt.Errorf("EC key missing 'x' or 'y' coordinate")
		}

		// Validate curve is supported
		switch jwk.Crv {
		case "P-256":
			// OK
		default:
			return fmt.Errorf("unsupported EC curve: %s", jwk.Crv)
		}

	case "OKP":
		if jwk.Crv == "" {
			return fmt.Errorf("OKP key missing 'crv' field")
		}
		if jwk.X == "" {
			return fmt.Errorf("OKP key missing 'x' field")
		}

		// Validate curve is supported
		switch jwk.Crv {
		case "X25519", "Ed25519":
			// OK
		default:
			return fmt.Errorf("unsupported OKP curve: %s", jwk.Crv)
		}

	default:
		return fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}

	return nil
}

// GetJWKKeyType returns the key type and curve from base64url-encoded JWK data
// without fully decoding the key. Useful for inspection.
// Returns: (kty, crv, error)
func GetJWKKeyType(jwkData string) (string, string, error) {
	if jwkData == "" {
		return "", "", fmt.Errorf("JWK data is empty")
	}

	// Decode base64url
	jsonBytes, err := base64.RawURLEncoding.DecodeString(jwkData)
	if err != nil {
		return "", "", fmt.Errorf("invalid base64url encoding: %w", err)
	}

	// Unmarshal JSON
	var jwk JWKKey
	if err := json.Unmarshal(jsonBytes, &jwk); err != nil {
		return "", "", fmt.Errorf("invalid JSON: %w", err)
	}

	return jwk.Kty, jwk.Crv, nil
}
