/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Example usage of HPKE functions
 * Run with: go test -run Example -v
 */

package hpke

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func ExampleGenerateKeyPair() {
	// Generate a new HPKE keypair
	pubKey, privKey, err := GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Public key: %s\n", hex.EncodeToString(pubKey))
	fmt.Printf("Private key: %s\n", hex.EncodeToString(privKey))
	// Output:
	// Public key: [32 hex bytes]
	// Private key: [32 hex bytes]
}

func ExampleEncrypt() {
	// Generate recipient keypair
	recipientPub, recipientPriv, _ := GenerateKeyPair()

	// Plaintext to encrypt (simulating a DNSSEC private key)
	plaintext := []byte("This is a simulated DNSSEC private key")

	// Encrypt
	ciphertext, ephemeralPub, err := Encrypt(recipientPub, nil, plaintext)
	if err != nil {
		fmt.Printf("Encryption error: %v\n", err)
		return
	}

	fmt.Printf("Encrypted %d bytes to %d bytes\n", len(plaintext), len(ciphertext))
	fmt.Printf("Ephemeral public key: %s\n", hex.EncodeToString(ephemeralPub))

	// Decrypt
	decrypted, err := Decrypt(recipientPriv, ephemeralPub, ciphertext)
	if err != nil {
		fmt.Printf("Decryption error: %v\n", err)
		return
	}

	fmt.Printf("Decrypted: %s\n", string(decrypted))
	fmt.Printf("Match: %v\n", string(decrypted) == string(plaintext))
	// Output:
	// Encrypted [N] bytes to [M] bytes
	// Ephemeral public key: [32 hex bytes]
	// Decrypted: This is a simulated DNSSEC private key
	// Match: true
}

func ExampleGenerateDistributionID() {
	// Generate a distribution ID
	distID, err := GenerateDistributionID()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Distribution ID: %s\n", distID)

	// Validate it
	err = ValidateDistributionID(distID)
	if err != nil {
		fmt.Printf("Validation error: %v\n", err)
		return
	}

	fmt.Printf("Valid distribution ID\n")
	// Output:
	// Distribution ID: [32 hex characters]
	// Valid distribution ID
}

func ExampleEncrypt_encryptDNSSECKey() {
	// Simulate encrypting a DNSSEC private key for distribution
	recipientPub, recipientPriv, _ := GenerateKeyPair()

	// Simulated DNSSEC private key (PEM format, base64-encoded)
	dnssecKeyPEM := `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIExampleKeyMaterialHere1234567890ABCDEF
-----END PRIVATE KEY-----`
	plaintext := []byte(dnssecKeyPEM)

	// Encrypt
	ciphertext, ephemeralPub, _ := Encrypt(recipientPub, nil, plaintext)

	// In a real scenario, this would be sent to the edge node
	fmt.Printf("Encrypted key package:\n")
	fmt.Printf("  Size: %d bytes\n", len(ciphertext))
	fmt.Printf("  Base64: %s\n", base64.StdEncoding.EncodeToString(ciphertext[:50])+"...")
	fmt.Printf("  Ephemeral pub: %s\n", hex.EncodeToString(ephemeralPub))

	// Edge node decrypts
	decrypted, _ := Decrypt(recipientPriv, ephemeralPub, ciphertext)
	fmt.Printf("Decrypted key matches: %v\n", string(decrypted) == string(plaintext))
	// Output:
	// Encrypted key package:
	//   Size: [N] bytes
	//   Base64: [base64 string]...
	//   Ephemeral pub: [32 hex bytes]
	// Decrypted key matches: true
}
