/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Standalone test program for HPKE functions
 * Usage: go run hpke/test_main.go
 */

package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/johanix/tdns/v2/hpke"
)

func main() {
	fmt.Println("=== HPKE Function Tests ===\n")

	// Test 1: Generate keypair
	fmt.Println("Test 1: Generate HPKE keypair")
	pubKey, privKey, err := hpke.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate keypair: %v", err)
	}
	fmt.Printf("  Public key (hex):  %s\n", hex.EncodeToString(pubKey))
	fmt.Printf("  Private key (hex): %s\n", hex.EncodeToString(privKey))
	fmt.Println("  ✓ Keypair generated successfully\n")

	// Test 2: Encrypt/Decrypt simple message
	fmt.Println("Test 2: Encrypt and decrypt simple message")
	plaintext := []byte("Hello, HPKE! This is a test message.")
	fmt.Printf("  Plaintext: %q\n", string(plaintext))

	ciphertext, ephemeralPub, err := hpke.Encrypt(pubKey, nil, plaintext)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Printf("  Ciphertext (base64): %s\n", base64.StdEncoding.EncodeToString(ciphertext))
	fmt.Printf("  Ephemeral pub key (hex): %s\n", hex.EncodeToString(ephemeralPub))

	decrypted, err := hpke.Decrypt(privKey, ephemeralPub, ciphertext)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	fmt.Printf("  Decrypted: %q\n", string(decrypted))

	if string(decrypted) != string(plaintext) {
		log.Fatalf("Decrypted text doesn't match original!")
	}
	fmt.Println("  ✓ Encryption/decryption successful\n")

	// Test 3: Encrypt/Decrypt larger data (simulating DNSSEC private key)
	fmt.Println("Test 3: Encrypt and decrypt larger data (simulating DNSSEC key)")
	largeData := make([]byte, 1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	fmt.Printf("  Data size: %d bytes\n", len(largeData))

	ciphertext2, ephemeralPub2, err := hpke.Encrypt(pubKey, nil, largeData)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Printf("  Encrypted size: %d bytes\n", len(ciphertext2))

	decrypted2, err := hpke.Decrypt(privKey, ephemeralPub2, ciphertext2)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	if len(decrypted2) != len(largeData) {
		log.Fatalf("Size mismatch: got %d, want %d", len(decrypted2), len(largeData))
	}

	match := true
	for i := range largeData {
		if decrypted2[i] != largeData[i] {
			match = false
			fmt.Printf("  Mismatch at byte %d\n", i)
			break
		}
	}
	if !match {
		log.Fatal("Data mismatch!")
	}
	fmt.Println("  ✓ Large data encryption/decryption successful\n")

	// Test 4: Multiple encryptions with same keypair
	fmt.Println("Test 4: Multiple encryptions with same keypair")
	messages := []string{
		"Message 1",
		"Message 2",
		"Message 3",
	}
	for i, msg := range messages {
		pt := []byte(msg)
		ct, ep, err := hpke.Encrypt(pubKey, nil, pt)
		if err != nil {
			log.Fatalf("Encryption %d failed: %v", i+1, err)
		}
		dt, err := hpke.Decrypt(privKey, ep, ct)
		if err != nil {
			log.Fatalf("Decryption %d failed: %v", i+1, err)
		}
		if string(dt) != msg {
			log.Fatalf("Message %d mismatch", i+1)
		}
		fmt.Printf("  ✓ Message %d encrypted/decrypted successfully\n", i+1)
	}
	fmt.Println()

	// Test 5: Distribution ID generation
	fmt.Println("Test 5: Generate distribution IDs")
	for i := 0; i < 5; i++ {
		distID, err := hpke.GenerateDistributionID()
		if err != nil {
			log.Fatalf("Failed to generate distribution ID: %v", err)
		}
		fmt.Printf("  Distribution ID %d: %s\n", i+1, distID)
		if err := hpke.ValidateDistributionID(distID); err != nil {
			log.Fatalf("Invalid distribution ID: %v", err)
		}
	}
	fmt.Println("  ✓ Distribution ID generation successful\n")

	fmt.Println("=== All tests passed! ===")
}
