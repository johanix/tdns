package hpke

import (
	"crypto/rand"
	"fmt"
	"log"

	"github.com/cloudflare/circl/hpke"
)

// TestInlineEncryptDecrypt tests HPKE directly without our wrapper to isolate the issue
func TestInlineEncryptDecrypt() {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
	kemScheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()

	fmt.Printf("=== Inline HPKE Test ===\n")
	fmt.Printf("PublicKeySize: %d\n", kemScheme.PublicKeySize())
	fmt.Printf("CiphertextSize: %d\n", kemScheme.CiphertextSize())

	// Generate keypair
	// Note: kemScheme.GenerateKeyPair() returns (pubKey, privKey, error) - public key first!
	pubKey, privKey, err := kemScheme.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate keypair: %v", err)
	}

	pubBytes, _ := pubKey.MarshalBinary()
	privBytes, _ := privKey.MarshalBinary()

	fmt.Printf("Marshaled public key size: %d\n", len(pubBytes))
	fmt.Printf("Marshaled private key size: %d\n", len(privBytes))

	// Create sender (needs public key)
	sender, err := suite.NewSender(pubKey, nil)
	if err != nil {
		log.Fatalf("Failed to create sender: %v", err)
	}

	// Setup encryption
	encapsulatedKey, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to setup encryption: %v", err)
	}

	fmt.Printf("Encapsulated key size: %d (expected: %d)\n", len(encapsulatedKey), kemScheme.CiphertextSize())

	// Encrypt
	plaintext := []byte("Hello, HPKE! This is a test message.")
	fmt.Printf("Plaintext size: %d\n", len(plaintext))
	
	encryptedData, err := sealer.Seal(plaintext, nil)
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}

	fmt.Printf("Encrypted data size: %d\n", len(encryptedData))
	fmt.Printf("Total size (encapsulated + encrypted): %d\n", len(encapsulatedKey)+len(encryptedData))

	// Now simulate what our wrapper does: combine and split
	combined := make([]byte, len(encapsulatedKey)+len(encryptedData))
	copy(combined[:len(encapsulatedKey)], encapsulatedKey)
	copy(combined[len(encapsulatedKey):], encryptedData)
	fmt.Printf("Combined ciphertext size: %d\n", len(combined))

	// Extract back
	encLen := kemScheme.CiphertextSize()
	fmt.Printf("Extracting with CiphertextSize(): %d\n", encLen)
	
	extractedEnc := make([]byte, encLen)
	copy(extractedEnc, combined[:encLen])
	extractedData := combined[encLen:]
	
	fmt.Printf("Extracted encapsulated key size: %d\n", len(extractedEnc))
	fmt.Printf("Extracted encrypted data size: %d\n", len(extractedData))
	
	// Compare
	if len(extractedEnc) != len(encapsulatedKey) {
		log.Fatalf("Encapsulated key size mismatch: got %d, expected %d", len(extractedEnc), len(encapsulatedKey))
	}
	if len(extractedData) != len(encryptedData) {
		log.Fatalf("Encrypted data size mismatch: got %d, expected %d", len(extractedData), len(encryptedData))
	}
	
	// Check if bytes match
	for i := 0; i < len(encapsulatedKey); i++ {
		if extractedEnc[i] != encapsulatedKey[i] {
			log.Fatalf("Encapsulated key byte mismatch at index %d", i)
		}
	}
	for i := 0; i < len(encryptedData); i++ {
		if extractedData[i] != encryptedData[i] {
			log.Fatalf("Encrypted data byte mismatch at index %d", i)
		}
	}
	fmt.Printf("✓ Data extraction verified\n")

	// Now try to decrypt with extracted data
	// Receiver needs private key
	receiver, err := suite.NewReceiver(privKey, nil)
	if err != nil {
		log.Fatalf("Failed to create receiver: %v", err)
	}

	opener, err := receiver.Setup(extractedEnc)
	if err != nil {
		log.Fatalf("Failed to setup decryption: %v", err)
	}

	decrypted, err := opener.Open(extractedData, nil)
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}

	fmt.Printf("Decrypted size: %d\n", len(decrypted))
	if string(decrypted) != string(plaintext) {
		log.Fatalf("Decrypted text doesn't match!")
	}

	fmt.Printf("✓ Decryption successful!\n")
}

