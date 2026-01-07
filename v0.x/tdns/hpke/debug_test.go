package hpke

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/cloudflare/circl/hpke"
)

// DebugEncryptDecrypt is a debug version that prints intermediate values
func DebugEncryptDecrypt() {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
	kemScheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()

	fmt.Printf("PublicKeySize: %d\n", kemScheme.PublicKeySize())
	fmt.Printf("CiphertextSize: %d\n", kemScheme.CiphertextSize())
	fmt.Printf("PrivateKeySize: %d\n", kemScheme.PrivateKeySize())

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

	// Create sender
	sender, err := suite.NewSender(pubKey, nil)
	if err != nil {
		log.Fatalf("Failed to create sender: %v", err)
	}

	// Setup encryption
	encapsulatedKey, sealer, err := sender.Setup(nil)
	if err != nil {
		log.Fatalf("Failed to setup encryption: %v", err)
	}

	fmt.Printf("Encapsulated key size: %d\n", len(encapsulatedKey))
	fmt.Printf("Encapsulated key (hex): %s\n", hex.EncodeToString(encapsulatedKey))

	// Encrypt
	plaintext := []byte("Hello, HPKE!")
	encryptedData, err := sealer.Seal(plaintext, nil)
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}

	fmt.Printf("Encrypted data size: %d\n", len(encryptedData))
	fmt.Printf("Total ciphertext size (encapsulated + encrypted): %d\n", len(encapsulatedKey)+len(encryptedData))

	// Create receiver
	receiver, err := suite.NewReceiver(privKey, nil)
	if err != nil {
		log.Fatalf("Failed to create receiver: %v", err)
	}

	// Try to setup decryption with the encapsulated key
	opener, err := receiver.Setup(encapsulatedKey)
	if err != nil {
		log.Fatalf("Failed to setup decryption: %v", err)
	}

	// Decrypt
	decrypted, err := opener.Open(encryptedData, nil)
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}

	fmt.Printf("Decrypted: %s\n", string(decrypted))
	fmt.Println("Success!")
}

