/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * HPKE decryption and key storage for tdns-krs
 */

package krs

import (
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/johanix/tdns/v0.x/tdns/hpke"
)

// DecryptAndStoreKey decrypts a KMPKG record and stores the key in the database
func DecryptAndStoreKey(krsDB *KrsDB, encryptedKey []byte, ephemeralPrivKey []byte, longTermPrivKey []byte, distributionID, zoneID string) error {
	// Decrypt using HPKE
	// The encryptedKey contains the encapsulated key + ciphertext
	// We use the long-term private key to decrypt
	plaintext, err := hpke.Decrypt(longTermPrivKey, nil, encryptedKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt key: %v", err)
	}

	// TODO: Parse the decrypted plaintext as a DNSSEC private key (PEM format)
	// For now, we'll store it as-is
	log.Printf("KRS: Successfully decrypted key for distribution %s, zone %s (size: %d bytes)", distributionID, zoneID, len(plaintext))

	// TODO: Extract key metadata from the KMPKG or from a separate metadata query
	// For now, create a basic ReceivedKey structure
	key := &ReceivedKey{
		ID:             distributionID,
		ZoneName:       zoneID, // zoneID parameter is actually zone name
		KeyID:          0, // TODO: Extract from metadata
		KeyType:        "ZSK", // TODO: Extract from metadata
		Algorithm:      15,    // TODO: Extract from metadata (ED25519)
		Flags:          256,   // TODO: Extract from metadata (ZSK flags)
		PublicKey:      "",    // TODO: Extract from metadata
		PrivateKey:     plaintext,
		State:          "received",
		ReceivedAt:     time.Now(),
		DistributionID: distributionID,
	}

	// Store in database
	if err := krsDB.AddReceivedKey(key); err != nil {
		return fmt.Errorf("failed to store received key: %v", err)
	}

	log.Printf("KRS: Stored key for distribution %s, zone %s", distributionID, zoneID)
	return nil
}

// ProcessKMPKG processes KMPKG records from a DNS response
func ProcessKMPKG(krsDB *KrsDB, kmpkgRecords []*hpke.KMPKG, ephemeralPrivKey []byte, longTermPrivKey []byte, distributionID, zoneID string) error {
	// KMPKG records may be split across multiple records
	// Combine them if necessary
	var encryptedData []byte
	for _, kmpkg := range kmpkgRecords {
		if kmpkg.Sequence == 0 && kmpkg.Total == 1 {
			// Single record
			encryptedData = kmpkg.EncryptedData
			break
		} else {
			// Multiple records - combine them
			encryptedData = append(encryptedData, kmpkg.EncryptedData...)
		}
	}

	if len(encryptedData) == 0 {
		return fmt.Errorf("no encrypted data found in KMPKG records")
	}

	// Decode base64 if needed (KMPKG stores data as base64 in wire format)
	// Actually, KMPKG stores binary data, so encryptedData is already binary
	// But the API might send it as base64, so check
	if len(encryptedData) > 0 && encryptedData[0] != 0x00 {
		// Might be base64-encoded
		decoded, err := base64.StdEncoding.DecodeString(string(encryptedData))
		if err == nil {
			encryptedData = decoded
		}
	}

	// Decrypt and store
	return DecryptAndStoreKey(krsDB, encryptedData, ephemeralPrivKey, longTermPrivKey, distributionID, zoneID)
}

