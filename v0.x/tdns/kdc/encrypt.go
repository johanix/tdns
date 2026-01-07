/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * HPKE encryption functions for key distribution
 */

package kdc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/johanix/tdns/v0.x/tdns/hpke"
)

// EncryptKeyForNode encrypts a DNSSEC key's private key material for a specific node
// using HPKE with the node's long-term public key
// Returns: encrypted key data, ephemeral public key used, distribution ID, error
// This function also stores the distribution record in the database
// kdcConf is optional - if provided, expires_at will be set based on DistributionTTL
func (kdc *KdcDB) EncryptKeyForNode(key *DNSSECKey, node *Node, kdcConf *KdcConf) (encryptedKey []byte, ephemeralPubKey []byte, distributionID string, err error) {
	if key == nil {
		return nil, nil, "", fmt.Errorf("key is nil")
	}
	if node == nil {
		return nil, nil, "", fmt.Errorf("node is nil")
	}
	if len(node.LongTermPubKey) != 32 {
		return nil, nil, "", fmt.Errorf("node long-term public key must be 32 bytes (got %d)", len(node.LongTermPubKey))
	}

	// Get or create a stable distribution ID for this key
	distributionID, err = kdc.GetOrCreateDistributionID(key.ZoneName, key)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to get/create distribution ID: %v", err)
	}

	// Encrypt the private key using HPKE
	// Note: HPKE Base mode generates its own ephemeral key internally
	ciphertext, ephemeralPub, err := hpke.Encrypt(node.LongTermPubKey, nil, key.PrivateKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to encrypt key: %v", err)
	}

	// Generate a unique ID for this distribution record
	distRecordID := make([]byte, 16)
	if _, err := rand.Read(distRecordID); err != nil {
		return nil, nil, "", fmt.Errorf("failed to generate distribution record ID: %v", err)
	}
	distRecordIDHex := hex.EncodeToString(distRecordID)

	// Calculate expires_at based on DistributionTTL if config is provided
	var expiresAt *time.Time
	if kdcConf != nil {
		ttl := kdcConf.GetDistributionTTL()
		if ttl > 0 {
			expires := time.Now().Add(ttl)
			expiresAt = &expires
		}
	}

	// Store the distribution record in the database
	distRecord := &DistributionRecord{
		ID:             distRecordIDHex,
		ZoneName:       key.ZoneName,
		KeyID:          key.ID,
		NodeID:         node.ID,
		EncryptedKey:   ciphertext,
		EphemeralPubKey: ephemeralPub,
		CreatedAt:      time.Now(),
		ExpiresAt:      expiresAt,
		Status:         hpke.DistributionStatusPending,
		DistributionID: distributionID,
	}

	if err := kdc.AddDistributionRecord(distRecord); err != nil {
		// Log error but don't fail - the encryption succeeded
		// TODO: Consider making this a hard error
		fmt.Printf("Warning: Failed to store distribution record: %v\n", err)
	}

	return ciphertext, ephemeralPub, distributionID, nil
}

