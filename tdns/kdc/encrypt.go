/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * HPKE encryption functions for key distribution
 */

package kdc

import (
	"fmt"
	"time"

	"github.com/johanix/tdns/tdns/hpke"
)

// EncryptKeyForNode encrypts a DNSSEC key's private key material for a specific node
// using HPKE with the node's long-term public key
// Returns: encrypted key data, ephemeral public key used, distribution ID, error
func (kdc *KdcDB) EncryptKeyForNode(key *DNSSECKey, node *Node) (encryptedKey []byte, ephemeralPubKey []byte, distributionID string, err error) {
	if key == nil {
		return nil, nil, "", fmt.Errorf("key is nil")
	}
	if node == nil {
		return nil, nil, "", fmt.Errorf("node is nil")
	}
	if len(node.LongTermPubKey) != 32 {
		return nil, nil, "", fmt.Errorf("node long-term public key must be 32 bytes (got %d)", len(node.LongTermPubKey))
	}

	// Encrypt the private key using HPKE
	// Note: HPKE Base mode generates its own ephemeral key internally
	// The ephemeralPubKey parameter is currently ignored but returned for future use
	ciphertext, ephemeralPub, err := hpke.Encrypt(node.LongTermPubKey, nil, key.PrivateKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to encrypt key: %v", err)
	}

	// Generate a distribution ID (simple timestamp-based for now)
	distributionID = fmt.Sprintf("dist-%d-%s-%d", time.Now().Unix(), key.ID, key.KeyID)

	return ciphertext, ephemeralPub, distributionID, nil
}

