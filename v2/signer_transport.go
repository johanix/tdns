/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Signer-side transport for multi-provider DNSSEC (Phase 3).
 * Enables tdns-auth to receive CHUNK NOTIFYs from its local agent
 * and respond to pings. KEYSTATE handling added in Phase 4.
 */

package tdns

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/johanix/tdns/v2/agent/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/crypto"
	"github.com/johanix/tdns/v2/crypto/jose"
)

// RegisterSignerChunkHandler registers a CHUNK NOTIFY handler for the signer (tdns-auth).
// Reuses CombinerChunkHandler as the dispatch shell (Router + CreateNotifyHandlerFunc).
// The signer does not use ProcessUpdate — it only routes messages to the signer router
// which handles ping (Phase 3) and KEYSTATE (Phase 4).
func RegisterSignerChunkHandler(localID string, router *transport.DNSMessageRouter) (*CombinerChunkHandler, error) {
	handler := &CombinerChunkHandler{
		RequestChan:  make(chan *CombinerSyncRequestPlus, 10),
		LocalID:      localID,
		Router:       router,
		ErrorJournal: NewErrorJournal(100, 24*time.Hour),
	}
	log.Printf("RegisterSignerChunkHandler: Registering CHUNK handler for signer %s", localID)
	return handler, RegisterNotifyHandler(core.TypeCHUNK, handler.CreateNotifyHandlerFunc())
}

// initSignerCrypto initializes PayloadCrypto for the signer from MultiProviderConf.
// Loads the signer's JOSE private key and the agent's public key (if configured).
func initSignerCrypto(conf *Config) (*transport.PayloadCrypto, error) {
	mp := conf.MultiProvider
	if mp == nil {
		return nil, fmt.Errorf("multi-provider config is not set")
	}

	backend := jose.NewBackend()

	// Load signer's private key
	privKeyPath := strings.TrimSpace(mp.LongTermJosePrivKey)
	privKeyData, err := os.ReadFile(privKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("signer private key file not found: %q: %w", privKeyPath, err)
		}
		return nil, fmt.Errorf("read signer private key %q: %w", privKeyPath, err)
	}
	privKeyData = StripKeyFileComments(privKeyData)

	privKey, err := backend.ParsePrivateKey(privKeyData)
	if err != nil {
		return nil, fmt.Errorf("parse signer private key: %w", err)
	}

	// Derive public key from private key
	joseBackend, ok := backend.(*jose.Backend)
	if !ok {
		return nil, fmt.Errorf("backend is not JOSE")
	}
	pubKey, err := joseBackend.PublicFromPrivate(privKey)
	if err != nil {
		return nil, fmt.Errorf("derive signer public key: %w", err)
	}

	// Create PayloadCrypto instance
	pc, err := transport.NewPayloadCrypto(&transport.PayloadCryptoConfig{
		Backend: backend.(crypto.Backend),
		Enabled: true,
	})
	if err != nil {
		return nil, fmt.Errorf("create PayloadCrypto: %w", err)
	}

	pc.SetLocalKeys(privKey, pubKey)
	log.Printf("initSignerCrypto: Loaded signer JOSE key from %s", privKeyPath)

	// Load agent's public key if configured
	if mp.Agent != nil && strings.TrimSpace(mp.Agent.LongTermJosePubKey) != "" {
		agentPubKeyPath := strings.TrimSpace(mp.Agent.LongTermJosePubKey)
		agentPubKeyData, err := os.ReadFile(agentPubKeyPath)
		if err != nil {
			if os.IsNotExist(err) {
				log.Printf("initSignerCrypto: agent public key file not found %q: %v (agent encryption disabled)", agentPubKeyPath, err)
			} else {
				log.Printf("initSignerCrypto: failed to read agent public key %q: %v (agent encryption disabled)", agentPubKeyPath, err)
			}
		} else {
			agentPubKeyData = StripKeyFileComments(agentPubKeyData)
			agentPubKey, err := backend.ParsePublicKey(agentPubKeyData)
			if err != nil {
				log.Printf("initSignerCrypto: failed to parse agent public key: %v (agent encryption disabled)", err)
			} else {
				agentID := "agent"
				if mp.Agent.Identity != "" {
					agentID = mp.Agent.Identity
				}
				pc.AddPeerKey(agentID, agentPubKey)
				pc.AddPeerVerificationKey(agentID, agentPubKey)
				log.Printf("initSignerCrypto: Loaded agent public key from %s (peer: %s)", agentPubKeyPath, agentID)
			}
		}
	}

	return pc, nil
}
