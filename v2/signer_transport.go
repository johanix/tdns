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
	"os"
	"strings"

	"github.com/johanix/tdns/v2/agent/transport"
	"github.com/johanix/tdns/v2/crypto/jose"
)

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
		Backend: backend,
		Enabled: true,
	})
	if err != nil {
		return nil, fmt.Errorf("create PayloadCrypto: %w", err)
	}

	pc.SetLocalKeys(privKey, pubKey)
	lgSigner.Info("loaded signer JOSE key", "path", privKeyPath)

	// Load public keys for all configured agents
	for i, agentConf := range mp.Agents {
		if agentConf == nil || strings.TrimSpace(agentConf.LongTermJosePubKey) == "" {
			continue
		}
		agentPubKeyPath := strings.TrimSpace(agentConf.LongTermJosePubKey)
		agentPubKeyData, err := os.ReadFile(agentPubKeyPath)
		if err != nil {
			if os.IsNotExist(err) {
				lgSigner.Warn("agent public key file not found, encryption disabled", "agent_index", i, "path", agentPubKeyPath, "err", err)
			} else {
				lgSigner.Warn("failed to read agent public key, encryption disabled", "agent_index", i, "path", agentPubKeyPath, "err", err)
			}
			continue
		}
		agentPubKeyData = StripKeyFileComments(agentPubKeyData)
		agentPubKey, err := backend.ParsePublicKey(agentPubKeyData)
		if err != nil {
			lgSigner.Warn("failed to parse agent public key, encryption disabled", "agent_index", i, "err", err)
			continue
		}
		agentID := agentConf.Identity
		if agentID == "" {
			agentID = fmt.Sprintf("agent-%d", i)
		}
		pc.AddPeerKey(agentID, agentPubKey)
		pc.AddPeerVerificationKey(agentID, agentPubKey)
		lgSigner.Info("loaded agent public key", "path", agentPubKeyPath, "peer", agentID)
	}

	return pc, nil
}
