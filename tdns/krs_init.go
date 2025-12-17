/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KRS initialization functions for tdns package
 */

package tdns

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/johanix/tdns/tdns/hpke"
	"github.com/johanix/tdns/tdns/krs"
	"gopkg.in/yaml.v3"
)

// StartKrs starts subsystems for tdns-krs
func (conf *Config) StartKrs(ctx context.Context, apirouter *mux.Router) error {
	// Parse KRS configuration from stored YAML bytes
	var krsConf krs.KrsConf
	
	// conf.Internal.KrsConf is either []byte (YAML) or already *krs.KrsConf
	switch v := conf.Internal.KrsConf.(type) {
	case []byte:
		// Unmarshal YAML bytes into krs.KrsConf
		if err := yaml.Unmarshal(v, &krsConf); err != nil {
			return fmt.Errorf("failed to unmarshal KRS config: %v", err)
		}
		conf.Internal.KrsConf = &krsConf
	case *krs.KrsConf:
		krsConf = *v
	default:
		return fmt.Errorf("KRS configuration not found or invalid type (got %T)", conf.Internal.KrsConf)
	}

	// Initialize KRS database
	krsDB, err := krs.NewKrsDB(krsConf.Database.DSN)
	if err != nil {
		return fmt.Errorf("failed to initialize KRS database: %v", err)
	}
	conf.Internal.KrsDB = krsDB

	// Load node configuration (long-term HPKE private key)
	privKeyData, err := os.ReadFile(krsConf.Node.LongTermPrivKey)
	if err != nil {
		return fmt.Errorf("failed to read long-term private key: %v", err)
	}

	// Parse private key (hex format with optional comments)
	privKeyHex := ""
	lines := strings.Split(string(privKeyData), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			privKeyHex += line
		}
	}

	// Decode hex private key
	privKey, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return fmt.Errorf("failed to decode private key (must be hex): %v", err)
	}
	if len(privKey) != 32 {
		return fmt.Errorf("private key must be 32 bytes (got %d)", len(privKey))
	}

	// TODO: Get public key from private key (derive it)
	// For now, we'll need to load it separately or derive it
	// For HPKE X25519, we can derive the public key from the private key
	pubKey, err := hpke.DerivePublicKey(privKey)
	if err != nil {
		return fmt.Errorf("failed to derive public key: %v", err)
	}

	// Store node config in database
	nodeConfig := &krs.NodeConfig{
		ID:              krsConf.Node.ID,
		LongTermPubKey:  pubKey,
		LongTermPrivKey: privKey,
		KdcAddress:     krsConf.Node.KdcAddress,
		ControlZone:     krsConf.ControlZone,
		RegisteredAt:    time.Now(),
		LastSeen:        time.Now(),
	}
	if err := krsDB.SetNodeConfig(nodeConfig); err != nil {
		return fmt.Errorf("failed to store node config: %v", err)
	}

	// Setup KRS API routes
	krs.SetupKrsAPIRoutes(apirouter, krsDB, &krsConf)

	// Start API dispatcher
	startEngine(&Globals.App, "APIdispatcher", func() error {
		return APIdispatcher(conf, apirouter, conf.Internal.APIStopCh)
	})

	// Start NOTIFY receiver
	if len(krsConf.DnsEngine.Addresses) > 0 {
		startEngine(&Globals.App, "NotifyReceiver", func() error {
			return krs.StartNotifyReceiver(ctx, krsDB, &krsConf)
		})
	}

	log.Printf("TDNS %s (%s): KRS started successfully", Globals.App.Name, AppTypeToString[Globals.App.Type])
	return nil
}

