/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Signer message handler goroutine.
 * Consumes beat, hello, ping, and RFI messages from MsgQs.
 * Handles RFI KEYSTATE by querying KeyDB and pushing a complete
 * KEYSTATE inventory back to the requesting agent.
 */

package tdns

import (
	"context"
	"fmt"
	"time"

	"github.com/johanix/tdns/v2/agent/transport"
)

var lgSigner = Logger("signer")

// SignerMsgHandler consumes beat, hello, ping, and RFI messages from MsgQs.
// Updates PeerRegistry liveness on beats and logs hello/ping messages.
// Processes RFI KEYSTATE requests by querying KeyDB and pushing inventory.
func SignerMsgHandler(ctx context.Context, conf *Config, msgQs *MsgQs) {
	if msgQs == nil {
		lgSigner.Warn("No MsgQs configured, exiting")
		return
	}

	tm := conf.Internal.TransportManager
	var peerRegistry *transport.PeerRegistry
	if tm != nil {
		peerRegistry = tm.PeerRegistry
	}

	lgSigner.Info("Starting", "peerRegistry", peerRegistry != nil)

	for {
		select {
		case <-ctx.Done():
			lgSigner.Info("Context cancelled, stopping")
			return

		case report := <-msgQs.Beat:
			if report == nil {
				continue
			}
			senderID := string(report.Identity)
			lgSigner.Debug("Beat received", "sender", senderID, "interval", report.BeatInterval, "distrib", report.DistributionID)

			// Update PeerRegistry liveness
			if peerRegistry != nil {
				peer := peerRegistry.GetOrCreate(senderID)
				peer.LastBeatReceived = time.Now()
				peer.SetState(transport.PeerStateOperational, "beat received")
			}

		case report := <-msgQs.Hello:
			if report == nil {
				continue
			}
			senderID := string(report.Identity)
			lgSigner.Debug("Hello received", "sender", senderID)

			// Update PeerRegistry on hello
			if peerRegistry != nil {
				peer := peerRegistry.GetOrCreate(senderID)
				peer.SetState(transport.PeerStateOperational, "hello received")
			}

		case report := <-msgQs.Ping:
			if report == nil {
				continue
			}
			lgSigner.Debug("Ping received", "sender", string(report.Identity), "distrib", report.DistributionID)

		case msg := <-msgQs.Msg:
			if msg == nil {
				continue
			}
			senderID := string(msg.OriginatorID)
			if senderID == "" {
				senderID = string(msg.DeliveredBy) // Fallback to transport sender
			}
			zone := string(msg.Zone)
			rfiType := msg.RfiType

			lgSigner.Debug("RFI received", "type", rfiType, "sender", senderID, "zone", zone)

			switch rfiType {
			case "KEYSTATE":
				if err := sendKeystateInventoryToAgent(conf, tm, senderID, zone); err != nil {
					lgSigner.Error("Failed to send KEYSTATE inventory", "agent", senderID, "zone", zone, "err", err)
				}
			default:
				lgSigner.Warn("Unknown RFI type, ignoring", "type", rfiType, "sender", senderID)
			}
		}
	}
}

// sendKeystateInventoryToAgent queries KeyDB for all keys in the zone and sends
// a complete KEYSTATE inventory message back to the requesting agent.
func sendKeystateInventoryToAgent(conf *Config, tm *TransportManager, agentID string, zone string) error {
	kdb := conf.Internal.KeyDB
	if kdb == nil {
		return fmt.Errorf("KeyDB not available")
	}

	// Query all keys for this zone
	items, err := kdb.GetKeyInventory(zone)
	if err != nil {
		return fmt.Errorf("GetKeyInventory failed: %w", err)
	}

	lgSigner.Debug("KeyDB inventory queried", "zone", zone, "keys", len(items))

	// Convert KeyInventoryItem → transport.KeyInventoryEntry
	inventory := make([]transport.KeyInventoryEntry, len(items))
	for i, item := range items {
		inventory[i] = transport.KeyInventoryEntry{
			KeyTag:    item.KeyTag,
			Algorithm: item.Algorithm,
			Flags:     item.Flags,
			State:     item.State,
			KeyRR:     item.KeyRR,
		}
	}

	// Look up agent peer in PeerRegistry
	if tm == nil || tm.DNSTransport == nil {
		return fmt.Errorf("TransportManager or DNSTransport not available")
	}
	if tm.PeerRegistry == nil {
		return fmt.Errorf("PeerRegistry not available")
	}

	peer, exists := tm.PeerRegistry.Get(agentID)
	if !exists || peer == nil {
		return fmt.Errorf("agent %q not found in PeerRegistry", agentID)
	}

	// Build and send KEYSTATE inventory
	req := &transport.KeystateRequest{
		SenderID:     conf.MultiProvider.Identity,
		Zone:         zone,
		Signal:       "inventory",
		KeyInventory: inventory,
		Timestamp:    time.Now(),
	}

	sendCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := tm.DNSTransport.Keystate(sendCtx, peer, req)
	if err != nil {
		return fmt.Errorf("Keystate send failed: %w", err)
	}

	if !resp.Accepted {
		return fmt.Errorf("agent %s rejected inventory: %s", agentID, resp.Message)
	}

	lgSigner.Info("KEYSTATE inventory sent", "zone", zone, "agent", agentID, "keys", len(inventory))
	return nil
}
