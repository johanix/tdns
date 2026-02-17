/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/johanix/tdns/v2/agent/transport"
	"github.com/miekg/dns"
)

// InitializeCombinerAsPeer registers the combiner as a virtual peer in the AgentRegistry
// so that the HsyncEngine's Beat mechanism will automatically send heartbeats to it.
// This ensures we verify combiner connectivity and get early warning of communication issues.
func (ar *AgentRegistry) InitializeCombinerAsPeer(conf *Config) error {
	if conf.Agent == nil || conf.Agent.Combiner == nil {
		log.Printf("InitializeCombinerAsPeer: No combiner configured, skipping")
		return nil
	}

	if conf.Agent.Combiner.Address == "" {
		log.Printf("InitializeCombinerAsPeer: Combiner address not configured, skipping")
		return nil
	}

	// Parse combiner address
	host, portStr, err := net.SplitHostPort(conf.Agent.Combiner.Address)
	if err != nil {
		return fmt.Errorf("invalid combiner address %q: %w", conf.Agent.Combiner.Address, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port in combiner address %q", conf.Agent.Combiner.Address)
	}

	// Use configured combiner identity, or default to "combiner" for backwards compatibility
	combinerID := AgentId("combiner")
	if conf.Agent.Combiner.Identity != "" {
		combinerID = AgentId(conf.Agent.Combiner.Identity)
		log.Printf("InitializeCombinerAsPeer: Using configured combiner identity: %s", combinerID)
	} else {
		log.Printf("InitializeCombinerAsPeer: WARNING: No combiner identity configured, using default 'combiner' (agents with chunk_mode=query will fail)")
	}

	// Create an agent entry for the combiner
	combinerAgent := &Agent{
		Identity:  combinerID,
		DnsMethod: true,  // Combiner only supports DNS transport (CHUNK)
		ApiMethod: false, // Combiner doesn't support API transport for Beat
		DnsDetails: &AgentDetails{
			State:           AgentStateOperational, // Start as operational
			BaseUri:         fmt.Sprintf("dns://%s:%d/", host, port),
			Host:            host,
			Port:            uint16(port),
			Addrs:           []string{host},
			HelloTime:       time.Now(),
			LastContactTime: time.Now(),
		},
		ApiDetails: &AgentDetails{
			State: AgentStateNeeded, // Not using API transport
		},
		Zones:     make(map[ZoneName]bool),
		State:     AgentStateOperational,
		LastState: time.Now(),
	}

	// Register in AgentRegistry with configured identity
	ar.S.Set(combinerID, combinerAgent)
	log.Printf("InitializeCombinerAsPeer: Registered combiner %s at %s as virtual peer for heartbeat monitoring", combinerID, conf.Agent.Combiner.Address)

	// Load and register combiner's public key for encrypted communication
	// If combiner is configured, encryption is MANDATORY
	if conf.Agent.Combiner.LongTermJosePubKey == "" {
		return fmt.Errorf("combiner configured but agent.combiner.long_term_jose_pub_key is not set - encrypted communication to combiner is mandatory")
	}

	if conf.Internal.TransportManager == nil || conf.Internal.TransportManager.DNSTransport == nil || conf.Internal.TransportManager.DNSTransport.SecureWrapper == nil {
		return fmt.Errorf("TransportManager or DNSTransport or SecureWrapper not initialized - cannot load combiner public key")
	}

	// Load combiner's public key from file
	payloadCrypto := conf.Internal.TransportManager.DNSTransport.SecureWrapper.GetCrypto()
	if payloadCrypto == nil || payloadCrypto.Backend == nil {
		return fmt.Errorf("PayloadCrypto or Backend not initialized - cannot load combiner public key")
	}

	combinerPubKeyData, err := os.ReadFile(conf.Agent.Combiner.LongTermJosePubKey)
	if err != nil {
		return fmt.Errorf("failed to read combiner public key from %s: %w", conf.Agent.Combiner.LongTermJosePubKey, err)
	}

	combinerPubKey, err := payloadCrypto.Backend.ParsePublicKey(combinerPubKeyData)
	if err != nil {
		return fmt.Errorf("failed to parse combiner public key from %s: %w", conf.Agent.Combiner.LongTermJosePubKey, err)
	}

	// Register combiner's public key for encryption
	payloadCrypto.AddPeerKey(string(combinerID), combinerPubKey)
	payloadCrypto.PeerVerificationKeys[string(combinerID)] = combinerPubKey // Also add for signature verification

	log.Printf("InitializeCombinerAsPeer: Loaded combiner public key from %s", conf.Agent.Combiner.LongTermJosePubKey)

	// Perform initial connectivity check
	if err := performCombinerConnectivityCheck(conf); err != nil {
		log.Printf("InitializeCombinerAsPeer: WARNING: Initial connectivity check failed: %v", err)
		log.Printf("InitializeCombinerAsPeer: Combiner heartbeats will continue to retry")
	} else {
		log.Printf("InitializeCombinerAsPeer: Initial connectivity check passed")
	}

	return nil
}

// performCombinerConnectivityCheck verifies the combiner is reachable via DNS ping.
func performCombinerConnectivityCheck(conf *Config) error {
	if conf.Internal.TransportManager == nil {
		return fmt.Errorf("TransportManager not available")
	}

	// Parse combiner address
	host, portStr, err := net.SplitHostPort(conf.Agent.Combiner.Address)
	if err != nil {
		return fmt.Errorf("invalid combiner address %q: %w", conf.Agent.Combiner.Address, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port in combiner address %q", conf.Agent.Combiner.Address)
	}

	// Create peer for combiner — use configured identity so CHUNK qname matches
	combinerID := "combiner"
	if conf.Agent.Combiner.Identity != "" {
		combinerID = dns.Fqdn(conf.Agent.Combiner.Identity)
	}
	peer := transport.NewPeer(combinerID)
	peer.SetDiscoveryAddress(&transport.Address{
		Host:      host,
		Port:      uint16(port),
		Transport: "udp",
	})

	// Send ping with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pingResp, err := conf.Internal.TransportManager.SendPing(ctx, peer)
	if err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	if !pingResp.OK {
		return fmt.Errorf("combiner did not acknowledge ping (responder: %s)", pingResp.ResponderID)
	}

	return nil
}
