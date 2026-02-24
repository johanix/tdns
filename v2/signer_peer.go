/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Registers the signer (tdns-auth) as a virtual peer in the agent's AgentRegistry,
 * mirroring InitializeCombinerAsPeer. This allows the signer to appear in
 * "agent peer list" and enables agent→signer DNS CHUNK ping.
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

// InitializeSignerAsPeer registers the signer as a virtual peer in the AgentRegistry
// so that it shows up in "agent peer list" and can be pinged via "agent peer ping".
// Mirrors InitializeCombinerAsPeer for the signer role.
func (ar *AgentRegistry) InitializeSignerAsPeer(conf *Config) error {
	if conf.Agent == nil || conf.Agent.Signer == nil {
		log.Printf("InitializeSignerAsPeer: No signer configured, skipping")
		return nil
	}

	if conf.Agent.Signer.Address == "" {
		log.Printf("InitializeSignerAsPeer: Signer address not configured, skipping")
		return nil
	}

	// Parse signer address
	host, portStr, err := net.SplitHostPort(conf.Agent.Signer.Address)
	if err != nil {
		return fmt.Errorf("invalid signer address %q: %w", conf.Agent.Signer.Address, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port in signer address %q", conf.Agent.Signer.Address)
	}

	signerID := AgentId("signer")
	if conf.Agent.Signer.Identity != "" {
		signerID = AgentId(conf.Agent.Signer.Identity)
		log.Printf("InitializeSignerAsPeer: Using configured signer identity: %s", signerID)
	} else {
		log.Printf("InitializeSignerAsPeer: WARNING: No signer identity configured, using default 'signer'")
	}

	// Create an agent entry for the signer
	signerAgent := &Agent{
		Identity:  signerID,
		DnsMethod: true,  // Signer uses DNS transport (CHUNK)
		ApiMethod: false, // No API transport for signer
		DnsDetails: &AgentDetails{
			State:           AgentStateOperational,
			BaseUri:         fmt.Sprintf("dns://%s:%d/", host, port),
			Host:            host,
			Port:            uint16(port),
			Addrs:           []string{host},
			HelloTime:       time.Now(),
			LastContactTime: time.Now(),
		},
		ApiDetails: &AgentDetails{
			State: AgentStateNeeded,
		},
		Zones:     make(map[ZoneName]bool),
		State:     AgentStateOperational,
		LastState: time.Now(),
	}

	// Register in AgentRegistry
	ar.S.Set(signerID, signerAgent)
	log.Printf("InitializeSignerAsPeer: Registered signer %s at %s as virtual peer", signerID, conf.Agent.Signer.Address)

	// Load and register signer's public key for encrypted communication
	if conf.Agent.Signer.LongTermJosePubKey == "" {
		return fmt.Errorf("signer configured but agent.signer.long_term_jose_pub_key is not set - encrypted communication to signer is mandatory")
	}

	if conf.Internal.TransportManager == nil || conf.Internal.TransportManager.DNSTransport == nil || conf.Internal.TransportManager.DNSTransport.SecureWrapper == nil {
		return fmt.Errorf("TransportManager or DNSTransport or SecureWrapper not initialized - cannot load signer public key")
	}

	payloadCrypto := conf.Internal.TransportManager.DNSTransport.SecureWrapper.GetCrypto()
	if payloadCrypto == nil || payloadCrypto.Backend == nil {
		return fmt.Errorf("PayloadCrypto or Backend not initialized - cannot load signer public key")
	}

	signerPubKeyData, err := os.ReadFile(conf.Agent.Signer.LongTermJosePubKey)
	if err != nil {
		return fmt.Errorf("failed to read signer public key from %s: %w", conf.Agent.Signer.LongTermJosePubKey, err)
	}

	signerPubKey, err := payloadCrypto.Backend.ParsePublicKey(signerPubKeyData)
	if err != nil {
		return fmt.Errorf("failed to parse signer public key from %s: %w", conf.Agent.Signer.LongTermJosePubKey, err)
	}

	payloadCrypto.AddPeerKey(string(signerID), signerPubKey)
	payloadCrypto.PeerVerificationKeys[string(signerID)] = signerPubKey

	log.Printf("InitializeSignerAsPeer: Loaded signer public key from %s", conf.Agent.Signer.LongTermJosePubKey)

	// Perform initial connectivity check
	if err := performSignerConnectivityCheck(conf); err != nil {
		log.Printf("InitializeSignerAsPeer: WARNING: Initial connectivity check failed: %v", err)
		log.Printf("InitializeSignerAsPeer: Signer pings will continue to work once signer is reachable")
	} else {
		log.Printf("InitializeSignerAsPeer: Initial connectivity check passed")
	}

	return nil
}

// performSignerConnectivityCheck verifies the signer is reachable via DNS ping.
func performSignerConnectivityCheck(conf *Config) error {
	if conf.Internal.TransportManager == nil {
		return fmt.Errorf("TransportManager not available")
	}

	host, portStr, err := net.SplitHostPort(conf.Agent.Signer.Address)
	if err != nil {
		return fmt.Errorf("invalid signer address %q: %w", conf.Agent.Signer.Address, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port in signer address %q", conf.Agent.Signer.Address)
	}

	signerID := "signer"
	if conf.Agent.Signer.Identity != "" {
		signerID = dns.Fqdn(conf.Agent.Signer.Identity)
	}
	peer := transport.NewPeer(signerID)
	peer.SetDiscoveryAddress(&transport.Address{
		Host:      host,
		Port:      uint16(port),
		Transport: "udp",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pingResp, err := conf.Internal.TransportManager.SendPing(ctx, peer)
	if err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	if !pingResp.OK {
		return fmt.Errorf("signer did not acknowledge ping (responder: %s)", pingResp.ResponderID)
	}

	return nil
}
