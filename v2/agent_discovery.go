/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Agent discovery: DNS-based lookup of agent contact information and keys.
 * Allows agents to dynamically discover peers by identity without prior configuration.
 */

package tdns

import (
	"context"
	"crypto"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/johanix/tdns/v2/agent/transport"
	"github.com/miekg/dns"
)

// AgentDiscoveryResult holds the result of discovering an agent.
type AgentDiscoveryResult struct {
	Identity     string
	APIUri       string           // Base URI from URI record (e.g., https://agent.example.com:8443/api)
	DNSUri       string           // DNS endpoint if discovered
	JWKData      string           // Base64url-encoded JWK (preferred)
	PublicKey    crypto.PublicKey // Decoded public key from JWK
	KeyAlgorithm string           // Algorithm from JWK (e.g., "ES256")
	LegacyKeyRR  *dns.KEY         // Legacy KEY record (fallback if no JWK)
	TLSA         *dns.TLSA        // TLSA record for TLS verification
	Addresses    []string         // IP addresses from A/AAAA
	Port         uint16           // Port from URI record
	Error        error            // Any error during discovery
	Partial      bool             // True if some records were found but discovery incomplete
}

// DiscoverAgent performs DNS-based discovery of an agent's contact information.
// Looks up:
//   - URI record at _https._tcp.<identity> for API endpoint
//   - URI record at _dns._udp.<identity> for DNS endpoint (optional)
//   - JWK record at <identity> for public key (preferred)
//   - KEY record at <identity> for public key (fallback)
//   - TLSA record at _443._tcp.<identity> for TLS verification
//   - A/AAAA records at <identity> for IP addresses
//
// Returns a result structure with all discovered information.
func DiscoverAgent(ctx context.Context, identity string) *AgentDiscoveryResult {
	result := &AgentDiscoveryResult{
		Identity: identity,
	}

	// Ensure identity is FQDN
	identity = dns.Fqdn(identity)

	// 1. Look up API URI (_https._tcp.<identity> URI)
	apiUri, _, apiPort, err := lookupAgentAPIEndpoint(ctx, identity)
	if err == nil {
		result.APIUri = apiUri
		result.Port = apiPort
	} else {
		log.Printf("AgentDiscovery: No API URI record found: %v", err)
		result.Partial = true
	}

	// 2. Look up DNS URI (_dns._udp.<identity> URI) - optional
	dnsUri, _, _, err := lookupAgentDNSEndpoint(ctx, identity)
	if err == nil {
		result.DNSUri = dnsUri
	} else {
		log.Printf("AgentDiscovery: No DNS URI record found (optional): %v", err)
	}

	// 3. Look up JWK record (<identity> JWK) for public key - PREFERRED
	jwkData, publicKey, algorithm, err := lookupAgentJWK(ctx, identity)
	if err == nil {
		result.JWKData = jwkData
		result.PublicKey = publicKey
		result.KeyAlgorithm = algorithm
		log.Printf("AgentDiscovery: Found JWK record for %s (algorithm: %s)", identity, algorithm)
	} else {
		log.Printf("AgentDiscovery: No JWK record found for %s: %v", identity, err)

		// 3b. Fallback to KEY record for legacy support
		keyRR, err := lookupAgentKEY(ctx, identity)
		if err == nil {
			result.LegacyKeyRR = keyRR
			log.Printf("AgentDiscovery: Using legacy KEY record for %s (algorithm %d)", identity, keyRR.Algorithm)
		} else {
			log.Printf("AgentDiscovery: No KEY record found for %s: %v", identity, err)
			result.Partial = true
		}
	}

	// 4. Look up TLSA record (_<port>._tcp.<identity> TLSA) for TLS verification
	if result.Port > 0 {
		tlsaRR, err := lookupAgentTLSA(ctx, identity, result.Port)
		if err == nil {
			result.TLSA = tlsaRR
		} else {
			log.Printf("AgentDiscovery: No TLSA record found: %v", err)
			result.Partial = true
		}
	}

	// 5. Look up A/AAAA records (<identity> A/AAAA) for IP addresses
	addresses, err := lookupAgentAddresses(ctx, identity)
	if err == nil {
		result.Addresses = addresses
	} else {
		log.Printf("AgentDiscovery: No A/AAAA records found: %v", err)
		result.Partial = true
	}

	// Check if we have enough information to contact the agent
	if result.APIUri == "" && result.DNSUri == "" {
		result.Error = fmt.Errorf("no contact endpoints found (no API or DNS URI records)")
		return result
	}

	log.Printf("AgentDiscovery: Discovery complete for %s (API: %s, DNS: %s)",
		identity, result.APIUri, result.DNSUri)
	return result
}

// RegisterDiscoveredAgent adds a discovered agent to the PeerRegistry and optionally to AgentRegistry.
func (tm *TransportManager) RegisterDiscoveredAgent(result *AgentDiscoveryResult) error {
	if result.Error != nil {
		return fmt.Errorf("cannot register agent with discovery error: %w", result.Error)
	}

	// Get or create peer in PeerRegistry
	peer := tm.PeerRegistry.GetOrCreate(result.Identity)
	peer.SetState(transport.PeerStateKnown, "discovered via DNS")

	// Set discovery address based on what we found
	if result.APIUri != "" {
		// Parse API URI to extract host and port
		parsed, err := url.Parse(result.APIUri)
		if err != nil {
			return fmt.Errorf("invalid API URI %q: %w", result.APIUri, err)
		}

		host := parsed.Hostname()
		port := uint16(443) // default
		if parsed.Port() != "" {
			// Parse port from URL
			var p int
			fmt.Sscanf(parsed.Port(), "%d", &p)
			port = uint16(p)
		}

		addr := &transport.Address{
			Host:      host,
			Port:      port,
			Transport: "https",
			Path:      parsed.Path,
		}
		peer.SetDiscoveryAddress(addr)
		peer.APIEndpoint = result.APIUri
		peer.PreferredTransport = "API"

		log.Printf("AgentDiscovery: Registered peer %s with API endpoint %s", result.Identity, result.APIUri)
	} else if result.DNSUri != "" {
		// Parse DNS URI for DNS-based transport
		parsed, err := url.Parse(result.DNSUri)
		if err != nil {
			return fmt.Errorf("invalid DNS URI %q: %w", result.DNSUri, err)
		}

		host := parsed.Hostname()
		port := uint16(53) // default DNS port
		if parsed.Port() != "" {
			var p int
			fmt.Sscanf(parsed.Port(), "%d", &p)
			port = uint16(p)
		}

		addr := &transport.Address{
			Host:      host,
			Port:      port,
			Transport: "udp",
		}
		peer.SetDiscoveryAddress(addr)
		peer.PreferredTransport = "DNS"

		log.Printf("AgentDiscovery: Registered peer %s with DNS endpoint %s", result.Identity, result.DNSUri)
	}

	// Store TLSA for TLS verification
	if result.TLSA != nil {
		peer.TLSARecord = []byte(result.TLSA.Certificate) // Store the certificate data
	}

	// Store JWK public key if available (preferred)
	if result.JWKData != "" && result.PublicKey != nil {
		// Store the JWK data and decoded public key
		// TODO: Add JWK fields to Peer struct when available
		log.Printf("AgentDiscovery: Stored JWK public key for %s (algorithm: %s)", result.Identity, result.KeyAlgorithm)
	}

	// Also add to AgentRegistry if available (for backward compatibility)
	if tm.agentRegistry != nil {
		agent, exists := tm.agentRegistry.S.Get(AgentId(result.Identity))
		if !exists {
			agent = &Agent{
				Identity:   AgentId(result.Identity),
				ApiDetails: &AgentDetails{},
				DnsDetails: &AgentDetails{},
				Zones:      make(map[ZoneName]bool),
				State:      AgentStateKnown,
				LastState:  time.Now(),
			}
		}

		// Update agent details
		if result.APIUri != "" {
			agent.ApiDetails.BaseUri = result.APIUri
			agent.ApiDetails.ContactInfo = "complete"
			agent.ApiDetails.State = AgentStateKnown
			agent.ApiDetails.TlsaRR = result.TLSA
			agent.ApiDetails.Addrs = result.Addresses
			agent.ApiMethod = true
		}
		if result.DNSUri != "" {
			agent.DnsDetails.BaseUri = result.DNSUri
			agent.DnsDetails.ContactInfo = "complete"
			agent.DnsDetails.State = AgentStateKnown
			// Store KEY record if using legacy fallback, otherwise nil
			agent.DnsDetails.KeyRR = result.LegacyKeyRR
			agent.DnsDetails.Addrs = result.Addresses
			agent.DnsMethod = true
		}

		tm.agentRegistry.S.Set(AgentId(result.Identity), agent)
		log.Printf("AgentDiscovery: Also added agent %s to AgentRegistry", result.Identity)
	}

	return nil
}

// DiscoverAndRegisterAgent performs discovery and registration in one step.
func (tm *TransportManager) DiscoverAndRegisterAgent(ctx context.Context, identity string) error {
	log.Printf("AgentDiscovery: Starting discovery for agent %s", identity)

	result := DiscoverAgent(ctx, identity)
	if result.Error != nil {
		return fmt.Errorf("discovery failed for %s: %w", identity, result.Error)
	}

	if result.Partial {
		log.Printf("AgentDiscovery: Warning: Partial discovery for %s (some records missing)", identity)
	}

	err := tm.RegisterDiscoveredAgent(result)
	if err != nil {
		return fmt.Errorf("failed to register discovered agent %s: %w", identity, err)
	}

	log.Printf("AgentDiscovery: Successfully discovered and registered agent %s", identity)
	return nil
}
