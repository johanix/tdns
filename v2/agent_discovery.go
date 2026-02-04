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
	Identity      string
	APIUri        string           // Base URI from URI record (e.g., https://agent.example.com:8443/api)
	DNSUri        string           // DNS endpoint if discovered
	JWKData       string           // Base64url-encoded JWK (preferred)
	PublicKey     crypto.PublicKey // Decoded public key from JWK
	KeyAlgorithm  string           // Algorithm from JWK (e.g., "ES256")
	LegacyKeyRR   *dns.KEY         // Legacy KEY record (fallback if no JWK)
	TLSA          *dns.TLSA        // TLSA record for TLS verification
	APIAddresses  []string         // IP addresses for API service from SVCB
	DNSAddresses  []string         // IP addresses for DNS service from SVCB
	Port          uint16           // Port from URI record
	Error         error            // Any error during discovery
	Partial       bool             // True if some records were found but discovery incomplete
}

// DiscoverAgent performs DNS-based discovery of an agent's contact information.
// Discovery flow for API transport:
//   1. URI record at _https._tcp.<identity> → get API endpoint URI and port
//   2. SVCB record at api.<identity> → get ipv4hint/ipv6hint addresses
//   3. TLSA record at _<port>._tcp.api.<identity> → get TLS certificate for verification
//
// Discovery flow for DNS transport (optional):
//   1. URI record at _dns._tcp.<identity> → get DNS endpoint URI and port
//   2. SVCB record at dns.<identity> → get ipv4hint/ipv6hint addresses
//   3. JWK record at dns.<identity> → get JOSE/HPKE public key (preferred)
//   4. KEY record at dns.<identity> → get SIG(0) public key (legacy fallback if no JWK)
//
// Returns a result structure with all discovered information.
func DiscoverAgent(ctx context.Context, imr *Imr, identity string) *AgentDiscoveryResult {
	result := &AgentDiscoveryResult{
		Identity: identity,
	}

	// Ensure identity is FQDN
	identity = dns.Fqdn(identity)

	// 1. Look up API URI (_https._tcp.<identity> URI)
	// This gives us the API endpoint URI and the port
	apiUri, apiHost, apiPort, err := imr.lookupAgentAPIEndpoint(ctx, identity)
	if err == nil {
		result.APIUri = apiUri
		result.Port = apiPort

		// 1a. Look up SVCB at api.<identity> to get IP addresses
		apiServiceName := "api." + identity
		addresses, err := imr.lookupServiceAddresses(ctx, apiServiceName)
		if err == nil {
			result.APIAddresses = addresses
		} else {
			log.Printf("AgentDiscovery: No SVCB record found for API service at %s: %v", apiServiceName, err)
			result.Partial = true
		}

		// 1b. Look up TLSA at _<port>._tcp.api.<identity> for TLS verification
		tlsaRR, err := imr.lookupAgentTLSA(ctx, apiServiceName, apiPort)
		if err == nil {
			result.TLSA = tlsaRR
		} else {
			log.Printf("AgentDiscovery: No TLSA record found for API service: %v", err)
			result.Partial = true
		}

		log.Printf("AgentDiscovery: Found API endpoint %s at %s", apiUri, apiHost)
	} else {
		log.Printf("AgentDiscovery: No API URI record found: %v", err)
		result.Partial = true
	}

	// 2. Look up DNS URI (_dns._udp.<identity> URI) - optional
	// This gives us the DNS endpoint URI
	dnsUri, dnsHost, dnsPort, err := imr.lookupAgentDNSEndpoint(ctx, identity)
	if err == nil {
		result.DNSUri = dnsUri

		// 2a. Look up SVCB at dns.<identity> to get IP addresses
		dnsServiceName := "dns." + identity
		addresses, err := imr.lookupServiceAddresses(ctx, dnsServiceName)
		if err == nil {
			result.DNSAddresses = addresses
		} else {
			log.Printf("AgentDiscovery: No SVCB record found for DNS service at %s: %v", dnsServiceName, err)
			result.Partial = true
		}

		// 2b. Look up JWK at dns.<identity> for JOSE/HPKE public key
		jwkData, publicKey, algorithm, err := imr.lookupAgentJWK(ctx, identity)
		if err == nil {
			result.JWKData = jwkData
			result.PublicKey = publicKey
			result.KeyAlgorithm = algorithm
			log.Printf("AgentDiscovery: Found JWK record for %s (algorithm: %s)", identity, algorithm)
		} else {
			log.Printf("AgentDiscovery: No JWK record found for %s: %v", identity, err)

			// 2c. Fallback to KEY record for legacy support
			keyRR, err := imr.lookupAgentKEY(ctx, identity)
			if err == nil {
				result.LegacyKeyRR = keyRR
				log.Printf("AgentDiscovery: Using legacy KEY record for %s (algorithm %d)", identity, keyRR.Algorithm)
			} else {
				log.Printf("AgentDiscovery: No KEY record found for %s: %v", identity, err)
				result.Partial = true
			}
		}

		log.Printf("AgentDiscovery: Found DNS endpoint %s at %s:%d", dnsUri, dnsHost, dnsPort)
	} else {
		log.Printf("AgentDiscovery: No DNS URI record found (optional): %v", err)
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

	// Register API transport address
	if result.APIUri != "" {
		parsed, err := url.Parse(result.APIUri)
		if err != nil {
			return fmt.Errorf("invalid API URI %q: %w", result.APIUri, err)
		}

		port := uint16(443) // default
		if parsed.Port() != "" {
			var p int
			fmt.Sscanf(parsed.Port(), "%d", &p)
			port = uint16(p)
		}

		// Use discovered IP address instead of hostname (DNS-34 fix)
		if len(result.APIAddresses) == 0 {
			return fmt.Errorf("no IP addresses discovered for API transport (DNS-35 prevention)")
		}
		host := result.APIAddresses[0]
		log.Printf("AgentDiscovery: Using discovered IP %s for API transport (from SVCB)", host)

		addr := &transport.Address{
			Host:      host,
			Port:      port,
			Transport: "https",
			Path:      parsed.Path,
		}
		peer.SetDiscoveryAddress(addr)
		peer.APIEndpoint = result.APIUri
		peer.PreferredTransport = "API"

		log.Printf("AgentDiscovery: Registered peer %s with API endpoint %s (address: %s:%d)", result.Identity, result.APIUri, host, port)
	}

	// Register DNS transport address (DNS-33 fix: NOT else if - both can exist)
	if result.DNSUri != "" {
		parsed, err := url.Parse(result.DNSUri)
		if err != nil {
			return fmt.Errorf("invalid DNS URI %q: %w", result.DNSUri, err)
		}

		port := uint16(53) // default DNS port
		if parsed.Port() != "" {
			var p int
			fmt.Sscanf(parsed.Port(), "%d", &p)
			port = uint16(p)
		}

		// Use discovered IP address instead of hostname (DNS-34 fix)
		if len(result.DNSAddresses) == 0 {
			return fmt.Errorf("no IP addresses discovered for DNS transport (DNS-35 prevention)")
		}
		host := result.DNSAddresses[0]
		log.Printf("AgentDiscovery: Using discovered IP %s for DNS transport (from SVCB)", host)

		addr := &transport.Address{
			Host:      host,
			Port:      port,
			Transport: "udp",
		}

		// If both transports exist, DNS address goes to DiscoveryAddress (preferred for ping)
		// API address was already set above but will be overwritten
		peer.SetDiscoveryAddress(addr)
		peer.PreferredTransport = "DNS"

		log.Printf("AgentDiscovery: Registered peer %s with DNS endpoint %s (address: %s:%d)", result.Identity, result.DNSUri, host, port)
	}

	// Store TLSA for TLS verification
	if result.TLSA != nil {
		peer.TLSARecord = []byte(result.TLSA.Certificate) // Store the certificate data
	}

	// Store JWK public key if available (preferred)
	if result.JWKData != "" && result.PublicKey != nil {
		// Add peer's public key to PayloadCrypto for encryption
		if tm.DNSTransport != nil && tm.DNSTransport.SecureWrapper != nil {
			payloadCrypto := tm.DNSTransport.SecureWrapper.GetCrypto()
			if payloadCrypto != nil && payloadCrypto.Backend != nil {
				// Wrap the stdlib crypto.PublicKey in a backend-specific wrapper
				// The backend can reconstruct its own PublicKey type from the raw key
				wrappedKey, err := payloadCrypto.Backend.PublicKeyFromStdlib(result.PublicKey)
				if err != nil {
					log.Printf("AgentDiscovery: Warning: Failed to wrap public key for %s: %v", result.Identity, err)
				} else {
					payloadCrypto.AddPeerKey(result.Identity, wrappedKey)
					payloadCrypto.AddPeerVerificationKey(result.Identity, wrappedKey)
					log.Printf("AgentDiscovery: Added JWK public key to PayloadCrypto for %s (algorithm: %s)", result.Identity, result.KeyAlgorithm)
				}
			} else {
				log.Printf("AgentDiscovery: Warning: Cannot add peer key - PayloadCrypto not configured")
			}
		} else {
			log.Printf("AgentDiscovery: Warning: Cannot add peer key - SecureWrapper not configured")
		}
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
			agent.ApiDetails.Addrs = result.APIAddresses
			agent.ApiMethod = true
		}
		if result.DNSUri != "" {
			agent.DnsDetails.BaseUri = result.DNSUri
			agent.DnsDetails.ContactInfo = "complete"
			agent.DnsDetails.State = AgentStateKnown
			// Store JWK data if available (preferred)
			if result.JWKData != "" {
				agent.DnsDetails.JWKData = result.JWKData
				agent.DnsDetails.KeyAlgorithm = result.KeyAlgorithm
			}
			// Store KEY record if using legacy fallback
			agent.DnsDetails.KeyRR = result.LegacyKeyRR
			agent.DnsDetails.Addrs = result.DNSAddresses
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

	// Get IMR engine from global config
	imr := Conf.Internal.ImrEngine
	if imr == nil {
		return fmt.Errorf("IMR engine not available for discovery")
	}

	result := DiscoverAgent(ctx, imr, identity)
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
