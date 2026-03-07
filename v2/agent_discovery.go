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
	APIAddresses []string         // IP addresses for API service from SVCB
	DNSAddresses []string         // IP addresses for DNS service from SVCB
	Port         uint16           // Port from URI record
	Error        error            // Any error during discovery
	Partial      bool             // True if some records were found but discovery incomplete
}

// DiscoverAgentAPI performs DNS-based discovery of an agent's API transport.
//  1. URI record at _https._tcp.<identity> → get API endpoint URI and port
//  2. SVCB record at api.<identity> → get ipv4hint/ipv6hint addresses
//  3. TLSA record at _<port>._tcp.api.<identity> → get TLS certificate for verification
func DiscoverAgentAPI(ctx context.Context, imr *Imr, identity string, result *AgentDiscoveryResult) {
	identity = dns.Fqdn(identity)

	apiUri, apiHost, apiPort, err := imr.lookupAgentAPIEndpoint(ctx, identity)
	if err == nil {
		result.APIUri = apiUri
		result.Port = apiPort

		// Look up SVCB at api.<identity> to get IP addresses
		apiServiceName := "api." + identity
		addresses, err := imr.lookupServiceAddresses(ctx, apiServiceName)
		if err == nil {
			result.APIAddresses = addresses
		} else {
			lgAgent.Debug("no SVCB record for API service", "service", apiServiceName, "err", err)
			result.Partial = true
		}

		// Look up TLSA at _<port>._tcp.api.<identity> for TLS verification
		tlsaRR, err := imr.lookupAgentTLSA(ctx, apiServiceName, apiPort)
		if err == nil {
			result.TLSA = tlsaRR
		} else {
			lgAgent.Debug("no TLSA record for API service", "err", err)
			result.Partial = true
		}

		lgAgent.Info("found API endpoint", "uri", apiUri, "host", apiHost)
	} else {
		lgAgent.Debug("no API URI record found", "err", err)
		result.Partial = true
	}
}

// DiscoverAgentDNS performs DNS-based discovery of an agent's DNS transport.
//  1. URI record at _dns._tcp.<identity> → get DNS endpoint URI and port
//  2. SVCB record at dns.<identity> → get ipv4hint/ipv6hint addresses
//  3. JWK record at dns.<identity> → get JOSE/HPKE public key (preferred)
//  4. KEY record at dns.<identity> → get SIG(0) public key (legacy fallback if no JWK)
func DiscoverAgentDNS(ctx context.Context, imr *Imr, identity string, result *AgentDiscoveryResult) {
	identity = dns.Fqdn(identity)

	dnsUri, dnsHost, dnsPort, err := imr.lookupAgentDNSEndpoint(ctx, identity)
	if err == nil {
		result.DNSUri = dnsUri

		// Look up SVCB at dns.<identity> to get IP addresses
		dnsServiceName := "dns." + identity
		addresses, err := imr.lookupServiceAddresses(ctx, dnsServiceName)
		if err == nil {
			result.DNSAddresses = addresses
		} else {
			lgAgent.Warn("SVCB lookup failed for DNS service", "service", dnsServiceName, "err", err)
			result.Partial = true
		}

		// Look up JWK at dns.<identity> for JOSE/HPKE public key
		jwkData, publicKey, algorithm, err := imr.lookupAgentJWK(ctx, identity)
		if err == nil {
			result.JWKData = jwkData
			result.PublicKey = publicKey
			result.KeyAlgorithm = algorithm
			lgAgent.Info("found JWK record", "identity", identity, "algorithm", algorithm)
		} else {
			lgAgent.Warn("JWK lookup failed", "identity", identity, "err", err)

			// Fallback to KEY record for legacy support
			keyRR, err := imr.lookupAgentKEY(ctx, identity)
			if err == nil {
				result.LegacyKeyRR = keyRR
				lgAgent.Info("using legacy KEY record", "identity", identity, "algorithm", keyRR.Algorithm)
			} else {
				lgAgent.Warn("KEY lookup failed (legacy fallback)", "identity", identity, "err", err)
				result.Partial = true
			}
		}

		lgAgent.Info("found DNS endpoint", "uri", dnsUri, "host", dnsHost, "port", dnsPort)
	} else {
		lgAgent.Debug("no DNS URI record found (optional)", "err", err)
	}
}

// DiscoverAgent performs full DNS-based discovery of an agent's contact information
// for both API and DNS transports. Convenience wrapper around DiscoverAgentAPI + DiscoverAgentDNS.
func DiscoverAgent(ctx context.Context, imr *Imr, identity string) *AgentDiscoveryResult {
	result := &AgentDiscoveryResult{
		Identity: identity,
	}

	DiscoverAgentAPI(ctx, imr, identity, result)
	DiscoverAgentDNS(ctx, imr, identity, result)

	// Check if we have enough information to contact the agent
	if result.APIUri == "" && result.DNSUri == "" {
		result.Error = fmt.Errorf("no contact endpoints found (no API or DNS URI records)")
		return result
	}

	lgAgent.Info("discovery complete", "identity", identity, "apiUri", result.APIUri, "dnsUri", result.DNSUri)
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
		// Non-fatal: skip API peer registration if SVCB addresses are missing,
		// but continue to DNS and AgentRegistry update.
		if len(result.APIAddresses) == 0 {
			lgAgent.Warn("no SVCB addresses for API transport, skipping API peer registration", "identity", result.Identity)
		} else {
			host := result.APIAddresses[0]
			lgAgent.Debug("using discovered IP for API transport", "host", host)

			addr := &transport.Address{
				Host:      host,
				Port:      port,
				Transport: "https",
				Path:      parsed.Path,
			}
			peer.SetDiscoveryAddress(addr)
			peer.APIEndpoint = result.APIUri
			peer.PreferredTransport = "API"

			lgAgent.Info("registered peer with API endpoint", "identity", result.Identity, "endpoint", result.APIUri, "address", host, "port", port)
		}
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
		// Non-fatal: skip DNS peer registration if SVCB addresses are missing,
		// but continue to AgentRegistry update.
		if len(result.DNSAddresses) == 0 {
			lgAgent.Warn("no SVCB addresses for DNS transport, skipping DNS peer registration", "identity", result.Identity)
		} else {
			host := result.DNSAddresses[0]
			lgAgent.Debug("using discovered IP for DNS transport", "host", host)

			addr := &transport.Address{
				Host:      host,
				Port:      port,
				Transport: "udp",
			}

			// If both transports exist, DNS address goes to DiscoveryAddress (preferred for ping)
			// API address was already set above but will be overwritten
			peer.SetDiscoveryAddress(addr)
			peer.PreferredTransport = "DNS"

			lgAgent.Info("registered peer with DNS endpoint", "identity", result.Identity, "endpoint", result.DNSUri, "address", host, "port", port)
		}
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
					lgAgent.Warn("failed to wrap public key", "identity", result.Identity, "err", err)
				} else {
					payloadCrypto.AddPeerKey(result.Identity, wrappedKey)
					payloadCrypto.AddPeerVerificationKey(result.Identity, wrappedKey)
					lgAgent.Info("added JWK public key to PayloadCrypto", "identity", result.Identity, "algorithm", result.KeyAlgorithm)
				}
			} else {
				lgAgent.Warn("cannot add peer key - PayloadCrypto not configured")
			}
		} else {
			lgAgent.Warn("cannot add peer key - SecureWrapper not configured")
		}
	}

	// Verify that a verification key was actually registered.
	// If no JWK or KEY was found, the peer is unusable for encrypted communication.
	hasVerificationKey := false
	if tm.DNSTransport != nil && tm.DNSTransport.SecureWrapper != nil {
		if pc := tm.DNSTransport.SecureWrapper.GetCrypto(); pc != nil {
			_, hasVerificationKey = pc.GetPeerVerificationKey(result.Identity)
		}
	}
	if !hasVerificationKey {
		return fmt.Errorf("discovery for %s found endpoint but no verification key (JWK/KEY lookup failed)", result.Identity)
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

		// Update agent details — only set state to KNOWN if not already beyond it.
		// Re-discovery must not regress an OPERATIONAL or INTRODUCED transport.
		if result.APIUri != "" {
			agent.ApiDetails.BaseUri = result.APIUri
			agent.ApiDetails.ContactInfo = "complete"
			if agent.ApiDetails.State <= AgentStateNeeded {
				agent.ApiDetails.State = AgentStateKnown
			}
			agent.ApiDetails.TlsaRR = result.TLSA
			agent.ApiDetails.Addrs = result.APIAddresses
			agent.ApiMethod = true
		} else {
			// No API endpoint found — clear the flag so DiscoveryRetrierNG
			// doesn't perpetually retry discovery for a non-existent transport.
			agent.ApiMethod = false
		}
		if result.DNSUri != "" {
			agent.DnsDetails.BaseUri = result.DNSUri
			agent.DnsDetails.ContactInfo = "complete"
			if agent.DnsDetails.State <= AgentStateNeeded {
				agent.DnsDetails.State = AgentStateKnown
			}

			// Extract port from DNS URI for SyncPeerFromAgent
			parsed, err := url.Parse(result.DNSUri)
			if err == nil {
				port := uint16(53) // default DNS port
				if parsed.Port() != "" {
					var p int
					fmt.Sscanf(parsed.Port(), "%d", &p)
					port = uint16(p)
				}
				agent.DnsDetails.Port = port
			}

			// Store JWK data if available (preferred)
			if result.JWKData != "" {
				agent.DnsDetails.JWKData = result.JWKData
				agent.DnsDetails.KeyAlgorithm = result.KeyAlgorithm
			}
			// Store KEY record if using legacy fallback
			agent.DnsDetails.KeyRR = result.LegacyKeyRR
			agent.DnsDetails.Addrs = result.DNSAddresses
			agent.DnsMethod = true
		} else {
			// No DNS endpoint found — clear the flag so DiscoveryRetrierNG
			// doesn't perpetually retry discovery for a non-existent transport.
			agent.DnsMethod = false
		}

		tm.agentRegistry.S.Set(AgentId(result.Identity), agent)
		lgAgent.Debug("also added agent to AgentRegistry", "identity", result.Identity)
	}

	return nil
}

// DiscoverAndRegisterAgent performs discovery and registration in one step.
func (tm *TransportManager) DiscoverAndRegisterAgent(ctx context.Context, identity string) error {
	lgAgent.Info("starting discovery for agent", "identity", identity)

	// Get IMR engine via injected callback (late-binding: IMR starts asynchronously)
	if tm.getImrEngine == nil {
		return fmt.Errorf("IMR engine not configured for this TransportManager")
	}
	imr := tm.getImrEngine()
	if imr == nil {
		return fmt.Errorf("IMR engine not available for discovery (not yet started)")
	}

	result := DiscoverAgent(ctx, imr, identity)
	if result.Error != nil {
		return fmt.Errorf("discovery failed for %s: %w", identity, result.Error)
	}

	if result.Partial {
		lgAgent.Warn("partial discovery (some records missing)", "identity", identity)
	}

	err := tm.RegisterDiscoveredAgent(result)
	if err != nil {
		return fmt.Errorf("failed to register discovered agent %s: %w", identity, err)
	}

	lgAgent.Info("successfully discovered and registered agent", "identity", identity)
	return nil
}
