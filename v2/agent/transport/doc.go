/*
Package transport provides a unified interface for agent-to-agent communication
in the multi-provider DNSSEC coordination (HSYNC) system.

# Overview

The transport package abstracts the communication layer, allowing the HSYNC
business logic to work identically regardless of whether agents communicate
via HTTPS API or DNS NOTIFY/Query patterns.

# Transport Interface

The Transport interface defines five core operations:

  - Hello: Establishes identity and negotiates capabilities between agents
  - Beat: Maintains the relationship through periodic heartbeats
  - Sync: Synchronizes DNS data (NS, DNSKEY, GLUE, CDS, CSYNC records)
  - Relocate: Requests use of a different address (DDoS mitigation)
  - Confirm: Acknowledges receipt and processing of sync operations

# Implementations

Two transport implementations are provided:

  - APITransport: Uses HTTPS REST API (current/working)
  - DNSTransport: Uses DNS NOTIFY(CHUNK) + Query (Phase 3 stub)

# Zone-Specific Communication

All sync operations are zone-specific. An agent can only make statements about
zones and data under its own control. This is a core security principle:
agents speak only for themselves, not for other providers.

# Peer Management

The Peer struct tracks the state and addresses of remote agents:

  - Discovery address: Found via DNS (URI/SVCB records)
  - Operational address: Private address from Relocate (DDoS mitigation)
  - State machine: NEEDED → KNOWN → INTRODUCING → OPERATIONAL

The PeerRegistry provides thread-safe management of all known peers.

# Example Usage

	// Create API transport
	transport := NewAPITransport(&APITransportConfig{
		LocalID:        "provider-a.example.com",
		DefaultTimeout: 5 * time.Second,
	})

	// Create peer registry
	registry := NewPeerRegistry()
	peer := registry.GetOrCreate("provider-b.example.com")
	peer.SetDiscoveryAddress(&Address{
		Host:      "api.provider-b.example.com",
		Port:      8443,
		Transport: "https",
	})

	// Send hello
	resp, err := transport.Hello(ctx, peer, &HelloRequest{
		SenderID:    "provider-a.example.com",
		SharedZones: []string{"example.com."},
	})
*/
package transport
