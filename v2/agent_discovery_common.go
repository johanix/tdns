/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Common DNS lookup helpers for agent discovery.
 * Provides shared functions for looking up agent contact information and keys.
 */

package tdns

import (
	"context"
	"crypto"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// getResolvers returns the configured DNS resolvers for agent discovery.
func getResolvers() []string {
	resolverAddress := viper.GetString("resolver.address")
	if resolverAddress == "" {
		resolverAddress = "8.8.8.8:53"
	}
	return []string{resolverAddress}
}

// lookupAgentJWK looks up JWK record for an agent identity.
// Returns: (jwk-data, public-key, algorithm, error)
//
// The JWK record contains a base64url-encoded JSON Web Key per RFC 7517.
// This function decodes the JWK to a crypto.PublicKey for immediate use.
func lookupAgentJWK(ctx context.Context, identity string) (string, crypto.PublicKey, string, error) {
	identity = dns.Fqdn(identity)
	resolvers := getResolvers()
	timeout := 5 * time.Second
	retries := 2

	log.Printf("AgentDiscovery: Looking up JWK at %s", identity)

	// Query for JWK record
	rrset, err := RecursiveDNSQueryWithServers(identity, core.TypeJWK, timeout, retries, resolvers)
	if err != nil {
		return "", nil, "", fmt.Errorf("JWK query failed for %s: %w", identity, err)
	}

	if rrset == nil || len(rrset.RRs) == 0 {
		return "", nil, "", fmt.Errorf("no JWK record found for %s", identity)
	}

	// Extract JWK record (expecting dns.PrivateRR wrapping our JWK PrivateRdata)
	for _, rr := range rrset.RRs {
		if privateRR, ok := rr.(*dns.PrivateRR); ok {
			if jwk, ok := privateRR.Data.(*core.JWK); ok {
				// Validate JWK data
				if err := core.ValidateJWK(jwk.JWKData); err != nil {
					log.Printf("AgentDiscovery: Invalid JWK data for %s: %v", identity, err)
					continue
				}

				// Decode to public key
				publicKey, algorithm, err := core.DecodeJWKToPublicKey(jwk.JWKData)
				if err != nil {
					log.Printf("AgentDiscovery: Failed to decode JWK for %s: %v", identity, err)
					continue
				}

				log.Printf("AgentDiscovery: Found JWK record for %s (algorithm: %s)", identity, algorithm)
				return jwk.JWKData, publicKey, algorithm, nil
			}
		}
	}

	return "", nil, "", fmt.Errorf("no valid JWK record found for %s", identity)
}

// lookupAgentKEY looks up KEY record for an agent identity (legacy fallback).
// Returns: (key-rr, error)
func lookupAgentKEY(ctx context.Context, identity string) (*dns.KEY, error) {
	identity = dns.Fqdn(identity)
	resolvers := getResolvers()
	timeout := 5 * time.Second
	retries := 2

	log.Printf("AgentDiscovery: Looking up KEY at %s (legacy fallback)", identity)

	keyRRset, err := RecursiveDNSQueryWithServers(identity, dns.TypeKEY, timeout, retries, resolvers)
	if err != nil {
		return nil, fmt.Errorf("KEY query failed for %s: %w", identity, err)
	}

	if keyRRset == nil || len(keyRRset.RRs) == 0 {
		return nil, fmt.Errorf("no KEY record found for %s", identity)
	}

	for _, rr := range keyRRset.RRs {
		if keyRR, ok := rr.(*dns.KEY); ok {
			log.Printf("AgentDiscovery: Found KEY record for %s (algorithm %d)", identity, keyRR.Algorithm)
			return keyRR, nil
		}
	}

	return nil, fmt.Errorf("no valid KEY record found for %s", identity)
}

// lookupAgentAPIEndpoint looks up the API endpoint URI for an agent.
// Queries: _https._tcp.<identity> URI
// Returns: (uri, host, port, error)
func lookupAgentAPIEndpoint(ctx context.Context, identity string) (string, string, uint16, error) {
	identity = dns.Fqdn(identity)
	resolvers := getResolvers()
	timeout := 5 * time.Second
	retries := 2

	apiQname := "_https._tcp." + identity
	log.Printf("AgentDiscovery: Looking up API URI at %s", apiQname)

	apiUriRRset, err := RecursiveDNSQueryWithServers(apiQname, dns.TypeURI, timeout, retries, resolvers)
	if err != nil {
		return "", "", 0, fmt.Errorf("API URI query failed for %s: %w", apiQname, err)
	}

	if apiUriRRset == nil || len(apiUriRRset.RRs) == 0 {
		return "", "", 0, fmt.Errorf("no API URI record found at %s", apiQname)
	}

	for _, rr := range apiUriRRset.RRs {
		if uriRR, ok := rr.(*dns.URI); ok {
			// Parse URI to extract host and port
			parsed, err := url.Parse(uriRR.Target)
			if err != nil {
				log.Printf("AgentDiscovery: Invalid API URI %q: %v", uriRR.Target, err)
				continue
			}

			host := parsed.Hostname()
			port := uint16(443) // default HTTPS port
			if parsed.Port() != "" {
				var p int
				fmt.Sscanf(parsed.Port(), "%d", &p)
				port = uint16(p)
			}

			log.Printf("AgentDiscovery: Found API URI: %s (host: %s, port: %d)", uriRR.Target, host, port)
			return uriRR.Target, host, port, nil
		}
	}

	return "", "", 0, fmt.Errorf("no valid API URI record found at %s", apiQname)
}

// lookupAgentDNSEndpoint looks up the DNS endpoint URI for an agent (optional).
// Queries: _dns._udp.<identity> URI
// Returns: (uri, host, port, error)
func lookupAgentDNSEndpoint(ctx context.Context, identity string) (string, string, uint16, error) {
	identity = dns.Fqdn(identity)
	resolvers := getResolvers()
	timeout := 5 * time.Second
	retries := 2

	dnsQname := "_dns._udp." + identity
	log.Printf("AgentDiscovery: Looking up DNS URI at %s", dnsQname)

	dnsUriRRset, err := RecursiveDNSQueryWithServers(dnsQname, dns.TypeURI, timeout, retries, resolvers)
	if err != nil {
		return "", "", 0, fmt.Errorf("DNS URI query failed for %s: %w", dnsQname, err)
	}

	if dnsUriRRset == nil || len(dnsUriRRset.RRs) == 0 {
		return "", "", 0, fmt.Errorf("no DNS URI record found at %s", dnsQname)
	}

	for _, rr := range dnsUriRRset.RRs {
		if uriRR, ok := rr.(*dns.URI); ok {
			// Parse URI to extract host and port
			parsed, err := url.Parse(uriRR.Target)
			if err != nil {
				log.Printf("AgentDiscovery: Invalid DNS URI %q: %v", uriRR.Target, err)
				continue
			}

			host := parsed.Hostname()
			port := uint16(53) // default DNS port
			if parsed.Port() != "" {
				var p int
				fmt.Sscanf(parsed.Port(), "%d", &p)
				port = uint16(p)
			}

			log.Printf("AgentDiscovery: Found DNS URI: %s (host: %s, port: %d)", uriRR.Target, host, port)
			return uriRR.Target, host, port, nil
		}
	}

	return "", "", 0, fmt.Errorf("no valid DNS URI record found at %s", dnsQname)
}

// lookupAgentTLSA looks up TLSA record for an agent's HTTPS service.
// Queries: _443._tcp.<identity> TLSA
// Returns: (tlsa-rr, error)
func lookupAgentTLSA(ctx context.Context, identity string, port uint16) (*dns.TLSA, error) {
	identity = dns.Fqdn(identity)
	resolvers := getResolvers()
	timeout := 5 * time.Second
	retries := 2

	tlsaQname := fmt.Sprintf("_%d._tcp.%s", port, identity)
	log.Printf("AgentDiscovery: Looking up TLSA at %s", tlsaQname)

	tlsaRRset, err := RecursiveDNSQueryWithServers(tlsaQname, dns.TypeTLSA, timeout, retries, resolvers)
	if err != nil {
		return nil, fmt.Errorf("TLSA query failed for %s: %w", tlsaQname, err)
	}

	if tlsaRRset == nil || len(tlsaRRset.RRs) == 0 {
		return nil, fmt.Errorf("no TLSA record found at %s", tlsaQname)
	}

	for _, rr := range tlsaRRset.RRs {
		if tlsaRR, ok := rr.(*dns.TLSA); ok {
			log.Printf("AgentDiscovery: Found TLSA record at %s (usage %d, selector %d, type %d)",
				tlsaQname, tlsaRR.Usage, tlsaRR.Selector, tlsaRR.MatchingType)
			return tlsaRR, nil
		}
	}

	return nil, fmt.Errorf("no valid TLSA record found at %s", tlsaQname)
}

// lookupAgentAddresses looks up A and AAAA records for an agent.
// Returns: (addresses, error)
func lookupAgentAddresses(ctx context.Context, identity string) ([]string, error) {
	identity = dns.Fqdn(identity)
	resolvers := getResolvers()
	timeout := 5 * time.Second
	retries := 2

	var addresses []string

	log.Printf("AgentDiscovery: Looking up A/AAAA at %s", identity)

	// Query A records
	aRRset, err := RecursiveDNSQueryWithServers(identity, dns.TypeA, timeout, retries, resolvers)
	if err == nil && aRRset != nil {
		for _, rr := range aRRset.RRs {
			if aRR, ok := rr.(*dns.A); ok {
				addresses = append(addresses, aRR.A.String())
			}
		}
	}

	// Query AAAA records
	aaaaRRset, err := RecursiveDNSQueryWithServers(identity, dns.TypeAAAA, timeout, retries, resolvers)
	if err == nil && aaaaRRset != nil {
		for _, rr := range aaaaRRset.RRs {
			if aaaaRR, ok := rr.(*dns.AAAA); ok {
				addresses = append(addresses, aaaaRR.AAAA.String())
			}
		}
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no A/AAAA records found for %s", identity)
	}

	log.Printf("AgentDiscovery: Found %d address(es) for %s: %v", len(addresses), identity, addresses)
	return addresses, nil
}
