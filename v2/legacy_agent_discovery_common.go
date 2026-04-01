/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Common DNS lookup helpers for agent discovery.
 * Provides shared IMR-based functions for looking up agent contact information and keys.
 */

package tdns

import (
	"context"
	"crypto"
	"fmt"
	"net/url"
	"strconv"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// LookupAgentJWK looks up JWK record for an agent identity using the IMR engine.
// Returns: (jwk-data, public-key, algorithm, error)
//
// The JWK record contains a base64url-encoded JSON Web Key per RFC 7517.
// This function decodes the JWK to a crypto.PublicKey for immediate use.
//
// The JWK record is published at dns.<identity> following DNS transport naming conventions.
func (imr *Imr) LookupAgentJWK(ctx context.Context, identity string) (string, crypto.PublicKey, string, error) {
	identity = dns.Fqdn(identity)

	// JWK records are published at dns.<identity> (with DNS transport records)
	jwkQname := "dns." + identity
	lgAgent.Debug("looking up JWK", "qname", jwkQname)

	// Query for JWK record using IMR
	resp, err := imr.ImrQuery(ctx, jwkQname, core.TypeJWK, dns.ClassINET, nil)
	if err != nil {
		return "", nil, "", fmt.Errorf("JWK query failed for %s: %w", jwkQname, err)
	}

	if resp.Error {
		return "", nil, "", fmt.Errorf("JWK query error for %s: %s", jwkQname, resp.ErrorMsg)
	}

	if resp.RRset == nil || len(resp.RRset.RRs) == 0 {
		return "", nil, "", fmt.Errorf("no JWK record found at %s", jwkQname)
	}

	// Extract JWK record (expecting dns.PrivateRR wrapping our JWK PrivateRdata)
	for _, rr := range resp.RRset.RRs {
		if privateRR, ok := rr.(*dns.PrivateRR); ok {
			if jwk, ok := privateRR.Data.(*core.JWK); ok {
				// Validate JWK data
				if err := core.ValidateJWK(jwk.JWKData); err != nil {
					lgAgent.Warn("invalid JWK data", "qname", jwkQname, "err", err)
					continue
				}

				// Decode to public key
				publicKey, algorithm, err := core.DecodeJWKToPublicKey(jwk.JWKData)
				if err != nil {
					lgAgent.Warn("failed to decode JWK", "qname", jwkQname, "err", err)
					continue
				}

				lgAgent.Debug("found JWK record", "qname", jwkQname, "algorithm", algorithm)
				return jwk.JWKData, publicKey, algorithm, nil
			}
		}
	}

	return "", nil, "", fmt.Errorf("no valid JWK record found at %s", jwkQname)
}

// LookupAgentKEY looks up KEY record for an agent identity (legacy fallback) using the IMR engine.
// Returns: (key-rr, error)
func (imr *Imr) LookupAgentKEY(ctx context.Context, identity string) (*dns.KEY, error) {
	identity = dns.Fqdn(identity)

	lgAgent.Debug("looking up KEY (legacy fallback)", "identity", identity)

	resp, err := imr.ImrQuery(ctx, identity, dns.TypeKEY, dns.ClassINET, nil)
	if err != nil {
		return nil, fmt.Errorf("KEY query failed for %s: %w", identity, err)
	}

	if resp.Error {
		return nil, fmt.Errorf("KEY query error for %s: %s", identity, resp.ErrorMsg)
	}

	if resp.RRset == nil || len(resp.RRset.RRs) == 0 {
		return nil, fmt.Errorf("no KEY record found for %s", identity)
	}

	for _, rr := range resp.RRset.RRs {
		if keyRR, ok := rr.(*dns.KEY); ok {
			lgAgent.Debug("found KEY record", "identity", identity, "algorithm", keyRR.Algorithm)
			return keyRR, nil
		}
	}

	return nil, fmt.Errorf("no valid KEY record found for %s", identity)
}

// LookupAgentAPIEndpoint looks up the API endpoint URI for an agent using the IMR engine.
// Queries: _https._tcp.<identity> URI
// Returns: (uri, host, port, error)
func (imr *Imr) LookupAgentAPIEndpoint(ctx context.Context, identity string) (string, string, uint16, error) {
	identity = dns.Fqdn(identity)

	apiQname := "_https._tcp." + identity
	lgAgent.Debug("looking up API URI", "qname", apiQname)

	resp, err := imr.ImrQuery(ctx, apiQname, dns.TypeURI, dns.ClassINET, nil)
	if err != nil {
		return "", "", 0, fmt.Errorf("API URI query failed for %s: %w", apiQname, err)
	}

	if resp.Error {
		return "", "", 0, fmt.Errorf("API URI query error for %s: %s", apiQname, resp.ErrorMsg)
	}

	if resp.RRset == nil || len(resp.RRset.RRs) == 0 {
		return "", "", 0, fmt.Errorf("no API URI record found at %s", apiQname)
	}

	for _, rr := range resp.RRset.RRs {
		if uriRR, ok := rr.(*dns.URI); ok {
			// Parse URI to extract host and port
			parsed, err := url.Parse(uriRR.Target)
			if err != nil {
				lgAgent.Warn("invalid API URI", "uri", uriRR.Target, "err", err)
				continue
			}

			host := parsed.Hostname()
			port := uint16(443) // default HTTPS port
			if parsed.Port() != "" {
				p, err := strconv.Atoi(parsed.Port())
				if err != nil || p < 1 || p > 65535 {
					lgAgent.Warn("invalid port in API URI, skipping", "uri", uriRR.Target, "port", parsed.Port())
					continue
				}
				port = uint16(p)
			}

			lgAgent.Debug("found API URI", "uri", uriRR.Target, "host", host, "port", port)
			return uriRR.Target, host, port, nil
		}
	}

	return "", "", 0, fmt.Errorf("no valid API URI record found at %s", apiQname)
}

// LookupAgentDNSEndpoint looks up the DNS endpoint URI for an agent (optional) using the IMR engine.
// Queries: _dns._tcp.<identity> URI
// Returns: (uri, host, port, error)
func (imr *Imr) LookupAgentDNSEndpoint(ctx context.Context, identity string) (string, string, uint16, error) {
	identity = dns.Fqdn(identity)

	dnsQname := "_dns._tcp." + identity
	lgAgent.Debug("looking up DNS URI", "qname", dnsQname)

	resp, err := imr.ImrQuery(ctx, dnsQname, dns.TypeURI, dns.ClassINET, nil)
	if err != nil {
		return "", "", 0, fmt.Errorf("DNS URI query failed for %s: %w", dnsQname, err)
	}

	if resp.Error {
		return "", "", 0, fmt.Errorf("DNS URI query error for %s: %s", dnsQname, resp.ErrorMsg)
	}

	if resp.RRset == nil || len(resp.RRset.RRs) == 0 {
		return "", "", 0, fmt.Errorf("no DNS URI record found at %s", dnsQname)
	}

	for _, rr := range resp.RRset.RRs {
		if uriRR, ok := rr.(*dns.URI); ok {
			// Parse URI to extract host and port
			parsed, err := url.Parse(uriRR.Target)
			if err != nil {
				lgAgent.Warn("invalid DNS URI", "uri", uriRR.Target, "err", err)
				continue
			}

			host := parsed.Hostname()
			port := uint16(53) // default DNS port
			if parsed.Port() != "" {
				p, err := strconv.Atoi(parsed.Port())
				if err != nil || p < 1 || p > 65535 {
					lgAgent.Warn("invalid port in DNS URI, skipping", "uri", uriRR.Target, "port", parsed.Port())
					continue
				}
				port = uint16(p)
			}

			lgAgent.Debug("found DNS URI", "uri", uriRR.Target, "host", host, "port", port)
			return uriRR.Target, host, port, nil
		}
	}

	return "", "", 0, fmt.Errorf("no valid DNS URI record found at %s", dnsQname)
}

// LookupAgentTLSA looks up TLSA record for an agent's HTTPS service using the IMR engine.
// Queries: _<port>._tcp.<identity> TLSA
// Returns: (tlsa-rr, error)
func (imr *Imr) LookupAgentTLSA(ctx context.Context, identity string, port uint16) (*dns.TLSA, error) {
	identity = dns.Fqdn(identity)

	tlsaQname := fmt.Sprintf("_%d._tcp.%s", port, identity)
	lgAgent.Debug("looking up TLSA", "qname", tlsaQname)

	resp, err := imr.ImrQuery(ctx, tlsaQname, dns.TypeTLSA, dns.ClassINET, nil)
	if err != nil {
		return nil, fmt.Errorf("TLSA query failed for %s: %w", tlsaQname, err)
	}

	if resp.Error {
		return nil, fmt.Errorf("TLSA query error for %s: %s", tlsaQname, resp.ErrorMsg)
	}

	if resp.RRset == nil || len(resp.RRset.RRs) == 0 {
		return nil, fmt.Errorf("no TLSA record found at %s", tlsaQname)
	}

	for _, rr := range resp.RRset.RRs {
		if tlsaRR, ok := rr.(*dns.TLSA); ok {
			lgAgent.Debug("found TLSA record", "qname", tlsaQname,
				"usage", tlsaRR.Usage, "selector", tlsaRR.Selector, "matchingType", tlsaRR.MatchingType,
				"validated", resp.Validated)
			if imr.RequireDnssecValidation && !resp.Validated {
				return nil, fmt.Errorf("TLSA record at %s has unvalidated DNSSEC state (require_dnssec_validation=true)", tlsaQname)
			}
			return tlsaRR, nil
		}
	}

	return nil, fmt.Errorf("no valid TLSA record found at %s", tlsaQname)
}

// LookupServiceAddresses looks up SVCB record for a service name using the IMR engine.
// Queries SVCB at the service name (e.g., dns.<identity> or api.<identity>).
// Returns: (addresses, error) - addresses extracted from ipv4hint and ipv6hint parameters
func (imr *Imr) LookupServiceAddresses(ctx context.Context, serviceName string) ([]string, error) {
	serviceName = dns.Fqdn(serviceName)

	var addresses []string

	lgAgent.Debug("looking up SVCB", "service", serviceName)

	// Query SVCB record
	resp, err := imr.ImrQuery(ctx, serviceName, dns.TypeSVCB, dns.ClassINET, nil)
	if err != nil {
		return nil, fmt.Errorf("SVCB query failed for %s: %w", serviceName, err)
	}

	if resp.Error {
		return nil, fmt.Errorf("SVCB query error for %s: %s", serviceName, resp.ErrorMsg)
	}

	if resp.RRset == nil || len(resp.RRset.RRs) == 0 {
		return nil, fmt.Errorf("no SVCB record found at %s", serviceName)
	}

	// Extract addresses from SVCB ipv4hint and ipv6hint parameters
	for _, rr := range resp.RRset.RRs {
		if svcbRR, ok := rr.(*dns.SVCB); ok {
			// Extract IPv4 addresses from ipv4hint
			for _, kv := range svcbRR.Value {
				if kv.Key() == dns.SVCB_IPV4HINT {
					if ipv4hint, ok := kv.(*dns.SVCBIPv4Hint); ok {
						for _, ip := range ipv4hint.Hint {
							addresses = append(addresses, ip.String())
						}
					}
				}
				// Extract IPv6 addresses from ipv6hint
				if kv.Key() == dns.SVCB_IPV6HINT {
					if ipv6hint, ok := kv.(*dns.SVCBIPv6Hint); ok {
						for _, ip := range ipv6hint.Hint {
							addresses = append(addresses, ip.String())
						}
					}
				}
			}
		}
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no IP hints found in SVCB record at %s", serviceName)
	}

	lgAgent.Debug("found addresses from SVCB", "count", len(addresses), "service", serviceName, "addresses", addresses)
	return addresses, nil
}
