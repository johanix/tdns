/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * XoT (XFR-over-TLS, RFC 9103) support: SPKI pinning helpers and the
 * client-side verifying TLS configuration builder.
 */
package tdns

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// PeerConf.Transport values.
const (
	TransportDo53 = "do53"
	TransportDoT  = "dot"
)

// PeerConf.TLSAuth values (how the peer's certificate is authenticated).
const (
	TLSAuthPin  = "pin"  // static SPKI SHA-256 pin(s)
	TLSAuthDANE = "dane" // TLSA at _<port>._tcp.<tls-name>, DNSSEC-validated
	TLSAuthPKIX = "pkix" // CA chain (ca-file, or system roots if empty)
)

// defaultPortForPeer returns the default port implied by the peer's transport:
// 853 for DoT (RFC 7858/9103), 53 otherwise.
func defaultPortForPeer(p PeerConf) string {
	if p.Transport == TransportDoT {
		return "853"
	}
	return "53"
}

// peerUsesDoT reports whether this peer is configured for XFR-over-TLS.
// (Transport is normalized to lowercase by validatePeerXoT at config load.)
func peerUsesDoT(p PeerConf) bool {
	return p.Transport == TransportDoT
}

// peerHostIsIPLiteral reports whether the host part of p.Addr is an IP
// literal (as opposed to a DNS name).
func peerHostIsIPLiteral(p PeerConf) bool {
	host := p.Addr
	if h, _, err := net.SplitHostPort(p.Addr); err == nil {
		host = h
	}
	return net.ParseIP(host) != nil
}

// validatePeerXoT validates (and normalizes in place) the XoT fields of one
// primary entry. Called from the secondary-zone config validation loop; an
// error quarantines the zone. The empty/do53 case must stay cheap and always
// succeed for a plain {addr, key} entry, so pre-XoT configs parse unchanged.
func validatePeerXoT(p *PeerConf) error {
	p.Transport = strings.ToLower(strings.TrimSpace(p.Transport))
	p.TLSAuth = strings.ToLower(strings.TrimSpace(p.TLSAuth))

	switch p.Transport {
	case "", TransportDo53:
		// Plain Do53: the TLS-only knobs are meaningless there — reject
		// loudly rather than silently ignoring a security setting.
		if p.TLSAuth != "" || p.TLSName != "" || len(p.Pins) > 0 || p.CAFile != "" {
			return fmt.Errorf("tls-auth/tls-name/pins/ca-file require transport: dot")
		}
		return nil
	case TransportDoT:
		// validated below
	default:
		return fmt.Errorf("unknown transport %q (supported: do53, dot)", p.Transport)
	}

	switch p.TLSAuth {
	case TLSAuthPin:
		if len(p.Pins) == 0 {
			return fmt.Errorf("tls-auth: pin requires at least one pin in pins:")
		}
		for _, pin := range p.Pins {
			raw, err := base64.StdEncoding.DecodeString(pin)
			if err != nil || len(raw) != sha256.Size {
				return fmt.Errorf("pin %q is not a base64 SHA-256 SPKI digest", pin)
			}
		}
	case TLSAuthDANE:
		// DANE needs a DNS name to form the TLSA base (_<port>._tcp.<name>).
		// A hostname primary provides it implicitly; an IP literal cannot.
		if peerHostIsIPLiteral(*p) && p.TLSName == "" {
			return fmt.Errorf("tls-auth: dane with an IP-literal primary requires tls-name")
		}
	case TLSAuthPKIX:
		// Empty ca-file means system roots. An IP-literal primary without
		// tls-name is allowed: the cert must then carry an IP SAN.
		if p.CAFile != "" {
			if err := checkPEMCertFile(p.CAFile); err != nil {
				return fmt.Errorf("ca-file %q: %v", p.CAFile, err)
			}
		}
	case "":
		return fmt.Errorf("transport: dot requires tls-auth (pin | dane | pkix)")
	default:
		return fmt.Errorf("unknown tls-auth %q (supported: pin, dane, pkix)", p.TLSAuth)
	}
	return nil
}

// checkPEMCertFile verifies that path is readable and contains at least one
// CERTIFICATE PEM block, so a broken ca-file is caught at config load rather
// than at the first transfer attempt.
func checkPEMCertFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "CERTIFICATE" {
			return nil
		}
	}
	return fmt.Errorf("no CERTIFICATE PEM block found")
}

// daneLookupTimeout bounds the TLSA lookup performed inside the TLS handshake
// callback so a slow resolver cannot hang an outbound transfer indefinitely.
const daneLookupTimeout = 5 * time.Second

// ClientTLSConfigForPeer builds the *tls.Config for an outbound XoT connection
// to peer, dispatching certificate verification to the configured tls-auth
// mode. Returns (nil, nil) when the peer is not configured for DoT: the
// caller stays on plain TCP/Do53 (a nil *tls.Config is the Do53 signal
// throughout the transfer path).
func (conf *Config) ClientTLSConfigForPeer(peer PeerConf) (*tls.Config, error) {
	if !peerUsesDoT(peer) {
		return nil, nil
	}

	host, port := splitHostPortDefault(peer.Addr, defaultPortForPeer(peer))
	serverName := peer.TLSName
	if serverName == "" && net.ParseIP(host) == nil {
		serverName = host
	}

	tlsCfg := &tls.Config{
		// SNI: with DANE-EE the name match is not strictly required, but we
		// send it for interop with primaries that vhost on SNI. For an
		// IP-literal peer with no tls-name it stays empty and crypto/tls
		// fills it from the dial address.
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"dot"},
	}

	switch peer.TLSAuth {
	case TLSAuthPin:
		// Pinning replaces PKIX chain building entirely: InsecureSkipVerify
		// disables the default chain+hostname verification and
		// VerifyConnection (which still runs) becomes the sole gate.
		pins := append([]string(nil), peer.Pins...)
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			return verifyPeerCertPins(cs, pins)
		}
	case TLSAuthDANE:
		if serverName == "" {
			// validatePeerXoT enforces this at config load; kept as a
			// backstop for PeerConfs built programmatically.
			return nil, fmt.Errorf("xot: dane peer %s has no DNS name for the TLSA base (set tls-name)", peer.Addr)
		}
		name, lookupPort := serverName, port
		tlsCfg.InsecureSkipVerify = true // DANE-EE replaces PKIX; VerifyConnection is the gate
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			return conf.verifyPeerCertDANE(cs, name, lookupPort)
		}
	case TLSAuthPKIX:
		if peer.CAFile != "" {
			data, err := os.ReadFile(peer.CAFile)
			if err != nil {
				return nil, fmt.Errorf("xot: peer %s: reading ca-file: %v", peer.Addr, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(data) {
				return nil, fmt.Errorf("xot: peer %s: no usable certificates in ca-file %s", peer.Addr, peer.CAFile)
			}
			tlsCfg.RootCAs = pool
		}
		// RootCAs nil = system roots. Standard chain + hostname/IP-SAN
		// verification; no callback needed.
	default:
		return nil, fmt.Errorf("xot: peer %s: unsupported tls-auth %q", peer.Addr, peer.TLSAuth)
	}
	return tlsCfg, nil
}

// verifyPeerCertPins is the VerifyConnection gate for tls-auth: pin. The
// leaf certificate's SPKI SHA-256 must match one of the configured pins.
func verifyPeerCertPins(cs tls.ConnectionState, pins []string) error {
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("xot: peer presented no certificate")
	}
	got := SPKISHA256(cs.PeerCertificates[0])
	for _, want := range pins {
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
			return nil
		}
	}
	return fmt.Errorf("xot: peer SPKI digest %s matches none of the %d configured pin(s)", got, len(pins))
}

// verifyPeerCertDANE is the VerifyConnection gate for tls-auth: dane: the
// leaf certificate must match a TLSA record at _<port>._tcp.<name> obtained
// through a DNSSEC-validated lookup.
func (conf *Config) verifyPeerCertDANE(cs tls.ConnectionState, name, port string) error {
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("xot: peer presented no certificate")
	}
	leaf := cs.PeerCertificates[0]
	rrset, err := conf.lookupTLSAValidated(name, port)
	if err != nil {
		return err
	}
	for _, rr := range rrset.RRs {
		tlsa, ok := rr.(*dns.TLSA)
		if !ok {
			continue
		}
		if err := VerifyCertAgainstTlsaRR(tlsa, leaf); err == nil {
			return nil
		}
	}
	return fmt.Errorf("xot: no TLSA record at _%s._tcp.%s matches the peer certificate", port, name)
}

// lookupTLSAValidated returns the TLSA RRset at _<port>._tcp.<name>. DANE over
// an unvalidated lookup is meaningless, so this fails closed: no IMR, lookup
// failure, or a not-secure validation state are all errors. The per-server
// TLSA cache (populated, with validation state, by SVCB/TSYNC discovery and
// direct TLSA answers) is consulted first; otherwise the RRset is fetched and
// validated through the in-process IMR. The imr.RequireDnssecValidation
// lab-mode escape hatch (config: imrengine.require_dnssec_validation) is
// honored, with a loud warning, to match how the rest of tdns treats TLSA.
func (conf *Config) lookupTLSAValidated(name, port string) (*core.RRset, error) {
	imr := conf.Internal.ImrEngine
	if imr == nil {
		return nil, fmt.Errorf("xot: tls-auth dane requires the built-in IMR to be active")
	}
	fqdn := dns.Fqdn(name)
	owner := fmt.Sprintf("_%s._tcp.%s", port, fqdn)

	requireSecure := imr.RequireDnssecValidation
	acceptState := func(state cache.ValidationState) bool {
		if state == cache.ValidationStateSecure {
			return true
		}
		if !requireSecure {
			lg.Warn("xot: accepting non-secure TLSA RRset because require_dnssec_validation is disabled (lab mode)", "owner", owner, "state", cache.ValidationStateToString[state])
			return true
		}
		return false
	}

	if cr := imr.Cache.LookupTLSAForServer(fqdn, owner); cr != nil && cr.RRset != nil && len(cr.RRset.RRs) > 0 && acceptState(cr.State) {
		return cr.RRset, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), daneLookupTimeout)
	defer cancel()
	rrset, err := imr.DefaultRRsetFetcher(ctx, owner, dns.TypeTLSA)
	if err != nil {
		return nil, fmt.Errorf("xot: TLSA lookup for %s failed: %v", owner, err)
	}
	vstate, err := imr.Cache.ValidateRRsetWithParentZone(ctx, rrset, imr.IterativeDNSQueryFetcher(), imr.ParentZone)
	if err != nil {
		return nil, fmt.Errorf("xot: TLSA validation for %s failed: %v", owner, err)
	}
	if !acceptState(vstate) {
		return nil, fmt.Errorf("xot: TLSA RRset for %s is not DNSSEC-secure (state %s); refusing DANE (fail closed)", owner, cache.ValidationStateToString[vstate])
	}
	return rrset, nil
}

// SPKISHA256 returns the base64 (standard encoding) SHA-256 digest of the
// certificate's SubjectPublicKeyInfo. This is the value used for static
// certificate pinning (tls-auth: pin) and matches the digest carried in a
// TLSA 3-1-1 record (which encodes the same bytes in hex).
func SPKISHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}
