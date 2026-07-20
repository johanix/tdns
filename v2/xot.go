/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * XoT (XFR-over-TLS, RFC 9103) support: SPKI pinning helpers and the
 * client-side verifying TLS configuration builder.
 */
package tdns

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
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

// SPKISHA256 returns the base64 (standard encoding) SHA-256 digest of the
// certificate's SubjectPublicKeyInfo. This is the value used for static
// certificate pinning (tls-auth: pin) and matches the digest carried in a
// TLSA 3-1-1 record (which encodes the same bytes in hex).
func SPKISHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}
