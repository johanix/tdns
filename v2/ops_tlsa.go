/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func (zd *ZoneData) PublishTlsaRR(name string, port uint16, certPEM string) error {
	lgHandler.Debug("PublishTlsaRR: received request to publish TLSA record", "name", name, "port", port)

	// The owner must be at or below the zone apex, checked on LABEL boundaries:
	// a bare strings.HasSuffix accepts "notexample.com." for zone "example.com."
	// (suffix match across a label), which would inject an out-of-zone owner.
	// dns.IsSubDomain compares whole labels (and is case-insensitive).
	if !dns.IsSubDomain(dns.Fqdn(zd.ZoneName), dns.Fqdn(name)) {
		return fmt.Errorf("PublishTlsaRR: name %q is not a subdomain of %q", name, zd.ZoneName)
	}

	cert, err := parseCertificate(certPEM)
	if err != nil {
		return err
	}

	tlsa, err := NewTlsaRR(name, port, cert)
	if err != nil {
		return err
	}

	lgHandler.Info("PublishTlsaRR: publishing TLSA RR", "rr", tlsa.String())

	if zd.KeyDB.UpdateQ == nil {
		return fmt.Errorf("PublishTlsaRR: KeyDB.UpdateQ is nil")
	}

	// A set that already is this record alone, with this TTL, and signed
	// where the zone signs, is left as it is: replacing it would only
	// re-sign it, and a signing failure then would leave it unsigned. One
	// served unsigned in a signing zone is replaced, which signs it again.
	// core.IsDuplicate: the stored record may spell its hex in another case.
	// zd.Options is replaced under zd.mu on a reload; read it there, and
	// let go before the zone is read. Only if no other record was asked for
	// since: one queued and not yet served would otherwise land after this
	// request was skipped, and the record last asked for would be gone.
	// The lock is held until the update is queued: the queue then holds
	// publications in the order they were asked for.
	owner := dns.CanonicalName(tlsa.Hdr.Name)
	zd.tlsaPublishMu.Lock()
	defer zd.tlsaPublishMu.Unlock()
	prev, asked := zd.tlsaRequested[owner]
	if zd.tlsaRequested == nil {
		zd.tlsaRequested = make(map[string]dns.RR)
	}
	zd.tlsaRequested[owner] = dns.Copy(tlsa)
	lastAsked := !asked || (core.IsDuplicate(prev, tlsa) && prev.Header().Ttl == tlsa.Hdr.Ttl)
	zd.mu.Lock()
	signs := zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning]
	zd.mu.Unlock()
	if cur, err := zd.GetRRset(tlsa.Hdr.Name, dns.TypeTLSA); err == nil && cur != nil && lastAsked &&
		len(cur.RRs) == 1 && core.IsDuplicate(cur.RRs[0], tlsa) && cur.RRs[0].Header().Ttl == tlsa.Hdr.Ttl &&
		(!signs || len(cur.RRSIGs) > 0) {
		lgHandler.Debug("PublishTlsaRR: the TLSA RRset already is this record", "rr", tlsa.String())
		return nil
	}

	// Replace the RRset, not add to it: a certificate passes when it
	// matches any record of the set, so a record left from the last
	// certificate would stay trusted after a rollover.
	zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{tlsaDeleteRR(tlsa.Hdr.Name), tlsa},
		InternalUpdate: true,
	}

	return nil
}

// tlsaDeleteRR is the update-section delete of the whole TLSA RRset at
// owner (RFC 2136 2.5.2).
func tlsaDeleteRR(owner string) dns.RR {
	return &dns.ANY{Hdr: dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeTLSA, Class: dns.ClassANY, Ttl: 0}}
}

// NewTlsaRR builds a DANE-EE / SPKI / SHA-256 ("3 1 1") TLSA record for the
// given service name and port. The certificate association data is the SHA-256
// digest of the SubjectPublicKeyInfo, per the advertised Selector.
func NewTlsaRR(name string, port uint16, cert *x509.Certificate) (*dns.TLSA, error) {
	data, err := tlsaSelectorBytes(cert, 1)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)

	tlsa := &dns.TLSA{
		Usage:        3, // DANE-EE
		Selector:     1, // SPKI
		MatchingType: 1, // SHA-256
		Certificate:  hex.EncodeToString(hash[:]),
	}
	tlsa.Hdr = dns.RR_Header{
		Name:   fmt.Sprintf("_%d._tcp.%s", port, name),
		Rrtype: dns.TypeTLSA,
		Class:  dns.ClassINET,
		Ttl:    120,
	}
	return tlsa, nil
}

func parseCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM data")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected PEM block type: %s (expected CERTIFICATE)", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}
	return cert, nil
}

// tlsaSelectorBytes returns the certificate bytes that a TLSA record's
// Selector field says the association data is computed over.
func tlsaSelectorBytes(cert *x509.Certificate, selector uint8) ([]byte, error) {
	switch selector {
	case 0: // full certificate
		return cert.Raw, nil
	case 1: // SubjectPublicKeyInfo
		return cert.RawSubjectPublicKeyInfo, nil
	default:
		return nil, fmt.Errorf("unsupported TLSA selector: %d", selector)
	}
}

func (zd *ZoneData) UnpublishTlsaRR(port uint16) error {
	anti_tlsa_rr, err := dns.NewRR(fmt.Sprintf("_%d._tcp.%s 0 IN TLSA 3 1 1 %s", port, zd.ZoneName, "example_certificate_data"))
	if err != nil {
		return err
	}
	anti_tlsa_rr.Header().Class = dns.ClassANY // XXX: dns.NewRR fails to parse a CLASS ANY TLSA RRset, so we set the class manually.

	if zd.KeyDB.UpdateQ == nil {
		return fmt.Errorf("UnpublishTlsaRR: KeyDB.UpdateQ is nil")
	}

	zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{anti_tlsa_rr},
		InternalUpdate: true,
	}

	return nil
}

func LookupTlsaRR(name string) (*core.RRset, error) {
	rrset, err := RecursiveDNSQueryWithConfig(dns.Fqdn(name), dns.TypeTLSA, 3*time.Second, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup %s TLSA record: %v", name, err)
	}
	if len(rrset.RRs) == 0 {
		return nil, fmt.Errorf("no %s TLSA records found", name)
	}
	return rrset, nil
}

// VerifyCertAgainstTlsaRR checks a presented certificate against one TLSA
// record. Only usage 3 (DANE-EE) is supported. The Selector field decides
// which certificate bytes the association data is computed over (0 = full
// cert, 1 = SPKI); taking the parsed certificate (rather than raw bytes)
// ensures the caller cannot hash the wrong form.
func VerifyCertAgainstTlsaRR(tlsarr *dns.TLSA, cert *x509.Certificate) error {
	decodedCert, err := hex.DecodeString(tlsarr.Certificate)
	if err != nil {
		return fmt.Errorf("failed to decode TLSA certificate: %v", err)
	}
	if tlsarr.Usage != 3 {
		return fmt.Errorf("only TLSA usage 3 is supported (this TLSA has usage %d)", tlsarr.Usage)
	}
	data, err := tlsaSelectorBytes(cert, tlsarr.Selector)
	if err != nil {
		return err
	}
	switch tlsarr.MatchingType {
	case 1: // SHA-256
		hash := sha256.Sum256(data)
		if subtle.ConstantTimeCompare(hash[:], decodedCert) == 1 {
			return nil
		}
	case 2: // SHA-512
		hash := sha512.Sum512(data)
		if subtle.ConstantTimeCompare(hash[:], decodedCert) == 1 {
			return nil
		}
	default:
		return fmt.Errorf("unsupported TLSA matching type: %d", tlsarr.MatchingType)
	}
	return fmt.Errorf("TLSA RR %s did not match cert", tlsarr.String())
}
