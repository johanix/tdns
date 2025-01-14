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
	"log"
	"time"

	"github.com/miekg/dns"
)

func (zd *ZoneData) PublishTlsaRR(name string, port uint16, certPEM string) error {
	certData, err := parseCertificate(certPEM)
	if err != nil {
		return err
	}

	tlsa := dns.TLSA{
		Usage:        3, // DANE-EE
		Selector:     1, // SPKI
		MatchingType: 1, // SHA-256
		Certificate:  certData,
	}
	tlsa.Hdr = dns.RR_Header{
		Name:   fmt.Sprintf("_%d._tcp.%s", port, name),
		Rrtype: dns.TypeTLSA,
		Class:  dns.ClassINET,
		Ttl:    120,
	}

	log.Printf("PublishTlsaRR: publishing TLSA RR: %s", tlsa.String())

	if zd.KeyDB.UpdateQ == nil {
		return fmt.Errorf("PublishTlsaRR: KeyDB.UpdateQ is nil")
	}

	zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{&tlsa},
		InternalUpdate: true,
	}

	return nil
}

func parseCertificate(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Use the entire certificate for hashing instead of just the public key
	hash := sha256.Sum256(cert.Raw)
	// log.Printf("parseCertificate: hash: %s", hex.EncodeToString(hash[:]))
	return hex.EncodeToString(hash[:]), nil
}

func (zd *ZoneData) UnpublishTlsaRR() error {
	anti_tlsa_rr, err := dns.NewRR(fmt.Sprintf("_443._tcp.%s 0 IN TLSA 3 1 1 %s", zd.ZoneName, "example_certificate_data"))
	if err != nil {
		return err
	}
	anti_tlsa_rr.Header().Class = dns.ClassANY // XXX: dns.NewRR fails to parse a CLASS ANY TLSA RRset, so we set the class manually.

	zd.KeyDB.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{anti_tlsa_rr},
		InternalUpdate: true,
	}

	return nil
}

func LookupTlsaRR(name string) (*RRset, error) {
	rrset, err := RecursiveDNSQueryWithConfig(dns.Fqdn(name), dns.TypeTLSA, 3*time.Second, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup %s TLSA record: %v", name, err)
	}
	if len(rrset.RRs) == 0 {
		return nil, fmt.Errorf("no %s TLSA records found", name)
	}
	return rrset, nil
}

func VerifyCertAgainstTlsaRR(tlsarr *dns.TLSA, rawcert []byte) error {
	decodedCert, err := hex.DecodeString(tlsarr.Certificate)
	if err != nil {
		return fmt.Errorf("failed to decode TLSA certificate: %v", err)
	}
	switch tlsarr.Usage {
	case 3:
		switch tlsarr.MatchingType {
		case 1: // SHA-256
			hash := sha256.Sum256(rawcert)
			if subtle.ConstantTimeCompare(hash[:], decodedCert) == 1 {
				return nil
			}
		case 2: // SHA-512
			hash := sha512.Sum512(rawcert)
			if subtle.ConstantTimeCompare(hash[:], decodedCert) == 1 {
				return nil
			}
		default:
			return fmt.Errorf("unsupported TLSA matching type: %d", tlsarr.MatchingType)
		}
	default:
		return fmt.Errorf("only TLSA usage 3 is supported (this TLSA has usage %d)", tlsarr.Usage)
	}
	return fmt.Errorf("TLSA RR %s did not match cert", tlsarr.String())
}
