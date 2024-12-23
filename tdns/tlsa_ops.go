/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/miekg/dns"
)

func (zd *ZoneData) PublishTLSARR(certPEM string, port uint16) error {
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
		Name:   fmt.Sprintf("_%d._tcp.%s", port, zd.ZoneName),
		Rrtype: dns.TypeTLSA,
		Class:  dns.ClassINET,
		Ttl:    120,
	}

	log.Printf("PublishTLSARR: publishing TLSA RR: %s", tlsa.String())

	if zd.KeyDB.UpdateQ == nil {
		return fmt.Errorf("PublishTLSARR: KeyDB.UpdateQ is nil")
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

	spkiASN1, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %v", err)
	}

	hash := sha256.Sum256(spkiASN1)
	return hex.EncodeToString(hash[:]), nil
}

func (zd *ZoneData) UnpublishTLSARR() error {
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

func LookupTLSA(name string) (*RRset, error) {
	clientConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("failed to load DNS client configuration: %v", err)
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeTLSA)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, clientConfig.Servers[0]+":53")
	if err != nil {
		return nil, fmt.Errorf("failed to lookup %s TLSA record: %v", name, err)
	}
	if len(r.Answer) == 0 {
		return nil, fmt.Errorf("no %s TLSA records found", name)
	}

	// var tlsaRecords []*dns.TLSA
	var rrset RRset
	for _, ans := range r.Answer {
		if tlsa, ok := ans.(*dns.TLSA); ok {
			rrset.RRs = append(rrset.RRs, tlsa)
			continue
		}
		if rrsig, ok := ans.(*dns.RRSIG); ok {
			if rrsig.TypeCovered == dns.TypeTLSA {
				rrset.RRSIGs = append(rrset.RRSIGs, rrsig)
			}
			continue
		}
	}
	return &rrset, nil
}

func VerifyCertAgainstTLSA(tlsarrset *RRset, rawcert []byte) error {
	for _, rr := range tlsarrset.RRs {
		tlsarr, ok := rr.(*dns.TLSA)
		if !ok {
			continue
		}
		if tlsarr.Usage == 3 {
			switch tlsarr.MatchingType {
			case 1: // SHA-256
				hash := sha256.Sum256(rawcert)
				if bytes.Equal(hash[:], []byte(tlsarr.Certificate)) {
					return nil
				}
			case 2: // SHA-512
				hash := sha512.Sum512(rawcert)
				if bytes.Equal(hash[:], []byte(tlsarr.Certificate)) {
					return nil
				}
			}
		}
	}
	return nil
}
