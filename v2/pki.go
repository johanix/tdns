/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Minimal internal PKI for XoT provisioning (docs/2026-07-21-pkix-cert-
 * tooling-design.md): mint a private root, sign server/client leaves, and
 * round-trip CSRs. Deliberately tiny scope — no CRL/OCSP/renewal, no CA
 * database (serials are random 128-bit), hard-coded safe constraints
 * (pathlen 0 on the CA, IsCA=false on leaves). File handling and the
 * issued.log live in the CLI layer (v2/cli/cert_cmds.go); this file is
 * pure crypto so the XoT tests can verify the tool's output directly.
 */
package tdns

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// CertAlgorithm selects the key algorithm for CA and leaf keys.
type CertAlgorithm string

const (
	CertAlgEd25519   CertAlgorithm = "ed25519" // default: smallest/fastest, fine for TLS 1.3
	CertAlgECDSAP256 CertAlgorithm = "ecdsa-p256"
	CertAlgRSA2048   CertAlgorithm = "rsa2048"
)

const (
	// DefaultCAValidity: a private root can be long-lived.
	DefaultCAValidity = 3650 * 24 * time.Hour
	// DefaultLeafValidity: 397 days, the CA/Browser cap — a sane habit even
	// for a private CA.
	DefaultLeafValidity = 397 * 24 * time.Hour
)

// PKICert bundles the PEM artifacts and parsed certificate produced by
// CreateCA / IssueLeaf.
type PKICert struct {
	CertPEM []byte
	KeyPEM  []byte // PKCS#8; empty for SignCSR results (the key stays remote)
	Cert    *x509.Certificate
}

type CAOptions struct {
	Name     string // Subject CN
	Validity time.Duration
	Alg      CertAlgorithm
}

type LeafOptions struct {
	Name     string // Subject CN
	DNSNames []string
	IPs      []net.IP
	Server   bool // ExtKeyUsage serverAuth
	Client   bool // ExtKeyUsage clientAuth
	Validity time.Duration
	Alg      CertAlgorithm
}

type CSROptions struct {
	Name     string
	DNSNames []string
	IPs      []net.IP
	Alg      CertAlgorithm
}

type SignOptions struct {
	Server   bool
	Client   bool
	Validity time.Duration
}

// CreateCA mints a self-signed root: pathlen 0 (signs leaves only, never a
// sub-CA), KeyUsage CertSign|CRLSign.
func CreateCA(opts CAOptions) (*PKICert, error) {
	if opts.Name == "" {
		return nil, fmt.Errorf("pki: CA needs a name")
	}
	if opts.Validity == 0 {
		opts.Validity = DefaultCAValidity
	}
	key, err := generateKey(opts.Alg)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: opts.Name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(opts.Validity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("pki: create CA certificate: %v", err)
	}
	return assemblePKICert(der, key)
}

// IssueLeaf signs an end-entity certificate (freshly generated key) with the
// CA. At least one of Server/Client must be set; a daemon that both serves
// DoT and presents a client cert for mutual XoT wants both.
func IssueLeaf(caCert *x509.Certificate, caKey crypto.Signer, opts LeafOptions) (*PKICert, error) {
	if opts.Name == "" {
		return nil, fmt.Errorf("pki: leaf needs a name")
	}
	if !opts.Server && !opts.Client {
		return nil, fmt.Errorf("pki: leaf needs at least one of server/client usage")
	}
	if opts.Validity == 0 {
		opts.Validity = DefaultLeafValidity
	}
	key, err := generateKey(opts.Alg)
	if err != nil {
		return nil, err
	}
	tmpl, err := leafTemplate(opts.Name, opts.DNSNames, opts.IPs, opts.Server, opts.Client, opts.Validity)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, key.Public(), caKey)
	if err != nil {
		return nil, fmt.Errorf("pki: sign leaf certificate: %v", err)
	}
	return assemblePKICert(der, key)
}

// CreateCSR generates a fresh key plus a certificate signing request — the
// split-provisioning path where the private key never leaves the requesting
// host.
func CreateCSR(opts CSROptions) (csrPEM, keyPEM []byte, err error) {
	if opts.Name == "" {
		return nil, nil, fmt.Errorf("pki: CSR needs a name")
	}
	key, err := generateKey(opts.Alg)
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: opts.Name},
		DNSNames:    opts.DNSNames,
		IPAddresses: opts.IPs,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: create CSR: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// SignCSR signs a parsed-and-verified CSR with the CA, copying the CSR's
// subject and SANs. The resulting PKICert carries no key (it stayed with the
// requester).
func SignCSR(caCert *x509.Certificate, caKey crypto.Signer, csrPEM []byte, opts SignOptions) (*PKICert, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("pki: no CERTIFICATE REQUEST block found")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: CSR signature check failed: %v", err)
	}
	if !opts.Server && !opts.Client {
		return nil, fmt.Errorf("pki: sign needs at least one of server/client usage")
	}
	if opts.Validity == 0 {
		opts.Validity = DefaultLeafValidity
	}
	tmpl, err := leafTemplate(csr.Subject.CommonName, csr.DNSNames, csr.IPAddresses, opts.Server, opts.Client, opts.Validity)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("pki: sign CSR: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &PKICert{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Cert:    cert,
	}, nil
}

// ParseCertPEM parses the first CERTIFICATE block in data.
func ParseCertPEM(data []byte) (*x509.Certificate, error) {
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
	return nil, fmt.Errorf("pki: no CERTIFICATE block found")
}

// ParsePrivateKeyPEM parses a PKCS#8 PRIVATE KEY block into a crypto.Signer.
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "PRIVATE KEY" {
			continue
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pki: parse PKCS#8 key: %v", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("pki: key type %T is not a signer", key)
		}
		return signer, nil
	}
	return nil, fmt.Errorf("pki: no PRIVATE KEY block found")
}

func leafTemplate(name string, dnsNames []string, ips []net.IP, server, client bool, validity time.Duration) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	var ekus []x509.ExtKeyUsage
	if server {
		ekus = append(ekus, x509.ExtKeyUsageServerAuth)
	}
	if client {
		ekus = append(ekus, x509.ExtKeyUsageClientAuth)
	}
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validity),
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           ekus,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}, nil
}

func generateKey(alg CertAlgorithm) (crypto.Signer, error) {
	switch alg {
	case "", CertAlgEd25519:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	case CertAlgECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case CertAlgRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("pki: unknown algorithm %q (supported: ed25519, ecdsa-p256, rsa2048)", alg)
	}
}

// randomSerial returns a random 128-bit serial — the reason this CA needs no
// serial-file state.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("pki: generate serial: %v", err)
	}
	return serial, nil
}

func assemblePKICert(der []byte, key crypto.Signer) (*PKICert, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal key: %v", err)
	}
	return &PKICert{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		Cert:    cert,
	}, nil
}
