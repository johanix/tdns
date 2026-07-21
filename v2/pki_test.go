/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"testing"

	cache "github.com/johanix/tdns/v2/cache"
)

func testCA(t *testing.T, alg CertAlgorithm) *PKICert {
	t.Helper()
	ca, err := CreateCA(CAOptions{Name: "test-ca", Alg: alg})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	return ca
}

func TestPKI_CACreation(t *testing.T) {
	ca := testCA(t, "")
	if !ca.Cert.IsCA {
		t.Fatal("CA cert must have IsCA")
	}
	if !ca.Cert.MaxPathLenZero || ca.Cert.MaxPathLen != 0 {
		t.Fatal("CA must be pathlen 0 (signs leaves only)")
	}
	if ca.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("CA must have CertSign key usage")
	}
	// Self-verifies as a root.
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := ca.Cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("CA does not verify as its own root: %v", err)
	}
	// Round-trips through the PEM parsers.
	cert, err := ParseCertPEM(ca.CertPEM)
	if err != nil || !cert.Equal(ca.Cert) {
		t.Fatalf("ParseCertPEM round-trip failed: %v", err)
	}
	if _, err := ParsePrivateKeyPEM(ca.KeyPEM); err != nil {
		t.Fatalf("ParsePrivateKeyPEM: %v", err)
	}
}

func TestPKI_LeafVerifies(t *testing.T) {
	ca := testCA(t, "")
	caKey, err := ParsePrivateKeyPEM(ca.KeyPEM)
	if err != nil {
		t.Fatalf("parse CA key: %v", err)
	}
	leaf, err := IssueLeaf(ca.Cert, caKey, LeafOptions{
		Name:     "ns1.test",
		DNSNames: []string{"ns1.test"},
		IPs:      []net.IP{net.ParseIP("127.0.0.1")},
		Server:   true,
		Client:   true,
	})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	if leaf.Cert.IsCA {
		t.Fatal("leaf must not be a CA")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	for _, eku := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := leaf.Cert.Verify(x509.VerifyOptions{
			Roots:     pool,
			DNSName:   "ns1.test",
			KeyUsages: []x509.ExtKeyUsage{eku},
		}); err != nil {
			t.Fatalf("leaf verify (eku %v): %v", eku, err)
		}
	}
	// Wrong name must fail.
	if _, err := leaf.Cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "ns2.test"}); err == nil {
		t.Fatal("leaf must not verify for a name it does not carry")
	}
	// A leaf without any usage is refused at issuance.
	if _, err := IssueLeaf(ca.Cert, caKey, LeafOptions{Name: "x"}); err == nil {
		t.Fatal("leaf without server/client usage must be refused")
	}
}

// TestPKI_LeafCannotSign: the pathlen-0 + IsCA=false constraints must prevent
// a leaf from acting as an intermediate.
func TestPKI_LeafCannotSign(t *testing.T) {
	ca := testCA(t, "")
	caKey, _ := ParsePrivateKeyPEM(ca.KeyPEM)
	leaf, err := IssueLeaf(ca.Cert, caKey, LeafOptions{Name: "ns1.test", DNSNames: []string{"ns1.test"}, Server: true})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	leafKey, _ := ParsePrivateKeyPEM(leaf.KeyPEM)

	// Attempt to use the leaf as a signing parent. Either CreateCertificate
	// itself refuses (Go checks the parent's CertSign usage), or the result
	// must fail chain verification against the root.
	rogue, err := IssueLeaf(leaf.Cert, leafKey, LeafOptions{Name: "rogue.test", DNSNames: []string{"rogue.test"}, Server: true})
	if err != nil {
		return // refused at creation: good
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	inter := x509.NewCertPool()
	inter.AddCert(leaf.Cert)
	if _, err := rogue.Cert.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, DNSName: "rogue.test"}); err == nil {
		t.Fatal("a leaf-signed cert must never verify against the root")
	}
}

func TestPKI_CSRRoundTrip(t *testing.T) {
	ca := testCA(t, "")
	caKey, _ := ParsePrivateKeyPEM(ca.KeyPEM)

	csrPEM, keyPEM, err := CreateCSR(CSROptions{
		Name:     "ns2.example.net",
		DNSNames: []string{"ns2.example.net"},
		IPs:      []net.IP{net.ParseIP("192.0.2.2")},
	})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	signed, err := SignCSR(ca.Cert, caKey, csrPEM, SignOptions{Client: true})
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if len(signed.KeyPEM) != 0 {
		t.Fatal("SignCSR must not carry a private key (it stays with the requester)")
	}
	// SANs copied from the CSR.
	if len(signed.Cert.DNSNames) != 1 || signed.Cert.DNSNames[0] != "ns2.example.net" {
		t.Fatalf("DNS SANs not copied: %v", signed.Cert.DNSNames)
	}
	if len(signed.Cert.IPAddresses) != 1 || !signed.Cert.IPAddresses[0].Equal(net.ParseIP("192.0.2.2")) {
		t.Fatalf("IP SANs not copied: %v", signed.Cert.IPAddresses)
	}
	// The signed cert must match the CSR's key: pair it with the CSR-side key.
	if _, err := tls.X509KeyPair(signed.CertPEM, keyPEM); err != nil {
		t.Fatalf("signed cert does not pair with the CSR key: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := signed.Cert.Verify(x509.VerifyOptions{
		Roots: pool, DNSName: "ns2.example.net",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("signed CSR cert verify: %v", err)
	}
	// A tampered CSR must be refused.
	broken := append([]byte(nil), csrPEM...)
	if _, err := SignCSR(ca.Cert, caKey, broken[:len(broken)/2], SignOptions{Client: true}); err == nil {
		t.Fatal("truncated CSR must be refused")
	}
}

func TestPKI_Algorithms(t *testing.T) {
	for _, alg := range []CertAlgorithm{CertAlgEd25519, CertAlgECDSAP256, CertAlgRSA2048} {
		ca := testCA(t, alg)
		caKey, err := ParsePrivateKeyPEM(ca.KeyPEM)
		if err != nil {
			t.Fatalf("%s: parse key: %v", alg, err)
		}
		leaf, err := IssueLeaf(ca.Cert, caKey, LeafOptions{Name: "n." + string(alg), DNSNames: []string{"n." + string(alg)}, Server: true, Alg: alg})
		if err != nil {
			t.Fatalf("%s: IssueLeaf: %v", alg, err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(ca.Cert)
		if _, err := leaf.Cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "n." + string(alg)}); err != nil {
			t.Fatalf("%s: verify: %v", alg, err)
		}
	}
	if _, err := CreateCA(CAOptions{Name: "x", Alg: "dsa"}); err == nil {
		t.Fatal("unknown algorithm must be refused")
	}
}

// TestPKI_XoTIntegration is the §2.6 closing-the-loop test: a CA + server
// leaf minted by the PKI primitives must satisfy all three XoT client auth
// modes against the real transfer path.
func TestPKI_XoTIntegration(t *testing.T) {
	ca := testCA(t, "")
	caKey, _ := ParsePrivateKeyPEM(ca.KeyPEM)
	leaf, err := IssueLeaf(ca.Cert, caKey, LeafOptions{
		Name:     "ns1.test",
		DNSNames: []string{"ns1.test"},
		IPs:      []net.IP{net.ParseIP("127.0.0.1")},
		Server:   true,
	})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	serverCert, err := tls.X509KeyPair(leaf.CertPEM, leaf.KeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	zd := loadTestTransferZone(t, basicZone)
	srv := startTestAXFRServerTLS(t, zd, nil, serverCert)
	defer srv.shutdown()

	// pkix: ca-file = the minted CA cert.
	caPath := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(caPath, ca.CertPEM, 0o644); err != nil {
		t.Fatalf("write ca-file: %v", err)
	}
	conf := &Config{}
	pkixPeer := PeerConf{Addr: srv.addr, Key: NOKEY, Transport: TransportDoT,
		TLSAuth: TLSAuthPKIX, TLSName: "ns1.test", CAFile: caPath}
	if _, err := xotTransfer(t, conf, pkixPeer, srv, zd.ZoneName); err != nil {
		t.Fatalf("pkix transfer with minted CA failed: %v", err)
	}

	// pin: the same digest cert pin/--emit-pin would print.
	pinPeer := PeerConf{Addr: srv.addr, Key: NOKEY, Transport: TransportDoT,
		TLSAuth: TLSAuthPin, Pins: []string{SPKISHA256(leaf.Cert)}}
	if _, err := xotTransfer(t, conf, pinPeer, srv, zd.ZoneName); err != nil {
		t.Fatalf("pin transfer with minted leaf failed: %v", err)
	}

	// dane: the TLSA record --emit-tlsa would print, injected as validated.
	danePeer := PeerConf{Addr: srv.addr, Key: NOKEY, Transport: TransportDoT,
		TLSAuth: TLSAuthDANE, TLSName: "ns1.test"}
	daneConf := daneTestConf(t, leaf.Cert, serverPort(t, srv), cache.ValidationStateSecure, true)
	if _, err := xotTransfer(t, daneConf, danePeer, srv, zd.ZoneName); err != nil {
		t.Fatalf("dane transfer with minted leaf failed: %v", err)
	}
}
