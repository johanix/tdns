/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// newTestTLSCert generates an in-memory self-signed server certificate for the
// given names/IPs and returns both the tls.Certificate (server side) and the
// parsed x509 leaf (for pin/TLSA computation on the client side).
func newTestTLSCert(t *testing.T, dnsNames []string, ips []net.IP) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "xot-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
		BasicConstraintsValid: true,
		IsCA:                  true, // self-signed: lets the client use it as its own root
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// startTestAXFRServerTLS is the DoT variant of startTestAXFRServerCore: the
// same AXFR-out handler behind a TLS listener, optionally with TSIG.
func startTestAXFRServerTLS(t *testing.T, zd *ZoneData, tsigProvider dns.TsigProvider, cert tls.Certificate) *axfrTestServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"dot"},
	})

	srv := &axfrTestServer{addr: ln.Addr().String()}
	zone := dns.Fqdn(zd.ZoneName)
	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, r *dns.Msg) {
		rec := &recordingResponseWriter{
			ResponseWriter: w,
			record:         srv.recordSize,
		}
		serve := func(w2 dns.ResponseWriter, req *dns.Msg) {
			_, _ = zd.ZoneTransferOut(w2, req)
		}
		if tsigProvider != nil {
			TsigSigningHandler(serve)(rec, r)
		} else {
			serve(rec, r)
		}
	})

	started := make(chan struct{})
	dnsSrv := &dns.Server{
		Listener:          tlsLn,
		Handler:           mux,
		TsigProvider:      tsigProvider,
		NotifyStartedFunc: func() { close(started) },
	}
	go func() { _ = dnsSrv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("test DoT AXFR server did not start")
	}
	srv.shutdown = func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = dnsSrv.ShutdownContext(ctx)
	}
	return srv
}

// axfrClientTLS runs an AXFR through the fork's dns.Transfer with the TLS
// field set (the XoT client path), optionally with TSIG.
func axfrClientTLS(t *testing.T, addr, zone string, tlsCfg *tls.Config, provider dns.TsigProvider) ([]dns.RR, error) {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetAxfr(zone)
	tr := &dns.Transfer{TLS: tlsCfg, TsigProvider: provider}
	ch, err := tr.In(msg, addr)
	if err != nil {
		return nil, err
	}
	var rrs []dns.RR
	for env := range ch {
		if env.Error != nil {
			return rrs, env.Error
		}
		rrs = append(rrs, env.RR...)
	}
	return rrs, nil
}

// TestXoT_TransferTSIGInsideTLS is the fork-risk spike (plan §6.1): AXFR over
// TLS with TSIG on both request and response envelopes, TSIG signed/verified
// inside the TLS stream, PKIX-verified against the server's self-signed cert.
func TestXoT_TransferTSIGInsideTLS(t *testing.T) {
	conf := testXfrConf(t)
	zd := loadTestTransferZone(t, basicZone)
	zd.Downstreams = []AclEntry{{Prefix: "127.0.0.0/8", Key: "tkey"}}

	cert, leaf := newTestTLSCert(t, []string{"ns1.test"}, []net.IP{net.ParseIP("127.0.0.1")})
	srv := startTestAXFRServerTLS(t, zd, conf.tsigProvider(), cert)
	defer srv.shutdown()

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	msg := new(dns.Msg)
	msg.SetAxfr(zd.ZoneName)
	provider, err := SignForPeer(msg, "tkey", conf)
	if err != nil {
		t.Fatalf("SignForPeer: %v", err)
	}

	tlsCfg := &tls.Config{
		RootCAs:    pool,
		ServerName: "ns1.test",
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"dot"},
	}
	tr := &dns.Transfer{TLS: tlsCfg, TsigProvider: provider}
	ch, err := tr.In(msg, srv.addr)
	if err != nil {
		t.Fatalf("Transfer.In over TLS: %v", err)
	}
	var rrs []dns.RR
	for env := range ch {
		if env.Error != nil {
			t.Fatalf("envelope error (TSIG-inside-TLS broken?): %v", env.Error)
		}
		rrs = append(rrs, env.RR...)
	}
	if len(rrs) < 4 {
		t.Fatalf("expected at least 4 RRs (SOA bookends + data), got %d", len(rrs))
	}
	if _, ok := rrs[0].(*dns.SOA); !ok {
		t.Fatalf("first RR should be SOA, got %T", rrs[0])
	}
	if _, ok := rrs[len(rrs)-1].(*dns.SOA); !ok {
		t.Fatalf("last RR should be SOA, got %T", rrs[len(rrs)-1])
	}
}

// TestTLSA_GenerateVerifyRoundTrip: a TLSA record generated by NewTlsaRR
// (true 3-1-1: the hash really is over the SPKI) must verify against the same
// certificate, and must NOT verify against a different certificate.
func TestTLSA_GenerateVerifyRoundTrip(t *testing.T) {
	_, cert := newTestTLSCert(t, []string{"ns1.test"}, nil)
	_, other := newTestTLSCert(t, []string{"ns2.test"}, nil)

	tlsa, err := NewTlsaRR("ns1.test.", 853, cert)
	if err != nil {
		t.Fatalf("NewTlsaRR: %v", err)
	}
	if tlsa.Usage != 3 || tlsa.Selector != 1 || tlsa.MatchingType != 1 {
		t.Fatalf("expected 3-1-1 TLSA, got %d-%d-%d", tlsa.Usage, tlsa.Selector, tlsa.MatchingType)
	}
	if tlsa.Hdr.Name != "_853._tcp.ns1.test." {
		t.Fatalf("unexpected owner name %q", tlsa.Hdr.Name)
	}
	// The association data must be the SPKI hash (selector 1 semantics), not
	// the full-cert hash (the old bug).
	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if tlsa.Certificate != hex.EncodeToString(spkiHash[:]) {
		t.Fatalf("TLSA data is not the SPKI SHA-256: got %s", tlsa.Certificate)
	}
	if err := VerifyCertAgainstTlsaRR(tlsa, cert); err != nil {
		t.Fatalf("verify against own cert: %v", err)
	}
	if err := VerifyCertAgainstTlsaRR(tlsa, other); err == nil {
		t.Fatal("verify against a different cert should fail")
	}
}

// TestTLSA_VerifyHonorsSelector: selector 0 (full cert) and selector 1 (SPKI)
// must be hashed over different bytes, and each must verify only when the
// association data matches its own selector semantics.
func TestTLSA_VerifyHonorsSelector(t *testing.T) {
	_, cert := newTestTLSCert(t, []string{"ns1.test"}, nil)

	fullHash := sha256.Sum256(cert.Raw)
	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if fullHash == spkiHash {
		t.Fatal("test is vacuous: full-cert and SPKI hashes are identical")
	}

	mk := func(selector uint8, data [32]byte) *dns.TLSA {
		return &dns.TLSA{
			Hdr:          dns.RR_Header{Name: "_853._tcp.ns1.test.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 120},
			Usage:        3,
			Selector:     selector,
			MatchingType: 1,
			Certificate:  hex.EncodeToString(data[:]),
		}
	}

	if err := VerifyCertAgainstTlsaRR(mk(0, fullHash), cert); err != nil {
		t.Fatalf("selector 0 with full-cert hash should verify: %v", err)
	}
	if err := VerifyCertAgainstTlsaRR(mk(1, spkiHash), cert); err != nil {
		t.Fatalf("selector 1 with SPKI hash should verify: %v", err)
	}
	// Crossed: selector says one thing, data is the other -> must fail.
	if err := VerifyCertAgainstTlsaRR(mk(0, spkiHash), cert); err == nil {
		t.Fatal("selector 0 with SPKI hash must not verify")
	}
	if err := VerifyCertAgainstTlsaRR(mk(1, fullHash), cert); err == nil {
		t.Fatal("selector 1 with full-cert hash must not verify")
	}
}

// TestTLSA_VerifySHA512AndRejects: matching type 2 (SHA-512) works per
// selector; unsupported usage/selector/matching-type are rejected.
func TestTLSA_VerifySHA512AndRejects(t *testing.T) {
	_, cert := newTestTLSCert(t, []string{"ns1.test"}, nil)

	spki512 := sha512.Sum512(cert.RawSubjectPublicKeyInfo)
	tlsa := &dns.TLSA{
		Hdr:          dns.RR_Header{Name: "_853._tcp.ns1.test.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 120},
		Usage:        3,
		Selector:     1,
		MatchingType: 2,
		Certificate:  hex.EncodeToString(spki512[:]),
	}
	if err := VerifyCertAgainstTlsaRR(tlsa, cert); err != nil {
		t.Fatalf("selector 1 + SHA-512 should verify: %v", err)
	}

	bad := *tlsa
	bad.Usage = 1 // PKIX-EE, unsupported
	if err := VerifyCertAgainstTlsaRR(&bad, cert); err == nil {
		t.Fatal("usage 1 must be rejected")
	}
	bad = *tlsa
	bad.Selector = 7
	if err := VerifyCertAgainstTlsaRR(&bad, cert); err == nil {
		t.Fatal("unknown selector must be rejected")
	}
	bad = *tlsa
	bad.MatchingType = 0 // exact match, unsupported
	if err := VerifyCertAgainstTlsaRR(&bad, cert); err == nil {
		t.Fatal("matching type 0 must be rejected")
	}
}

// TestSPKISHA256_PinRoundTrip: the pin helper hashes the SPKI (not the whole
// cert), is stable, and two different keys yield different pins.
func TestSPKISHA256_PinRoundTrip(t *testing.T) {
	_, cert := newTestTLSCert(t, []string{"ns1.test"}, nil)
	_, other := newTestTLSCert(t, []string{"ns1.test"}, nil)

	pin := SPKISHA256(cert)
	want := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if pin != base64.StdEncoding.EncodeToString(want[:]) {
		t.Fatalf("pin mismatch: got %s", pin)
	}
	if pin != SPKISHA256(cert) {
		t.Fatal("pin not stable")
	}
	if pin == SPKISHA256(other) {
		t.Fatal("different keys must yield different pins")
	}
	// A TLSA 3-1-1 record and a pin are the same digest in different encodings.
	tlsa, err := NewTlsaRR("ns1.test.", 853, cert)
	if err != nil {
		t.Fatalf("NewTlsaRR: %v", err)
	}
	rawPin, err := base64.StdEncoding.DecodeString(pin)
	if err != nil {
		t.Fatalf("decode pin: %v", err)
	}
	if hex.EncodeToString(rawPin) != tlsa.Certificate {
		t.Fatal("pin and TLSA 3-1-1 association data disagree")
	}
}

// TestValidatePeerXoT covers the config-load validation matrix for the XoT
// fields on a primary entry.
func TestValidatePeerXoT(t *testing.T) {
	// A valid pin: base64 of 32 bytes.
	goodPin := base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))

	// A readable CA file with a CERTIFICATE block.
	certTLS, _ := newTestTLSCert(t, []string{"ca.test"}, nil)
	caPath := t.TempDir() + "/ca.pem"
	if err := writeCertPEM(caPath, certTLS.Certificate[0]); err != nil {
		t.Fatalf("write ca file: %v", err)
	}
	junkPath := t.TempDir() + "/junk.pem"
	if err := os.WriteFile(junkPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write junk file: %v", err)
	}

	cases := []struct {
		name string
		peer PeerConf
		ok   bool
	}{
		{"plain do53 untouched", PeerConf{Addr: "192.0.2.1:53", Key: NOKEY}, true},
		{"explicit do53", PeerConf{Addr: "192.0.2.1:53", Key: NOKEY, Transport: "do53"}, true},
		{"do53 with tls-auth", PeerConf{Addr: "192.0.2.1:53", Key: NOKEY, TLSAuth: "pin"}, false},
		{"do53 with pins", PeerConf{Addr: "192.0.2.1:53", Key: NOKEY, Pins: []string{goodPin}}, false},
		{"unknown transport", PeerConf{Addr: "192.0.2.1", Key: NOKEY, Transport: "doq"}, false},
		{"dot without tls-auth", PeerConf{Addr: "ns1.test", Key: NOKEY, Transport: "dot"}, false},
		{"dot unknown tls-auth", PeerConf{Addr: "ns1.test", Key: NOKEY, Transport: "dot", TLSAuth: "spki"}, false},
		{"pin ok", PeerConf{Addr: "ns1.test", Key: NOKEY, Transport: "dot", TLSAuth: "pin", Pins: []string{goodPin}}, true},
		{"pin without pins", PeerConf{Addr: "ns1.test", Key: NOKEY, Transport: "dot", TLSAuth: "pin"}, false},
		{"pin bad base64", PeerConf{Addr: "ns1.test", Key: NOKEY, Transport: "dot", TLSAuth: "pin", Pins: []string{"!!!"}}, false},
		{"pin wrong digest size", PeerConf{Addr: "ns1.test", Key: NOKEY, Transport: "dot", TLSAuth: "pin", Pins: []string{"AAAA"}}, false},
		{"dane hostname ok", PeerConf{Addr: "ns1.test", Key: NOKEY, Transport: "dot", TLSAuth: "dane"}, true},
		{"dane ip needs tls-name", PeerConf{Addr: "192.0.2.1:853", Key: NOKEY, Transport: "dot", TLSAuth: "dane"}, false},
		{"dane ip with tls-name", PeerConf{Addr: "192.0.2.1:853", Key: NOKEY, Transport: "dot", TLSAuth: "dane", TLSName: "ns1.test"}, true},
		{"pkix system roots", PeerConf{Addr: "ns1.test", Key: NOKEY, Transport: "dot", TLSAuth: "pkix"}, true},
		{"pkix ca file ok", PeerConf{Addr: "ns1.test", Key: NOKEY, Transport: "dot", TLSAuth: "pkix", CAFile: caPath}, true},
		{"pkix ca file missing", PeerConf{Addr: "ns1.test", Key: NOKEY, Transport: "dot", TLSAuth: "pkix", CAFile: "/nonexistent/ca.pem"}, false},
		{"pkix ca file junk", PeerConf{Addr: "ns1.test", Key: NOKEY, Transport: "dot", TLSAuth: "pkix", CAFile: junkPath}, false},
		{"case-insensitive DoT/DANE", PeerConf{Addr: "ns1.test", Key: NOKEY, Transport: "DoT", TLSAuth: "DANE"}, true},
	}
	for _, tc := range cases {
		p := tc.peer
		err := validatePeerXoT(&p)
		if tc.ok && err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s: expected error, got none", tc.name)
		}
	}

	// Normalization: transport/tls-auth are lowercased in place.
	p := PeerConf{Addr: "ns1.test", Key: NOKEY, Transport: "DOT", TLSAuth: "PKIX"}
	if err := validatePeerXoT(&p); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if p.Transport != TransportDoT || p.TLSAuth != TLSAuthPKIX {
		t.Fatalf("expected normalized transport/tls-auth, got %+v", p)
	}
}

func writeCertPEM(path string, der []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestNormalizeAddressPort(t *testing.T) {
	if got := NormalizeAddressPort("192.0.2.1", "853"); got != "192.0.2.1:853" {
		t.Fatalf("got %q", got)
	}
	if got := NormalizeAddressPort("192.0.2.1:53", "853"); got != "192.0.2.1:53" {
		t.Fatalf("explicit port must win: %q", got)
	}
	if got := NormalizeAddressPort("2001:db8::1", "853"); got != "[2001:db8::1]:853" {
		t.Fatalf("v6 literal: %q", got)
	}
	if got := NormalizeAddress("192.0.2.1"); got != "192.0.2.1:53" {
		t.Fatalf("NormalizeAddress default unchanged: %q", got)
	}
}

// TestXoT_TransferRejectsUntrustedCert: the same server, but the client does
// not trust the server cert -> the handshake (and thus the transfer) must fail.
func TestXoT_TransferRejectsUntrustedCert(t *testing.T) {
	zd := loadTestTransferZone(t, basicZone)

	cert, _ := newTestTLSCert(t, []string{"ns1.test"}, []net.IP{net.ParseIP("127.0.0.1")})
	srv := startTestAXFRServerTLS(t, zd, nil, cert)
	defer srv.shutdown()

	tlsCfg := &tls.Config{
		// Empty root pool: nothing is trusted.
		RootCAs:    x509.NewCertPool(),
		ServerName: "ns1.test",
		MinVersion: tls.VersionTLS13,
	}
	_, err := axfrClientTLS(t, srv.addr, zd.ZoneName, tlsCfg, nil)
	if err == nil {
		t.Fatal("expected transfer to fail against an untrusted cert")
	}
	if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "x509") {
		t.Logf("note: failure was not an x509 error (still acceptable): %v", err)
	}
}
