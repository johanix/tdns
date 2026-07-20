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
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
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
			// Answer SOA probes (the DoTransfer path) from the zone apex;
			// AXFR/IXFR goes through the real transfer-out path.
			if len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeSOA {
				m := new(dns.Msg)
				m.SetReply(req)
				if apex, ok := zd.Data.Get(zd.ZoneName); ok {
					m.Answer = append(m.Answer, apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs...)
				}
				_ = w2.WriteMsg(m)
				return
			}
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

// --- ClientTLSConfigForPeer -------------------------------------------------

func TestClientTLSConfigForPeer_Do53ReturnsNil(t *testing.T) {
	conf := &Config{}
	for _, p := range []PeerConf{
		{Addr: "192.0.2.1:53", Key: NOKEY},
		{Addr: "192.0.2.1:53", Key: NOKEY, Transport: "do53"},
	} {
		cfg, err := conf.ClientTLSConfigForPeer(p)
		if err != nil || cfg != nil {
			t.Fatalf("do53 peer must yield (nil, nil), got (%v, %v)", cfg, err)
		}
	}
}

func TestClientTLSConfigForPeer_ServerNameSelection(t *testing.T) {
	conf := &Config{}
	// Hostname primary: hostname becomes SNI.
	cfg, err := conf.ClientTLSConfigForPeer(PeerConf{Addr: "ns1.test:853", Key: NOKEY, Transport: TransportDoT, TLSAuth: TLSAuthPKIX})
	if err != nil || cfg.ServerName != "ns1.test" {
		t.Fatalf("hostname SNI: cfg=%+v err=%v", cfg, err)
	}
	// Explicit tls-name wins.
	cfg, err = conf.ClientTLSConfigForPeer(PeerConf{Addr: "192.0.2.1:853", Key: NOKEY, Transport: TransportDoT, TLSAuth: TLSAuthPKIX, TLSName: "ns2.test"})
	if err != nil || cfg.ServerName != "ns2.test" {
		t.Fatalf("tls-name SNI: cfg=%+v err=%v", cfg, err)
	}
	// IP literal without tls-name: empty (crypto/tls fills from dial addr).
	cfg, err = conf.ClientTLSConfigForPeer(PeerConf{Addr: "192.0.2.1:853", Key: NOKEY, Transport: TransportDoT, TLSAuth: TLSAuthPKIX})
	if err != nil || cfg.ServerName != "" {
		t.Fatalf("ip-literal SNI: cfg=%+v err=%v", cfg, err)
	}
	// DANE without any name is refused (backstop; config validation catches it earlier).
	if _, err = conf.ClientTLSConfigForPeer(PeerConf{Addr: "192.0.2.1:853", Key: NOKEY, Transport: TransportDoT, TLSAuth: TLSAuthDANE}); err == nil {
		t.Fatal("dane without name must error")
	}
	// Unknown auth mode is refused.
	if _, err = conf.ClientTLSConfigForPeer(PeerConf{Addr: "ns1.test:853", Key: NOKEY, Transport: TransportDoT, TLSAuth: "nope"}); err == nil {
		t.Fatal("unknown tls-auth must error")
	}
}

// xotTransfer runs an AXFR against srv using the tls.Config built for peer.
func xotTransfer(t *testing.T, conf *Config, peer PeerConf, srv *axfrTestServer, zone string) ([]dns.RR, error) {
	t.Helper()
	tlsCfg, err := conf.ClientTLSConfigForPeer(peer)
	if err != nil {
		return nil, err
	}
	if tlsCfg == nil {
		t.Fatal("expected a TLS config for a dot peer")
	}
	return axfrClientTLS(t, srv.addr, zone, tlsCfg, nil)
}

// TestXoT_PinModeEndToEnd: pin match transfers; pin mismatch aborts the
// handshake (and thus the transfer).
func TestXoT_PinModeEndToEnd(t *testing.T) {
	conf := &Config{}
	zd := loadTestTransferZone(t, basicZone)
	cert, leaf := newTestTLSCert(t, []string{"ns1.test"}, []net.IP{net.ParseIP("127.0.0.1")})
	srv := startTestAXFRServerTLS(t, zd, nil, cert)
	defer srv.shutdown()

	good := PeerConf{Addr: srv.addr, Key: NOKEY, Transport: TransportDoT, TLSAuth: TLSAuthPin,
		Pins: []string{SPKISHA256(leaf)}}
	rrs, err := xotTransfer(t, conf, good, srv, zd.ZoneName)
	if err != nil {
		t.Fatalf("pin-match transfer failed: %v", err)
	}
	if len(rrs) < 4 {
		t.Fatalf("expected full zone, got %d RRs", len(rrs))
	}

	wrongPin := base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
	bad := good
	bad.Pins = []string{wrongPin}
	if _, err := xotTransfer(t, conf, bad, srv, zd.ZoneName); err == nil {
		t.Fatal("pin-mismatch transfer must fail")
	}
	// Second pin in the list may be the matching one.
	multi := good
	multi.Pins = []string{wrongPin, SPKISHA256(leaf)}
	if _, err := xotTransfer(t, conf, multi, srv, zd.ZoneName); err != nil {
		t.Fatalf("any-pin-matches transfer failed: %v", err)
	}
}

// daneTestConf builds a Config whose IMR has a pre-populated, validated TLSA
// cache entry for ns1.test. at the given port: the injected-validated-TLSA
// seam from the plan (the network fetch path needs a live resolver and is
// exercised in the manual/testbed runs instead).
func daneTestConf(t *testing.T, leafCert *x509.Certificate, port uint16, vstate cache.ValidationState, requireSecure bool) *Config {
	t.Helper()
	rrcache := cache.NewRRsetCache(log.Default(), false, false)
	as := rrcache.GetOrCreateAuthServer("ns1.test.")
	rrcache.ServerMap.Set("test.", map[string]*cache.AuthServer{"ns1.test.": as})

	tlsa, err := NewTlsaRR("ns1.test.", port, leafCert)
	if err != nil {
		t.Fatalf("NewTlsaRR: %v", err)
	}
	rrset := &core.RRset{Name: tlsa.Hdr.Name, Class: dns.ClassINET, RRtype: dns.TypeTLSA, RRs: []dns.RR{tlsa}}
	rrcache.StoreTLSAForServer("ns1.test.", tlsa.Hdr.Name, rrset, vstate)

	conf := &Config{}
	conf.Internal.ImrEngine = &Imr{Cache: rrcache, RequireDnssecValidation: requireSecure}
	return conf
}

func serverPort(t *testing.T, srv *axfrTestServer) uint16 {
	t.Helper()
	_, portStr, err := net.SplitHostPort(srv.addr)
	if err != nil {
		t.Fatalf("split server addr: %v", err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("parse server port: %v", err)
	}
	return uint16(port)
}

// TestXoT_DANEModeEndToEnd: a secure cached TLSA matching the server cert
// admits the transfer; a TLSA for a different cert aborts it.
func TestXoT_DANEModeEndToEnd(t *testing.T) {
	zd := loadTestTransferZone(t, basicZone)
	cert, leaf := newTestTLSCert(t, []string{"ns1.test"}, []net.IP{net.ParseIP("127.0.0.1")})
	srv := startTestAXFRServerTLS(t, zd, nil, cert)
	defer srv.shutdown()
	port := serverPort(t, srv)

	peer := PeerConf{Addr: srv.addr, Key: NOKEY, Transport: TransportDoT, TLSAuth: TLSAuthDANE, TLSName: "ns1.test"}

	conf := daneTestConf(t, leaf, port, cache.ValidationStateSecure, true)
	rrs, err := xotTransfer(t, conf, peer, srv, zd.ZoneName)
	if err != nil {
		t.Fatalf("dane-match transfer failed: %v", err)
	}
	if len(rrs) < 4 {
		t.Fatalf("expected full zone, got %d RRs", len(rrs))
	}

	_, otherLeaf := newTestTLSCert(t, []string{"ns1.test"}, nil)
	confMismatch := daneTestConf(t, otherLeaf, port, cache.ValidationStateSecure, true)
	if _, err := xotTransfer(t, confMismatch, peer, srv, zd.ZoneName); err == nil {
		t.Fatal("dane-mismatch transfer must fail")
	}
}

// TestXoT_DANEFailsClosedOnUnvalidated: an unvalidated TLSA is refused when
// validation is required (the default), and accepted only in explicit lab mode
// (require_dnssec_validation: false).
func TestXoT_DANEFailsClosedOnUnvalidated(t *testing.T) {
	zd := loadTestTransferZone(t, basicZone)
	cert, leaf := newTestTLSCert(t, []string{"ns1.test"}, []net.IP{net.ParseIP("127.0.0.1")})
	srv := startTestAXFRServerTLS(t, zd, nil, cert)
	defer srv.shutdown()
	port := serverPort(t, srv)

	peer := PeerConf{Addr: srv.addr, Key: NOKEY, Transport: TransportDoT, TLSAuth: TLSAuthDANE, TLSName: "ns1.test"}

	for _, state := range []cache.ValidationState{cache.ValidationStateNone, cache.ValidationStateInsecure, cache.ValidationStateBogus} {
		conf := daneTestConf(t, leaf, port, state, true)
		if _, err := xotTransfer(t, conf, peer, srv, zd.ZoneName); err == nil {
			t.Fatalf("state %s: transfer must fail closed", cache.ValidationStateToString[state])
		}
	}

	// Lab mode: insecure state is accepted (with a warning), matching the
	// imrengine.require_dnssec_validation escape hatch semantics.
	confLab := daneTestConf(t, leaf, port, cache.ValidationStateInsecure, false)
	if _, err := xotTransfer(t, confLab, peer, srv, zd.ZoneName); err != nil {
		t.Fatalf("lab-mode transfer failed: %v", err)
	}
}

// TestXoT_DANEWithoutIMRFails: tls-auth dane with no IMR engine must refuse
// the connection (fail closed), not fall back to unverified TLS.
func TestXoT_DANEWithoutIMRFails(t *testing.T) {
	zd := loadTestTransferZone(t, basicZone)
	cert, _ := newTestTLSCert(t, []string{"ns1.test"}, []net.IP{net.ParseIP("127.0.0.1")})
	srv := startTestAXFRServerTLS(t, zd, nil, cert)
	defer srv.shutdown()

	conf := &Config{} // no ImrEngine
	peer := PeerConf{Addr: srv.addr, Key: NOKEY, Transport: TransportDoT, TLSAuth: TLSAuthDANE, TLSName: "ns1.test"}
	if _, err := xotTransfer(t, conf, peer, srv, zd.ZoneName); err == nil {
		t.Fatal("dane without IMR must fail")
	}
}

// TestXoT_PKIXModeEndToEnd: chain verification against a ca-file; a CA that
// did not issue the server cert aborts the handshake.
func TestXoT_PKIXModeEndToEnd(t *testing.T) {
	conf := &Config{}
	zd := loadTestTransferZone(t, basicZone)
	cert, leaf := newTestTLSCert(t, []string{"ns1.test"}, []net.IP{net.ParseIP("127.0.0.1")})
	srv := startTestAXFRServerTLS(t, zd, nil, cert)
	defer srv.shutdown()

	caPath := t.TempDir() + "/ca.pem"
	if err := writeCertPEM(caPath, leaf.Raw); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	good := PeerConf{Addr: srv.addr, Key: NOKEY, Transport: TransportDoT, TLSAuth: TLSAuthPKIX,
		TLSName: "ns1.test", CAFile: caPath}
	rrs, err := xotTransfer(t, conf, good, srv, zd.ZoneName)
	if err != nil {
		t.Fatalf("pkix transfer failed: %v", err)
	}
	if len(rrs) < 4 {
		t.Fatalf("expected full zone, got %d RRs", len(rrs))
	}

	// A different (wrong) CA must not admit the server.
	_, otherCA := newTestTLSCert(t, []string{"other-ca.test"}, nil)
	wrongCAPath := t.TempDir() + "/wrong-ca.pem"
	if err := writeCertPEM(wrongCAPath, otherCA.Raw); err != nil {
		t.Fatalf("write wrong ca: %v", err)
	}
	bad := good
	bad.CAFile = wrongCAPath
	if _, err := xotTransfer(t, conf, bad, srv, zd.ZoneName); err == nil {
		t.Fatal("pkix with wrong CA must fail")
	}

	// Wrong hostname expectation must fail too (SNI/hostname check).
	badName := good
	badName.TLSName = "ns2.test"
	if _, err := xotTransfer(t, conf, badName, srv, zd.ZoneName); err == nil {
		t.Fatal("pkix with wrong tls-name must fail")
	}
}

// --- Phase 3: the real secondary pull path (ZoneTransferIn / DoTransfer) ----

// newTestSecondary builds a secondary ZoneData pulling from the given peer.
func newTestSecondary(t *testing.T, up PeerConf) *ZoneData {
	t.Helper()
	return &ZoneData{
		ZoneName:  "example.test.",
		ZoneStore: MapZone,
		ZoneType:  Secondary,
		Logger:    log.Default(),
		Upstreams: []PeerConf{up},
	}
}

// TestXoT_ZoneTransferInOverDoT: the production inbound-transfer function
// pulls a zone over verified TLS (pin) with TSIG on the envelopes; a wrong
// pin aborts; DANE mode works against an injected validated TLSA.
func TestXoT_ZoneTransferInOverDoT(t *testing.T) {
	conf := testXfrConf(t)
	primary := loadTestTransferZone(t, basicZone)
	primary.Downstreams = []AclEntry{{Prefix: "127.0.0.0/8", Key: "tkey"}}
	cert, leaf := newTestTLSCert(t, []string{"ns1.test"}, []net.IP{net.ParseIP("127.0.0.1")})
	srv := startTestAXFRServerTLS(t, primary, conf.tsigProvider(), cert)
	defer srv.shutdown()

	pinPeer := PeerConf{Addr: srv.addr, Key: "tkey", Transport: TransportDoT,
		TLSAuth: TLSAuthPin, Pins: []string{SPKISHA256(leaf)}}
	sec := newTestSecondary(t, pinPeer)
	serial, err := sec.ZoneTransferIn(pinPeer, 0, "axfr", conf)
	if err != nil {
		t.Fatalf("XoT pull (pin+tsig) failed: %v", err)
	}
	if serial != 1 {
		t.Fatalf("expected serial 1, got %d", serial)
	}
	if sec.Data.IsEmpty() {
		t.Fatal("secondary has no zone data after transfer")
	}

	// Tampered/wrong pin: the transfer must abort at the handshake.
	badPeer := pinPeer
	badPeer.Pins = []string{base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))}
	secBad := newTestSecondary(t, badPeer)
	if _, err := secBad.ZoneTransferIn(badPeer, 0, "axfr", conf); err == nil {
		t.Fatal("XoT pull with wrong pin must fail")
	}

	// DANE mode through the same production path.
	danePeer := PeerConf{Addr: srv.addr, Key: "tkey", Transport: TransportDoT,
		TLSAuth: TLSAuthDANE, TLSName: "ns1.test"}
	daneConf := testXfrConf(t)
	daneConf.Internal.ImrEngine = daneTestConf(t, leaf, serverPort(t, srv), cache.ValidationStateSecure, true).Internal.ImrEngine
	secDane := newTestSecondary(t, danePeer)
	if _, err := secDane.ZoneTransferIn(danePeer, 0, "axfr", daneConf); err != nil {
		t.Fatalf("XoT pull (dane+tsig) failed: %v", err)
	}
}

// TestXoT_DoTransferSOAProbeOverDoT: the SOA probe uses the same verified TLS
// channel (and TSIG) as the transfer; a wrong pin makes the upstream count as
// unreachable.
func TestXoT_DoTransferSOAProbeOverDoT(t *testing.T) {
	conf := testXfrConf(t)
	primary := loadTestTransferZone(t, basicZone)
	primary.Downstreams = []AclEntry{{Prefix: "127.0.0.0/8", Key: "tkey"}}
	cert, leaf := newTestTLSCert(t, []string{"ns1.test"}, []net.IP{net.ParseIP("127.0.0.1")})
	srv := startTestAXFRServerTLS(t, primary, conf.tsigProvider(), cert)
	defer srv.shutdown()

	pinPeer := PeerConf{Addr: srv.addr, Key: "tkey", Transport: TransportDoT,
		TLSAuth: TLSAuthPin, Pins: []string{SPKISHA256(leaf)}}
	sec := newTestSecondary(t, pinPeer)
	should, serial, err := sec.DoTransfer(conf)
	if err != nil {
		t.Fatalf("SOA probe over DoT failed: %v", err)
	}
	if !should || serial != 1 {
		t.Fatalf("expected (transfer=true, serial=1), got (%v, %d)", should, serial)
	}

	// Wrong pin: handshake fails -> all upstreams unreachable -> hard error.
	badPeer := pinPeer
	badPeer.Pins = []string{base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))}
	secBad := newTestSecondary(t, badPeer)
	if _, _, err := secBad.DoTransfer(conf); err == nil {
		t.Fatal("SOA probe with wrong pin must fail")
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
