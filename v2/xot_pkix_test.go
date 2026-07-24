/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * PKIX loose-end tests (docs/2026-07-21-pkix-cert-tooling-design.md LE-3/LE-7):
 * intermediate-chain presentation and the agent-parity fetch path.
 */
package tdns

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"testing"
	"time"
)

// buildThreeTierChain hand-builds root -> intermediate -> leaf. The tdns-cli
// CA is deliberately pathlen-0 and cannot produce this shape, but operators
// with an external CA can — the verifier must handle it.
func buildThreeTierChain(t *testing.T) (rootCert *x509.Certificate, interDER []byte, leafDER []byte, leafKey *ecdsa.PrivateKey) {
	t.Helper()
	mkKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("key: %v", err)
		}
		return k
	}
	serial := func() *big.Int {
		s, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			t.Fatalf("serial: %v", err)
		}
		return s
	}
	rootKey, interKey, lKey := mkKey(), mkKey(), mkKey()

	rootTmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "test-root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	root, _ := x509.ParseCertificate(rootDER)

	interTmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "test-intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	interDER, err = x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("intermediate: %v", err)
	}
	inter, _ := x509.ParseCertificate(interDER)

	leafTmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "ns1.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"ns1.test"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err = x509.CreateCertificate(rand.Reader, leafTmpl, inter, &lKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	return root, interDER, leafDER, lKey
}

// TestXoT_PKIXIntermediateChain (LE-7/LE-2): a secondary trusting only the
// root must build the chain when the primary presents leaf+intermediate,
// and must fail when the intermediate is omitted.
func TestXoT_PKIXIntermediateChain(t *testing.T) {
	root, interDER, leafDER, leafKey := buildThreeTierChain(t)

	rootPath := t.TempDir() + "/root.pem"
	if err := writeCertPEM(rootPath, root.Raw); err != nil {
		t.Fatalf("write root: %v", err)
	}
	conf := &Config{}
	peer := PeerConf{Addr: "", Key: NOKEY, Transport: TransportDoT,
		TLSAuth: TLSAuthPKIX, TLSName: "ns1.test", CAFile: rootPath}

	// Server presents leaf + intermediate: chain builds, transfer succeeds.
	zd := loadTestTransferZone(t, basicZone)
	withInter := tls.Certificate{Certificate: [][]byte{leafDER, interDER}, PrivateKey: leafKey}
	srv := startTestAXFRServerTLS(t, zd, nil, withInter)
	defer srv.shutdown()
	peer.Addr = srv.addr
	if _, err := xotTransfer(t, conf, peer, srv, zd.ZoneName); err != nil {
		t.Fatalf("transfer with leaf+intermediate failed: %v", err)
	}

	// Server presents only the leaf: no path to the root, must fail.
	zd2 := loadTestTransferZone(t, basicZone)
	leafOnly := tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
	srv2 := startTestAXFRServerTLS(t, zd2, nil, leafOnly)
	defer srv2.shutdown()
	peer.Addr = srv2.addr
	if _, err := xotTransfer(t, conf, peer, srv2, zd2.ZoneName); err == nil {
		t.Fatal("transfer without the intermediate must fail chain building")
	}
}

// TestXoT_FetchFromUpstreamPKIX (LE-3 agent parity): the full production
// fetch path — FetchFromUpstream including the hard flip and snapshot
// publish — over dot+pkix. Both tdns-auth and tdns-agent drive exactly this
// function from the shared RefreshEngine, so this guards against the two
// daemons drifting apart.
func TestXoT_FetchFromUpstreamPKIX(t *testing.T) {
	conf := testXfrConf(t)
	primary := loadTestTransferZone(t, basicZone)
	primary.Downstreams = []AclEntry{{Prefix: "127.0.0.0/8", Key: "tkey"}}
	cert, leaf := newTestTLSCert(t, []string{"ns1.test"}, []net.IP{net.ParseIP("127.0.0.1")})
	srv := startTestAXFRServerTLS(t, primary, conf.tsigProvider(), cert)
	defer srv.shutdown()

	caPath := t.TempDir() + "/ca.pem"
	if err := writeCertPEM(caPath, leaf.Raw); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	sec := &ZoneData{
		ZoneName:      "example.test.",
		ZoneStore:     MapZone,
		ZoneType:      Secondary,
		Logger:        log.Default(),
		FirstZoneLoad: false, // refresh path: applyRefreshReplacementLocked flips Ready itself
		Upstreams: []PeerConf{{
			Addr: srv.addr, Key: "tkey", Transport: TransportDoT,
			TLSAuth: TLSAuthPKIX, TLSName: "ns1.test", CAFile: caPath,
		}},
	}
	t.Cleanup(sec.stopPublisher)
	// The snapshot publish path only publishes for zones registered in the
	// global Zones map (zoneStillLive); register like the daemons do.
	Zones.Set(sec.ZoneName, sec)
	t.Cleanup(func() { Zones.Remove(sec.ZoneName) })

	updated, err := sec.FetchFromUpstream(false, false, nil, conf)
	if err != nil {
		t.Fatalf("FetchFromUpstream over dot+pkix: %v", err)
	}
	if !updated {
		t.Fatal("expected the zone to be fetched and flipped")
	}
	if sec.GetStatus() != ZoneStatusReady || !sec.Ready {
		t.Fatalf("secondary not Ready after fetch: status=%v", sec.GetStatus())
	}
	// The published snapshot must serve the transferred data (the query path
	// reads the snapshot, not zd.Data — GetSOA is the servable-data check).
	soa, err := sec.GetSOA()
	if err != nil || soa == nil {
		t.Fatalf("no servable SOA after fetch: %v", err)
	}
	if soa.Serial != 1 {
		t.Fatalf("expected transferred serial 1, got %d", soa.Serial)
	}
}
