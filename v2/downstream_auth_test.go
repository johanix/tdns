/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Acceptance matrix for the per-zone downstream-auth mechanism ladder
 * (docs/2026-07-21-peers-xfr-auth-design.md §9 P2), driven end-to-end
 * through the real transfer path against the in-process DoT server with
 * RequestClientCert — the production listener shape.
 */
package tdns

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"strings"
	"testing"

	cache "github.com/johanix/tdns/v2/cache"
	"github.com/miekg/dns"
)

func pemEncode(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func TestDownstreamAuth_Validate(t *testing.T) {
	mechs := []string{"TSIG", " tls-pin "}
	if err := validateDownstreamAuth(mechs); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if mechs[0] != "tsig" || mechs[1] != "tls-pin" {
		t.Fatalf("not normalized: %v", mechs)
	}
	if err := validateDownstreamAuth([]string{"mtls"}); err == nil || !strings.Contains(err.Error(), "unknown downstream-auth") {
		t.Fatalf("unknown mechanism must be rejected, got %v", err)
	}
}

// dsAuthHarness starts a DoT AXFR server whose listener REQUESTS (never
// requires) a client certificate — the production shape — and returns the
// zone, server, and the base client TLS config trusting the server.
func dsAuthHarness(t *testing.T, conf *Config, downstreams []AclEntry, downstreamAuth []string) (*ZoneData, *axfrTestServer, *tls.Config) {
	t.Helper()
	zd := loadTestTransferZone(t, basicZone)
	zd.Downstreams = downstreams
	zd.DownstreamAuth = downstreamAuth

	serverCert, serverLeaf := newTestTLSCert(t, []string{"ns1.test"}, []net.IP{net.ParseIP("127.0.0.1")})
	srvTLS, err := ServerTLSConfigForDoT(conf, &serverCert, true)
	if err != nil {
		t.Fatalf("ServerTLSConfigForDoT: %v", err)
	}
	if srvTLS.ClientAuth != tls.RequestClientCert {
		t.Fatal("auth listener must use RequestClientCert")
	}
	var tsig dns.TsigProvider
	if conf != nil && len(conf.Keys.Tsig) > 0 {
		tsig = conf.tsigProvider()
	}
	srv := startTestAXFRServerTLSConfig(t, zd, tsig, srvTLS)
	t.Cleanup(srv.shutdown)

	pool := x509.NewCertPool()
	pool.AddCert(serverLeaf)
	base := &tls.Config{RootCAs: pool, ServerName: "ns1.test", MinVersion: tls.VersionTLS13}
	return zd, srv, base
}

// TestDownstreamAuth_NoLadderUnchanged: an empty downstream-auth preserves
// pre-ladder behavior — any matched entry authorizes, cert or no cert.
func TestDownstreamAuth_NoLadderUnchanged(t *testing.T) {
	_, srv, base := dsAuthHarness(t, &Config{},
		[]AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY}}, nil)
	if _, err := axfrClientTLS(t, srv.addr, "example.test.", base.Clone(), nil); err != nil {
		t.Fatalf("cert-less transfer with no ladder failed: %v", err)
	}
}

// TestDownstreamAuth_PinLadder: [tls-pin] — only the pinned client cert
// admits; cert-less and wrong-cert clients are REFUSEd at transfer time
// (the handshake itself succeeds: RequestClientCert verifies nothing).
func TestDownstreamAuth_PinLadder(t *testing.T) {
	clientCert, clientLeaf := newTestTLSCert(t, []string{"sec1.test"}, nil)
	rogueCert, _ := newTestTLSCert(t, []string{"rogue.test"}, nil)

	ds := []AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY, PeerName: "sec1",
		TLSIdentity: &TLSIdentity{Name: "sec1.test", Pins: []string{SPKISHA256(clientLeaf)}}}}
	_, srv, base := dsAuthHarness(t, &Config{}, ds, []string{MechTLSPin})

	good := base.Clone()
	good.Certificates = []tls.Certificate{clientCert}
	if rrs, err := axfrClientTLS(t, srv.addr, "example.test.", good, nil); err != nil || len(rrs) < 4 {
		t.Fatalf("pinned client transfer failed: %v (%d RRs)", err, len(rrs))
	}
	if _, err := axfrClientTLS(t, srv.addr, "example.test.", base.Clone(), nil); err == nil {
		t.Fatal("cert-less client must be refused under [tls-pin]")
	}
	bad := base.Clone()
	bad.Certificates = []tls.Certificate{rogueCert}
	if _, err := axfrClientTLS(t, srv.addr, "example.test.", bad, nil); err == nil {
		t.Fatal("unpinned client must be refused under [tls-pin]")
	}
}

// TestDownstreamAuth_MUSTs: the two hard requirements. A zone locked to
// [tls-pin] must still answer an ordinary cert-less DoT QUERY (the ladder
// gates transfers only), and a [tsig] zone must transfer over plain Do53.
func TestDownstreamAuth_MUSTs(t *testing.T) {
	// MUST 1: cert-less DoT query against a tls-pin-only zone.
	_, clientLeaf := newTestTLSCert(t, []string{"sec1.test"}, nil)
	ds := []AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY,
		TLSIdentity: &TLSIdentity{Pins: []string{SPKISHA256(clientLeaf)}}}}
	_, srv, base := dsAuthHarness(t, &Config{}, ds, []string{MechTLSPin})

	m := new(dns.Msg)
	m.SetQuestion("example.test.", dns.TypeSOA)
	c := &dns.Client{Net: "tcp-tls", TLSConfig: base.Clone()} // no client cert
	resp, _, err := c.Exchange(m, srv.addr)
	if err != nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Fatalf("cert-less DoT SOA query MUST work: err=%v resp=%v", err, resp)
	}

	// MUST 2: Do53 transfer under [tsig].
	conf := testXfrConf(t)
	zd := loadTestTransferZone(t, basicZone)
	zd.Downstreams = []AclEntry{{Prefix: "127.0.0.0/8", Key: "tkey"}}
	zd.DownstreamAuth = []string{MechTsig}
	do53 := startTestAXFRServerTSIG(t, zd, conf)
	t.Cleanup(do53.shutdown)
	if rrs, err := axfrClientTSIG(t, conf, do53.addr, zd.ZoneName, "tkey"); err != nil || len(rrs) < 4 {
		t.Fatalf("Do53 transfer under [tsig] MUST work: %v (%d RRs)", err, len(rrs))
	}
}

// TestDownstreamAuth_NokeyShadowRefusal: under [tsig, ...] a transfer that
// only satisfies a NOKEY entry maps to mechanism `prefix` and is refused
// even though an ACL entry matched — the documented NOKEY-shadows-TSIG
// footgun becomes a hard refusal.
func TestDownstreamAuth_NokeyShadowRefusal(t *testing.T) {
	conf := testXfrConf(t)
	ds := []AclEntry{
		{Prefix: "127.0.0.0/8", Key: NOKEY},  // the shadowing entry
		{Prefix: "127.0.0.0/8", Key: "tkey"}, // the intended one
	}
	_, srv, base := dsAuthHarness(t, conf, ds, []string{MechTsig})

	// Unsigned: only the NOKEY entry matches -> prefix -> refused.
	if _, err := axfrClientTLS(t, srv.addr, "example.test.", base.Clone(), nil); err == nil {
		t.Fatal("unsigned transfer must be refused under [tsig] despite the NOKEY entry")
	}
	// TSIG-signed: the keyed entry matches -> tsig -> authorized.
	msg := new(dns.Msg)
	msg.SetAxfr("example.test.")
	provider, err := SignForPeer(msg, "tkey", conf)
	if err != nil {
		t.Fatalf("SignForPeer: %v", err)
	}
	tr := &dns.Transfer{TLS: base.Clone(), TsigProvider: provider}
	ch, err := tr.In(msg, srv.addr)
	if err != nil {
		t.Fatalf("signed transfer: %v", err)
	}
	n := 0
	for env := range ch {
		if env.Error != nil {
			t.Fatalf("signed transfer envelope: %v", env.Error)
		}
		n += len(env.RR)
	}
	if n < 4 {
		t.Fatalf("signed transfer under [tsig] should succeed, got %d RRs", n)
	}
}

// TestDownstreamAuth_AnyOverride: [any] is the template-relaxation sentinel
// — unrestricted, exactly like an absent list.
func TestDownstreamAuth_AnyOverride(t *testing.T) {
	_, srv, base := dsAuthHarness(t, &Config{},
		[]AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY}}, []string{MechAny})
	if _, err := axfrClientTLS(t, srv.addr, "example.test.", base.Clone(), nil); err != nil {
		t.Fatalf("[any] must be unrestricted: %v", err)
	}
}

// TestDownstreamAuth_PkixLadder: [tls-pkix] — chain to the entry's CA plus
// the SAN identity check; chain-valid-wrong-name refused.
func TestDownstreamAuth_PkixLadder(t *testing.T) {
	clientCert, clientLeaf := newTestTLSCert(t, []string{"sec1.test"}, nil)
	caPath := t.TempDir() + "/ca.pem"
	if err := writeCertPEM(caPath, clientLeaf.Raw); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	ds := []AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY,
		TLSIdentity: &TLSIdentity{Name: "sec1.test", CAFile: caPath}}}
	_, srv, base := dsAuthHarness(t, &Config{}, ds, []string{MechTLSPkix})

	good := base.Clone()
	good.Certificates = []tls.Certificate{clientCert}
	if _, err := axfrClientTLS(t, srv.addr, "example.test.", good, nil); err != nil {
		t.Fatalf("CA-signed client transfer failed: %v", err)
	}

	// Same trust anchors, but the identity check names someone else.
	ds2 := []AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY,
		TLSIdentity: &TLSIdentity{Name: "other.test", CAFile: caPath}}}
	_, srv2, base2 := dsAuthHarness(t, &Config{}, ds2, []string{MechTLSPkix})
	good2 := base2.Clone()
	good2.Certificates = []tls.Certificate{clientCert}
	if _, err := axfrClientTLS(t, srv2.addr, "example.test.", good2, nil); err == nil {
		t.Fatal("chain-valid client with the wrong SAN must be refused")
	}
}

// TestDownstreamAuth_DaneLadder: [tls-dane] against an injected validated
// TLSA for the client cert; fails closed without an IMR.
func TestDownstreamAuth_DaneLadder(t *testing.T) {
	clientCert, clientLeaf := newTestTLSCert(t, []string{"ns1.test"}, nil)
	// daneTestConf injects a Secure TLSA for ns1.test. at the given port.
	imr := daneTestConf(t, clientLeaf, 853, cache.ValidationStateSecure, true).Internal.ImrEngine

	ds := []AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY,
		TLSIdentity: &TLSIdentity{Name: "ns1.test", Dane: true}}}

	zd := loadTestTransferZone(t, basicZone)
	zd.Downstreams = ds
	zd.DownstreamAuth = []string{MechTLSDane}
	serverCert, serverLeaf := newTestTLSCert(t, []string{"ns1.test"}, []net.IP{net.ParseIP("127.0.0.1")})
	srvTLS, _ := ServerTLSConfigForDoT(&Config{}, &serverCert, true)
	// Wire the imr into the transfer handler (production passes it from
	// QueryResponder); the harness serve func calls ZoneTransferOut directly.
	srv := startTestAXFRServerTLSConfigIMR(t, zd, nil, srvTLS, imr)
	t.Cleanup(srv.shutdown)

	pool := x509.NewCertPool()
	pool.AddCert(serverLeaf)
	base := &tls.Config{RootCAs: pool, ServerName: "ns1.test", MinVersion: tls.VersionTLS13}

	good := base.Clone()
	good.Certificates = []tls.Certificate{clientCert}
	if _, err := axfrClientTLS(t, srv.addr, "example.test.", good, nil); err != nil {
		t.Fatalf("DANE-matching client transfer failed: %v", err)
	}

	// Same setup, no IMR: fail closed.
	zd2 := loadTestTransferZone(t, basicZone)
	zd2.Downstreams = ds
	zd2.DownstreamAuth = []string{MechTLSDane}
	srv2 := startTestAXFRServerTLSConfigIMR(t, zd2, nil, srvTLS, nil)
	t.Cleanup(srv2.shutdown)
	good2 := base.Clone()
	good2.Certificates = []tls.Certificate{clientCert}
	if _, err := axfrClientTLS(t, srv2.addr, "example.test.", good2, nil); err == nil {
		t.Fatal("tls-dane without an IMR must fail closed")
	}
}

// TestDownstreamAuth_SecondaryPresentsClientCert: the full daemon-to-daemon
// shape — the secondary's ZoneTransferIn presents the daemon's own
// dnsengine cert (Internal.CertData/KeyData) as its client identity, and
// the primary's [tls-pkix] ladder accepts it. This is the wiring that makes
// the inbound tls-* mechanisms satisfiable by a real tdns secondary at all.
func TestDownstreamAuth_SecondaryPresentsClientCert(t *testing.T) {
	// The secondary's identity cert (what cert init would issue: dual EKU).
	secCert, secLeaf := newTestTLSCert(t, []string{"sec1.test"}, nil)

	// Primary: zone locked to [tls-pkix], trusting the secondary's cert as
	// its own root and requiring its SAN.
	caPath := t.TempDir() + "/sec-ca.pem"
	if err := writeCertPEM(caPath, secLeaf.Raw); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	ds := []AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY,
		TLSIdentity: &TLSIdentity{Name: "sec1.test", CAFile: caPath}}}
	_, srv, _ := dsAuthHarness(t, &Config{}, ds, []string{MechTLSPkix})

	// Secondary: pin the primary's server cert, and carry its own cert/key
	// in Internal.CertData/KeyData exactly as DnsEngine startup does.
	serverPin := func() string {
		// dsAuthHarness generated the server cert internally; fetch its pin
		// via a plain unverified connection (the +showpin flow).
		conn, err := tls.Dial("tcp", srv.addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}, MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatalf("dial for pin: %v", err)
		}
		defer conn.Close()
		return SPKISHA256(conn.ConnectionState().PeerCertificates[0])
	}()

	conf := &Config{}
	secKeyDER, _ := x509.MarshalPKCS8PrivateKey(secCert.PrivateKey)
	conf.Internal.CertData = string(pemEncode("CERTIFICATE", secCert.Certificate[0]))
	conf.Internal.KeyData = string(pemEncode("PRIVATE KEY", secKeyDER))

	peer := PeerConf{Addr: srv.addr, Key: NOKEY, Transport: TransportDoT,
		TLSAuth: TLSAuthPin, Pins: []string{serverPin}}
	sec := newTestSecondary(t, peer)
	serial, err := sec.ZoneTransferIn(peer, 0, "axfr", conf)
	if err != nil {
		t.Fatalf("secondary pull with client cert failed: %v", err)
	}
	if serial != 1 {
		t.Fatalf("expected serial 1, got %d", serial)
	}

	// Without the client identity the same pull must be refused.
	confNoID := &Config{}
	sec2 := newTestSecondary(t, peer)
	if _, err := sec2.ZoneTransferIn(peer, 0, "axfr", confNoID); err == nil {
		t.Fatal("pull without a client cert must be refused under [tls-pkix]")
	}
}

// TestDownstreamAuth_CrossChecks: the load-time warnings must not error and
// must fire for the documented shapes (asserted on behavior only — the
// warnings go to the log).
func TestDownstreamAuth_CrossChecks(t *testing.T) {
	// Purely exercising the paths: unsatisfiable mechanism, dead entry,
	// dane without IMR. Must not panic; warnings are log-only.
	crossCheckDownstreamAuth("z1.", []string{MechTLSPin},
		[]AclEntry{{Prefix: "10.0.0.0/8", Key: NOKEY}}, false)
	crossCheckDownstreamAuth("z2.", []string{MechTsig, MechTLSDane},
		[]AclEntry{{Prefix: "10.0.0.0/8", Key: NOKEY}}, false)
	crossCheckDownstreamAuth("z3.", []string{MechAny}, nil, false)
	crossCheckDownstreamAuth("z4.", nil, nil, false)
}
