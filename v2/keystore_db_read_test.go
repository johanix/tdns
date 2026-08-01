package tdns

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// Regression test for reading stored keys out of the keystore.
//
// Keys are stored as PKCS#8 PEM. The old path (ParsePrivateKeyFromDB followed
// by PrepareKeyCache) parsed that PEM correctly and then discarded the result,
// re-deriving a BIND-format blob with dns.DNSKEY.PrivateKeyString() and handing
// that back to PrepareKeyCache -- which re-parsed it through
// dns.DNSKEY.NewPrivateKey(), a dispatch on the algorithm CODEPOINT. Any key
// written under a codepoint that had since been renumbered then failed with a
// bare "dns: bad private key", despite the PEM parsing cleanly. On the gocpt101
// testbed that silently killed signing for slhdsa128s.foo and cpt.p.axfr.net:
// the zones answered, but every signing operation failed.
//
// PrivateKeyCacheFromDB keeps the PEM and lets PrepareKeyCache's PEM branch do
// the work, so no codepoint dispatch is involved at all.
func TestPrivateKeyCacheFromDBKeepsPEM(t *testing.T) {
	for _, tc := range []struct {
		name string
		alg  uint8
		bits int
	}{
		{"ED25519", dns.ED25519, 256},
		{"ECDSAP256SHA256", dns.ECDSAP256SHA256, 256},
		{"RSASHA256", dns.RSASHA256, 2048},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
				Flags:     257,
				Protocol:  3,
				Algorithm: tc.alg,
			}
			priv, err := key.Generate(tc.bits)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			der, err := x509.MarshalPKCS8PrivateKey(priv)
			if err != nil {
				t.Fatalf("MarshalPKCS8: %v", err)
			}
			stored := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

			pkc, alg, err := PrivateKeyCacheFromDB(stored, dns.AlgorithmToString[tc.alg], key.String())
			if err != nil {
				t.Fatalf("PrivateKeyCacheFromDB: %v", err)
			}
			if alg != tc.alg {
				t.Errorf("algorithm: got %d want %d", alg, tc.alg)
			}
			if pkc.Algorithm != tc.alg {
				t.Errorf("pkc.Algorithm: got %d want %d", pkc.Algorithm, tc.alg)
			}
			if _, ok := pkc.K.(crypto.Signer); !ok {
				t.Fatalf("stored key did not come back usable: %T", pkc.K)
			}
			if pkc.CS == nil {
				t.Error("CS (crypto.Signer) not populated")
			}
			if !strings.HasPrefix(pkc.PrivateKeyPEM, "-----BEGIN PRIVATE KEY-----") {
				t.Error("PrivateKeyPEM should be populated for a PEM-stored key")
			}
		})
	}
}

// The legacy row format -- bare base64 with no "Private-key-format:" header --
// must keep working, since existing keystores still hold rows written that way.
func TestPrivateKeyCacheFromDBAcceptsLegacyBareBase64(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.ED25519,
	}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Extract just the base64, the way legacy rows stored it.
	var bare string
	for _, line := range strings.Split(key.PrivateKeyString(priv), "\n") {
		if strings.HasPrefix(line, "PrivateKey:") {
			bare = strings.TrimSpace(strings.TrimPrefix(line, "PrivateKey:"))
		}
	}
	if bare == "" {
		t.Fatal("could not extract the legacy base64 form")
	}

	pkc, alg, err := PrivateKeyCacheFromDB(bare, "ED25519", key.String())
	if err != nil {
		t.Fatalf("PrivateKeyCacheFromDB (legacy): %v", err)
	}
	if alg != dns.ED25519 {
		t.Errorf("algorithm: got %d want %d", alg, dns.ED25519)
	}
	if _, ok := pkc.K.(crypto.Signer); !ok {
		t.Fatalf("legacy key did not come back usable: %T", pkc.K)
	}
}
