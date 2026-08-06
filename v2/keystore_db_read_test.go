package tdns

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
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

// --- registered (non-built-in) algorithm coverage -----------------------

// orphanedAlg is a registered algorithm whose BIND private-key parser always
// fails. That is precisely what a renumbered codepoint looks like from the
// keystore's side: the stored PEM is fine, but anything that re-parses it by
// dispatching on the algorithm number cannot reconstruct the key.
//
// Everything else is ed25519 underneath, so the key material is real and the
// PKCS#8 encoding goes through the stdlib marshaller.
type orphanedAlg struct{}

func (orphanedAlg) Name() string      { return testOrphanAlgName }
func (orphanedAlg) Hash() crypto.Hash { return 0 }

func (orphanedAlg) Generate(bits int) (crypto.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

func (orphanedAlg) PublicKeyFromWire(keybuf []byte) (crypto.PublicKey, error) {
	if len(keybuf) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad public key size %d", len(keybuf))
	}
	return ed25519.PublicKey(keybuf), nil
}

func (orphanedAlg) PublicKeyToWire(pub crypto.PublicKey) ([]byte, error) {
	k, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ed25519 public key: %T", pub)
	}
	return k, nil
}

// ReadPrivateKey is the orphaned half: the codepoint no longer resolves to a
// usable parser. This is the failure the fix must not depend on.
func (orphanedAlg) ReadPrivateKey(map[string]string) (crypto.PrivateKey, error) {
	return nil, fmt.Errorf("dns: bad private key")
}

func (orphanedAlg) PrivateKeyToString(priv crypto.PrivateKey) (string, error) {
	k, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return "", fmt.Errorf("not an ed25519 private key: %T", priv)
	}
	return "PrivateKey: " + base64.StdEncoding.EncodeToString(k.Seed()) + "\n", nil
}

// SignaturePostProcess is pass-through, as it is for ED25519.
func (orphanedAlg) SignaturePostProcess(sig []byte) ([]byte, error) { return sig, nil }

func (orphanedAlg) Verify(pub crypto.PublicKey, hashed, sig []byte) error {
	k, ok := pub.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("not an ed25519 public key: %T", pub)
	}
	if !ed25519.Verify(k, hashed, sig) {
		return dns.ErrSig
	}
	return nil
}

const (
	// 253 is private use, so it cannot collide with a real assignment.
	testOrphanAlgCode = 253
	testOrphanAlgName = "TESTORPHAN253"
)

// TestPrivateKeyCacheFromDBHandlesRegisteredAlgorithm is the test that actually
// covers the bug this change was written for. The other cases here use
// built-in algorithms, whose BIND round trip works -- so they would pass with
// or without the fix. This one uses a REGISTERED algorithm whose BIND parser
// fails, which is what a renumbered codepoint leaves behind, and asserts both
// halves: the old route breaks, the new one does not.
func TestPrivateKeyCacheFromDBHandlesRegisteredAlgorithm(t *testing.T) {
	if err := dns.RegisterAlgorithm(testOrphanAlgCode, orphanedAlg{}); err != nil &&
		!errors.Is(err, dns.ErrAlgRegistered) {
		t.Fatalf("registering test algorithm: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	rr := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "orphan.example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: testOrphanAlgCode,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	keyrr := rr.String()

	// The fix: straight from PEM, no codepoint-dispatched re-parse.
	pkc, alg, err := PrivateKeyCacheFromDB(privPEM, testOrphanAlgName, keyrr)
	if err != nil {
		t.Fatalf("PrivateKeyCacheFromDB must read a registered algorithm's stored PEM: %v", err)
	}
	if alg != testOrphanAlgCode {
		t.Errorf("algorithm = %d, want %d", alg, testOrphanAlgCode)
	}
	if pkc.CS == nil {
		t.Fatal("no crypto.Signer produced")
	}
	if got, ok := pkc.CS.Public().(ed25519.PublicKey); !ok || !got.Equal(pub) {
		t.Error("the signer does not carry the key that was stored")
	}

	// And the shape of the old route, to show this test would have caught it:
	// ParsePrivateKeyFromDB hands back BIND format, and re-parsing that
	// dispatches on the codepoint -- which is exactly what no longer works.
	if _, _, bindFormat, perr := ParsePrivateKeyFromDB(privPEM, testOrphanAlgName, keyrr); perr == nil {
		if _, cerr := PrepareKeyCache(bindFormat, keyrr); cerr == nil {
			t.Error("expected the BIND re-parse route to fail for an orphaned codepoint; " +
				"if this now succeeds the regression this test pins has changed shape")
		}
	}
}
