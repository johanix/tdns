package tdns

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

// Regression test for the DNSSEC key import failing with
//
//	Error: failed to convert private key to PEM: failed to marshal private key
//	       to PKCS#8: dnssec-algorithms/pkcs8: codec does not support this key/OID
//
// tdns-cli reads the key files locally and POSTs the whole PrivateKeyCache to
// tdns-auth. PrivateKeyCache used to ship its interface fields (K, CS, RR) as
// JSON: an ed25519.PrivateKey is a []byte, so it marshalled to a base64 string,
// which then decoded fine into the empty interface crypto.PrivateKey but FAILED
// against the non-empty crypto.Signer. The server logged that decode error and
// continued, leaving K holding a plain string that reached the PKCS#8
// marshaller — hence the misleading "codec does not support this key/OID".
//
// The interface fields are now json:"-"; the wire form carries PrivateKey
// (base64) + DnskeyRR, which is all the server needs to rebuild the key.
func TestDnssecImportSurvivesAPIRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		alg  uint8
	}{
		{"ED25519", dns.ED25519},
		{"ECDSAP256SHA256", dns.ECDSAP256SHA256},
		{"RSASHA256", dns.RSASHA256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bits := 256
			if tc.alg == dns.RSASHA256 {
				bits = 2048
			}
			dir := t.TempDir()
			base := filepath.Join(dir, "Kp.axfr.net.+015+32445")

			key := &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: "p.axfr.net.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
				Flags:     256,
				Protocol:  3,
				Algorithm: tc.alg,
			}
			priv, err := key.Generate(bits)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			der, err := x509.MarshalPKCS8PrivateKey(priv)
			if err != nil {
				t.Fatalf("MarshalPKCS8: %v", err)
			}
			// .private as PKCS#8 PEM, matching what `keystore ... export` writes.
			if err := os.WriteFile(base+".private",
				pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(base+".key", []byte(key.String()+"\n"), 0644); err != nil {
				t.Fatal(err)
			}

			// --- tdns-cli side ---
			pkc, err := ReadPrivateKey(base + ".key")
			if err != nil {
				t.Fatalf("ReadPrivateKey: %v", err)
			}
			if _, ok := pkc.K.(crypto.Signer); !ok {
				t.Fatalf("client: K should be a usable key, got %T", pkc.K)
			}

			// --- the API hop ---
			wire, err := json.Marshal(KeystorePost{
				Command: "dnssec-mgmt", SubCommand: "add",
				Zone: "p.axfr.net.", PrivateKeyCache: pkc, State: "created",
			})
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			var got KeystorePost
			if err := json.Unmarshal(wire, &got); err != nil {
				t.Fatalf("json.Unmarshal must succeed (it used to fail on CS): %v", err)
			}
			srv := got.PrivateKeyCache

			if srv.K != nil {
				t.Errorf("K must not cross the API, got %T", srv.K)
			}
			if srv.CS != nil {
				t.Errorf("CS must not cross the API, got %T", srv.CS)
			}
			if srv.PrivateKeyPEM == "" {
				t.Fatal("PrivateKeyPEM must cross the API; it is what the server rebuilds from")
			}

			// --- tdns-auth side: the guard in keystore.go "add" ---
			var privkey crypto.PrivateKey
			if signer, ok := srv.K.(crypto.Signer); ok {
				privkey = signer
			} else if srv.PrivateKeyPEM != "" {
				privkey, err = PEMToPrivateKey(srv.PrivateKeyPEM)
				if err != nil {
					t.Fatalf("PEMToPrivateKey: %v", err)
				}
			} else {
				t.Fatal("no usable private key crossed the API")
			}

			if _, err := PrivateKeyToPEM(privkey); err != nil {
				t.Fatalf("PrivateKeyToPEM: %v", err)
			}
		})
	}
}

// TestDnssecImportRSACarriesPEM records why the wire form is PKCS#8 PEM rather
// than the BIND single-field base64.
//
// RSA's BIND private-key format has eight fields — Modulus, PublicExponent,
// PrivateExponent, Prime1, Prime2, Exponent1, Exponent2, Coefficient — and no
// single "PrivateKey:" line, so PrepareKeyCache cannot fill pkc.PrivateKey for
// it. Rebuilding the key server-side from that base64 therefore only ever
// worked for the single-field algorithms (Ed25519, ECDSA, the PQ ones). The PEM
// is algorithm-agnostic and is what the server now uses.
func TestDnssecImportRSACarriesPEM(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "Krsa.example.+008+00000")

	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "rsa.example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
	}
	priv, err := key.Generate(2048)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8: %v", err)
	}
	if err := os.WriteFile(base+".private",
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+".key", []byte(key.String()+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	pkc, err := ReadPrivateKey(base + ".key")
	if err != nil {
		t.Fatalf("ReadPrivateKey: %v", err)
	}
	if pkc.PrivateKey != "" {
		t.Logf("note: RSA now also yields a single-field base64 %q", pkc.PrivateKey)
	} else {
		t.Log("as expected: RSA yields no single-field BIND base64")
	}
	if pkc.PrivateKeyPEM == "" {
		t.Fatal("RSA must still get a PKCS#8 PEM -- that is what makes RSA import work")
	}
	back, err := PEMToPrivateKey(pkc.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("PEMToPrivateKey: %v", err)
	}
	if _, ok := back.(crypto.Signer); !ok {
		t.Fatalf("round-tripped RSA key is not usable: %T", back)
	}
}
