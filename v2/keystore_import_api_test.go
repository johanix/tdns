package tdns

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// TestReconstructSigningKeyRejectsMismatchedKeyType covers the guard that used
// to sit behind the two branches that actually run: a SIG(0) cache offered to
// the DNSSEC import (or the reverse) must be refused, not stored in the wrong
// table under a zero-valued RR.
func TestReconstructSigningKeyRejectsMismatchedKeyType(t *testing.T) {
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ED25519,
	}
	priv, err := k.Generate(256)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pem, err := PrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("to PEM: %v", err)
	}

	// A SIG(0) cache, as it would arrive over the API: K is json:"-" so it is
	// nil, and the usable material is in PrivateKeyPEM.
	sig0Cache := &PrivateKeyCache{
		KeyType:       dns.TypeKEY,
		Algorithm:     dns.ED25519,
		PrivateKeyPEM: pem,
	}
	if _, err := reconstructSigningKey(sig0Cache, k.String(), dns.TypeDNSKEY); err == nil {
		t.Error("a TypeKEY cache must be refused by the DNSSEC import path")
	}

	// The matching type still works.
	dnssecCache := &PrivateKeyCache{
		KeyType:       dns.TypeDNSKEY,
		Algorithm:     dns.ED25519,
		PrivateKeyPEM: pem,
	}
	if _, err := reconstructSigningKey(dnssecCache, k.String(), dns.TypeDNSKEY); err != nil {
		t.Errorf("a matching cache must still be accepted: %v", err)
	}
}

// TestAPIkeystoreRejectsMalformedJSON covers the decode-failure path added with
// the import fix. The handler used to log a decode error and carry on, which is
// how a half-decoded PrivateKeyCache reached the PKCS#8 marshaller in the first
// place. It must now answer 400, in JSON (every other exit from this handler is
// JSON, so a text/plain body would break any client that decodes
// unconditionally), and start no keystore work at all.
func TestAPIkeystoreRejectsMalformedJSON(t *testing.T) {
	kdb := newTestKeyDB(t)
	handler := kdb.APIkeystore(&Config{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/keystore",
		strings.NewReader(`{"command":"dnssec-mgmt","subcommand":"add","privatekeycache":`))
	w := httptest.NewRecorder()
	handler(w, req)

	res := w.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", res.StatusCode, http.StatusBadRequest)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var kr KeystoreResponse
	if err := json.NewDecoder(res.Body).Decode(&kr); err != nil {
		t.Fatalf("response body must be a decodable KeystoreResponse: %v", err)
	}
	if !kr.Error || kr.ErrorMsg == "" {
		t.Errorf("malformed request must be reported as an error, got %+v", kr)
	}

	// Nothing may have been written: a rejected request must not leave a
	// partially-built key behind.
	var n int
	if err := kdb.QueryRow("SELECT COUNT(*) FROM DnssecKeyStore").Scan(&n); err != nil {
		t.Fatalf("counting DnssecKeyStore: %v", err)
	}
	if n != 0 {
		t.Errorf("a rejected request must not touch the keystore, found %d row(s)", n)
	}
}
