/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"errors"
	"os"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
)

// TestDNSSECJWKKeyPairChecksRegistered: with this package linked, the
// draft's ML-DSA-44 key imports (its seed expands to its pub), and a wrong
// seed is refused as a private/public mismatch.
func TestDNSSECJWKKeyPairChecksRegistered(t *testing.T) {
	data, err := os.ReadFile("core/testdata/dnssec-jwk/mldsa44.json")
	if err != nil {
		t.Fatal(err)
	}
	_, rr, err := core.ParseDNSSECJWK(data)
	if err != nil {
		t.Fatalf("ML-DSA-44 vector: %v", err)
	}
	if rr.KeyTag() != 59828 {
		t.Errorf("keytag %d, want 59828", rr.KeyTag())
	}
	bad := strings.Replace(string(data), `"priv": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`, `"priv": "AQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"`, 1)
	if bad == string(data) {
		t.Fatal("test did not alter the seed")
	}
	if _, _, err := core.ParseDNSSECJWK([]byte(bad)); !errors.Is(err, core.ErrDNSKEYPrivateMismatch) {
		t.Errorf("wrong seed: err = %v, want ErrDNSKEYPrivateMismatch", err)
	}
	ed448 := &core.JSONWebKey{Kty: core.JWKKtyOKP, Crv: core.JWKCrvEd448, X: make([]byte, 57), D: make([]byte, 57)}
	if err := ed448.CheckKeyPair(); !errors.Is(err, core.ErrDNSKEYPrivateMismatch) {
		t.Errorf("Ed448 mismatch: err = %v, want ErrDNSKEYPrivateMismatch", err)
	}
}
