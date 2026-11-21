/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Golden tests for the P-256 JWK RR helpers. EncodePublicKeyToJWK and
 * DecodeJWKToPublicKey sit at both ends of tdns-mp agent discovery: an
 * agent publishes what the first returns, and its peers decode it with
 * the second. Any change to the bytes they produce or accept reaches the
 * agents with the next re-pin, so these tests pin today's output byte for
 * byte. A change that breaks them must be deliberate (and coordinated
 * with tdns-mp), not a side effect of the DNSSEC JWK codec work.
 */

package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"math/big"
	"testing"
)

func p256PublicKeyFromJWKCoords(t *testing.T, x, y string) *ecdsa.PublicKey {
	t.Helper()
	xb, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		t.Fatalf("decode x: %v", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(y)
	if err != nil {
		t.Fatalf("decode y: %v", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}
}

func TestEncodePublicKeyToJWKGoldenP256(t *testing.T) {
	cases := []struct {
		name string
		x, y string
		use  string
		json string
	}{
		{
			// The public key of the draft's Appendix A ECDSAP256SHA256 example.
			name: "draft vector, no use",
			x:    "9cqheie08FXlvnU17YJJm1FMUXD4rwi7-4atSdZ3og8",
			y:    "PR66xkQK4YKumafBX4tYV4N008RfZHQZdMxs_7ToK5A",
			use:  "",
			json: `{"kty":"EC","crv":"P-256","x":"9cqheie08FXlvnU17YJJm1FMUXD4rwi7-4atSdZ3og8","y":"PR66xkQK4YKumafBX4tYV4N008RfZHQZdMxs_7ToK5A"}`,
		},
		{
			name: "draft vector, use sig",
			x:    "9cqheie08FXlvnU17YJJm1FMUXD4rwi7-4atSdZ3og8",
			y:    "PR66xkQK4YKumafBX4tYV4N008RfZHQZdMxs_7ToK5A",
			use:  "sig",
			json: `{"kty":"EC","crv":"P-256","x":"9cqheie08FXlvnU17YJJm1FMUXD4rwi7-4atSdZ3og8","y":"PR66xkQK4YKumafBX4tYV4N008RfZHQZdMxs_7ToK5A","use":"sig"}`,
		},
		{
			// d = 379 is the smallest scalar whose X has a leading zero
			// byte: pins the left-padding of coordinates to 32 bytes.
			name: "leading zero in x (d=379), use enc",
			x:    "AFVDiUrz0A7X10Cr29dclrBod7eH219w7qeLkKjXwAo",
			y:    "u0yFo9jqKe-q-iRAaRLdhNWxTcMr9lbvbGvVil2UP5I",
			use:  "enc",
			json: `{"kty":"EC","crv":"P-256","x":"AFVDiUrz0A7X10Cr29dclrBod7eH219w7qeLkKjXwAo","y":"u0yFo9jqKe-q-iRAaRLdhNWxTcMr9lbvbGvVil2UP5I","use":"enc"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub := p256PublicKeyFromJWKCoords(t, tc.x, tc.y)
			got, alg, err := EncodePublicKeyToJWK(pub, tc.use)
			if err != nil {
				t.Fatalf("EncodePublicKeyToJWK: %v", err)
			}
			if alg != "ES256" {
				t.Errorf("alg = %q, want ES256", alg)
			}
			want := base64.RawURLEncoding.EncodeToString([]byte(tc.json))
			if got != want {
				gotJSON, _ := base64.RawURLEncoding.DecodeString(got)
				t.Fatalf("EncodePublicKeyToJWK output changed:\n got %s\nwant %s", gotJSON, tc.json)
			}

			dec, dalg, err := DecodeJWKToPublicKey(got)
			if err != nil {
				t.Fatalf("DecodeJWKToPublicKey: %v", err)
			}
			if dalg != "ES256" {
				t.Errorf("decoded alg = %q, want ES256", dalg)
			}
			dpub, ok := dec.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("decoded key is %T, want *ecdsa.PublicKey", dec)
			}
			if !dpub.Equal(pub) {
				t.Errorf("decoded key differs from the encoded one")
			}
			if err := ValidateJWK(got); err != nil {
				t.Errorf("ValidateJWK: %v", err)
			}
			kty, crv, err := GetJWKKeyType(got)
			if err != nil || kty != "EC" || crv != "P-256" {
				t.Errorf("GetJWKKeyType = %q, %q, %v; want EC, P-256, nil", kty, crv, err)
			}
		})
	}
}

// TestDecodeJWKToPublicKeyGoldenAccepts pins what the decoder accepts
// today beyond its own output: padded input is refused, and unknown
// members (such as a kid a newer publisher might add) are ignored.
func TestDecodeJWKToPublicKeyGoldenAccepts(t *testing.T) {
	withKid := `{"kid":"ni1azkx1Qe3zOuUw1eRd3oNN_91av68ll49pGTLF_BM","kty":"EC","crv":"P-256","x":"9cqheie08FXlvnU17YJJm1FMUXD4rwi7-4atSdZ3og8","y":"PR66xkQK4YKumafBX4tYV4N008RfZHQZdMxs_7ToK5A","dnskey":{"name":"example.com."}}`
	if _, alg, err := DecodeJWKToPublicKey(base64.RawURLEncoding.EncodeToString([]byte(withKid))); err != nil || alg != "ES256" {
		t.Errorf("unknown members: alg %q, err %v; want ES256, nil", alg, err)
	}
	padded := base64.URLEncoding.EncodeToString([]byte(withKid + " "))
	if _, _, err := DecodeJWKToPublicKey(padded); err == nil {
		t.Errorf("padded base64url accepted; today's decoder refuses it")
	}
}
