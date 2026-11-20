/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Tests for the DNSSEC JWK key-material codec (dnssec_jwk.go).
 */

package core

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func mustMarshalJWK(t *testing.T, k *JSONWebKey) []byte {
	t.Helper()
	b, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func fill(n int, v byte) []byte { return bytes.Repeat([]byte{v}, n) }

// testKeys returns one private JWK per key type the codec knows. Keys
// without a stdlib form get fixed member octets: the codec does not check
// them against an algorithm.
func testKeys(t *testing.T) map[string]*JSONWebKey {
	t.Helper()
	out := map[string]*JSONWebKey{}

	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, priv := range map[string]any{"RSA": rk} {
		k, err := NewJSONWebKeyFromPrivate(priv)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = k
	}
	for name, c := range map[string]elliptic.Curve{"EC P-256": elliptic.P256(), "EC P-384": elliptic.P384()} {
		ek, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		k, err := NewJSONWebKeyFromPrivate(ek)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = k
	}
	_, edk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if out["OKP Ed25519"], err = NewJSONWebKeyFromPrivate(edk); err != nil {
		t.Fatal(err)
	}
	xk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if out["OKP X25519"], err = NewJSONWebKeyFromPrivate(xk); err != nil {
		t.Fatal(err)
	}
	out["OKP Ed448"] = &JSONWebKey{Kty: JWKKtyOKP, Crv: JWKCrvEd448, X: fill(57, 1), D: fill(57, 2)}
	out["AKP ML-DSA-44"] = &JSONWebKey{Kty: JWKKtyAKP, Alg: JWKAlgMLDSA44, Pub: fill(1312, 3), Priv: fill(32, 4)}
	out["AKP ML-DSA-65"] = &JSONWebKey{Kty: JWKKtyAKP, Alg: JWKAlgMLDSA65, Pub: fill(1952, 5), Priv: fill(32, 6)}
	out["AKP ML-DSA-87"] = &JSONWebKey{Kty: JWKKtyAKP, Alg: JWKAlgMLDSA87, Pub: fill(2592, 7), Priv: fill(32, 8)}
	return out
}

func TestJSONWebKeyRoundTrip(t *testing.T) {
	for name, k := range testKeys(t) {
		t.Run(name, func(t *testing.T) {
			if err := k.SetKid(); err != nil {
				t.Fatalf("SetKid: %v", err)
			}
			for _, kk := range []*JSONWebKey{k, k.PublicJWK()} {
				b := mustMarshalJWK(t, kk)
				if bytes.Contains(b, []byte("=")) {
					t.Errorf("output has base64 padding: %s", b)
				}
				got, err := ParseJSONWebKey(b)
				if err != nil {
					t.Fatalf("parse %s: %v", b, err)
				}
				if b2 := mustMarshalJWK(t, got); !bytes.Equal(b, b2) {
					t.Errorf("round trip differs:\n%s\n%s", b, b2)
				}
				if got.IsPrivate() != kk.IsPrivate() {
					t.Errorf("IsPrivate %v, want %v", got.IsPrivate(), kk.IsPrivate())
				}
				// The thumbprint covers only public members, so the
				// public and private forms share one kid.
				tp, err := got.Thumbprint()
				if err != nil || tp != k.Kid {
					t.Errorf("thumbprint %q (%v), want %q", tp, err, k.Kid)
				}
			}
			if pub := k.PublicJWK(); pub.IsPrivate() {
				t.Errorf("PublicJWK still has private members")
			}
		})
	}
}

func TestJSONWebKeyStdlibConversions(t *testing.T) {
	for name, k := range testKeys(t) {
		t.Run(name, func(t *testing.T) {
			stdlib := k.Kty == JWKKtyRSA || k.Kty == JWKKtyEC || k.Crv == JWKCrvEd25519 || k.Crv == JWKCrvX25519
			pub, err := k.PublicKey()
			if !stdlib {
				if !errors.Is(err, ErrJWKNoStdlibKey) {
					t.Fatalf("PublicKey err %v, want ErrJWKNoStdlibKey", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("PublicKey: %v", err)
			}
			priv, err := k.PrivateKey()
			if err != nil {
				t.Fatalf("PrivateKey: %v", err)
			}
			k2, err := NewJSONWebKeyFromPrivate(priv)
			if err != nil {
				t.Fatalf("NewJSONWebKeyFromPrivate: %v", err)
			}
			if !bytes.Equal(mustMarshalJWK(t, k), mustMarshalJWK(t, k2)) {
				t.Errorf("private conversion round trip differs")
			}
			k3, err := NewJSONWebKeyFromPublic(pub)
			if err != nil {
				t.Fatalf("NewJSONWebKeyFromPublic: %v", err)
			}
			if !bytes.Equal(mustMarshalJWK(t, k.PublicJWK()), mustMarshalJWK(t, k3)) {
				t.Errorf("public conversion round trip differs")
			}
		})
	}
}

// TestJSONWebKeyEd25519NotX25519 pins that the two curves stay apart: the
// old JWK RR stub labelled an Ed25519 key X25519.
func TestJSONWebKeyEd25519NotX25519(t *testing.T) {
	keys := testKeys(t)
	ed, x := keys["OKP Ed25519"], keys["OKP X25519"]
	if ed.Crv != JWKCrvEd25519 || x.Crv != JWKCrvX25519 {
		t.Fatalf("crv %q / %q", ed.Crv, x.Crv)
	}
	pub, _ := ed.PublicKey()
	if _, ok := pub.(ed25519.PublicKey); !ok {
		t.Errorf("Ed25519 JWK gives %T", pub)
	}
	pub, _ = x.PublicKey()
	if _, ok := pub.(*ecdh.PublicKey); !ok {
		t.Errorf("X25519 JWK gives %T", pub)
	}
}

func TestJSONWebKeyUnknownMembersIgnored(t *testing.T) {
	k := testKeys(t)["EC P-256"]
	var m map[string]any
	if err := json.Unmarshal(mustMarshalJWK(t, k), &m); err != nil {
		t.Fatal(err)
	}
	m["use"] = "sig"
	m["key_ops"] = []string{"sign"}
	m["x5u"] = 17
	m["dnskey"] = map[string]any{"future": true}
	b, _ := json.Marshal(m)
	got, err := ParseJSONWebKey(b)
	if err != nil {
		t.Fatalf("parse with unknown members: %v", err)
	}
	if !bytes.Equal(got.D, k.D) || got.Use != "sig" {
		t.Errorf("members lost")
	}
}

// TestJSONWebKeyMemberNamesCaseSensitive: encoding/json would match "D" to
// a field tagged "d"; JWK names are case-sensitive, so "D" is unknown.
func TestJSONWebKeyMemberNamesCaseSensitive(t *testing.T) {
	k := testKeys(t)["OKP Ed25519"]
	b := strings.Replace(string(mustMarshalJWK(t, k)), `"d":`, `"D":`, 1)
	got, err := ParseJSONWebKey([]byte(b))
	if err != nil {
		t.Fatal(err)
	}
	if got.IsPrivate() {
		t.Errorf("\"D\" was read as \"d\"")
	}
}

func TestJSONWebKeyRejects(t *testing.T) {
	keys := testKeys(t)
	jsonOf := func(name string, edit func(m map[string]any)) []byte {
		var m map[string]any
		if err := json.Unmarshal(mustMarshalJWK(t, keys[name]), &m); err != nil {
			t.Fatal(err)
		}
		edit(m)
		b, _ := json.Marshal(m)
		return b
	}
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"not JSON", []byte(`{"kty":`), ErrJWKMalformed},
		{"JSON array", []byte(`[]`), ErrJWKMalformed},
		{"JSON null", []byte(`null`), ErrJWKMalformed},
		{"no kty", jsonOf("EC P-256", func(m map[string]any) { delete(m, "kty") }), ErrJWKMissingMember},
		{"unknown kty", jsonOf("EC P-256", func(m map[string]any) { m["kty"] = "oct" }), ErrJWKUnsupportedKty},
		{"kty not a string", jsonOf("EC P-256", func(m map[string]any) { m["kty"] = 1 }), ErrJWKMemberType},
		{"x not a string", jsonOf("EC P-256", func(m map[string]any) { m["x"] = 12 }), ErrJWKMemberType},
		{"padded base64url", jsonOf("OKP Ed25519", func(m map[string]any) { m["x"] = m["x"].(string) + "=" }), ErrJWKBadBase64},
		{"std base64 alphabet", jsonOf("OKP Ed25519", func(m map[string]any) {
			m["x"] = strings.NewReplacer("-", "+", "_", "/").Replace(m["x"].(string)) + "+/"
		}), ErrJWKBadBase64},
		{"empty member", jsonOf("OKP Ed25519", func(m map[string]any) { m["d"] = "" }), ErrJWKBadKeySize},
		{"EC no crv", jsonOf("EC P-256", func(m map[string]any) { delete(m, "crv") }), ErrJWKMissingMember},
		{"EC unknown crv", jsonOf("EC P-256", func(m map[string]any) { m["crv"] = "P-521" }), ErrJWKUnsupportedCurve},
		{"EC no y", jsonOf("EC P-256", func(m map[string]any) { delete(m, "y") }), ErrJWKMissingMember},
		{"EC P-384 coords under P-256", jsonOf("EC P-384", func(m map[string]any) { m["crv"] = "P-256" }), ErrJWKBadKeySize},
		{"EC short d", jsonOf("EC P-256", func(m map[string]any) { m["d"] = b64(fill(31, 1)) }), ErrJWKBadKeySize},
		{"EC point off curve", jsonOf("EC P-256", func(m map[string]any) { m["y"] = b64(fill(32, 1)) }), ErrJWKInvalidPublicKey},
		{"OKP no crv", jsonOf("OKP Ed25519", func(m map[string]any) { delete(m, "crv") }), ErrJWKMissingMember},
		{"OKP unknown crv", jsonOf("OKP Ed25519", func(m map[string]any) { m["crv"] = "Ed25519ph" }), ErrJWKUnsupportedCurve},
		{"OKP no x", jsonOf("OKP Ed25519", func(m map[string]any) { delete(m, "x") }), ErrJWKMissingMember},
		{"Ed448 with Ed25519 length", jsonOf("OKP Ed25519", func(m map[string]any) { m["crv"] = "Ed448" }), ErrJWKBadKeySize},
		{"AKP no alg", jsonOf("AKP ML-DSA-44", func(m map[string]any) { delete(m, "alg") }), ErrJWKMissingMember},
		{"AKP unknown alg", jsonOf("AKP ML-DSA-44", func(m map[string]any) { m["alg"] = "ML-DSA-99" }), ErrJWKUnsupportedCurve},
		{"AKP no pub", jsonOf("AKP ML-DSA-44", func(m map[string]any) { delete(m, "pub") }), ErrJWKMissingMember},
		{"AKP pub of another set", jsonOf("AKP ML-DSA-44", func(m map[string]any) { m["alg"] = "ML-DSA-65" }), ErrJWKBadKeySize},
		{"AKP expanded priv", jsonOf("AKP ML-DSA-44", func(m map[string]any) { m["priv"] = b64(fill(2560, 1)) }), ErrJWKBadKeySize},
		{"line feed in a member", jsonOf("OKP Ed25519", func(m map[string]any) {
			x := m["x"].(string)
			m["x"] = x[:10] + "\n" + x[10:]
		}), ErrJWKBadBase64},
		{"carriage return in a member", jsonOf("OKP Ed25519", func(m map[string]any) {
			x := m["x"].(string)
			m["x"] = x + "\r"
		}), ErrJWKBadBase64},
		{"RSA e with a leading zero", jsonOf("RSA", func(m map[string]any) { m["e"] = "AAEAAQ" }), ErrJWKNotMinimal},
		{"RSA n with a leading zero", jsonOf("RSA", func(m map[string]any) {
			n, _ := b64url.DecodeString(m["n"].(string))
			m["n"] = b64(append([]byte{0}, n...))
		}), ErrJWKNotMinimal},
		{"RSA no n", jsonOf("RSA", func(m map[string]any) { delete(m, "n") }), ErrJWKMissingMember},
		{"RSA no e", jsonOf("RSA", func(m map[string]any) { delete(m, "e") }), ErrJWKMissingMember},
		{"RSA oth", jsonOf("RSA", func(m map[string]any) { m["oth"] = []any{} }), ErrJWKRSAOth},
		{"RSA oth on public", jsonOf("RSA", func(m map[string]any) {
			for _, n := range []string{"d", "p", "q", "dp", "dq", "qi"} {
				delete(m, n)
			}
			m["oth"] = []any{}
		}), ErrJWKRSAOth},
	}
	for _, crt := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		crt := crt
		cases = append(cases, struct {
			name string
			data []byte
			want error
		}{"RSA private without " + crt, jsonOf("RSA", func(m map[string]any) { delete(m, crt) }), ErrJWKRSAIncomplete})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseJSONWebKey(tc.data)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestJSONWebKeyMarshalValue: json.Marshal of a JSONWebKey or a
// JSONWebKeySet value (not a pointer) must write the wire format too.
func TestJSONWebKeyMarshalValue(t *testing.T) {
	k := testKeys(t)["OKP Ed25519"]
	b, err := json.Marshal(*k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseJSONWebKey(b); err != nil {
		t.Errorf("key value marshalled as %s, which does not parse: %v", b, err)
	}
	sb, err := json.Marshal(JSONWebKeySet{Keys: []*JSONWebKey{k}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseJSONWebKeySet(sb); err != nil {
		t.Errorf("set value marshalled as %s, which does not parse: %v", sb, err)
	}
	if eb, _ := json.Marshal(JSONWebKeySet{}); string(eb) != `{"keys":[]}` {
		t.Errorf("empty set value = %s", eb)
	}
}

func TestJSONWebKeySetMarshalNilKey(t *testing.T) {
	set := &JSONWebKeySet{Keys: []*JSONWebKey{testKeys(t)["EC P-256"], nil}}
	_, err := json.Marshal(set)
	if !errors.Is(err, ErrJWKSetMalformed) || !strings.Contains(err.Error(), "keys[1]") {
		t.Errorf("nil key in a set: err = %v, want ErrJWKSetMalformed naming keys[1]", err)
	}
}

// TestJSONWebKeyStrayPrivateMember: a member that belongs to another key
// type must not make a public key look private. An Ed25519 JWK with a
// stray RSA "p" and no "d" used to reach ed25519.NewKeyFromSeed(nil),
// which panics.
func TestJSONWebKeyStrayPrivateMember(t *testing.T) {
	x := b64(testKeys(t)["OKP Ed25519"].X)
	k, err := ParseJSONWebKey([]byte(`{"kty":"OKP","crv":"Ed25519","x":"` + x + `","p":"AQ"}`))
	if err != nil {
		t.Fatal(err)
	}
	if k.IsPrivate() {
		t.Error("Ed25519 key with only a stray RSA member reports IsPrivate")
	}
	if _, err := k.PrivateKey(); !errors.Is(err, ErrJWKMissingMember) {
		t.Errorf("PrivateKey: err = %v, want ErrJWKMissingMember", err)
	}
	// The same key with its own "d" is still private and converts.
	priv := testKeys(t)["OKP Ed25519"]
	if !priv.IsPrivate() {
		t.Error("Ed25519 key with d is not private")
	}
	if _, err := priv.PrivateKey(); err != nil {
		t.Errorf("Ed25519 PrivateKey: %v", err)
	}
}

func TestJSONWebKeyRSAEvenModulus(t *testing.T) {
	k := &JSONWebKey{Kty: JWKKtyRSA, N: fill(256, 0xFE), E: []byte{1, 0, 1}}
	if err := k.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if _, err := k.PublicKey(); !errors.Is(err, ErrJWKInvalidPublicKey) {
		t.Errorf("even modulus: err = %v, want ErrJWKInvalidPublicKey", err)
	}
}

// TestJSONWebKeyFromRSAWithoutCRT: an RSA key with no cached CRT values
// exports when they can be computed and is refused, not panicked on, when
// they cannot (Precompute has no way to report that).
func TestJSONWebKeyFromRSAWithoutCRT(t *testing.T) {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fresh := func(d *big.Int) *rsa.PrivateKey {
		return &rsa.PrivateKey{PublicKey: rk.PublicKey, D: d, Primes: rk.Primes}
	}
	k, err := NewJSONWebKeyFromPrivate(fresh(rk.D))
	if err != nil {
		t.Fatalf("valid key without cached CRT values: %v", err)
	}
	if len(k.DP) == 0 || len(k.DQ) == 0 || len(k.QI) == 0 {
		t.Error("CRT members not filled in")
	}
	for name, bad := range map[string]*rsa.PrivateKey{
		"D does not fit the primes": fresh(big.NewInt(1)),
		"no D":                      fresh(nil),
	} {
		if _, err := NewJSONWebKeyFromPrivate(bad); !errors.Is(err, ErrJWKInvalidPrivateKey) {
			t.Errorf("%s: err = %v, want ErrJWKInvalidPrivateKey", name, err)
		}
	}
}

func TestJSONWebKeyPrivateMismatch(t *testing.T) {
	keys := testKeys(t)
	other := testKeys(t)
	for _, name := range []string{"RSA", "EC P-256", "EC P-384", "OKP Ed25519", "OKP X25519"} {
		t.Run(name, func(t *testing.T) {
			k := *keys[name]
			o := other[name]
			k.D = o.D
			if name == "RSA" {
				k.P, k.Q, k.DP, k.DQ, k.QI = o.P, o.Q, o.DP, o.DQ, o.QI
			}
			if _, err := k.PrivateKey(); !errors.Is(err, ErrJWKInvalidPrivateKey) {
				t.Errorf("err = %v, want ErrJWKInvalidPrivateKey", err)
			}
		})
	}
	t.Run("RSA wrong dp", func(t *testing.T) {
		k := *keys["RSA"]
		dp := new(big.Int).SetBytes(k.DP)
		k.DP = dp.Add(dp, big.NewInt(2)).Bytes()
		if _, err := k.PrivateKey(); !errors.Is(err, ErrJWKInvalidPrivateKey) {
			t.Errorf("err = %v, want ErrJWKInvalidPrivateKey", err)
		}
	})
	// The standard library's RSA check never looks at d, so a changed d
	// alone used to convert.
	t.Run("RSA d minus one", func(t *testing.T) {
		k := *keys["RSA"]
		d := new(big.Int).SetBytes(k.D)
		k.D = d.Sub(d, big.NewInt(1)).Bytes()
		if _, err := k.PrivateKey(); !errors.Is(err, ErrJWKInvalidPrivateKey) {
			t.Errorf("err = %v, want ErrJWKInvalidPrivateKey", err)
		}
	})
	t.Run("RSA d plus lambda still converts", func(t *testing.T) {
		// d + lcm(p-1, q-1) inverts e just as d does, and gives the same dp
		// and dq: an unreduced d is a valid private exponent.
		k := *keys["RSA"]
		p1 := new(big.Int).Sub(new(big.Int).SetBytes(k.P), big.NewInt(1))
		q1 := new(big.Int).Sub(new(big.Int).SetBytes(k.Q), big.NewInt(1))
		lambda := new(big.Int).Div(new(big.Int).Mul(p1, q1), new(big.Int).GCD(nil, nil, p1, q1))
		k.D = new(big.Int).Add(new(big.Int).SetBytes(k.D), lambda).Bytes()
		if _, err := k.PrivateKey(); err != nil {
			t.Errorf("an unreduced but valid d was refused: %v", err)
		}
	})
	t.Run("public only", func(t *testing.T) {
		if _, err := keys["EC P-256"].PublicJWK().PrivateKey(); !errors.Is(err, ErrJWKMissingMember) {
			t.Errorf("err = %v, want ErrJWKMissingMember", err)
		}
	})
}

// TestCheckRSAExponentD tests the d check on its own: the standard library
// verifies d only from Go 1.26 on, so the end-to-end cases in
// TestJSONWebKeyPrivateMismatch cannot show the check works on 1.25.
func TestCheckRSAExponentD(t *testing.T) {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	with := func(d *big.Int) *rsa.PrivateKey {
		return &rsa.PrivateKey{PublicKey: rk.PublicKey, D: d, Primes: rk.Primes,
			Precomputed: rsa.PrecomputedValues{Dp: rk.Precomputed.Dp, Dq: rk.Precomputed.Dq, Qinv: rk.Precomputed.Qinv}}
	}
	if err := checkRSAExponentD(with(rk.D)); err != nil {
		t.Fatalf("the generated key: %v", err)
	}
	if err := checkRSAExponentD(with(new(big.Int).Sub(rk.D, big.NewInt(1)))); !errors.Is(err, ErrJWKInvalidPrivateKey) {
		t.Errorf("d-1: err = %v, want ErrJWKInvalidPrivateKey", err)
	}
	if err := checkRSAExponentD(with(new(big.Int).Add(rk.D, big.NewInt(1)))); !errors.Is(err, ErrJWKInvalidPrivateKey) {
		t.Errorf("d+1: err = %v, want ErrJWKInvalidPrivateKey", err)
	}
	// An unreduced d (d + lambda) inverts e the same way and is accepted.
	p1 := new(big.Int).Sub(rk.Primes[0], big.NewInt(1))
	q1 := new(big.Int).Sub(rk.Primes[1], big.NewInt(1))
	lambda := new(big.Int).Div(new(big.Int).Mul(p1, q1), new(big.Int).GCD(nil, nil, p1, q1))
	if err := checkRSAExponentD(with(new(big.Int).Add(rk.D, lambda))); err != nil {
		t.Errorf("d+lambda: %v", err)
	}
	// A degenerate prime is refused, not divided by zero.
	bad := with(rk.D)
	bad.Primes = []*big.Int{big.NewInt(1), rk.Primes[1]}
	if err := checkRSAExponentD(bad); !errors.Is(err, ErrJWKInvalidPrivateKey) {
		t.Errorf("prime 1: err = %v, want ErrJWKInvalidPrivateKey", err)
	}
}

func TestJSONWebKeyFromGoKeyRejects(t *testing.T) {
	ek, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if _, err := NewJSONWebKeyFromPrivate(ek); !errors.Is(err, ErrJWKUnsupportedCurve) {
		t.Errorf("P-521: err = %v", err)
	}
	if _, err := NewJSONWebKeyFromPublic("a string"); !errors.Is(err, ErrJWKUnsupportedGoKey) {
		t.Errorf("string: err = %v", err)
	}
	mp, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048) //lint:ignore SA1019 a multi-prime key is the case under test
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewJSONWebKeyFromPrivate(mp); !errors.Is(err, ErrJWKRSAOth) {
		t.Errorf("multi-prime RSA: err = %v, want ErrJWKRSAOth", err)
	}
}

func TestJSONWebKeySet(t *testing.T) {
	keys := testKeys(t)
	set := &JSONWebKeySet{}
	for _, name := range []string{"RSA", "EC P-256", "OKP Ed25519", "AKP ML-DSA-44"} {
		set.Keys = append(set.Keys, keys[name])
	}
	b, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseJSONWebKeySet(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	b2, _ := json.Marshal(got)
	if !bytes.Equal(b, b2) {
		t.Errorf("set round trip differs")
	}

	empty, _ := json.Marshal(&JSONWebKeySet{})
	if string(empty) != `{"keys":[]}` {
		t.Errorf("empty set = %s", empty)
	}

	for name, data := range map[string]string{
		"no keys":       `{"other":[]}`,
		"keys object":   `{"keys":{}}`,
		"not an object": `[]`,
	} {
		if _, err := ParseJSONWebKeySet([]byte(data)); !errors.Is(err, ErrJWKSetMalformed) {
			t.Errorf("%s: err = %v, want ErrJWKSetMalformed", name, err)
		}
	}
	bad := `{"keys":[` + string(mustMarshalJWK(t, keys["EC P-256"])) + `,{"kty":"EC"}]}`
	if _, err := ParseJSONWebKeySet([]byte(bad)); !errors.Is(err, ErrJWKMissingMember) {
		t.Errorf("one bad key: err = %v, want ErrJWKMissingMember", err)
	}
}

// TestJSONWebKeySetNamesBadKey checks that a set refused for one key says
// which key: its index in "keys" and its kid when it has a string one.
func TestJSONWebKeySetNamesBadKey(t *testing.T) {
	good := string(mustMarshalJWK(t, testKeys(t)["EC P-256"]))
	for _, tc := range []struct {
		name, bad, want string
		sentinel        error
	}{
		{"with kid", `{"kty":"XYZ","kid":"k-17"}`, `keys[1] (kid "k-17"): `, ErrJWKUnsupportedKty},
		{"no kid", `{"kty":"XYZ"}`, "keys[1]: ", ErrJWKUnsupportedKty},
		{"non-string kid", `{"kty":"XYZ","kid":7}`, "keys[1]: ", ErrJWKMemberType},
	} {
		_, err := ParseJSONWebKeySet([]byte(`{"keys":[` + good + `,` + tc.bad + `]}`))
		if !errors.Is(err, tc.sentinel) {
			t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.sentinel)
		}
		if msg := err.Error(); !strings.Contains(msg, tc.want) {
			t.Errorf("%s: err %q does not name %q", tc.name, msg, tc.want)
		}
	}
}

// TestJSONWebKeyThumbprintRFC7638 checks the thumbprint against the worked
// example of RFC 7638 section 3.1.
func TestJSONWebKeyThumbprintRFC7638(t *testing.T) {
	const doc = `{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}`
	k, err := ParseJSONWebKey([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	tp, err := k.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if want := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"; tp != want {
		t.Errorf("thumbprint %s, want %s", tp, want)
	}
}

// TestJSONWebKeyDraftVectors parses the draft's Appendix A keys (the J2
// testdata) with the codec: kid is the codec's thumbprint, the stdlib keys
// convert and check, and marshalling gives the same members back.
func TestJSONWebKeyDraftVectors(t *testing.T) {
	for _, vec := range jwkVectors {
		t.Run(vec.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", "dnssec-jwk", vec.name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			k, err := ParseJSONWebKey(data)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if k.IsPrivate() != vec.private {
				t.Errorf("IsPrivate = %v, want %v", k.IsPrivate(), vec.private)
			}
			tp, err := k.Thumbprint()
			if err != nil || tp != k.Kid {
				t.Errorf("thumbprint %q (%v), kid %q", tp, err, k.Kid)
			}
			if k.IsPrivate() && k.Kty != JWKKtyAKP {
				if _, err := k.PrivateKey(); err != nil {
					t.Errorf("PrivateKey: %v", err)
				}
			}
			// Same members and values as the draft, "dnskey" aside.
			var want, got map[string]any
			if err := json.Unmarshal(data, &want); err != nil {
				t.Fatal(err)
			}
			delete(want, "dnskey")
			if err := json.Unmarshal(mustMarshalJWK(t, k), &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("re-marshalled JWK differs:\n got %v\nwant %v", got, want)
			}
		})
	}
}
