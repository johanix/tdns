/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Tests for the "dnskey" parameter and the draft's import rules
 * (dnssec_jwk_dnskey.go).
 */

package core

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/miekg/dns"
)

// genDNSKEY returns a DNSKEY made by miekg/dns and its private key as a
// JWK, for the algorithms the stdlib covers.
func genDNSKEY(t *testing.T, name string, alg uint8, bits int) (*dns.DNSKEY, *JSONWebKey) {
	t.Helper()
	rr := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: alg,
	}
	priv, err := rr.Generate(bits)
	if err != nil {
		t.Fatalf("generate %s: %v", algName(alg), err)
	}
	k, err := NewJSONWebKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("jwk %s: %v", algName(alg), err)
	}
	return rr, k
}

var stdlibAlgs = []struct {
	alg  uint8
	bits int
}{
	{dns.RSASHA256, 2048},
	{dns.RSASHA512, 2048},
	{dns.ECDSAP256SHA256, 256},
	{dns.ECDSAP384SHA384, 384},
	{dns.ED25519, 256},
}

func sameDNSKEY(a, b *dns.DNSKEY) bool {
	return a.Hdr.Name == b.Hdr.Name && a.Flags == b.Flags && a.Protocol == b.Protocol &&
		a.Algorithm == b.Algorithm && a.PublicKey == b.PublicKey
}

func TestDNSSECJWKRoundTrip(t *testing.T) {
	for _, a := range stdlibAlgs {
		t.Run(algName(a.alg), func(t *testing.T) {
			rr, priv := genDNSKEY(t, "example.com.", a.alg, a.bits)
			for _, withPriv := range []bool{false, true} {
				var p *JSONWebKey
				if withPriv {
					p = priv
				}
				d, err := NewDNSSECJWK(rr, p)
				if err != nil {
					t.Fatalf("NewDNSSECJWK: %v", err)
				}
				if d.Key.IsPrivate() != withPriv {
					t.Fatalf("IsPrivate = %v", d.Key.IsPrivate())
				}
				if d.Key.Kid == "" || d.DNSKEY.KeyTag == nil || *d.DNSKEY.KeyTag != rr.KeyTag() {
					t.Errorf("kid %q / keytag not set", d.Key.Kid)
				}
				if d.Key.Alg != "" {
					t.Errorf("alg %q on a non-AKP key", d.Key.Alg)
				}
				b, err := json.Marshal(d)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.HasSuffix(string(b), `"keytag":`+itoa(int(rr.KeyTag()))+`}}`) {
					t.Errorf("dnskey is not the last member: %s", b)
				}
				_, got, err := ParseDNSSECJWK(b)
				if err != nil {
					t.Fatalf("ParseDNSSECJWK: %v\n%s", err, b)
				}
				if !sameDNSKEY(got, rr) {
					t.Errorf("DNSKEY differs:\n got %s\nwant %s", got, rr)
				}
			}
		})
	}
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func TestDNSSECJWKEscapedName(t *testing.T) {
	const name = `b\000rken.example.com.`
	rr, priv := genDNSKEY(t, name, dns.ED25519, 256)
	d, err := NewDNSSECJWK(rr, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(d)
	if !strings.Contains(string(b), `"name":"b\\000rken.example.com."`) {
		t.Errorf("escaped name not kept in JSON: %s", b)
	}
	_, got, err := ParseDNSSECJWK(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hdr.Name != name {
		t.Errorf("name %q, want %q", got.Hdr.Name, name)
	}
	// The owner name's wire form has a zero octet in the first label.
	buf := make([]byte, 255)
	n, err := dns.PackDomainName(got.Hdr.Name, buf, 0, nil, false)
	if err != nil || string(buf[:n]) != "\x06b\x00rken\x07example\x03com\x00" {
		t.Errorf("wire name %q (%v)", buf[:n], err)
	}
}

// editJSON returns the JSON of d after edit has changed its members.
func editJSON(t *testing.T, d *DNSSECJWK, edit func(top, dnskey map[string]any)) []byte {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]any
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatal(err)
	}
	dk, _ := top["dnskey"].(map[string]any)
	edit(top, dk)
	out, _ := json.Marshal(top)
	return out
}

func TestDNSSECJWKRejects(t *testing.T) {
	rrEC, privEC := genDNSKEY(t, "example.com.", dns.ECDSAP256SHA256, 256)
	dEC, err := NewDNSSECJWK(rrEC, privEC)
	if err != nil {
		t.Fatal(err)
	}
	rrRSA, privRSA := genDNSKEY(t, "example.com.", dns.RSASHA256, 2048)
	dRSA, err := NewDNSSECJWK(rrRSA, privRSA)
	if err != nil {
		t.Fatal(err)
	}
	_, otherEC := genDNSKEY(t, "example.com.", dns.ECDSAP256SHA256, 256)

	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"no dnskey", editJSON(t, dEC, func(top, dk map[string]any) { delete(top, "dnskey") }), ErrDNSKEYParamMissing},
		{"dnskey not an object", editJSON(t, dEC, func(top, dk map[string]any) { top["dnskey"] = "example.com." }), ErrDNSKEYParamMalformed},
		{"dnskey missing name", editJSON(t, dEC, func(top, dk map[string]any) { delete(dk, "name") }), ErrDNSKEYParamMalformed},
		{"dnskey missing flags", editJSON(t, dEC, func(top, dk map[string]any) { delete(dk, "flags") }), ErrDNSKEYParamMalformed},
		{"dnskey missing protocol", editJSON(t, dEC, func(top, dk map[string]any) { delete(dk, "protocol") }), ErrDNSKEYParamMalformed},
		{"dnskey missing algorithm", editJSON(t, dEC, func(top, dk map[string]any) { delete(dk, "algorithm") }), ErrDNSKEYParamMalformed},
		{"name not a string", editJSON(t, dEC, func(top, dk map[string]any) { dk["name"] = 7 }), ErrDNSKEYParamMalformed},
		{"flags a string", editJSON(t, dEC, func(top, dk map[string]any) { dk["flags"] = "256" }), ErrDNSKEYParamMalformed},
		{"flags fractional", editJSON(t, dEC, func(top, dk map[string]any) { dk["flags"] = 256.5 }), ErrDNSKEYParamMalformed},
		{"flags out of range", editJSON(t, dEC, func(top, dk map[string]any) { dk["flags"] = 65536 }), ErrDNSKEYParamMalformed},
		{"algorithm negative", editJSON(t, dEC, func(top, dk map[string]any) { dk["algorithm"] = -13 }), ErrDNSKEYParamMalformed},
		{"keytag not an integer", editJSON(t, dEC, func(top, dk map[string]any) { dk["keytag"] = true }), ErrDNSKEYParamMalformed},
		{"name without trailing dot", editJSON(t, dEC, func(top, dk map[string]any) { dk["name"] = "example.com" }), ErrDNSKEYName},
		{"name with empty label", editJSON(t, dEC, func(top, dk map[string]any) { dk["name"] = "example..com." }), ErrDNSKEYName},
		{"protocol 2", editJSON(t, dEC, func(top, dk map[string]any) { dk["protocol"] = 2 }), ErrDNSKEYProtocol},
		{"EC key under RSA algorithm", editJSON(t, dEC, func(top, dk map[string]any) { dk["algorithm"] = 8 }), ErrDNSKEYKeyTypeMismatch},
		{"P-256 key under P-384 algorithm", editJSON(t, dEC, func(top, dk map[string]any) { dk["algorithm"] = 14 }), ErrDNSKEYKeyTypeMismatch},
		{"EC key under Ed25519", editJSON(t, dEC, func(top, dk map[string]any) { dk["algorithm"] = 15 }), ErrDNSKEYKeyTypeMismatch},
		{"RSA key under ML-DSA-44", editJSON(t, dRSA, func(top, dk map[string]any) { dk["algorithm"] = 18 }), ErrDNSKEYKeyTypeMismatch},
		{"AKP alg on an EC key", editJSON(t, dEC, func(top, dk map[string]any) { top["alg"] = "ML-DSA-44" }), ErrDNSKEYKeyTypeMismatch},
		{"DSA algorithm", editJSON(t, dEC, func(top, dk map[string]any) { dk["algorithm"] = 3 }), ErrNoJWKRepresentation},
		{"wrong keytag", editJSON(t, dEC, func(top, dk map[string]any) { dk["keytag"] = int(rrEC.KeyTag()) ^ 1 }), ErrDNSKEYKeyTag},
		{"flags changed under the keytag", editJSON(t, dEC, func(top, dk map[string]any) { dk["flags"] = 256 }), ErrDNSKEYKeyTag},
		{"mismatched EC private key", editJSON(t, dEC, func(top, dk map[string]any) { top["d"] = b64(otherEC.D) }), ErrDNSKEYPrivateMismatch},
		{"RSA private missing qi", editJSON(t, dRSA, func(top, dk map[string]any) { delete(top, "qi") }), ErrJWKRSAIncomplete},
		{"RSA oth present", editJSON(t, dRSA, func(top, dk map[string]any) { top["oth"] = []any{map[string]any{"r": "AQ", "d": "AQ", "t": "AQ"}} }), ErrJWKRSAOth},
		{"no kty", editJSON(t, dEC, func(top, dk map[string]any) { delete(top, "kty") }), ErrJWKMissingMember},
		{"missing y", editJSON(t, dEC, func(top, dk map[string]any) { delete(top, "y") }), ErrJWKMissingMember},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ParseDNSSECJWK(tc.data)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v\n%s", err, tc.want, tc.data)
			}
		})
	}
}

func TestDNSSECJWKKeytagOptional(t *testing.T) {
	rr, priv := genDNSKEY(t, "example.com.", dns.ED25519, 256)
	d, _ := NewDNSSECJWK(rr, priv)
	b := editJSON(t, d, func(top, dk map[string]any) {
		delete(dk, "keytag")
		dk["future-member"] = map[string]any{"x": 1}
	})
	_, got, err := ParseDNSSECJWK(b)
	if err != nil {
		t.Fatalf("no keytag, unknown member: %v", err)
	}
	if !sameDNSKEY(got, rr) {
		t.Errorf("DNSKEY differs")
	}
}

func TestNewDNSSECJWKRejects(t *testing.T) {
	rr, _ := genDNSKEY(t, "example.com.", dns.ECDSAP256SHA256, 256)
	_, other := genDNSKEY(t, "example.com.", dns.ECDSAP256SHA256, 256)
	if _, err := NewDNSSECJWK(rr, other); !errors.Is(err, ErrDNSKEYPrivateMismatch) {
		t.Errorf("other key's private JWK: err = %v", err)
	}
	ek, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384, _ := NewJSONWebKeyFromPrivate(ek)
	if _, err := NewDNSSECJWK(rr, p384); !errors.Is(err, ErrDNSKEYPrivateMismatch) {
		t.Errorf("P-384 private JWK for a P-256 DNSKEY: err = %v", err)
	}
	noDot := *rr
	noDot.Hdr.Name = "example.com"
	if _, err := NewDNSSECJWK(&noDot, nil); !errors.Is(err, ErrDNSKEYName) {
		t.Errorf("name without dot: err = %v", err)
	}
	p2 := *rr
	p2.Protocol = 2
	if _, err := NewDNSSECJWK(&p2, nil); !errors.Is(err, ErrDNSKEYProtocol) {
		t.Errorf("protocol 2: err = %v", err)
	}
	short := *rr
	short.PublicKey = "AAAA"
	if _, err := NewDNSSECJWK(&short, nil); !errors.Is(err, ErrDNSKEYPublicKey) {
		t.Errorf("short EC key: err = %v", err)
	}
}

// TestNoJWKRepresentation: the algorithms the draft (section 2.5) and the
// tdns registry leave without a JWK form fail with ErrNoJWKRepresentation
// in both directions.
func TestNoJWKRepresentation(t *testing.T) {
	_, ek, _ := ed25519.GenerateKey(rand.Reader)
	edJWK, _ := NewJSONWebKeyFromPrivate(ek)
	noJWK := []uint8{
		dns.DSA, dns.DSANSEC3SHA1, dns.ECCGOST, 17, 23, // draft section 2.5
		202,      // SLH-DSA-128s
		203, 204, // Falcon
		205, 206, 207, 208, // MAYO
		209, 210, 211, // SNOVA
		212, // SQIsign
		213, // QR-UOV
		214, // CROSS
		250, // unassigned
	}
	for _, alg := range noJWK {
		if HasJWKRepresentation(alg) {
			t.Errorf("%s: HasJWKRepresentation", algName(alg))
		}
		rr := &dns.DNSKEY{
			Hdr:   dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
			Flags: 256, Protocol: 3, Algorithm: alg, PublicKey: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		}
		if _, err := NewDNSSECJWK(rr, nil); !errors.Is(err, ErrNoJWKRepresentation) {
			t.Errorf("export %s: err = %v", algName(alg), err)
		}
		d := &DNSSECJWK{Key: edJWK, DNSKEY: &DNSKEYParam{Name: "example.com.", Flags: 256, Protocol: 3, Algorithm: alg}}
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := ParseDNSSECJWK(b); !errors.Is(err, ErrNoJWKRepresentation) {
			t.Errorf("import %s: err = %v", algName(alg), err)
		}
	}
	for _, alg := range []uint8{5, 7, 8, 10, 13, 14, 15, 16, 18, 200, 201} {
		if !HasJWKRepresentation(alg) {
			t.Errorf("%s: no JWK representation", algName(alg))
		}
	}
}

// The tdns package registers the CIRCL checks in real binaries; core's
// tests register the same ones (CIRCL is a test-only dependency here).
func init() {
	seed32 := func(priv []byte) (*[32]byte, error) {
		if len(priv) != 32 {
			return nil, errors.New("seed is not 32 octets")
		}
		var s [32]byte
		copy(s[:], priv)
		return &s, nil
	}
	RegisterJWKKeyPairCheck(JWKKtyOKP, JWKCrvEd448, func(priv []byte) ([]byte, error) {
		if len(priv) != ed448.SeedSize {
			return nil, errors.New("bad Ed448 seed size")
		}
		return ed448.NewKeyFromSeed(priv).Public().(ed448.PublicKey), nil
	})
	RegisterJWKKeyPairCheck(JWKKtyAKP, JWKAlgMLDSA44, func(priv []byte) ([]byte, error) {
		s, err := seed32(priv)
		if err != nil {
			return nil, err
		}
		pk, _ := mldsa44.NewKeyFromSeed(s)
		return pk.Bytes(), nil
	})
	RegisterJWKKeyPairCheck(JWKKtyAKP, JWKAlgMLDSA65, func(priv []byte) ([]byte, error) {
		s, err := seed32(priv)
		if err != nil {
			return nil, err
		}
		pk, _ := mldsa65.NewKeyFromSeed(s)
		return pk.Bytes(), nil
	})
	RegisterJWKKeyPairCheck(JWKKtyAKP, JWKAlgMLDSA87, func(priv []byte) ([]byte, error) {
		s, err := seed32(priv)
		if err != nil {
			return nil, err
		}
		pk, _ := mldsa87.NewKeyFromSeed(s)
		return pk.Bytes(), nil
	})
}

// TestCheckKeyPairCIRCL covers rule 5 for the key types the stdlib has no
// type for, with the checks registered: a key made from a seed passes, a
// wrong seed fails.
func TestCheckKeyPairCIRCL(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	edPub := ed448.NewKeyFromSeed(fill(57, 9)).Public().(ed448.PublicKey)
	pk44, _ := mldsa44.NewKeyFromSeed(&seed)
	pk65, _ := mldsa65.NewKeyFromSeed(&seed)
	pk87, _ := mldsa87.NewKeyFromSeed(&seed)
	for _, k := range []*JSONWebKey{
		{Kty: JWKKtyOKP, Crv: JWKCrvEd448, X: []byte(edPub), D: fill(57, 9)},
		{Kty: JWKKtyAKP, Alg: JWKAlgMLDSA44, Pub: pk44.Bytes(), Priv: seed[:]},
		{Kty: JWKKtyAKP, Alg: JWKAlgMLDSA65, Pub: pk65.Bytes(), Priv: seed[:]},
		{Kty: JWKKtyAKP, Alg: JWKAlgMLDSA87, Pub: pk87.Bytes(), Priv: seed[:]},
	} {
		name := k.Kty + " " + k.Crv + k.Alg
		if err := k.CheckKeyPair(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		bad := *k
		if k.Kty == JWKKtyAKP {
			bad.Priv = fill(32, 0xee)
		} else {
			bad.D = fill(57, 0xee)
		}
		if err := bad.CheckKeyPair(); !errors.Is(err, ErrDNSKEYPrivateMismatch) {
			t.Errorf("%s wrong private: err = %v", name, err)
		}
	}
	x448 := &JSONWebKey{Kty: JWKKtyOKP, Crv: JWKCrvX448, X: fill(56, 1), D: fill(56, 2)}
	if err := x448.CheckKeyPair(); !errors.Is(err, ErrNoKeyPairCheck) {
		t.Errorf("X448: err = %v, want ErrNoKeyPairCheck", err)
	}
}

// TestCheckKeyPairUnregistered: a binary without the CIRCL checks refuses
// Ed448 and ML-DSA private keys rather than passing them unchecked, and
// the import path reports that as a rule-5 failure.
func TestCheckKeyPairUnregistered(t *testing.T) {
	keyPairChecksMu.Lock()
	saved := keyPairChecks
	keyPairChecks = map[string]JWKKeyPairCheck{}
	keyPairChecksMu.Unlock()
	defer func() {
		keyPairChecksMu.Lock()
		keyPairChecks = saved
		keyPairChecksMu.Unlock()
	}()
	for _, k := range []*JSONWebKey{
		{Kty: JWKKtyOKP, Crv: JWKCrvEd448, X: fill(57, 1), D: fill(57, 2)},
		{Kty: JWKKtyAKP, Alg: JWKAlgMLDSA44, Pub: fill(1312, 1), Priv: fill(32, 2)},
	} {
		if err := k.CheckKeyPair(); !errors.Is(err, ErrNoKeyPairCheck) {
			t.Errorf("%s %s%s: err = %v, want ErrNoKeyPairCheck", k.Kty, k.Crv, k.Alg, err)
		}
		if err := k.PublicJWK().CheckKeyPair(); err != nil {
			t.Errorf("public %s: %v", k.Kty, err)
		}
	}
	data, err := os.ReadFile(filepath.Join("testdata", "dnssec-jwk", "mldsa44.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseDNSSECJWK(data); !errors.Is(err, ErrNoKeyPairCheck) {
		t.Errorf("ML-DSA-44 vector without a check: err = %v", err)
	}
}

func TestRSAExponentEncoding(t *testing.T) {
	// A long exponent takes the three-octet length form of RFC 3110.
	k := &JSONWebKey{Kty: JWKKtyRSA, N: fill(256, 0xc1), E: fill(300, 1)}
	pk, err := dnskeyPublicKeyBytes(k)
	if err != nil {
		t.Fatal(err)
	}
	if pk[0] != 0 || int(pk[1])<<8|int(pk[2]) != 300 {
		t.Fatalf("length prefix % x", pk[:3])
	}
	back, err := jwkFromDNSKEYPublicKey(dns.RSASHA256, pk)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.E) != 300 || len(back.N) != 256 {
		t.Errorf("e %d n %d octets", len(back.E), len(back.N))
	}
	if _, err := jwkFromDNSKEYPublicKey(dns.RSASHA256, []byte{5, 1, 2}); !errors.Is(err, ErrDNSKEYPublicKey) {
		t.Errorf("truncated: err = %v", err)
	}
}

// TestDNSSECJWKDraftVectorsEndToEnd runs every Appendix A vector (the J2
// testdata) through the five import rules, compares the DNSKEY with the
// draft's RR, and exports it again: the export must equal the draft's JWK.
func TestDNSSECJWKDraftVectorsEndToEnd(t *testing.T) {
	for _, vec := range jwkVectors {
		t.Run(vec.name, func(t *testing.T) {
			dir := filepath.Join("testdata", "dnssec-jwk")
			data, err := os.ReadFile(filepath.Join(dir, vec.name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			rrText, err := os.ReadFile(filepath.Join(dir, vec.dnskeyFile))
			if err != nil {
				t.Fatal(err)
			}
			draftRR, err := dns.NewRR(string(rrText))
			if err != nil {
				t.Fatal(err)
			}
			want := draftRR.(*dns.DNSKEY)

			d, rr, err := ParseDNSSECJWK(data)
			if err != nil {
				t.Fatalf("import: %v", err)
			}
			if !sameDNSKEY(rr, want) || rr.KeyTag() != vec.draftTag {
				t.Fatalf("DNSKEY\n got %s\nwant %s", rr, want)
			}
			if d.Key.IsPrivate() != vec.private {
				t.Errorf("IsPrivate = %v", d.Key.IsPrivate())
			}

			var priv *JSONWebKey
			if vec.private {
				priv = d.Key
			}
			out, err := NewDNSSECJWK(want, priv)
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			b, err := json.Marshal(out)
			if err != nil {
				t.Fatal(err)
			}
			var gotM, wantM map[string]any
			if err := json.Unmarshal(b, &gotM); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(data, &wantM); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(gotM, wantM) {
				t.Errorf("export differs from the draft:\n got %s\nwant %s", b, data)
			}
		})
	}
}

// TestRegistryOnlyAlgorithmNote pins which algorithms an export warns
// about: only the registry's ML-DSA-65 and -87 numbers.
func TestRegistryOnlyAlgorithmNote(t *testing.T) {
	for alg, name := range map[uint8]string{200: "ML-DSA-65", 201: "ML-DSA-87"} {
		note := RegistryOnlyAlgorithmNote(alg)
		for _, want := range []string{name, "dnssec-algorithms registry", "IANA", "same number"} {
			if !strings.Contains(note, want) {
				t.Errorf("algorithm %d: note %q lacks %q", alg, note, want)
			}
		}
		if strings.Contains(note, "\n") {
			t.Errorf("algorithm %d: note is not one line: %q", alg, note)
		}
	}
	for _, alg := range []uint8{dns.RSASHA256, dns.ECDSAP256SHA256, dns.ED25519, dns.ED448, 18, 199, 202} {
		if note := RegistryOnlyAlgorithmNote(alg); note != "" {
			t.Errorf("algorithm %d: unexpected note %q", alg, note)
		}
	}
}
