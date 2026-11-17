/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Tests for the "sig0key" parameter (dnssec_jwk_sig0key.go).
 */

package core

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// genSIG0Key makes a KEY RR the way tdns's GenerateKeyMaterial does
// (flags 256, protocol 3), and returns it in the text form the keystore
// stores (keyrr column) read back, plus the private key as a JWK.
func genSIG0Key(t *testing.T, owner string, alg uint8, bits int) (*dns.KEY, *JSONWebKey) {
	t.Helper()
	key := new(dns.KEY)
	key.Hdr = dns.RR_Header{Name: owner, Rrtype: dns.TypeKEY, Class: dns.ClassINET, Ttl: 3600}
	key.Algorithm = alg
	key.Flags = 256
	key.Protocol = 3
	priv, err := key.Generate(bits)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	stored, err := dns.NewRR(key.String())
	if err != nil {
		t.Fatalf("keyrr %q: %v", key.String(), err)
	}
	k, err := NewJSONWebKeyFromPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	return stored.(*dns.KEY), k
}

func sameKEY(a, b *dns.KEY) bool {
	return a.Hdr.Name == b.Hdr.Name && a.Hdr.Rrtype == b.Hdr.Rrtype && sameDNSKEY(&a.DNSKEY, &b.DNSKEY)
}

func TestSIG0JWKRoundTrip(t *testing.T) {
	for _, a := range stdlibAlgs {
		t.Run(algName(a.alg), func(t *testing.T) {
			key, priv := genSIG0Key(t, "child.example.com.", a.alg, a.bits)
			for _, p := range []*JSONWebKey{nil, priv} {
				d, err := NewSIG0JWK(key, p)
				if err != nil {
					t.Fatalf("NewSIG0JWK: %v", err)
				}
				if d.DNSKEY != nil || d.Sig0Key == nil {
					t.Fatalf("parameters: dnskey %v sig0key %v", d.DNSKEY, d.Sig0Key)
				}
				b, err := json.Marshal(d)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(b), `"dnskey"`) || !strings.Contains(string(b), `"sig0key":{"name":"child.example.com.","flags":256,"protocol":3,`) {
					t.Errorf("JSON: %s", b)
				}
				_, got, err := ParseSIG0JWK(b)
				if err != nil {
					t.Fatalf("ParseSIG0JWK: %v", err)
				}
				if !sameKEY(got, key) {
					t.Errorf("KEY differs:\n got %s\nwant %s", got, key)
				}
				_, gotRR, err := ParseKeyJWK(b)
				if err != nil {
					t.Fatalf("ParseKeyJWK: %v", err)
				}
				if k, ok := gotRR.(*dns.KEY); !ok || !sameKEY(k, key) {
					t.Errorf("ParseKeyJWK gave %T %v", gotRR, gotRR)
				}
			}
		})
	}
}

// TestSIG0KeyNeverAsDNSKEY pins the fail-safe: a SIG(0) key cannot be
// written with "dnskey", and a DNSSEC consumer refuses a "sig0key" JWK.
func TestSIG0KeyNeverAsDNSKEY(t *testing.T) {
	key, priv := genSIG0Key(t, "child.example.com.", dns.ED25519, 256)

	// The KEY's embedded DNSKEY still says KEY in its header.
	if _, err := NewDNSSECJWK(&key.DNSKEY, priv); err == nil {
		t.Fatal("NewDNSSECJWK accepted a KEY RR")
	}
	d, err := NewSIG0JWK(key, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(d)
	if _, _, err := ParseDNSSECJWK(b); !errors.Is(err, ErrDNSKEYParamMissing) {
		t.Errorf("DNSSEC import of a SIG(0) JWK: err = %v, want ErrDNSKEYParamMissing", err)
	}
	if _, err := d.ToDNSKEY(); !errors.Is(err, ErrDNSKEYParamMissing) {
		t.Errorf("ToDNSKEY on a SIG(0) JWK: err = %v", err)
	}
	// A consumer that only knows "dnskey" and drops unknown members sees
	// no "dnskey" either.
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["dnskey"]; ok {
		t.Errorf("SIG(0) JWK has a dnskey member")
	}

	both := &DNSSECJWK{Key: d.Key, DNSKEY: d.Sig0Key, Sig0Key: d.Sig0Key}
	if _, err := json.Marshal(both); !errors.Is(err, ErrBothKeyParams) {
		t.Errorf("marshal with both: err = %v", err)
	}
	if _, err := both.ToKEY(); !errors.Is(err, ErrBothKeyParams) {
		t.Errorf("ToKEY with both: err = %v", err)
	}
	if _, err := both.ToDNSKEY(); !errors.Is(err, ErrBothKeyParams) {
		t.Errorf("ToDNSKEY with both: err = %v", err)
	}
}

func TestSIG0JWKBothAndNeither(t *testing.T) {
	key, priv := genSIG0Key(t, "child.example.com.", dns.ECDSAP256SHA256, 256)
	d, err := NewSIG0JWK(key, priv)
	if err != nil {
		t.Fatal(err)
	}
	both := editJSON(t, d, func(top, s0 map[string]any) {})
	var m map[string]any
	_ = json.Unmarshal(both, &m)
	m["dnskey"] = m["sig0key"]
	both, _ = json.Marshal(m)
	delete(m, "dnskey")
	delete(m, "sig0key")
	neither, _ := json.Marshal(m)

	for name, parse := range map[string]func([]byte) error{
		"ParseSIG0JWK":   func(b []byte) error { _, _, err := ParseSIG0JWK(b); return err },
		"ParseDNSSECJWK": func(b []byte) error { _, _, err := ParseDNSSECJWK(b); return err },
		"ParseKeyJWK":    func(b []byte) error { _, _, err := ParseKeyJWK(b); return err },
	} {
		if err := parse(both); !errors.Is(err, ErrBothKeyParams) {
			t.Errorf("%s both: err = %v, want ErrBothKeyParams", name, err)
		}
	}
	if _, _, err := ParseKeyJWK(neither); !errors.Is(err, ErrNoKeyParam) {
		t.Errorf("ParseKeyJWK neither: err = %v", err)
	}
	if _, _, err := ParseSIG0JWK(neither); !errors.Is(err, ErrSig0KeyParamMissing) {
		t.Errorf("ParseSIG0JWK neither: err = %v", err)
	}
	if _, _, err := ParseDNSSECJWK(neither); !errors.Is(err, ErrDNSKEYParamMissing) {
		t.Errorf("ParseDNSSECJWK neither: err = %v", err)
	}
	// A DNSSEC JWK is not a SIG(0) JWK.
	rr, dpriv := genDNSKEY(t, "example.com.", dns.ED25519, 256)
	dd, _ := NewDNSSECJWK(rr, dpriv)
	db, _ := json.Marshal(dd)
	if _, _, err := ParseSIG0JWK(db); !errors.Is(err, ErrSig0KeyParamMissing) {
		t.Errorf("ParseSIG0JWK of a DNSSEC JWK: err = %v", err)
	}
	if _, got, err := ParseKeyJWK(db); err != nil {
		t.Errorf("ParseKeyJWK of a DNSSEC JWK: %v", err)
	} else if _, ok := got.(*dns.DNSKEY); !ok {
		t.Errorf("ParseKeyJWK of a DNSSEC JWK gave %T", got)
	}
}

// TestSIG0JWKFlagsKept: KEY flags have KEY-RR meaning and are written and
// read as stored, whatever they are.
func TestSIG0JWKFlagsKept(t *testing.T) {
	key, priv := genSIG0Key(t, "child.example.com.", dns.ED25519, 256)
	key.Flags = 0x0200 // a host/user/zone bit pattern other than 256
	d, err := NewSIG0JWK(key, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(d)
	_, got, err := ParseSIG0JWK(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Flags != 0x0200 || got.KeyTag() != key.KeyTag() {
		t.Errorf("flags %d keytag %d, want %d %d", got.Flags, got.KeyTag(), 0x0200, key.KeyTag())
	}
}

func TestSIG0JWKRejects(t *testing.T) {
	key, priv := genSIG0Key(t, "child.example.com.", dns.ECDSAP256SHA256, 256)
	d, err := NewSIG0JWK(key, priv)
	if err != nil {
		t.Fatal(err)
	}
	_, other := genSIG0Key(t, "child.example.com.", dns.ECDSAP256SHA256, 256)
	rkey, rpriv := genSIG0Key(t, "child.example.com.", dns.RSASHA256, 2048)
	dr, err := NewSIG0JWK(rkey, rpriv)
	if err != nil {
		t.Fatal(err)
	}
	sig0 := func(d *DNSSECJWK, edit func(top, s0 map[string]any)) []byte {
		t.Helper()
		b, _ := json.Marshal(d)
		var top map[string]any
		_ = json.Unmarshal(b, &top)
		s0, _ := top["sig0key"].(map[string]any)
		edit(top, s0)
		out, _ := json.Marshal(top)
		return out
	}
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"sig0key not an object", sig0(d, func(top, s0 map[string]any) { top["sig0key"] = 1 }), ErrDNSKEYParamMalformed},
		{"missing algorithm", sig0(d, func(top, s0 map[string]any) { delete(s0, "algorithm") }), ErrDNSKEYParamMalformed},
		{"name without trailing dot", sig0(d, func(top, s0 map[string]any) { s0["name"] = "child.example.com" }), ErrDNSKEYName},
		{"protocol 2", sig0(d, func(top, s0 map[string]any) { s0["protocol"] = 2 }), ErrDNSKEYProtocol},
		{"wrong kty for the algorithm", sig0(d, func(top, s0 map[string]any) { s0["algorithm"] = 15 }), ErrDNSKEYKeyTypeMismatch},
		{"no JWK form", sig0(d, func(top, s0 map[string]any) { s0["algorithm"] = 6 }), ErrNoJWKRepresentation},
		{"wrong keytag", sig0(d, func(top, s0 map[string]any) { s0["keytag"] = int(key.KeyTag()) ^ 1 }), ErrDNSKEYKeyTag},
		{"mismatched private key", sig0(d, func(top, s0 map[string]any) { top["d"] = b64(other.D) }), ErrDNSKEYPrivateMismatch},
		{"RSA private missing dq", sig0(dr, func(top, s0 map[string]any) { delete(top, "dq") }), ErrJWKRSAIncomplete},
		{"RSA oth", sig0(dr, func(top, s0 map[string]any) { top["oth"] = []any{} }), ErrJWKRSAOth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := ParseSIG0JWK(tc.data); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	dnskeyRR, _ := genDNSKEY(t, "example.com.", dns.ED25519, 256)
	if _, err := NewSIG0JWK(&dns.KEY{DNSKEY: *dnskeyRR}, nil); !errors.Is(err, ErrDNSKEYParamMalformed) {
		t.Errorf("NewSIG0JWK of a DNSKEY: err = %v", err)
	}
	if _, err := NewSIG0JWK(key, other); !errors.Is(err, ErrDNSKEYPrivateMismatch) {
		t.Errorf("NewSIG0JWK with another key's private JWK: err = %v", err)
	}
}
