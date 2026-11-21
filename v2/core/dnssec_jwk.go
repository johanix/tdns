/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * JSON Web Key (RFC 7517) codec for DNSSEC and SIG(0) key material, after
 * draft-schlyter-dnsop-dnssec-jwk.
 *
 * This is additive: the P-256 JWK RR helpers in jwk_helpers.go (the
 * tdns-mp agent-discovery path) are untouched and do not use it.
 *
 * The codec works on the raw JWK members, not on algorithm packages, so
 * Ed448 and ML-DSA need nothing beyond the standard library here. The
 * private value of those two is the same octet string PKCS#8 holds (the
 * 57-byte Ed448 secret, the 32-byte ML-DSA seed), so a caller that can
 * open the PKCS#8 can fill the JWK and back. Converters to and from the
 * stdlib key types (RSA, ECDSA, Ed25519) live here too.
 */

package core

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// JWK key types (RFC 7518 section 6.1, RFC 8037, draft-ietf-cose-dilithium).
const (
	JWKKtyEC  = "EC"
	JWKKtyRSA = "RSA"
	JWKKtyOKP = "OKP"
	JWKKtyAKP = "AKP"
)

// JWK curves and AKP parameter sets the codec knows. X25519 and X448 are
// key-agreement curves: the codec carries them so they are never mistaken
// for Ed25519 or Ed448, but no DNSSEC algorithm uses them.
const (
	JWKCrvP256    = "P-256"
	JWKCrvP384    = "P-384"
	JWKCrvEd25519 = "Ed25519"
	JWKCrvEd448   = "Ed448"
	JWKCrvX25519  = "X25519"
	JWKCrvX448    = "X448"

	JWKAlgMLDSA44 = "ML-DSA-44"
	JWKAlgMLDSA65 = "ML-DSA-65"
	JWKAlgMLDSA87 = "ML-DSA-87"
)

// Errors returned by the codec. Each rule has its own sentinel so a caller
// (and a test) can tell which one a key broke; the returned error wraps the
// sentinel with the detail.
var (
	ErrJWKMalformed          = errors.New("jwk: malformed JSON")
	ErrJWKMemberType         = errors.New("jwk: member has the wrong JSON type")
	ErrJWKMissingMember      = errors.New("jwk: required member missing")
	ErrJWKBadBase64          = errors.New("jwk: member is not unpadded base64url")
	ErrJWKUnsupportedKty     = errors.New("jwk: unsupported key type")
	ErrJWKUnsupportedCurve   = errors.New("jwk: unsupported curve or parameter set")
	ErrJWKBadKeySize         = errors.New("jwk: key member has the wrong length")
	ErrJWKInvalidPublicKey   = errors.New("jwk: invalid public key")
	ErrJWKRSAIncomplete      = errors.New("jwk: RSA private key lacks a CRT member")
	ErrJWKRSAOth             = errors.New("jwk: RSA private key carries \"oth\"")
	ErrJWKNoStdlibKey        = errors.New("jwk: key type has no standard library form")
	ErrJWKUnsupportedGoKey   = errors.New("jwk: unsupported Go key type")
	ErrJWKSetMalformed       = errors.New("jwk: malformed JWK Set")
	ErrJWKInvalidPrivateKey  = errors.New("jwk: invalid private key")
	ErrJWKNotMinimal         = errors.New("jwk: RSA integer member is not the shortest encoding")
	errJWKInternalMemberKind = errors.New("jwk: internal: unknown member")
)

// JSONWebKey is a JWK holding the key material of one DNSSEC or SIG(0)
// key. Binary members hold the decoded octets; the JSON form is unpadded
// base64url (RFC 7515 section 2). Which members are set depends on Kty:
//
//	EC   Crv, X, Y; private: D
//	RSA  N, E; private: D, P, Q, DP, DQ, QI (all six, never "oth")
//	OKP  Crv, X; private: D
//	AKP  Alg, Pub; private: Priv (the 32-byte ML-DSA seed)
type JSONWebKey struct {
	Kty string
	Crv string
	Alg string
	Kid string

	X, Y []byte // EC, OKP (X only)
	N, E []byte // RSA

	D                []byte // EC scalar, OKP secret, RSA private exponent
	P, Q, DP, DQ, QI []byte // RSA CRT members

	Pub, Priv []byte // AKP

	// Use is carried through when present; the draft lets producers add
	// it and consumers ignore it.
	Use string
}

// jwkSizes gives the fixed lengths of the members of the fixed-size key
// types: public, private (0 means no private form defined here).
var jwkFixedSizes = map[string]struct{ pub, priv int }{
	JWKKtyEC + "/" + JWKCrvP256:     {32, 32}, // per coordinate
	JWKKtyEC + "/" + JWKCrvP384:     {48, 48},
	JWKKtyOKP + "/" + JWKCrvEd25519: {32, 32},
	JWKKtyOKP + "/" + JWKCrvEd448:   {57, 57},
	JWKKtyOKP + "/" + JWKCrvX25519:  {32, 32},
	JWKKtyOKP + "/" + JWKCrvX448:    {56, 56},
	JWKKtyAKP + "/" + JWKAlgMLDSA44: {1312, 32},
	JWKKtyAKP + "/" + JWKAlgMLDSA65: {1952, 32},
	JWKKtyAKP + "/" + JWKAlgMLDSA87: {2592, 32},
}

var b64url = base64.RawURLEncoding.Strict()

func b64(b []byte) string { return b64url.EncodeToString(b) }

// IsPrivate reports whether the key carries the private members of its own
// key type. A member that belongs to another type (an RSA "p" on an OKP
// key) does not count: it would send PrivateKey to a constructor that has
// no key material to build from, and some of those panic.
func (k *JSONWebKey) IsPrivate() bool {
	switch k.Kty {
	case JWKKtyRSA:
		return len(k.D) > 0 || len(k.P) > 0 || len(k.Q) > 0 ||
			len(k.DP) > 0 || len(k.DQ) > 0 || len(k.QI) > 0
	case JWKKtyEC, JWKKtyOKP:
		return len(k.D) > 0
	case JWKKtyAKP:
		return len(k.Priv) > 0
	}
	return false
}

// PublicJWK returns a copy of k without its private members, which is how
// the draft (section 2) derives a public DNSSEC JWK from a private one.
func (k *JSONWebKey) PublicJWK() *JSONWebKey {
	c := *k
	c.D, c.P, c.Q, c.DP, c.DQ, c.QI, c.Priv = nil, nil, nil, nil, nil, nil, nil
	c.X = append([]byte(nil), k.X...)
	c.Y = append([]byte(nil), k.Y...)
	c.N = append([]byte(nil), k.N...)
	c.E = append([]byte(nil), k.E...)
	c.Pub = append([]byte(nil), k.Pub...)
	return &c
}

// Validate checks the members k must have for its key type, their lengths,
// and for EC keys that the point is on the curve. It does not check that a
// private key matches its public key; that needs the algorithm (see the
// DNSSEC import path).
func (k *JSONWebKey) Validate() error {
	switch k.Kty {
	case JWKKtyEC:
		sz, ok := jwkFixedSizes[k.Kty+"/"+k.Crv]
		if !ok {
			if k.Crv == "" {
				return fmt.Errorf("%w: EC key needs \"crv\"", ErrJWKMissingMember)
			}
			return fmt.Errorf("%w: EC curve %q", ErrJWKUnsupportedCurve, k.Crv)
		}
		if len(k.X) == 0 || len(k.Y) == 0 {
			return fmt.Errorf("%w: EC key needs \"x\" and \"y\"", ErrJWKMissingMember)
		}
		if len(k.X) != sz.pub || len(k.Y) != sz.pub {
			return fmt.Errorf("%w: %s coordinates are %d octets, got %d and %d", ErrJWKBadKeySize, k.Crv, sz.pub, len(k.X), len(k.Y))
		}
		if k.D != nil && len(k.D) != sz.priv {
			return fmt.Errorf("%w: %s \"d\" is %d octets, got %d", ErrJWKBadKeySize, k.Crv, sz.priv, len(k.D))
		}
		if _, err := k.ecdsaPublicKey(); err != nil {
			return err
		}
	case JWKKtyOKP:
		sz, ok := jwkFixedSizes[k.Kty+"/"+k.Crv]
		if !ok {
			if k.Crv == "" {
				return fmt.Errorf("%w: OKP key needs \"crv\"", ErrJWKMissingMember)
			}
			return fmt.Errorf("%w: OKP curve %q", ErrJWKUnsupportedCurve, k.Crv)
		}
		if len(k.X) == 0 {
			return fmt.Errorf("%w: OKP key needs \"x\"", ErrJWKMissingMember)
		}
		if len(k.X) != sz.pub {
			return fmt.Errorf("%w: %s \"x\" is %d octets, got %d", ErrJWKBadKeySize, k.Crv, sz.pub, len(k.X))
		}
		if k.D != nil && len(k.D) != sz.priv {
			return fmt.Errorf("%w: %s \"d\" is %d octets, got %d", ErrJWKBadKeySize, k.Crv, sz.priv, len(k.D))
		}
	case JWKKtyAKP:
		sz, ok := jwkFixedSizes[k.Kty+"/"+k.Alg]
		if !ok {
			if k.Alg == "" {
				return fmt.Errorf("%w: AKP key needs \"alg\"", ErrJWKMissingMember)
			}
			return fmt.Errorf("%w: AKP alg %q", ErrJWKUnsupportedCurve, k.Alg)
		}
		if len(k.Pub) == 0 {
			return fmt.Errorf("%w: AKP key needs \"pub\"", ErrJWKMissingMember)
		}
		if len(k.Pub) != sz.pub {
			return fmt.Errorf("%w: %s \"pub\" is %d octets, got %d", ErrJWKBadKeySize, k.Alg, sz.pub, len(k.Pub))
		}
		if k.Priv != nil && len(k.Priv) != sz.priv {
			return fmt.Errorf("%w: %s \"priv\" must be the %d-octet seed, got %d", ErrJWKBadKeySize, k.Alg, sz.priv, len(k.Priv))
		}
	case JWKKtyRSA:
		if len(k.N) == 0 || len(k.E) == 0 {
			return fmt.Errorf("%w: RSA key needs \"n\" and \"e\"", ErrJWKMissingMember)
		}
		// RFC 7518 section 6.3.1: the shortest octet sequence. "AQAB" and
		// "AAEAAQ" are both 65537, and the kid hashes the octets, so the
		// same key would get two ids. Only n and e are held to this (the
		// kid does not depend on the private members, and other tools pad
		// those).
		for _, m := range []struct {
			name string
			v    []byte
		}{{"n", k.N}, {"e", k.E}} {
			if len(m.v) > 1 && m.v[0] == 0 {
				return fmt.Errorf("%w: %q has a leading zero octet", ErrJWKNotMinimal, m.name)
			}
		}
		priv := [][]byte{k.D, k.P, k.Q, k.DP, k.DQ, k.QI}
		n := 0
		for _, m := range priv {
			if len(m) > 0 {
				n++
			}
		}
		if n != 0 && n != len(priv) {
			return fmt.Errorf("%w: a private RSA JWK needs all of d, p, q, dp, dq, qi", ErrJWKRSAIncomplete)
		}
	case "":
		return fmt.Errorf("%w: \"kty\"", ErrJWKMissingMember)
	default:
		return fmt.Errorf("%w: %q", ErrJWKUnsupportedKty, k.Kty)
	}
	return nil
}

// thumbprintMembers are the required members of each key type, which RFC
// 7638 section 3.2 hashes. AKP follows draft-ietf-cose-dilithium (alg, kty,
// pub).
var thumbprintMembers = map[string][]string{
	JWKKtyEC:  {"crv", "kty", "x", "y"},
	JWKKtyRSA: {"e", "kty", "n"},
	JWKKtyOKP: {"crv", "kty", "x"},
	JWKKtyAKP: {"alg", "kty", "pub"},
}

func (k *JSONWebKey) member(name string) (string, error) {
	switch name {
	case "kty":
		return k.Kty, nil
	case "crv":
		return k.Crv, nil
	case "alg":
		return k.Alg, nil
	case "x":
		return b64(k.X), nil
	case "y":
		return b64(k.Y), nil
	case "n":
		return b64(k.N), nil
	case "e":
		return b64(k.E), nil
	case "pub":
		return b64(k.Pub), nil
	}
	return "", fmt.Errorf("%w: %q", errJWKInternalMemberKind, name)
}

// Thumbprint returns the RFC 7638 JWK Thumbprint of k with SHA-256, in
// unpadded base64url: the value the draft recommends for "kid".
func (k *JSONWebKey) Thumbprint() (string, error) {
	if err := k.Validate(); err != nil {
		return "", err
	}
	names := thumbprintMembers[k.Kty]
	var sb strings.Builder
	sb.WriteByte('{')
	for i, name := range names {
		v, err := k.member(name)
		if err != nil {
			return "", err
		}
		if i > 0 {
			sb.WriteByte(',')
		}
		// Every value is a JWK name or base64url, so json.Marshal emits
		// it unescaped, as RFC 7638 requires.
		vb, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		sb.WriteString(`"` + name + `":`)
		sb.Write(vb)
	}
	sb.WriteByte('}')
	sum := sha256.Sum256([]byte(sb.String()))
	return b64(sum[:]), nil
}

// SetKid sets Kid to the key's RFC 7638 thumbprint.
func (k *JSONWebKey) SetKid() error {
	t, err := k.Thumbprint()
	if err != nil {
		return err
	}
	k.Kid = t
	return nil
}

// jwkWire is the JSON layout. Field order is the member order on output,
// which follows the draft's examples (kid first, key material, dnskey last).
type jwkWire struct {
	Kid  string `json:"kid,omitempty"`
	Kty  string `json:"kty"`
	Crv  string `json:"crv,omitempty"`
	Alg  string `json:"alg,omitempty"`
	Use  string `json:"use,omitempty"`
	N    string `json:"n,omitempty"`
	E    string `json:"e,omitempty"`
	X    string `json:"x,omitempty"`
	Y    string `json:"y,omitempty"`
	Pub  string `json:"pub,omitempty"`
	D    string `json:"d,omitempty"`
	P    string `json:"p,omitempty"`
	Q    string `json:"q,omitempty"`
	DP   string `json:"dp,omitempty"`
	DQ   string `json:"dq,omitempty"`
	QI   string `json:"qi,omitempty"`
	Priv string `json:"priv,omitempty"`
}

func optB64(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return b64(b)
}

func (k *JSONWebKey) wire() jwkWire {
	return jwkWire{
		Kid: k.Kid, Kty: k.Kty, Crv: k.Crv, Alg: k.Alg, Use: k.Use,
		N: optB64(k.N), E: optB64(k.E), X: optB64(k.X), Y: optB64(k.Y),
		Pub: optB64(k.Pub), D: optB64(k.D), P: optB64(k.P), Q: optB64(k.Q),
		DP: optB64(k.DP), DQ: optB64(k.DQ), QI: optB64(k.QI), Priv: optB64(k.Priv),
	}
}

// MarshalJSON validates k and writes it as a JWK. It has a value receiver
// so json.Marshal(*k) gets the wire format too; with a pointer receiver
// encoding/json would write the Go field names (Kty, not kty), which
// ParseJSONWebKey refuses.
func (k JSONWebKey) MarshalJSON() ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(k.wire())
}

// jwkMembers holds the top-level members of a JWK object by exact name.
// encoding/json matches struct fields case-insensitively, but JWK member
// names are case-sensitive ("D" is not "d"), so parsing goes through a map.
type jwkMembers map[string]json.RawMessage

func (m jwkMembers) str(name string) (string, bool, error) {
	raw, ok := m[name]
	if !ok {
		return "", false, nil
	}
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", true, fmt.Errorf("%w: %q must be a string", ErrJWKMemberType, name)
	}
	return s, true, nil
}

func (m jwkMembers) bin(name string) ([]byte, error) {
	s, ok, err := m.str(name)
	if err != nil || !ok {
		return nil, err
	}
	// encoding/base64 skips CR and LF even in strict mode; a JSON escape
	// ("\n") can put one into a member that is otherwise canonical.
	if strings.ContainsAny(s, "\r\n") {
		return nil, fmt.Errorf("%w: %q contains a line break", ErrJWKBadBase64, name)
	}
	b, err := b64url.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrJWKBadBase64, name, err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("%w: %q is empty", ErrJWKBadKeySize, name)
	}
	return b, nil
}

// fromMembers fills k from the members it knows and ignores the rest
// (RFC 7517 section 4). It does not validate.
func (k *JSONWebKey) fromMembers(m jwkMembers) error {
	var err error
	for _, f := range []struct {
		name string
		dst  *string
	}{{"kty", &k.Kty}, {"crv", &k.Crv}, {"alg", &k.Alg}, {"kid", &k.Kid}, {"use", &k.Use}} {
		if *f.dst, _, err = m.str(f.name); err != nil {
			return err
		}
	}
	for _, f := range []struct {
		name string
		dst  *[]byte
	}{
		{"x", &k.X}, {"y", &k.Y}, {"n", &k.N}, {"e", &k.E}, {"d", &k.D},
		{"p", &k.P}, {"q", &k.Q}, {"dp", &k.DP}, {"dq", &k.DQ}, {"qi", &k.QI},
		{"pub", &k.Pub}, {"priv", &k.Priv},
	} {
		if *f.dst, err = m.bin(f.name); err != nil {
			return err
		}
	}
	if k.Kty == JWKKtyRSA {
		if _, ok := m["oth"]; ok {
			return fmt.Errorf("%w: the draft forbids multi-prime RSA keys", ErrJWKRSAOth)
		}
	}
	return nil
}

func parseJWKMembers(data []byte) (jwkMembers, error) {
	var m jwkMembers
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKMalformed, err)
	}
	if m == nil {
		return nil, fmt.Errorf("%w: not a JSON object", ErrJWKMalformed)
	}
	return m, nil
}

// UnmarshalJSON parses and validates a JWK. Unknown members are ignored.
func (k *JSONWebKey) UnmarshalJSON(data []byte) error {
	m, err := parseJWKMembers(data)
	if err != nil {
		return err
	}
	var nk JSONWebKey
	if err := nk.fromMembers(m); err != nil {
		return err
	}
	if err := nk.Validate(); err != nil {
		return err
	}
	*k = nk
	return nil
}

// ParseJSONWebKey parses and validates one JWK.
func ParseJSONWebKey(data []byte) (*JSONWebKey, error) {
	k := new(JSONWebKey)
	if err := k.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return k, nil
}

// JSONWebKeySet is a JWK Set (RFC 7517 section 5).
type JSONWebKeySet struct {
	Keys []*JSONWebKey
}

// MarshalJSON writes the set as {"keys":[...]}. Value receiver for the same
// reason as JSONWebKey.MarshalJSON. A nil element is an error: encoding/json
// would write null without asking the key, and ParseJSONWebKeySet refuses
// the result.
func (s JSONWebKeySet) MarshalJSON() ([]byte, error) {
	keys := s.Keys
	if keys == nil {
		keys = []*JSONWebKey{}
	}
	for i, k := range keys {
		if k == nil {
			return nil, fmt.Errorf("%w: keys[%d] is nil", ErrJWKSetMalformed, i)
		}
	}
	return json.Marshal(struct {
		Keys []*JSONWebKey `json:"keys"`
	}{keys})
}

// UnmarshalJSON parses a JWK Set. RFC 7517 section 5 lets a reader skip
// keys it cannot use; this reader refuses the whole set instead, because
// a key set imported into a signer with a key silently missing is worse
// than an error. Other top-level members are ignored.
func (s *JSONWebKeySet) UnmarshalJSON(data []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top == nil {
		return fmt.Errorf("%w: not a JSON object", ErrJWKSetMalformed)
	}
	raw, ok := top["keys"]
	if !ok {
		return fmt.Errorf("%w: no \"keys\" member", ErrJWKSetMalformed)
	}
	var elems []json.RawMessage
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &elems) != nil {
		return fmt.Errorf("%w: \"keys\" must be an array", ErrJWKSetMalformed)
	}
	keys := make([]*JSONWebKey, 0, len(elems))
	for i, e := range elems {
		k, err := ParseJSONWebKey(e)
		if err != nil {
			return fmt.Errorf("JWK Set %s: %w", jwkSetKeyName(i, e), err)
		}
		keys = append(keys, k)
	}
	s.Keys = keys
	return nil
}

// jwkSetKeyName names a set element for an error: its position in "keys"
// and, when it carries one, its kid. An operator with a set of many keys
// needs both to find the one that refused the set; the kid is read on its
// own because the key itself did not parse.
func jwkSetKeyName(i int, elem json.RawMessage) string {
	name := fmt.Sprintf("keys[%d]", i)
	var m map[string]json.RawMessage
	if json.Unmarshal(elem, &m) != nil {
		return name
	}
	var kid string
	if raw, ok := m["kid"]; ok && json.Unmarshal(raw, &kid) == nil && kid != "" {
		name += fmt.Sprintf(" (kid %q)", kid)
	}
	return name
}

// ParseJSONWebKeySet parses a JWK Set.
func ParseJSONWebKeySet(data []byte) (*JSONWebKeySet, error) {
	s := new(JSONWebKeySet)
	if err := s.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return s, nil
}

// --- stdlib converters ---

func ecCurve(crv string) (elliptic.Curve, ecdh.Curve, bool) {
	switch crv {
	case JWKCrvP256:
		return elliptic.P256(), ecdh.P256(), true
	case JWKCrvP384:
		return elliptic.P384(), ecdh.P384(), true
	}
	return nil, nil, false
}

func (k *JSONWebKey) ecdsaPublicKey() (*ecdsa.PublicKey, error) {
	c, _, ok := ecCurve(k.Crv)
	if !ok {
		return nil, fmt.Errorf("%w: EC curve %q", ErrJWKUnsupportedCurve, k.Crv)
	}
	pt := append(append([]byte{4}, k.X...), k.Y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(c, pt)
	if err != nil {
		return nil, fmt.Errorf("%w: %s point: %v", ErrJWKInvalidPublicKey, k.Crv, err)
	}
	return pub, nil
}

// PublicKey returns the public key as a standard library type:
// *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey or *ecdh.PublicKey
// (X25519). Ed448, X448 and ML-DSA keys have no stdlib form and return
// ErrJWKNoStdlibKey; their raw members (X, Pub) are the public key.
func (k *JSONWebKey) PublicKey() (crypto.PublicKey, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	switch k.Kty {
	case JWKKtyRSA:
		e := new(big.Int).SetBytes(k.E)
		if !e.IsInt64() || e.Int64() > 1<<31-1 || e.Int64() < 2 {
			return nil, fmt.Errorf("%w: RSA exponent out of range", ErrJWKInvalidPublicKey)
		}
		n := new(big.Int).SetBytes(k.N)
		// The stdlib refuses an even modulus when the key is used; say so
		// here, not at the first signature.
		if n.Bit(0) == 0 {
			return nil, fmt.Errorf("%w: RSA modulus is even", ErrJWKInvalidPublicKey)
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case JWKKtyEC:
		return k.ecdsaPublicKey()
	case JWKKtyOKP:
		switch k.Crv {
		case JWKCrvEd25519:
			return ed25519.PublicKey(append([]byte(nil), k.X...)), nil
		case JWKCrvX25519:
			pub, err := ecdh.X25519().NewPublicKey(k.X)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrJWKInvalidPublicKey, err)
			}
			return pub, nil
		}
	}
	return nil, fmt.Errorf("%w: %s %s%s", ErrJWKNoStdlibKey, k.Kty, k.Crv, k.Alg)
}

// PrivateKey returns the private key as a standard library type:
// *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey or
// *ecdh.PrivateKey (X25519). The stdlib constructors check the key: an
// RSA key whose members do not fit together, an EC scalar that does not
// give X and Y, or an Ed25519 seed that does not give X is refused with
// ErrJWKInvalidPrivateKey.
func (k *JSONWebKey) PrivateKey() (crypto.PrivateKey, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	if !k.IsPrivate() {
		return nil, fmt.Errorf("%w: JWK has no private members", ErrJWKMissingMember)
	}
	pub, err := k.PublicKey()
	if err != nil {
		return nil, err
	}
	switch p := pub.(type) {
	case *rsa.PublicKey:
		bi := func(b []byte) *big.Int { return new(big.Int).SetBytes(b) }
		priv := &rsa.PrivateKey{
			PublicKey: *p,
			D:         bi(k.D),
			Primes:    []*big.Int{bi(k.P), bi(k.Q)},
			Precomputed: rsa.PrecomputedValues{
				Dp: bi(k.DP), Dq: bi(k.DQ), Qinv: bi(k.QI),
			},
		}
		// Validate recomputes the CRT values and refuses a key whose
		// stored ones differ, so a wrong dp/dq/qi is caught too.
		if err := priv.Validate(); err != nil {
			return nil, fmt.Errorf("%w: RSA: %v", ErrJWKInvalidPrivateKey, err)
		}
		if err := checkRSAExponentD(priv); err != nil {
			return nil, err
		}
		return priv, nil
	case *ecdsa.PublicKey:
		priv, err := ecdsa.ParseRawPrivateKey(p.Curve, k.D)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrJWKInvalidPrivateKey, k.Crv, err)
		}
		if !priv.PublicKey.Equal(p) {
			return nil, fmt.Errorf("%w: %s \"d\" does not give \"x\", \"y\"", ErrJWKInvalidPrivateKey, k.Crv)
		}
		return priv, nil
	case ed25519.PublicKey:
		priv := ed25519.NewKeyFromSeed(k.D)
		if !p.Equal(priv.Public()) {
			return nil, fmt.Errorf("%w: Ed25519 \"d\" does not give \"x\"", ErrJWKInvalidPrivateKey)
		}
		return priv, nil
	case *ecdh.PublicKey:
		priv, err := ecdh.X25519().NewPrivateKey(k.D)
		if err != nil {
			return nil, fmt.Errorf("%w: X25519: %v", ErrJWKInvalidPrivateKey, err)
		}
		if !priv.PublicKey().Equal(p) {
			return nil, fmt.Errorf("%w: X25519 \"d\" does not give \"x\"", ErrJWKInvalidPrivateKey)
		}
		return priv, nil
	}
	return nil, fmt.Errorf("%w: %T", ErrJWKUnsupportedGoKey, pub)
}

// checkRSAExponentD checks that d gives the CRT exponents: dp is d mod (p-1)
// and dq is d mod (q-1). Any exponent that inverts e modulo lambda(N) does,
// so a d that was not reduced is accepted. The standard library's
// rsa.PrivateKey.Validate checks dp, dq and qi against e and the primes and,
// up to Go 1.25, never looks at d (the private operation does not use it),
// so a JWK whose "d" alone is wrong passed; Go 1.26 added the check, and
// this keeps the codec's answer the same on every toolchain the module
// builds with.
func checkRSAExponentD(priv *rsa.PrivateKey) error {
	one := big.NewInt(1)
	for _, c := range []struct {
		name       string
		prime, crt *big.Int
	}{{"dp", priv.Primes[0], priv.Precomputed.Dp}, {"dq", priv.Primes[1], priv.Precomputed.Dq}} {
		if c.prime.Cmp(big.NewInt(2)) < 0 {
			return fmt.Errorf("%w: RSA prime is below 2", ErrJWKInvalidPrivateKey)
		}
		if new(big.Int).Mod(priv.D, new(big.Int).Sub(c.prime, one)).Cmp(c.crt) != 0 {
			return fmt.Errorf("%w: RSA \"d\" does not give %q", ErrJWKInvalidPrivateKey, c.name)
		}
	}
	return nil
}

func ecCrvName(c elliptic.Curve) (string, bool) {
	switch c {
	case elliptic.P256():
		return JWKCrvP256, true
	case elliptic.P384():
		return JWKCrvP384, true
	}
	return "", false
}

// NewJSONWebKeyFromPublic builds a public JWK from a standard library key
// (*rsa.PublicKey, *ecdsa.PublicKey on P-256/P-384, ed25519.PublicKey,
// *ecdh.PublicKey on X25519). Kid is left empty; call SetKid.
func NewJSONWebKeyFromPublic(pub crypto.PublicKey) (*JSONWebKey, error) {
	var k JSONWebKey
	switch p := pub.(type) {
	case *rsa.PublicKey:
		k = JSONWebKey{Kty: JWKKtyRSA, N: p.N.Bytes(), E: big.NewInt(int64(p.E)).Bytes()}
	case *ecdsa.PublicKey:
		crv, ok := ecCrvName(p.Curve)
		if !ok {
			return nil, fmt.Errorf("%w: ECDSA curve %s", ErrJWKUnsupportedCurve, p.Curve.Params().Name)
		}
		pt, err := p.Bytes()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrJWKInvalidPublicKey, err)
		}
		n := (len(pt) - 1) / 2
		k = JSONWebKey{Kty: JWKKtyEC, Crv: crv, X: pt[1 : 1+n], Y: pt[1+n:]}
	case ed25519.PublicKey:
		k = JSONWebKey{Kty: JWKKtyOKP, Crv: JWKCrvEd25519, X: append([]byte(nil), p...)}
	case *ecdh.PublicKey:
		if p.Curve() != ecdh.X25519() {
			return nil, fmt.Errorf("%w: ECDH curve %v", ErrJWKUnsupportedCurve, p.Curve())
		}
		k = JSONWebKey{Kty: JWKKtyOKP, Crv: JWKCrvX25519, X: p.Bytes()}
	default:
		return nil, fmt.Errorf("%w: %T", ErrJWKUnsupportedGoKey, pub)
	}
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return &k, nil
}

// NewJSONWebKeyFromPrivate builds a private JWK from a standard library
// key. RSA keys must have exactly two primes: the draft forbids "oth".
func NewJSONWebKeyFromPrivate(priv crypto.PrivateKey) (*JSONWebKey, error) {
	switch p := priv.(type) {
	case *rsa.PrivateKey:
		if len(p.Primes) != 2 {
			return nil, fmt.Errorf("%w: key has %d primes", ErrJWKRSAOth, len(p.Primes))
		}
		k, err := NewJSONWebKeyFromPublic(&p.PublicKey)
		if err != nil {
			return nil, err
		}
		if p.D == nil || p.Primes[0] == nil || p.Primes[1] == nil {
			return nil, fmt.Errorf("%w: RSA key lacks D or a prime", ErrJWKInvalidPrivateKey)
		}
		pc := p.Precomputed
		if pc.Dp == nil || pc.Dq == nil || pc.Qinv == nil {
			c := *p
			c.Precompute()
			pc = c.Precomputed
			// Precompute cannot report an error: for a key whose D does
			// not fit its primes it returns and leaves these nil.
			if pc.Dp == nil || pc.Dq == nil || pc.Qinv == nil {
				return nil, fmt.Errorf("%w: RSA key has no CRT values and they cannot be computed", ErrJWKInvalidPrivateKey)
			}
		}
		k.D, k.P, k.Q = p.D.Bytes(), p.Primes[0].Bytes(), p.Primes[1].Bytes()
		k.DP, k.DQ, k.QI = pc.Dp.Bytes(), pc.Dq.Bytes(), pc.Qinv.Bytes()
		return k, nil
	case *ecdsa.PrivateKey:
		k, err := NewJSONWebKeyFromPublic(&p.PublicKey)
		if err != nil {
			return nil, err
		}
		if k.D, err = p.Bytes(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrJWKInvalidPrivateKey, err)
		}
		return k, nil
	case ed25519.PrivateKey:
		if len(p) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%w: Ed25519 private key is %d octets", ErrJWKBadKeySize, len(p))
		}
		k, err := NewJSONWebKeyFromPublic(p.Public())
		if err != nil {
			return nil, err
		}
		k.D = append([]byte(nil), p.Seed()...)
		return k, nil
	case *ecdh.PrivateKey:
		k, err := NewJSONWebKeyFromPublic(p.PublicKey())
		if err != nil {
			return nil, err
		}
		k.D = p.Bytes()
		return k, nil
	}
	return nil, fmt.Errorf("%w: %T", ErrJWKUnsupportedGoKey, priv)
}
