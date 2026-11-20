/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The "dnskey" JWK parameter and the import rules of
 * draft-schlyter-dnsop-dnssec-jwk (sections 2.2 and 2.6).
 */

package core

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"

	"github.com/miekg/dns"
)

// Errors for the "dnskey" parameter and the import rules. Each rule has
// its own sentinel; the returned error wraps it with the detail.
var (
	// ErrNoJWKRepresentation: the DNSSEC algorithm's key material has no
	// JWK form (draft section 2.5), so the key cannot be a DNSSEC JWK in
	// either direction.
	ErrNoJWKRepresentation = errors.New("dnssec jwk: algorithm has no JWK representation")

	ErrDNSKEYParamMissing    = errors.New("dnssec jwk: no \"dnskey\" parameter")                        // rule 1
	ErrDNSKEYParamMalformed  = errors.New("dnssec jwk: \"dnskey\" is malformed")                        // rule 1
	ErrDNSKEYName            = errors.New("dnssec jwk: bad \"dnskey\" name")                            // rule 1
	ErrDNSKEYProtocol        = errors.New("dnssec jwk: \"dnskey\" protocol is not 3")                   // rule 1
	ErrDNSKEYKeyTypeMismatch = errors.New("dnssec jwk: JWK key type does not fit the DNSSEC algorithm") // rule 2
	ErrDNSKEYPublicKey       = errors.New("dnssec jwk: bad DNSKEY public key")                          // rule 3
	ErrDNSKEYKeyTag          = errors.New("dnssec jwk: \"dnskey\" keytag does not match the key")       // rule 4
	ErrDNSKEYPrivateMismatch = errors.New("dnssec jwk: private key does not match the public key")      // rule 5
	// ErrNoKeyPairCheck: rule 5 has no check for the key type in this
	// binary (see RegisterJWKKeyPairCheck). The key is refused, since an
	// unchecked private key has not passed the rule.
	ErrNoKeyPairCheck = errors.New("dnssec jwk: no private/public check for this key type")
)

// DNSKEYParam is the "dnskey" parameter: the DNSKEY fields that are not
// key material. Name is in presentation format, \DDD escapes and all, and
// fully qualified. KeyTag is optional on input; producers here always set
// it.
type DNSKEYParam struct {
	Name      string
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	KeyTag    *uint16
}

type dnskeyParamWire struct {
	Name      string  `json:"name"`
	Flags     uint16  `json:"flags"`
	Protocol  uint8   `json:"protocol"`
	Algorithm uint8   `json:"algorithm"`
	KeyTag    *uint16 `json:"keytag,omitempty"`
}

func (p *DNSKEYParam) wire() *dnskeyParamWire {
	return &dnskeyParamWire{Name: p.Name, Flags: p.Flags, Protocol: p.Protocol, Algorithm: p.Algorithm, KeyTag: p.KeyTag}
}

// jsonUint reads a JSON integer (draft section 1.2: a number written as an
// integer, so no fraction or exponent) in [0, max].
func jsonUint(raw json.RawMessage, member string, max uint64) (uint64, error) {
	s := string(bytes.TrimSpace(raw))
	if s == "" || s[0] == '-' || s[0] == '"' {
		return 0, fmt.Errorf("%w: %q must be a non-negative JSON integer", ErrDNSKEYParamMalformed, member)
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v > max {
		return 0, fmt.Errorf("%w: %q must be a JSON integer in 0..%d, got %s", ErrDNSKEYParamMalformed, member, max, s)
	}
	return v, nil
}

// parseDNSKEYParam reads a "dnskey" (or, in J5, "sig0key") object. Unknown
// members are ignored (draft section 2.2).
func parseDNSKEYParam(raw json.RawMessage, param string) (*DNSKEYParam, error) {
	var m map[string]json.RawMessage
	if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &m) != nil {
		return nil, fmt.Errorf("%w: %q must be a JSON object", ErrDNSKEYParamMalformed, param)
	}
	need := func(name string) (json.RawMessage, error) {
		v, ok := m[name]
		if !ok {
			return nil, fmt.Errorf("%w: %q has no %q", ErrDNSKEYParamMalformed, param, name)
		}
		return v, nil
	}
	var p DNSKEYParam
	v, err := need("name")
	if err != nil {
		return nil, err
	}
	if len(v) == 0 || v[0] != '"' || json.Unmarshal(v, &p.Name) != nil {
		return nil, fmt.Errorf("%w: %q name must be a string", ErrDNSKEYParamMalformed, param)
	}
	for _, f := range []struct {
		name string
		max  uint64
		set  func(uint64)
	}{
		{"flags", 0xffff, func(u uint64) { p.Flags = uint16(u) }},
		{"protocol", 0xff, func(u uint64) { p.Protocol = uint8(u) }},
		{"algorithm", 0xff, func(u uint64) { p.Algorithm = uint8(u) }},
	} {
		v, err := need(f.name)
		if err != nil {
			return nil, err
		}
		u, err := jsonUint(v, f.name, f.max)
		if err != nil {
			return nil, err
		}
		f.set(u)
	}
	if v, ok := m["keytag"]; ok {
		u, err := jsonUint(v, "keytag", 0xffff)
		if err != nil {
			return nil, err
		}
		kt := uint16(u)
		p.KeyTag = &kt
	}
	if err := p.check(); err != nil {
		return nil, err
	}
	return &p, nil
}

// check applies the per-member rules of draft section 2.2.
func (p *DNSKEYParam) check() error {
	if !dns.IsFqdn(p.Name) {
		return fmt.Errorf("%w: %q is not fully qualified", ErrDNSKEYName, p.Name)
	}
	if _, ok := dns.IsDomainName(p.Name); !ok {
		return fmt.Errorf("%w: %q is not a domain name in presentation format", ErrDNSKEYName, p.Name)
	}
	if p.Protocol != 3 {
		return fmt.Errorf("%w: got %d", ErrDNSKEYProtocol, p.Protocol)
	}
	return nil
}

// jwkForm says which JWK key type (and curve or parameter set) carries a
// DNSSEC algorithm's key material. sub is the crv (EC, OKP) or alg (AKP).
type jwkForm struct{ kty, sub string }

// dnssecJWKForms maps every DNSSEC algorithm that has a JWK form. An
// algorithm not listed has none: DSA (3, 6), ECC-GOST (12), SM2SM3 (17),
// ECC-GOST12 (23), and the post-quantum families tdns can register at
// 202-214 (SLH-DSA, Falcon, MAYO, SNOVA, SQIsign, QR-UOV, CROSS). ML-DSA-65
// and -87 use the dnssec-algorithms registry's 200 and 201, so their JWKs
// only interoperate with peers that use the same numbers.
var dnssecJWKForms = map[uint8]jwkForm{
	dns.RSAMD5:           {JWKKtyRSA, ""},
	dns.RSASHA1:          {JWKKtyRSA, ""},
	dns.RSASHA1NSEC3SHA1: {JWKKtyRSA, ""},
	dns.RSASHA256:        {JWKKtyRSA, ""},
	dns.RSASHA512:        {JWKKtyRSA, ""},
	dns.ECDSAP256SHA256:  {JWKKtyEC, JWKCrvP256},
	dns.ECDSAP384SHA384:  {JWKKtyEC, JWKCrvP384},
	dns.ED25519:          {JWKKtyOKP, JWKCrvEd25519},
	dns.ED448:            {JWKKtyOKP, JWKCrvEd448},
	18:                   {JWKKtyAKP, JWKAlgMLDSA44},
	200:                  {JWKKtyAKP, JWKAlgMLDSA65},
	201:                  {JWKKtyAKP, JWKAlgMLDSA87},
}

func algName(alg uint8) string {
	if s, ok := dns.AlgorithmToString[alg]; ok {
		return s
	}
	return strconv.Itoa(int(alg))
}

func formFor(alg uint8) (jwkForm, error) {
	f, ok := dnssecJWKForms[alg]
	if !ok {
		return jwkForm{}, fmt.Errorf("%w: algorithm %s", ErrNoJWKRepresentation, algName(alg))
	}
	return f, nil
}

// HasJWKRepresentation reports whether keys of the DNSSEC algorithm can be
// carried as a DNSSEC JWK.
func HasJWKRepresentation(alg uint8) bool {
	_, ok := dnssecJWKForms[alg]
	return ok
}

// RegistryOnlyAlgorithmNote returns a one-line warning for a DNSSEC
// algorithm whose JWK carries a number from the dnssec-algorithms registry
// rather than IANA's table (ML-DSA-65 at 200, ML-DSA-87 at 201), and "" for
// every other algorithm. The JWK is well formed either way; the note is for
// the operator who hands it to a peer, because the number is in the
// "dnskey" parameter and a peer that numbers ML-DSA differently will not
// read the key as the same algorithm.
func RegistryOnlyAlgorithmNote(alg uint8) string {
	var name string
	switch alg {
	case 200:
		name = "ML-DSA-65"
	case 201:
		name = "ML-DSA-87"
	default:
		return ""
	}
	return fmt.Sprintf("algorithm %d (%s) is the dnssec-algorithms registry's number, not IANA's; "+
		"this JWK only interoperates with peers that use the same number", alg, name)
}

// jwsAlgDNSSEC maps the JOSE signature algorithm names that spell what a
// DNSSEC algorithm does (RFC 7518, RFC 8037, RFC 8812, and the
// fully-specified names ESP256, ESP384, Ed25519 and Ed448) to the DNSSEC
// algorithms they are consistent with. RS1 is RSA with SHA-1: both SHA-1
// DNSSEC algorithms. The hash is part of the name, so RS256 does not fit
// RSASHA512.
var jwsAlgDNSSEC = map[string][]uint8{
	"RS1":     {dns.RSASHA1, dns.RSASHA1NSEC3SHA1},
	"RS256":   {dns.RSASHA256},
	"RS512":   {dns.RSASHA512},
	"ES256":   {dns.ECDSAP256SHA256},
	"ESP256":  {dns.ECDSAP256SHA256},
	"ES384":   {dns.ECDSAP384SHA384},
	"ESP384":  {dns.ECDSAP384SHA384},
	"EdDSA":   {dns.ED25519, dns.ED448},
	"Ed25519": {dns.ED25519},
	"Ed448":   {dns.ED448},
}

// jwsAlgNoDNSSEC are JOSE signature algorithm names with no DNSSEC
// counterpart (another hash, RSASSA-PSS, P-521, secp256k1, MACs). A key
// that names one is not consistent with any DNSSEC algorithm.
var jwsAlgNoDNSSEC = map[string]bool{
	"RS384": true, "PS256": true, "PS384": true, "PS512": true,
	"ES512": true, "ESP512": true, "ES256K": true,
	"HS256": true, "HS384": true, "HS512": true, "none": true,
}

// checkForm is rule 2: the JWK's kty and crv/alg must be the ones the
// DNSSEC algorithm uses. An "alg" on a non-AKP key is optional but, when
// present, must be consistent with the DNSSEC algorithm: an AKP parameter
// set never is, and a JOSE signature algorithm name must be one that
// jwsAlgDNSSEC lists for it (so "ES256" on an RSA key under algorithm 8
// is refused). A value that is not a JOSE signature algorithm name at all
// is not judged: tdns cannot tell it from a private-use name.
func checkForm(k *JSONWebKey, alg uint8) error {
	f, err := formFor(alg)
	if err != nil {
		return err
	}
	sub := k.Crv
	if k.Kty == JWKKtyAKP {
		sub = k.Alg
	}
	if k.Kty != f.kty || sub != f.sub {
		return fmt.Errorf("%w: algorithm %s needs kty %q %s, JWK has kty %q %s",
			ErrDNSKEYKeyTypeMismatch, algName(alg), f.kty, f.sub, k.Kty, sub)
	}
	if k.Kty != JWKKtyAKP {
		if _, isAKP := jwkFixedSizes[JWKKtyAKP+"/"+k.Alg]; isAKP {
			return fmt.Errorf("%w: \"alg\" %q on a %s key", ErrDNSKEYKeyTypeMismatch, k.Alg, k.Kty)
		}
		if k.Alg != "" {
			if ok, known := jwsAlgDNSSEC[k.Alg]; known {
				if !slices.Contains(ok, alg) {
					return fmt.Errorf("%w: \"alg\" %q does not fit algorithm %s", ErrDNSKEYKeyTypeMismatch, k.Alg, algName(alg))
				}
			} else if jwsAlgNoDNSSEC[k.Alg] {
				return fmt.Errorf("%w: \"alg\" %q has no DNSSEC algorithm, so it does not fit %s", ErrDNSKEYKeyTypeMismatch, k.Alg, algName(alg))
			}
		}
	}
	return nil
}

// dnskeyPublicKeyBytes is the DNSKEY public key field for the JWK's key
// material, in the encoding of the DNSSEC algorithm.
func dnskeyPublicKeyBytes(k *JSONWebKey) ([]byte, error) {
	switch k.Kty {
	case JWKKtyRSA:
		// RFC 3110 section 2: exponent length, exponent, modulus.
		var b []byte
		if len(k.E) <= 255 {
			b = append(b, byte(len(k.E)))
		} else if len(k.E) <= 0xffff {
			b = append(b, 0, byte(len(k.E)>>8), byte(len(k.E)))
		} else {
			return nil, fmt.Errorf("%w: RSA exponent of %d octets", ErrDNSKEYPublicKey, len(k.E))
		}
		b = append(b, k.E...)
		return append(b, k.N...), nil
	case JWKKtyEC:
		return append(append([]byte(nil), k.X...), k.Y...), nil
	case JWKKtyOKP:
		return append([]byte(nil), k.X...), nil
	case JWKKtyAKP:
		return append([]byte(nil), k.Pub...), nil
	}
	return nil, fmt.Errorf("%w: kty %q", ErrJWKUnsupportedKty, k.Kty)
}

// jwkFromDNSKEYPublicKey is the inverse of dnskeyPublicKeyBytes.
func jwkFromDNSKEYPublicKey(alg uint8, pk []byte) (*JSONWebKey, error) {
	f, err := formFor(alg)
	if err != nil {
		return nil, err
	}
	k := &JSONWebKey{Kty: f.kty}
	switch f.kty {
	case JWKKtyRSA:
		if len(pk) < 1 {
			return nil, fmt.Errorf("%w: empty RSA key", ErrDNSKEYPublicKey)
		}
		el, off := int(pk[0]), 1
		if el == 0 {
			if len(pk) < 3 {
				return nil, fmt.Errorf("%w: short RSA key", ErrDNSKEYPublicKey)
			}
			el, off = int(pk[1])<<8|int(pk[2]), 3
		}
		if el == 0 || len(pk) <= off+el {
			return nil, fmt.Errorf("%w: RSA exponent length %d does not fit a %d-octet key", ErrDNSKEYPublicKey, el, len(pk))
		}
		k.E = append([]byte(nil), pk[off:off+el]...)
		k.N = append([]byte(nil), pk[off+el:]...)
	case JWKKtyEC:
		k.Crv = f.sub
		if len(pk)%2 != 0 {
			return nil, fmt.Errorf("%w: odd-length EC key", ErrDNSKEYPublicKey)
		}
		k.X = append([]byte(nil), pk[:len(pk)/2]...)
		k.Y = append([]byte(nil), pk[len(pk)/2:]...)
	case JWKKtyOKP:
		k.Crv = f.sub
		k.X = append([]byte(nil), pk...)
	case JWKKtyAKP:
		k.Alg = f.sub
		k.Pub = append([]byte(nil), pk...)
	}
	if err := k.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDNSKEYPublicKey, err)
	}
	return k, nil
}

// --- private/public consistency (rule 5) ---

// A JWKKeyPairCheck derives the public key member (OKP "x", AKP "pub")
// from the private one ("d", "priv").
type JWKKeyPairCheck func(priv []byte) (pub []byte, err error)

var (
	keyPairChecksMu sync.RWMutex
	keyPairChecks   = map[string]JWKKeyPairCheck{}
)

// RegisterJWKKeyPairCheck installs the rule-5 check for a key type the
// standard library has no type for: kty "OKP" with crv "Ed448", or kty
// "AKP" with alg "ML-DSA-44/65/87". The checks need CIRCL; importing it
// here would make it a dependency of every module that imports core
// (tdns-mp, tdns-transport, and v2/cache and v2/edns0 in this repo), so
// the tdns package (v2), which links CIRCL already for signing, registers
// them at init instead. A binary without that package refuses such keys
// with ErrNoKeyPairCheck.
func RegisterJWKKeyPairCheck(kty, sub string, fn JWKKeyPairCheck) {
	keyPairChecksMu.Lock()
	defer keyPairChecksMu.Unlock()
	keyPairChecks[kty+"/"+sub] = fn
}

// CheckKeyPair is rule 5: it verifies that the private members of k give
// its public members. RSA, EC, Ed25519 and X25519 go through the standard
// library (PrivateKey, which also checks the RSA CRT members); Ed448 and
// ML-DSA (from the seed) through the check registered with
// RegisterJWKKeyPairCheck, or fail with ErrNoKeyPairCheck when there is
// none. A public key passes.
func (k *JSONWebKey) CheckKeyPair() error {
	if !k.IsPrivate() {
		return nil
	}
	if err := k.Validate(); err != nil {
		return err
	}
	sub, priv, pub := k.Crv, k.D, k.X
	if k.Kty == JWKKtyAKP {
		sub, priv, pub = k.Alg, k.Priv, k.Pub
	}
	keyPairChecksMu.RLock()
	fn := keyPairChecks[k.Kty+"/"+sub]
	keyPairChecksMu.RUnlock()
	if fn != nil {
		got, err := fn(priv)
		if err != nil {
			return fmt.Errorf("%w: %s %s: %v", ErrDNSKEYPrivateMismatch, k.Kty, sub, err)
		}
		if subtle.ConstantTimeCompare(got, pub) != 1 {
			return fmt.Errorf("%w: %s %s private key gives another public key", ErrDNSKEYPrivateMismatch, k.Kty, sub)
		}
		return nil
	}
	if _, err := k.PrivateKey(); err != nil {
		if errors.Is(err, ErrJWKNoStdlibKey) {
			return fmt.Errorf("%w: %s %s", ErrNoKeyPairCheck, k.Kty, sub)
		}
		return fmt.Errorf("%w: %w", ErrDNSKEYPrivateMismatch, err)
	}
	return nil
}

// --- the DNSSEC JWK ---

// DNSSECJWK is a DNSSEC JWK: key material plus the "dnskey" parameter.
type DNSSECJWK struct {
	Key    *JSONWebKey
	DNSKEY *DNSKEYParam
}

// MarshalJSON writes the key with "dnskey" as its last member, as in the
// draft's examples.
func (d *DNSSECJWK) MarshalJSON() ([]byte, error) {
	if d.Key == nil || d.DNSKEY == nil {
		return nil, fmt.Errorf("%w: DNSSEC JWK needs key material and \"dnskey\"", ErrDNSKEYParamMissing)
	}
	if err := d.Key.Validate(); err != nil {
		return nil, err
	}
	if err := d.DNSKEY.check(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		jwkWire
		DNSKEY *dnskeyParamWire `json:"dnskey"`
	}{d.Key.wire(), d.DNSKEY.wire()})
}

// ParseDNSSECJWK parses a DNSSEC JWK and applies all five import rules of
// draft section 2.6; on success it returns the key and the DNSKEY RR it
// stands for. Each rule fails with its own error: ErrDNSKEYParamMissing,
// ErrDNSKEYParamMalformed, ErrDNSKEYName or ErrDNSKEYProtocol (1),
// ErrDNSKEYKeyTypeMismatch or ErrNoJWKRepresentation (2), ErrDNSKEYPublicKey
// (3), ErrDNSKEYKeyTag (4), ErrDNSKEYPrivateMismatch or ErrNoKeyPairCheck
// (5). Key material errors are the codec's (ErrJWK...).
func ParseDNSSECJWK(data []byte) (*DNSSECJWK, *dns.DNSKEY, error) {
	m, err := parseJWKMembers(data)
	if err != nil {
		return nil, nil, err
	}
	raw, ok := m["dnskey"]
	if !ok {
		return nil, nil, ErrDNSKEYParamMissing
	}
	p, err := parseDNSKEYParam(raw, "dnskey")
	if err != nil {
		return nil, nil, err
	}
	var k JSONWebKey
	if err := k.fromMembers(m); err != nil {
		return nil, nil, err
	}
	d := &DNSSECJWK{Key: &k, DNSKEY: p}
	rr, err := d.ToDNSKEY()
	if err != nil {
		return nil, nil, err
	}
	return d, rr, nil
}

// ToDNSKEY applies rules 2 to 5 to d and returns its DNSKEY RR.
func (d *DNSSECJWK) ToDNSKEY() (*dns.DNSKEY, error) {
	if d.DNSKEY == nil {
		return nil, ErrDNSKEYParamMissing
	}
	if err := d.DNSKEY.check(); err != nil {
		return nil, err
	}
	rr, err := buildKeyRR(d.Key, d.DNSKEY, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	return rr, nil
}

// buildKeyRR is rules 2 to 5 for a parameter p, returning the DNSKEY
// (its Hdr.Rrtype set to rrtype; a KEY RR wraps it).
func buildKeyRR(k *JSONWebKey, p *DNSKEYParam, rrtype uint16) (*dns.DNSKEY, error) {
	if _, err := formFor(p.Algorithm); err != nil {
		return nil, err
	}
	if err := k.Validate(); err != nil {
		return nil, err
	}
	if err := checkForm(k, p.Algorithm); err != nil {
		return nil, err
	}
	pk, err := dnskeyPublicKeyBytes(k)
	if err != nil {
		return nil, err
	}
	rr := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: p.Name, Rrtype: rrtype, Class: dns.ClassINET},
		Flags:     p.Flags,
		Protocol:  p.Protocol,
		Algorithm: p.Algorithm,
		PublicKey: base64.StdEncoding.EncodeToString(pk),
	}
	if p.KeyTag != nil {
		if got := rr.KeyTag(); got != *p.KeyTag {
			return nil, fmt.Errorf("%w: \"keytag\" %d, key has %d", ErrDNSKEYKeyTag, *p.KeyTag, got)
		}
	}
	if err := k.CheckKeyPair(); err != nil {
		return nil, err
	}
	return rr, nil
}

// paramFromKeyRR builds the parameter and the public JWK for a DNSKEY (or
// the DNSKEY inside a KEY), with the key tag always set.
func paramFromKeyRR(rr *dns.DNSKEY) (*DNSKEYParam, *JSONWebKey, error) {
	if rr == nil {
		return nil, nil, fmt.Errorf("%w: nil RR", ErrDNSKEYPublicKey)
	}
	p := &DNSKEYParam{Name: rr.Hdr.Name, Flags: rr.Flags, Protocol: rr.Protocol, Algorithm: rr.Algorithm}
	if err := p.check(); err != nil {
		return nil, nil, err
	}
	pk, err := base64.StdEncoding.DecodeString(rr.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: public key is not base64: %v", ErrDNSKEYPublicKey, err)
	}
	k, err := jwkFromDNSKEYPublicKey(rr.Algorithm, pk)
	if err != nil {
		return nil, nil, err
	}
	kt := rr.KeyTag()
	p.KeyTag = &kt
	return p, k, nil
}

// withPrivate checks that priv (a private JWK, or nil for a public key)
// carries the same public key as pub, and returns the key to export with
// its kid set.
func withPrivate(pub, priv *JSONWebKey) (*JSONWebKey, error) {
	k := pub
	if priv != nil {
		if err := priv.Validate(); err != nil {
			return nil, err
		}
		// "alg" on an RSA, EC or OKP key is optional metadata, not key
		// material: the RR has none, and the DNSSEC JWK carries "alg" for
		// AKP keys only (where it names the parameter set). Leave it out of
		// the comparison and the exported key, so a private JWK with a
		// consistent "alg" is not taken for another key.
		p := *priv
		if p.Kty != JWKKtyAKP {
			p.Alg = ""
		}
		priv = &p
		pb, err := json.Marshal(priv.PublicJWK().wire())
		if err != nil {
			return nil, err
		}
		cmp := *pub
		cmp.Kid, cmp.Use = priv.Kid, priv.Use
		qb, err := json.Marshal(cmp.wire())
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(pb, qb) {
			return nil, fmt.Errorf("%w: the private JWK's public members are not the RR's key", ErrDNSKEYPrivateMismatch)
		}
		if err := priv.CheckKeyPair(); err != nil {
			return nil, err
		}
		c := *priv
		k = &c
	}
	if err := k.SetKid(); err != nil {
		return nil, err
	}
	return k, nil
}

// NewDNSSECJWK builds a DNSSEC JWK from a DNSKEY RR. With priv nil it is
// the public key; otherwise priv is the private JWK (from
// NewJSONWebKeyFromPrivate, or filled from the PKCS#8 octets for Ed448 and
// ML-DSA), whose public members must be the RR's key and whose private
// members must pass CheckKeyPair. kid (the RFC 7638 thumbprint) and keytag
// are always set; "alg" is present only for AKP keys, where the key type
// needs it. An algorithm with no JWK form gives ErrNoJWKRepresentation.
func NewDNSSECJWK(rr *dns.DNSKEY, priv *JSONWebKey) (*DNSSECJWK, error) {
	if rr != nil && rr.Hdr.Rrtype != 0 && rr.Hdr.Rrtype != dns.TypeDNSKEY {
		return nil, fmt.Errorf("%w: RR type %s is not DNSKEY", ErrDNSKEYParamMalformed, dns.TypeToString[rr.Hdr.Rrtype])
	}
	p, pub, err := paramFromKeyRR(rr)
	if err != nil {
		return nil, err
	}
	k, err := withPrivate(pub, priv)
	if err != nil {
		return nil, err
	}
	return &DNSSECJWK{Key: k, DNSKEY: p}, nil
}
