/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Checks the example keys of draft-schlyter-dnsop-dnssec-jwk (DNSSEC keys as
 * JWK) against the draft's own rules, before any tdns codec exists.
 *
 * The vectors in testdata/dnssec-jwk are the draft's Appendix A private keys,
 * each with the DNSKEY RR the draft gives for it, plus the public key from its
 * Examples section. They come from the draft source at commit f9dc081
 * (2026-11-15), with the RFC 8792 line wrapping undone and nothing else
 * changed.
 *
 * Nothing here is production code: every helper lives in this file, so the
 * codec that later replaces jwk_helpers.go is not tied to what a test needed.
 * The checks follow the draft's processing rules: the "dnskey" parameter is
 * well typed, kty/crv/alg fit the algorithm, the DNSKEY rebuilt from the JWK
 * is the draft's RR, the key tag matches, and the private half matches the
 * public half. The RFC 7638 thumbprint is checked against "kid".
 */

package core

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/miekg/dns"
)

// jwkVector describes one file pair in testdata/dnssec-jwk.
type jwkVector struct {
	name       string // <name>.json is the JWK
	dnskeyFile string // the DNSKEY RR text the draft gives for it
	algorithm  uint8
	draftTag   uint16 // the key tag the draft's prose states for this key
	owner      string // owner name in presentation format
	ownerWire  []byte // when set, the exact wire form the owner must have
	private    bool
	// publicOf names the private vector a public one was derived from.
	publicOf string
}

var jwkVectors = []jwkVector{
	{name: "rsasha256", dnskeyFile: "rsasha256.dnskey", algorithm: 8, draftTag: 49458,
		owner: "example.com.", private: true},
	{name: "ecdsap256sha256", dnskeyFile: "ecdsap256sha256.dnskey", algorithm: 13, draftTag: 9115,
		owner: "example.com.", private: true},
	{name: "ed25519", dnskeyFile: "ed25519.dnskey", algorithm: 15, draftTag: 63713,
		owner: "example.com.", private: true},
	{name: "mldsa44", dnskeyFile: "mldsa44.dnskey", algorithm: 18, draftTag: 59828,
		owner: "example.com.", private: true},
	// A zero octet in the first label: the JWK holds "b\\000rken" (JSON), the
	// string is b\000rken in presentation format, and the wire label is
	// six octets with a 0x00 inside.
	{name: "ed25519-escaped-owner", dnskeyFile: "ed25519-escaped-owner.dnskey", algorithm: 15, draftTag: 17078,
		owner:     `b\000rken.example.com.`,
		ownerWire: []byte("\x06b\x00rken\x07example\x03com\x00"), private: true},
	// The Examples section's public key: the P-256 private key minus "d".
	{name: "ecdsap256sha256-public", dnskeyFile: "ecdsap256sha256.dnskey", algorithm: 13, draftTag: 9115,
		owner: "example.com.", publicOf: "ecdsap256sha256"},
}

// jwkVectorKnownBad lists "vector/step" pairs where one of the draft's own
// vectors disagrees with the draft's own rules. The step still runs and its
// error is logged, so the disagreement stays visible; the test fails if a
// listed step starts passing, so the table cannot go stale. The value says
// what was observed. It is empty when every vector passes.
var jwkVectorKnownBad = map[string]string{}

// jwkVectorProfile is what rule 2 expects of each algorithm's key material.
var jwkVectorProfile = map[uint8]struct{ kty, crv, alg string }{
	8:  {kty: "RSA"},
	13: {kty: "EC", crv: "P-256"},
	15: {kty: "OKP", crv: "Ed25519"},
	18: {kty: "AKP", alg: "ML-DSA-44"},
}

// jwkVectorMembers are the JWK members each key type must carry, public half
// first, then what a private key adds. "kid" and "dnskey" come on top.
var jwkVectorMembers = map[string]struct{ pub, priv []string }{
	"RSA": {[]string{"kty", "n", "e"}, []string{"d", "p", "q", "dp", "dq", "qi"}},
	"EC":  {[]string{"kty", "crv", "x", "y"}, []string{"d"}},
	"OKP": {[]string{"kty", "crv", "x"}, []string{"d"}},
	"AKP": {[]string{"kty", "alg", "pub"}, []string{"priv"}},
}

// jwkVectorState is one vector, loaded.
type jwkVectorState struct {
	vec     jwkVector
	members map[string]json.RawMessage
	str     map[string]string // the string-valued members, as written
	dnskey  struct {
		name                       string
		flags, protocol, algorithm int
		keytag                     int
		hasKeytag                  bool
	}
	draftRR *dns.DNSKEY
}

func loadJWKVector(vec jwkVector, jwkJSON []byte, dnskeyText string) (*jwkVectorState, error) {
	s := &jwkVectorState{vec: vec, str: map[string]string{}}
	if err := json.Unmarshal(jwkJSON, &s.members); err != nil {
		return nil, fmt.Errorf("JWK is not a JSON object: %w", err)
	}
	for k, raw := range s.members {
		var v string
		if json.Unmarshal(raw, &v) == nil {
			s.str[k] = v
		}
	}
	rr, err := dns.NewRR(dnskeyText)
	if err != nil {
		return nil, fmt.Errorf("draft DNSKEY RR does not parse: %w", err)
	}
	dk, ok := rr.(*dns.DNSKEY)
	if !ok {
		return nil, fmt.Errorf("draft RR is %T, not a DNSKEY", rr)
	}
	s.draftRR = dk
	return s, nil
}

// checkDNSKEYParameter is rule 1: "dnskey" is present and every required
// member has the right JSON type. Integers must be written as integers.
func (s *jwkVectorState) checkDNSKEYParameter() error {
	raw, ok := s.members["dnskey"]
	if !ok {
		return fmt.Errorf(`no "dnskey" parameter`)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf(`"dnskey" is not an object: %w`, err)
	}
	integer := func(member string, required bool) (int, bool, error) {
		r, ok := obj[member]
		if !ok {
			if required {
				return 0, false, fmt.Errorf("dnskey.%s missing", member)
			}
			return 0, false, nil
		}
		n, err := strconv.ParseInt(string(r), 10, 32)
		if err != nil {
			return 0, false, fmt.Errorf("dnskey.%s = %s is not a JSON integer", member, r)
		}
		return int(n), true, nil
	}
	nameRaw, ok := obj["name"]
	if !ok {
		return fmt.Errorf("dnskey.name missing")
	}
	if err := json.Unmarshal(nameRaw, &s.dnskey.name); err != nil {
		return fmt.Errorf("dnskey.name is not a string: %w", err)
	}
	var err error
	if s.dnskey.flags, _, err = integer("flags", true); err != nil {
		return err
	}
	if s.dnskey.protocol, _, err = integer("protocol", true); err != nil {
		return err
	}
	if s.dnskey.algorithm, _, err = integer("algorithm", true); err != nil {
		return err
	}
	if s.dnskey.keytag, s.dnskey.hasKeytag, err = integer("keytag", false); err != nil {
		return err
	}
	if s.dnskey.flags < 0 || s.dnskey.flags > 65535 {
		return fmt.Errorf("dnskey.flags %d outside 0..65535", s.dnskey.flags)
	}
	if s.dnskey.protocol != 3 {
		return fmt.Errorf("dnskey.protocol %d, must be 3", s.dnskey.protocol)
	}
	if s.dnskey.algorithm < 0 || s.dnskey.algorithm > 255 {
		return fmt.Errorf("dnskey.algorithm %d outside 0..255", s.dnskey.algorithm)
	}
	if s.dnskey.hasKeytag && (s.dnskey.keytag < 0 || s.dnskey.keytag > 65535) {
		return fmt.Errorf("dnskey.keytag %d outside 0..65535", s.dnskey.keytag)
	}
	if !dns.IsFqdn(s.dnskey.name) {
		return fmt.Errorf("dnskey.name %q is not fully qualified", s.dnskey.name)
	}
	if s.dnskey.name != s.vec.owner {
		return fmt.Errorf("dnskey.name %q, want %q", s.dnskey.name, s.vec.owner)
	}
	if int(s.vec.algorithm) != s.dnskey.algorithm {
		return fmt.Errorf("dnskey.algorithm %d, the draft's text says %d", s.dnskey.algorithm, s.vec.algorithm)
	}
	return nil
}

// checkMembers pins the exact member set: the key type's public members,
// plus the private ones for a private key, plus "kid" and "dnskey". It also
// covers the draft's rule that RSA private keys carry every CRT member and no
// "oth".
func (s *jwkVectorState) checkMembers() error {
	kty := s.str["kty"]
	want, ok := jwkVectorMembers[kty]
	if !ok {
		return fmt.Errorf("unknown kty %q", kty)
	}
	set := append([]string{"kid", "dnskey"}, want.pub...)
	if s.vec.private {
		set = append(set, want.priv...)
	}
	sort.Strings(set)
	var got []string
	for k := range s.members {
		got = append(got, k)
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, set) {
		return fmt.Errorf("members %v, want %v", got, set)
	}
	return nil
}

// checkProfile is rule 2: kty, crv and alg are consistent with the DNSSEC
// algorithm named in dnskey.algorithm.
func (s *jwkVectorState) checkProfile() error {
	p, ok := jwkVectorProfile[s.vec.algorithm]
	if !ok {
		return fmt.Errorf("no profile for algorithm %d", s.vec.algorithm)
	}
	if s.str["kty"] != p.kty || s.str["crv"] != p.crv || s.str["alg"] != p.alg {
		return fmt.Errorf("kty/crv/alg = %q/%q/%q, algorithm %d wants %q/%q/%q",
			s.str["kty"], s.str["crv"], s.str["alg"], s.vec.algorithm, p.kty, p.crv, p.alg)
	}
	return nil
}

// bytesOf decodes a base64url member the strict way: no padding, no stray
// trailing bits, so a vector cannot hide a non-canonical encoding.
func (s *jwkVectorState) bytesOf(member string) ([]byte, error) {
	v, ok := s.str[member]
	if !ok {
		return nil, fmt.Errorf("member %q missing or not a string", member)
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("member %q is not canonical unpadded base64url: %w", member, err)
	}
	return b, nil
}

// checkEncoding checks the lengths RFC 7518 section 6 and RFC 8037 give the
// key material: big-endian integers without a leading zero octet, EC and OKP
// values at full length.
func (s *jwkVectorState) checkEncoding() error {
	type size struct {
		member string
		length int // 0: any length, but no leading zero octet
	}
	var sizes []size
	switch s.str["kty"] {
	case "RSA":
		sizes = []size{{"n", 256}, {"e", 3}}
		if s.vec.private {
			sizes = append(sizes, size{"d", 0}, size{"p", 128}, size{"q", 128},
				size{"dp", 0}, size{"dq", 0}, size{"qi", 0})
		}
	case "EC":
		sizes = []size{{"x", 32}, {"y", 32}}
		if s.vec.private {
			sizes = append(sizes, size{"d", 32})
		}
	case "OKP":
		sizes = []size{{"x", 32}}
		if s.vec.private {
			sizes = append(sizes, size{"d", 32})
		}
	case "AKP":
		sizes = []size{{"pub", mldsa44.PublicKeySize}}
		if s.vec.private {
			sizes = append(sizes, size{"priv", mldsa44.SeedSize})
		}
	}
	for _, z := range sizes {
		b, err := s.bytesOf(z.member)
		if err != nil {
			return err
		}
		if z.length != 0 && len(b) != z.length {
			return fmt.Errorf("member %q is %d octets, want %d", z.member, len(b), z.length)
		}
		if s.str["kty"] == "RSA" && len(b) > 0 && b[0] == 0 {
			return fmt.Errorf("member %q has a leading zero octet (RFC 7518 6.3.1: Base64urlUInt)", z.member)
		}
	}
	return nil
}

// publicKeyField is the DNSKEY public key field built from the JWK public
// members, in the encoding the DNSSEC algorithm defines.
func (s *jwkVectorState) publicKeyField() ([]byte, error) {
	switch s.dnskey.algorithm {
	case 5, 7, 8, 10: // RFC 3110: exponent length, exponent, modulus
		e, err := s.bytesOf("e")
		if err != nil {
			return nil, err
		}
		n, err := s.bytesOf("n")
		if err != nil {
			return nil, err
		}
		var f []byte
		if len(e) <= 255 {
			f = append(f, byte(len(e)))
		} else {
			f = append(f, 0, byte(len(e)>>8), byte(len(e)))
		}
		return append(append(f, e...), n...), nil
	case 13: // RFC 6605: x || y
		x, err := s.bytesOf("x")
		if err != nil {
			return nil, err
		}
		y, err := s.bytesOf("y")
		if err != nil {
			return nil, err
		}
		return append(x, y...), nil
	case 15: // RFC 8080: x
		return s.bytesOf("x")
	case 18: // the ML-DSA public key as is
		return s.bytesOf("pub")
	}
	return nil, fmt.Errorf("test has no public key encoding for algorithm %d", s.dnskey.algorithm)
}

// rebuild returns the DNSKEY RR the JWK stands for. The TTL is the draft
// RR's, since a JWK has none and NewRR supplies a default.
func (s *jwkVectorState) rebuild() (*dns.DNSKEY, error) {
	pub, err := s.publicKeyField()
	if err != nil {
		return nil, err
	}
	return &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   s.dnskey.name,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    s.draftRR.Hdr.Ttl,
		},
		Flags:     uint16(s.dnskey.flags),
		Protocol:  uint8(s.dnskey.protocol),
		Algorithm: uint8(s.dnskey.algorithm),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// jwkVectorOwnerWire is the owner name in wire format; PackDomainName is the \DDD
// parser here, as it is for every name tdns reads.
func jwkVectorOwnerWire(name string) ([]byte, error) {
	buf := make([]byte, 256)
	off, err := dns.PackDomainName(name, buf, 0, nil, false)
	if err != nil {
		return nil, fmt.Errorf("owner name %q: %w", name, err)
	}
	return buf[:off], nil
}

func jwkVectorPack(rr dns.RR) ([]byte, error) {
	buf := make([]byte, 8192)
	off, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return nil, err
	}
	return buf[:off], nil
}

// jwkVectorRData cuts the RDATA out of a packed RR whose owner has ownerLen octets.
func jwkVectorRData(packed []byte, ownerLen int) []byte {
	return packed[ownerLen+10:]
}

// checkRebuild is rule 3: the DNSKEY built from flags, protocol, algorithm
// and the public key material is the RR the draft prints. It is compared
// on the wire, with the RDATA built by hand a second time, and the owner name
// is compared as wire labels so a mishandled \DDD cannot pass as a string.
func (s *jwkVectorState) checkRebuild() error {
	rebuilt, err := s.rebuild()
	if err != nil {
		return err
	}
	jwkOwner, err := jwkVectorOwnerWire(s.dnskey.name)
	if err != nil {
		return err
	}
	draftOwner, err := jwkVectorOwnerWire(s.draftRR.Hdr.Name)
	if err != nil {
		return err
	}
	if !bytes.Equal(jwkOwner, draftOwner) {
		return fmt.Errorf("owner wire form %x, the draft's RR has %x", jwkOwner, draftOwner)
	}
	if s.vec.ownerWire != nil && !bytes.Equal(jwkOwner, s.vec.ownerWire) {
		return fmt.Errorf("owner wire form %x, want %x", jwkOwner, s.vec.ownerWire)
	}
	if back, _, err := dns.UnpackDomainName(jwkOwner, 0); err != nil || back != s.vec.owner {
		return fmt.Errorf("owner does not survive wire and back: %q, %v", back, err)
	}
	got, err := jwkVectorPack(rebuilt)
	if err != nil {
		return fmt.Errorf("pack rebuilt DNSKEY: %w", err)
	}
	want, err := jwkVectorPack(s.draftRR)
	if err != nil {
		return fmt.Errorf("pack draft DNSKEY: %w", err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("rebuilt DNSKEY differs from the draft's RR:\n got  %s\n want %s", rebuilt, s.draftRR)
	}
	pub, _ := s.publicKeyField()
	rdata := append([]byte{byte(s.dnskey.flags >> 8), byte(s.dnskey.flags), byte(s.dnskey.protocol), byte(s.dnskey.algorithm)}, pub...)
	if !bytes.Equal(rdata, jwkVectorRData(want, len(draftOwner))) {
		return fmt.Errorf("hand-built RDATA differs from the draft's RR")
	}
	return nil
}

// keyTagRFC4034 is the RFC 4034 Appendix B checksum, written out so the
// miekg/dns implementation is not the only witness.
func keyTagRFC4034(rdata []byte) uint16 {
	var ac uint32
	for i, b := range rdata {
		if i&1 == 1 {
			ac += uint32(b)
		} else {
			ac += uint32(b) << 8
		}
	}
	ac += ac >> 16 & 0xFFFF
	return uint16(ac & 0xFFFF)
}

// checkKeyTag is rule 4 and the draft's prose: the computed tag equals the
// "keytag" member and the number the draft's text gives for the key.
func (s *jwkVectorState) checkKeyTag() error {
	rebuilt, err := s.rebuild()
	if err != nil {
		return err
	}
	packed, err := jwkVectorPack(rebuilt)
	if err != nil {
		return err
	}
	owner, err := jwkVectorOwnerWire(s.dnskey.name)
	if err != nil {
		return err
	}
	miekg := rebuilt.KeyTag()
	own := keyTagRFC4034(jwkVectorRData(packed, len(owner)))
	if miekg != own {
		return fmt.Errorf("key tag: miekg/dns %d, RFC 4034 Appendix B %d", miekg, own)
	}
	if !s.dnskey.hasKeytag {
		return fmt.Errorf(`no "keytag" member`)
	}
	if int(miekg) != s.dnskey.keytag {
		return fmt.Errorf(`computed key tag %d, "keytag" member %d`, miekg, s.dnskey.keytag)
	}
	if miekg != s.vec.draftTag {
		return fmt.Errorf("computed key tag %d, the draft's text says %d", miekg, s.vec.draftTag)
	}
	if dt := s.draftRR.KeyTag(); dt != miekg {
		return fmt.Errorf("key tag of the draft's RR %d, of the rebuilt RR %d", dt, miekg)
	}
	return nil
}

// jwkVectorThumbprint is RFC 7638: SHA-256 over the members as a JSON object with the
// keys in lexicographic order and no white space, base64url without padding.
func jwkVectorThumbprint(str map[string]string, members []string) (string, error) {
	sort.Strings(members)
	var b strings.Builder
	b.WriteByte('{')
	for i, m := range members {
		v, ok := str[m]
		if !ok {
			return "", fmt.Errorf("thumbprint member %q is not a string member", m)
		}
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(m)
		val, _ := json.Marshal(v)
		b.Write(k)
		b.WriteByte(':')
		b.Write(val)
	}
	b.WriteByte('}')
	sum := sha256.Sum256([]byte(b.String()))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// jwkVectorThumbprintMembers are the required members: RFC 7638 for RSA, EC and OKP;
// for AKP the draft-ietf-cose-dilithium set {alg, kty, pub}.
var jwkVectorThumbprintMembers = map[string][]string{
	"RSA": {"e", "kty", "n"},
	"EC":  {"crv", "kty", "x", "y"},
	"OKP": {"crv", "kty", "x"},
	"AKP": {"alg", "kty", "pub"},
}

// findThumbprintSet is for the failure message: it tries every subset of the
// string members (kid aside) and returns the smallest that gives want.
func (s *jwkVectorState) findThumbprintSet(want string) string {
	var names []string
	for k := range s.str {
		if k != "kid" {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	best := ""
	for mask := 1; mask < 1<<len(names); mask++ {
		var set []string
		for i, n := range names {
			if mask&(1<<i) != 0 {
				set = append(set, n)
			}
		}
		if got, _ := jwkVectorThumbprint(s.str, set); got == want {
			if best == "" || len(set) < strings.Count(best, ",")+1 {
				best = strings.Join(set, ",")
			}
		}
	}
	if best == "" {
		return "no subset of the string members matches"
	}
	return "member set {" + best + "} matches"
}

// checkKid is the "kid" recommendation: the SHA-256 JWK thumbprint, not the
// key tag.
func (s *jwkVectorState) checkKid() error {
	set, ok := jwkVectorThumbprintMembers[s.str["kty"]]
	if !ok {
		return fmt.Errorf("unknown kty %q", s.str["kty"])
	}
	got, err := jwkVectorThumbprint(s.str, append([]string(nil), set...))
	if err != nil {
		return err
	}
	if got != s.str["kid"] {
		return fmt.Errorf("thumbprint over {%s} is %s, kid is %s; %s",
			strings.Join(set, ","), got, s.str["kid"], s.findThumbprintSet(s.str["kid"]))
	}
	return nil
}

func (s *jwkVectorState) bigOf(member string) (*big.Int, error) {
	b, err := s.bytesOf(member)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// checkPrivate is rule 5: the private half corresponds to the public half.
func (s *jwkVectorState) checkPrivate() error {
	switch s.str["kty"] {
	case "RSA":
		return s.checkPrivateRSA()
	case "EC":
		d, err := s.bytesOf("d")
		if err != nil {
			return err
		}
		x, err := s.bytesOf("x")
		if err != nil {
			return err
		}
		y, err := s.bytesOf("y")
		if err != nil {
			return err
		}
		priv, err := ecdh.P256().NewPrivateKey(d)
		if err != nil {
			return fmt.Errorf("d is not a P-256 scalar: %w", err)
		}
		// 0x04 || x || y is the uncompressed point d*G.
		want := append(append([]byte{4}, x...), y...)
		if !bytes.Equal(priv.PublicKey().Bytes(), want) {
			return fmt.Errorf("d*G is not (x, y)")
		}
	case "OKP":
		d, err := s.bytesOf("d")
		if err != nil {
			return err
		}
		x, err := s.bytesOf("x")
		if err != nil {
			return err
		}
		if len(d) != ed25519.SeedSize {
			return fmt.Errorf("d is %d octets, an Ed25519 seed is %d", len(d), ed25519.SeedSize)
		}
		if !bytes.Equal(ed25519.NewKeyFromSeed(d).Public().(ed25519.PublicKey), x) {
			return fmt.Errorf("the public key of seed d is not x")
		}
	case "AKP":
		return s.checkPrivateMLDSA44()
	default:
		return fmt.Errorf("unknown kty %q", s.str["kty"])
	}
	return nil
}

func (s *jwkVectorState) checkPrivateRSA() error {
	n, err := s.bigOf("n")
	if err != nil {
		return err
	}
	e, err := s.bigOf("e")
	if err != nil {
		return err
	}
	d, err := s.bigOf("d")
	if err != nil {
		return err
	}
	p, err := s.bigOf("p")
	if err != nil {
		return err
	}
	q, err := s.bigOf("q")
	if err != nil {
		return err
	}
	if new(big.Int).Mul(p, q).Cmp(n) != 0 {
		return fmt.Errorf("p*q != n")
	}
	if !e.IsInt64() || e.Int64() > 1<<31-1 {
		return fmt.Errorf("e does not fit an int")
	}
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())},
		D:         d,
		Primes:    []*big.Int{p, q},
	}
	if err := key.Validate(); err != nil {
		return fmt.Errorf("RSA key does not validate: %w", err)
	}
	key.Precompute()
	for _, c := range []struct {
		member string
		have   *big.Int
	}{{"dp", key.Precomputed.Dp}, {"dq", key.Precomputed.Dq}, {"qi", key.Precomputed.Qinv}} {
		want, err := s.bigOf(c.member)
		if err != nil {
			return err
		}
		if c.have == nil || c.have.Cmp(want) != 0 {
			return fmt.Errorf("CRT member %q does not follow from p, q and d", c.member)
		}
	}
	// n and e as the draft's DNSKEY carries them (RFC 3110), read back out
	// of the RR text rather than out of the JWK.
	raw, err := base64.StdEncoding.DecodeString(s.draftRR.PublicKey)
	if err != nil || len(raw) < 2 {
		return fmt.Errorf("draft DNSKEY public key is not base64: %v", err)
	}
	elen, off := int(raw[0]), 1
	if elen == 0 {
		if len(raw) < 3 {
			return fmt.Errorf("draft DNSKEY public key is short")
		}
		elen, off = int(raw[1])<<8|int(raw[2]), 3
	}
	if off+elen >= len(raw) {
		return fmt.Errorf("draft DNSKEY public key is short")
	}
	if new(big.Int).SetBytes(raw[off:off+elen]).Cmp(e) != 0 || new(big.Int).SetBytes(raw[off+elen:]).Cmp(n) != 0 {
		return fmt.Errorf("n/e in the draft's DNSKEY are not the JWK's n/e")
	}
	return nil
}

// checkPrivateMLDSA44: priv is the 32-byte seed. Expanding it with CIRCL
// must give exactly pub.
func (s *jwkVectorState) checkPrivateMLDSA44() error {
	seed, err := s.bytesOf("priv")
	if err != nil {
		return err
	}
	if len(seed) != mldsa44.SeedSize {
		return fmt.Errorf("priv is %d octets, an ML-DSA seed is %d", len(seed), mldsa44.SeedSize)
	}
	pub, err := s.bytesOf("pub")
	if err != nil {
		return err
	}
	var sd [mldsa44.SeedSize]byte
	copy(sd[:], seed)
	got, _ := mldsa44.NewKeyFromSeed(&sd)
	gotBytes, err := got.MarshalBinary()
	if err != nil {
		return err
	}
	if !bytes.Equal(gotBytes, pub) {
		return fmt.Errorf("seed %x expands to a public key that is not pub", seed)
	}
	return nil
}

// checkPublicOf: the public vector is the private one minus its private
// members.
func (s *jwkVectorState) checkPublicOf(privJSON []byte) error {
	var priv map[string]json.RawMessage
	if err := json.Unmarshal(privJSON, &priv); err != nil {
		return err
	}
	for _, m := range jwkVectorMembers[s.str["kty"]].priv {
		delete(priv, m)
	}
	if len(priv) != len(s.members) {
		return fmt.Errorf("public JWK has %d members, the private one minus its private ones %d", len(s.members), len(priv))
	}
	for k, want := range priv {
		var a, b any
		if json.Unmarshal(want, &a) != nil || json.Unmarshal(s.members[k], &b) != nil || !reflect.DeepEqual(a, b) {
			return fmt.Errorf("member %q differs from the private JWK's", k)
		}
	}
	return nil
}

type jwkVectorStep struct {
	name string
	run  func(*jwkVectorState) error
}

var jwkVectorSteps = []jwkVectorStep{
	{"dnskey-parameter", (*jwkVectorState).checkDNSKEYParameter},
	{"members", (*jwkVectorState).checkMembers},
	{"kty-crv-alg", (*jwkVectorState).checkProfile},
	{"encoding", (*jwkVectorState).checkEncoding},
	{"rebuild-dnskey", (*jwkVectorState).checkRebuild},
	{"keytag", (*jwkVectorState).checkKeyTag},
	{"kid-thumbprint", (*jwkVectorState).checkKid},
	{"private-matches-public", func(s *jwkVectorState) error {
		if !s.vec.private {
			return nil
		}
		return s.checkPrivate()
	}},
}

func readJWKVectorFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "dnssec-jwk", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDNSSECJWKDraftVectors runs every check on every vector from the draft.
func TestDNSSECJWKDraftVectors(t *testing.T) {
	for _, vec := range jwkVectors {
		t.Run(vec.name, func(t *testing.T) {
			s, err := loadJWKVector(vec, readJWKVectorFile(t, vec.name+".json"),
				string(readJWKVectorFile(t, vec.dnskeyFile)))
			if err != nil {
				t.Fatal(err)
			}
			steps := jwkVectorSteps
			if vec.publicOf != "" {
				priv := readJWKVectorFile(t, vec.publicOf+".json")
				steps = append(append([]jwkVectorStep(nil), steps...), jwkVectorStep{
					"public-is-private-minus-d", func(s *jwkVectorState) error { return s.checkPublicOf(priv) }})
			}
			for _, st := range steps {
				t.Run(st.name, func(t *testing.T) {
					err := st.run(s)
					reason, known := jwkVectorKnownBad[vec.name+"/"+st.name]
					switch {
					case err != nil && known:
						t.Logf("known-bad vector (%s): %v", reason, err)
					case err != nil:
						t.Error(err)
					case known:
						t.Errorf("listed in jwkVectorKnownBad (%s) but passes: remove the entry", reason)
					}
				})
			}
		})
	}
}

// TestDNSSECJWKDraftVectorFileForm pins what the Appendix A text says about
// serialization: the escaped owner name appears in the JSON as b\\000rken, a
// doubled backslash, and in the DNSKEY RR as b\000rken.
func TestDNSSECJWKDraftVectorFileForm(t *testing.T) {
	if !bytes.Contains(readJWKVectorFile(t, "ed25519-escaped-owner.json"), []byte(`"name": "b\\000rken.example.com."`)) {
		t.Error(`JWK file does not hold "b\\000rken.example.com." (JSON-escaped backslash)`)
	}
	if !bytes.HasPrefix(readJWKVectorFile(t, "ed25519-escaped-owner.dnskey"), []byte(`b\000rken.example.com. IN DNSKEY`)) {
		t.Error(`DNSKEY file does not start with b\000rken.example.com.`)
	}
}

// TestDNSSECJWKVectorChecksHaveTeeth damages one vector in the way each
// check is meant to catch and requires that exact check to fail, so a check
// that can never fail does not pass for free.
func TestDNSSECJWKVectorChecksHaveTeeth(t *testing.T) {
	ed := jwkVectors[2]
	rsaVec := jwkVectors[0]
	mldsa := jwkVectors[3]
	cases := []struct {
		vec    jwkVector
		edit   func(string) string
		step   string
		reason string
	}{
		{ed, func(j string) string { return strings.Replace(j, `"keytag": 63713`, `"keytag": 63714`, 1) },
			"keytag", "wrong keytag member"},
		{ed, func(j string) string { return strings.Replace(j, `"keytag": 63713`, `"keytag": "63713"`, 1) },
			"dnskey-parameter", "keytag as a string"},
		{ed, func(j string) string { return strings.Replace(j, `"protocol": 3`, `"protocol": 4`, 1) },
			"dnskey-parameter", "protocol 4"},
		{ed, func(j string) string { return strings.Replace(j, `"flags": 256`, `"flags": 257`, 1) },
			"rebuild-dnskey", "flags that differ from the RR"},
		{ed, func(j string) string { return strings.Replace(j, `"crv": "Ed25519"`, `"crv": "Ed448"`, 1) },
			"kty-crv-alg", "curve that does not fit the algorithm"},
		{ed, func(j string) string { return strings.Replace(j, `"kid": "sddE`, `"kid": "sddF`, 1) },
			"kid-thumbprint", "kid that is not the thumbprint"},
		{ed, func(j string) string { return strings.Replace(j, `"d": "Dz9K`, `"d": "Dz9L`, 1) },
			"private-matches-public", "seed that does not give x"},
		{ed, func(j string) string { return strings.Replace(j, `"dnskey"`, `"dnskeyx"`, 1) },
			"dnskey-parameter", "no dnskey parameter"},
		{rsaVec, func(j string) string { return strings.Replace(j, `"dq": "HGtz`, `"dq": "HGt0`, 1) },
			"private-matches-public", "CRT member that does not follow"},
		{rsaVec, func(j string) string {
			return strings.Replace(j, `  "e": "AQAB",`, `  "e": "AQAB",`+"\n"+`  "oth": [],`, 1)
		},
			"members", "oth present"},
		{mldsa, func(j string) string { return strings.Replace(j, `"priv": "AAEC`, `"priv": "AAED`, 1) },
			"private-matches-public", "seed that does not expand to pub"},
	}
	for _, c := range cases {
		t.Run(c.reason, func(t *testing.T) {
			orig := string(readJWKVectorFile(t, c.vec.name+".json"))
			edited := c.edit(orig)
			if edited == orig {
				t.Fatal("edit changed nothing; the test text is out of date")
			}
			s, err := loadJWKVector(c.vec, []byte(edited), string(readJWKVectorFile(t, c.vec.dnskeyFile)))
			if err != nil {
				t.Fatal(err)
			}
			// "dnskey-parameter" fills in what the later steps read, as in
			// the real run; only the named step has to fail.
			perr := s.checkDNSKEYParameter()
			if c.step == "dnskey-parameter" {
				if perr == nil {
					t.Errorf("step %q did not fail for: %s", c.step, c.reason)
				}
				return
			}
			if perr != nil {
				t.Fatalf("dnskey-parameter failed first: %v", perr)
			}
			for _, st := range jwkVectorSteps {
				if st.name == c.step {
					if err := st.run(s); err == nil {
						t.Errorf("step %q did not fail for: %s", c.step, c.reason)
					}
					return
				}
			}
			t.Fatalf("no step %q", c.step)
		})
	}
}
