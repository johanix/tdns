/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Rendering keystore keys as DNSSEC JWKs (draft-schlyter-dnsop-dnssec-jwk),
 * for `keystore <class> export --format jwk` and the bulk equivalent.
 *
 * Daemon-side for the same reason as bind_export.go: opening the stored
 * PKCS#8 of an Ed448 or ML-DSA key needs the algorithm's codec, and the
 * daemon is the component that links the algorithms it signs with.
 *
 * DNSSEC keys carry the "dnskey" parameter and SIG(0) keys "sig0key", never
 * the other way round: a SIG(0) KEY RR has flags 256, and the same bytes in
 * "dnskey" would import into any DNSSEC signer as a ZSK. Which one is
 * written is decided by the store the row came from, and the row's own RR
 * type must agree.
 */
package tdns

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/miekg/dns"

	core "github.com/johanix/tdns/v2/core"
)

// KeyFormatJWK is the DNSSEC JWK export format (one JSON object per key).
const KeyFormatJWK = "jwk"

// ErrJWKNoSeed: an ML-DSA key stored in the expanded-only PKCS#8 form. A
// JWK's "priv" is the 32-byte seed, and the seed cannot be recomputed
// from the expanded key, so such a key has no JWK form.
var ErrJWKNoSeed = errors.New("ML-DSA key is stored without its seed")

// IsJWKUnsupported reports whether err says the key cannot be a JWK at all
// (an algorithm with no JWK form, or an ML-DSA key without its seed), as
// opposed to a broken row. Only these are skipped by --skip-unsupported.
func IsJWKUnsupported(err error) bool {
	return errors.Is(err, core.ErrNoJWKRepresentation) || errors.Is(err, ErrJWKNoSeed)
}

// parseStoredKeyRR parses a keystore row's public RR and insists it is the
// type the store holds: DNSKEY for the DNSSEC store, KEY for SIG(0).
func parseStoredKeyRR(keyRR string, wantType uint16) (*dns.DNSKEY, error) {
	rr, err := dns.NewRR(strings.TrimSpace(keyRR))
	if err != nil {
		return nil, fmt.Errorf("unparsable public key RR: %v", err)
	}
	if rr == nil {
		return nil, fmt.Errorf("no public key RR found")
	}
	var k *dns.DNSKEY
	switch t := rr.(type) {
	case *dns.DNSKEY:
		k = t
	case *dns.KEY:
		k = &t.DNSKEY
	default:
		return nil, fmt.Errorf("public key RR is %s, want DNSKEY or KEY", dns.TypeToString[rr.Header().Rrtype])
	}
	if got := rr.Header().Rrtype; got != wantType {
		return nil, fmt.Errorf("public key RR is %s, but this store holds %s keys: the keystore row is inconsistent",
			dns.TypeToString[got], dns.TypeToString[wantType])
	}
	return k, nil
}

func mldsaJWK(alg string, pub interface{ Bytes() []byte }, seed []byte) (*core.JSONWebKey, error) {
	if seed == nil {
		return nil, fmt.Errorf("%w: %s keys stored by tdns releases before the seed form (or imported in the "+
			"expanded-only form) keep only the expanded key, and the 32-byte seed a JWK carries as \"priv\" "+
			"cannot be recovered from it, so this key has no JWK form; export it with --format pem or "+
			"--format bind instead, or replace it with a new key through a rollover (new keys keep their seed)",
			ErrJWKNoSeed, alg)
	}
	return &core.JSONWebKey{Kty: core.JWKKtyAKP, Alg: alg, Pub: pub.Bytes(), Priv: append([]byte(nil), seed...)}, nil
}

// privateJWKFromKey builds the private JWK for a parsed keystore key. The
// stdlib types go through the codec's converter; Ed448 and ML-DSA are
// filled from the same octets their PKCS#8 holds.
func privateJWKFromKey(priv crypto.PrivateKey) (*core.JSONWebKey, error) {
	switch p := priv.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		return core.NewJSONWebKeyFromPrivate(p)
	case ed448.PrivateKey:
		return &core.JSONWebKey{Kty: core.JWKKtyOKP, Crv: core.JWKCrvEd448,
			X: append([]byte(nil), p.Public().(ed448.PublicKey)...), D: p.Seed()}, nil
	case *mldsa44.PrivateKey:
		return mldsaJWK(core.JWKAlgMLDSA44, p.Public().(*mldsa44.PublicKey), p.Seed())
	case *mldsa65.PrivateKey:
		return mldsaJWK(core.JWKAlgMLDSA65, p.Public().(*mldsa65.PublicKey), p.Seed())
	case *mldsa87.PrivateKey:
		return mldsaJWK(core.JWKAlgMLDSA87, p.Public().(*mldsa87.PublicKey), p.Seed())
	}
	return nil, fmt.Errorf("stored private key is %T, which tdns cannot write as a JWK", priv)
}

// privateKeyFromJWK is the inverse of privateJWKFromKey. It does not apply
// the import rules; ParseDNSSECJWK / ParseSIG0JWK have done that.
func privateKeyFromJWK(k *core.JSONWebKey) (crypto.PrivateKey, error) {
	switch {
	case k.Kty == core.JWKKtyOKP && k.Crv == core.JWKCrvEd448:
		if len(k.D) != ed448.SeedSize {
			return nil, fmt.Errorf("Ed448 \"d\" is %d octets, want %d", len(k.D), ed448.SeedSize)
		}
		return ed448.NewKeyFromSeed(k.D), nil
	case k.Kty == core.JWKKtyAKP:
		var seed [32]byte
		if len(k.Priv) != len(seed) {
			return nil, fmt.Errorf("%s \"priv\" is %d octets, want the %d-octet seed", k.Alg, len(k.Priv), len(seed))
		}
		copy(seed[:], k.Priv)
		switch k.Alg {
		case core.JWKAlgMLDSA44:
			_, sk := mldsa44.NewKeyFromSeed(&seed)
			return sk, nil
		case core.JWKAlgMLDSA65:
			_, sk := mldsa65.NewKeyFromSeed(&seed)
			return sk, nil
		case core.JWKAlgMLDSA87:
			_, sk := mldsa87.NewKeyFromSeed(&seed)
			return sk, nil
		}
		return nil, fmt.Errorf("AKP \"alg\" %q is not an ML-DSA parameter set tdns knows", k.Alg)
	}
	return k.PrivateKey()
}

// keyJWKFromRR builds the DNSSEC JWK of the right kind for wantType.
func keyJWKFromRR(wantType uint16, rr *dns.DNSKEY, priv *core.JSONWebKey) (*core.DNSSECJWK, error) {
	if wantType == dns.TypeKEY {
		return core.NewSIG0JWK(&dns.KEY{DNSKEY: *rr}, priv)
	}
	return core.NewDNSSECJWK(rr, priv)
}

// parseKeyJWKAs parses a JWK of the kind wantType asks for, with all of the
// draft's import rules, and returns the key and the RR it rebuilds (a
// DNSKEY, or the DNSKEY inside a KEY).
func parseKeyJWKAs(data []byte, wantType uint16) (*core.DNSSECJWK, *dns.DNSKEY, error) {
	if wantType == dns.TypeKEY {
		d, rr, err := core.ParseSIG0JWK(data)
		if err != nil {
			return nil, nil, err
		}
		return d, &rr.DNSKEY, nil
	}
	return core.ParseDNSSECJWK(data)
}

// sameKeyRR compares the parts of two key RRs a JWK carries: owner name,
// flags, protocol, algorithm and public key. TTL and class are not in a JWK.
func sameKeyRR(a, b *dns.DNSKEY) bool {
	if !core.EqualNames(a.Hdr.Name, b.Hdr.Name) || a.Flags != b.Flags ||
		a.Protocol != b.Protocol || a.Algorithm != b.Algorithm {
		return false
	}
	pa, errA := base64.StdEncoding.DecodeString(a.PublicKey)
	pb, errB := base64.StdEncoding.DecodeString(b.PublicKey)
	return errA == nil && errB == nil && bytes.Equal(pa, pb)
}

// JWKForExport renders one stored key as a private DNSSEC JWK: "dnskey" for
// the DNSSEC store (wantType dns.TypeDNSKEY), "sig0key" for SIG(0)
// (dns.TypeKEY). kid and keytag are always written, "alg" only for AKP.
//
// Refused, with an error IsJWKUnsupported recognises: an algorithm with no
// JWK form, and an ML-DSA key stored without its seed. Refused as a broken
// row: a private key that does not fit the public RR.
//
// The output is parsed back with the draft's import rules, rule 5 included,
// and must rebuild the stored RR and the stored private key before it is
// returned; a file the import side would reject is never written.
func JWKForExport(wantType uint16, keyRR, privPEM string) (string, error) {
	rr, err := parseStoredKeyRR(keyRR, wantType)
	if err != nil {
		return "", err
	}
	if !core.HasJWKRepresentation(rr.Algorithm) {
		return "", fmt.Errorf("%w: algorithm %d (%s) has no JWK form (draft-schlyter-dnsop-dnssec-jwk "+
			"section 2.5, or no JOSE key type is defined for it); export it as pem or bind",
			core.ErrNoJWKRepresentation, rr.Algorithm, dns.AlgorithmToString[rr.Algorithm])
	}
	priv, err := PEMToPrivateKey(privPEM)
	if err != nil {
		return "", fmt.Errorf("unusable stored private key: %v", err)
	}
	if err := checkKeyTypeMatchesAlgorithm(rr.Algorithm, priv); err != nil {
		return "", err
	}
	pj, err := privateJWKFromKey(priv)
	if err != nil {
		return "", err
	}
	d, err := keyJWKFromRR(wantType, rr, pj)
	if err != nil {
		return "", fmt.Errorf("stored private key and public RR do not make a JWK: %w", err)
	}
	compact, err := json.Marshal(d)
	if err != nil {
		return "", err
	}

	// Self-check, through the import side.
	back, backRR, err := parseKeyJWKAs(compact, wantType)
	if err != nil {
		return "", fmt.Errorf("internal: the exported JWK fails its own import rules: %w", err)
	}
	if !sameKeyRR(backRR, rr) {
		return "", fmt.Errorf("internal: the exported JWK rebuilds %s, not the stored %s", backRR.String(), rr.String())
	}
	backPriv, err := privateKeyFromJWK(back.Key)
	if err != nil {
		return "", fmt.Errorf("internal: the exported JWK's private key does not load: %v", err)
	}
	eq, ok := priv.(interface{ Equal(crypto.PrivateKey) bool })
	if !ok || !eq.Equal(backPriv) {
		return "", fmt.Errorf("internal: the exported JWK's private key is not the stored key")
	}

	var out bytes.Buffer
	if err := json.Indent(&out, compact, "", "  "); err != nil {
		return "", err
	}
	out.WriteByte('\n')
	return out.String(), nil
}

// exportKeyMaterial renders one stored key in format. For jwk the JWK text
// comes back in jwk and priv is empty; for pem and bind it is the other way
// round. wantType is the store's RR type (DNSKEY or KEY).
func exportKeyMaterial(format string, wantType uint16, keyRR, privPEM, publishedAt, activeAt, retiredAt string) (priv, jwk string, err error) {
	if format == KeyFormatJWK {
		jwk, err = JWKForExport(wantType, keyRR, privPEM)
		return "", jwk, err
	}
	priv, err = PrivateKeyForExport(format, keyRR, privPEM, publishedAt, activeAt, retiredAt)
	return priv, "", err
}
