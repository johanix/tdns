package mldsa44

import (
	"crypto"
	"encoding/asn1"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"

	dnsalgpkcs8 "github.com/johanix/dnssec-algorithms/pkcs8"
)

// oid is the NIST OID for ML-DSA-44 (FIPS 204), per CIRCL's
// mldsa44.Scheme().Oid().
var oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}

// privateKeyInfo is a minimal PKCS#8 PrivateKeyInfo (RFC 5958) for an
// ML-DSA-44 key. The privateKey OCTET STRING holds CIRCL's 2560-byte
// packed key (expanded form, no inner wrapping). This is a demo-
// profile choice until draft-ietf-lamps-dilithium-certificates lands.
type privateKeyInfo struct {
	Version    int
	Algo       algorithmIdentifier
	PrivateKey []byte
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type pkcs8Codec struct{}

func (pkcs8Codec) MarshalPKCS8(priv crypto.PrivateKey) ([]byte, error) {
	sk, ok := priv.(*mldsa44.PrivateKey)
	if !ok {
		return nil, dnsalgpkcs8.ErrUnsupported
	}
	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(privateKeyInfo{
		Version:    0,
		Algo:       algorithmIdentifier{Algorithm: oid},
		PrivateKey: skBytes,
	})
}

func (pkcs8Codec) ParsePKCS8(der []byte) (crypto.PrivateKey, error) {
	var p privateKeyInfo
	if _, err := asn1.Unmarshal(der, &p); err != nil {
		// Not parseable as our PrivateKeyInfo shape — let other
		// codecs try.
		return nil, dnsalgpkcs8.ErrUnsupported
	}
	if !p.Algo.Algorithm.Equal(oid) {
		return nil, dnsalgpkcs8.ErrUnsupported
	}
	sk := new(mldsa44.PrivateKey)
	if err := sk.UnmarshalBinary(p.PrivateKey); err != nil {
		return nil, fmt.Errorf("ML-DSA-44 private key decode: %w", err)
	}
	return sk, nil
}

func init() {
	dnsalgpkcs8.Register(pkcs8Codec{})
}
