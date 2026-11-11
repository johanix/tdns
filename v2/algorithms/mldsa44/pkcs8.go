package mldsa44

import (
	"crypto"
	"crypto/subtle"
	"encoding/asn1"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"

	"github.com/johanix/dnssec-algorithms/mldsakey"
	dnsalgpkcs8 "github.com/johanix/dnssec-algorithms/pkcs8"
)

var params = mldsakey.MLDSA44

// privateKeyInfo is the pre-RFC 9881 layout this codec still writes:
// CIRCL's 2560-byte packed expanded key straight in the privateKey
// OCTET STRING, no inner wrapping.
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
		Algo:       algorithmIdentifier{Algorithm: params.OID},
		PrivateKey: skBytes,
	})
}

// ParsePKCS8 reads all three RFC 9881 forms (seed, expandedKey, both)
// and the legacy layout earlier releases wrote. A key read from the
// seed or both form keeps its seed (see [mldsa44.PrivateKey.Seed]).
func (pkcs8Codec) ParsePKCS8(der []byte) (crypto.PrivateKey, error) {
	k, err := mldsakey.ParseAs(params, der)
	if err != nil {
		return nil, err
	}
	return privateKeyFrom(k)
}

// privateKeyFrom expands k. For the both form it refuses a key whose
// seed does not expand to its expanded key, as RFC 9881 section 8.2
// requires of a recipient that checks.
func privateKeyFrom(k mldsakey.Key) (*mldsa44.PrivateKey, error) {
	if k.Seed == nil {
		sk := new(mldsa44.PrivateKey)
		if err := sk.UnmarshalBinary(k.Expanded); err != nil {
			return nil, fmt.Errorf("%s private key decode: %w", params.Name, err)
		}
		return sk, nil
	}
	var seed [mldsa44.SeedSize]byte
	copy(seed[:], k.Seed)
	_, sk := mldsa44.NewKeyFromSeed(&seed)
	if k.Expanded != nil && subtle.ConstantTimeCompare(sk.Bytes(), k.Expanded) != 1 {
		return nil, fmt.Errorf("%s private key, both form: the seed does not expand to the stored expanded key", params.Name)
	}
	return sk, nil
}

func init() {
	dnsalgpkcs8.Register(pkcs8Codec{})
}
