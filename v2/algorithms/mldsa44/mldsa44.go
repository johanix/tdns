// Package mldsa44 provides a [dns.Algorithm] implementation of
// NIST FIPS 204 ML-DSA-44 for DNSSEC SIG(0) transaction signing and
// RRSIG zone signing.
//
// tdns registers it in every binary, at the codepoint IANA assigned to
// ML-DSA-44 (18, per draft-westerbaan-dnssec-mldsa): see
// github.com/johanix/tdns/v2/algorithms. Applications do not register it
// themselves.
//
// The package came from github.com/johanix/dnssec-algorithms/mldsa44
// (at 4d74f08). The key encodings are unchanged: the private key string
// and the PKCS#8 codec (pkcs8.go) are byte for byte the same, so keys
// minted there load here.
//
// All [dns.Algorithm] interface methods are implemented on top of
// github.com/cloudflare/circl/sign/mldsa/mldsa44.
package mldsa44

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/miekg/dns"
)

// Compile-time assertion that CIRCL's ML-DSA-44 private key satisfies
// crypto.Signer, so the shared sign() path in miekg/dns can use it.
var _ crypto.Signer = (*mldsa44.PrivateKey)(nil)

// Impl is the ML-DSA-44 [dns.Algorithm] implementation. Construct
// with [New]; pass the returned value to [dns.RegisterAlgorithm].
type Impl struct{}

// New returns a [dns.Algorithm] implementation for ML-DSA-44.
func New() *Impl { return &Impl{} }

func (*Impl) Name() string      { return "MLDSA44" }
func (*Impl) Hash() crypto.Hash { return 0 }

func (*Impl) Generate(bits int) (crypto.PrivateKey, error) {
	if bits != 0 {
		return nil, dns.ErrKeySize
	}
	_, priv, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func (*Impl) PublicKeyFromWire(buf []byte) (crypto.PublicKey, error) {
	if len(buf) != mldsa44.PublicKeySize {
		return nil, dns.ErrKey
	}
	pk := new(mldsa44.PublicKey)
	if err := pk.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	return pk, nil
}

func (*Impl) PublicKeyToWire(pub crypto.PublicKey) ([]byte, error) {
	p, ok := pub.(*mldsa44.PublicKey)
	if !ok {
		return nil, dns.ErrKey
	}
	return p.MarshalBinary()
}

func (*Impl) ReadPrivateKey(m map[string]string) (crypto.PrivateKey, error) {
	v, ok := m["privatekey"]
	if !ok {
		return nil, dns.ErrPrivKey
	}
	buf, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}
	if len(buf) != mldsa44.PrivateKeySize {
		return nil, dns.ErrPrivKey
	}
	p := new(mldsa44.PrivateKey)
	if err := p.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	return p, nil
}

func (*Impl) PrivateKeyToString(priv crypto.PrivateKey) (string, error) {
	p, ok := priv.(*mldsa44.PrivateKey)
	if !ok {
		return "", dns.ErrPrivKey
	}
	buf, err := p.MarshalBinary()
	if err != nil {
		return "", err
	}
	return "PrivateKey: " + base64.StdEncoding.EncodeToString(buf) + "\n", nil
}

func (*Impl) Verify(pub crypto.PublicKey, hashed, sig []byte) error {
	p, ok := pub.(*mldsa44.PublicKey)
	if !ok {
		return dns.ErrKey
	}
	if mldsa44.Verify(p, hashed, nil, sig) {
		return nil
	}
	return dns.ErrSig
}

func (*Impl) SignaturePostProcess(sig []byte) ([]byte, error) {
	return sig, nil
}
