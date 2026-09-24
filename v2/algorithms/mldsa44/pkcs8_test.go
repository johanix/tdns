package mldsa44

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"

	dnsalgpkcs8 "github.com/johanix/dnssec-algorithms/pkcs8"
)

func TestPKCS8RoundTrip(t *testing.T) {
	_, sk, err := mldsa44.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	der, err := dnsalgpkcs8.Marshal(sk)
	if err != nil {
		t.Fatalf("pkcs8.Marshal: %v", err)
	}

	parsed, err := dnsalgpkcs8.Parse(der)
	if err != nil {
		t.Fatalf("pkcs8.Parse: %v", err)
	}
	sk2, ok := parsed.(*mldsa44.PrivateKey)
	if !ok {
		t.Fatalf("pkcs8.Parse returned %T, want *mldsa44.PrivateKey", parsed)
	}
	if !sk.Equal(sk2) {
		t.Errorf("round-tripped key does not equal original")
	}

	// Re-marshal the parsed key and confirm byte-for-byte equality
	// with the first marshal — exercises the codec's determinism.
	der2, err := dnsalgpkcs8.Marshal(sk2)
	if err != nil {
		t.Fatalf("re-Marshal: %v", err)
	}
	if !bytes.Equal(der, der2) {
		t.Error("re-marshaled DER differs from original")
	}
}

func TestPKCS8MarshalRejectsWrongType(t *testing.T) {
	c := pkcs8Codec{}
	_, err := c.MarshalPKCS8("not a key")
	if !errors.Is(err, dnsalgpkcs8.ErrUnsupported) {
		t.Errorf("got %v, want ErrUnsupported", err)
	}
}

func TestPKCS8ParseRejectsWrongOID(t *testing.T) {
	c := pkcs8Codec{}
	// Valid ASN.1 PrivateKeyInfo shape with a different OID. The
	// inner OID 2.16.840.1.101.3.4.3.99 is not assigned to ML-DSA-44.
	// We synthesize it by editing a real marshaled ML-DSA-44 key.
	_, sk, err := mldsa44.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := c.MarshalPKCS8(sk)
	if err != nil {
		t.Fatalf("MarshalPKCS8 setup: %v", err)
	}
	// The OID's last component is 17 in the encoding. Find its
	// position by scanning for the OID prefix bytes and flip the
	// trailing 17 to 99 (both single-byte values).
	prefix := []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03}
	i := bytes.Index(der, prefix)
	if i < 0 || i+len(prefix) >= len(der) {
		t.Fatalf("could not locate ML-DSA OID prefix in DER")
	}
	if der[i+len(prefix)] != 17 {
		t.Fatalf("expected OID last component 17, got %d", der[i+len(prefix)])
	}
	der[i+len(prefix)] = 99
	_, err = c.ParsePKCS8(der)
	if !errors.Is(err, dnsalgpkcs8.ErrUnsupported) {
		t.Errorf("got %v, want ErrUnsupported", err)
	}
}
