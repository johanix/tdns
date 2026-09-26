package debug

import (
	"crypto"
	"testing"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// newTestSigner builds an in-memory SIG(0) signer for tests.
//
// LoadSig0Signer reads a keypair off disk, which a unit test should not need.
// This generates an Ed25519 keypair and assembles the same Sig0Signer shape
// directly, so tests get a real signature over real wire bytes without any
// provisioning. Ed25519 is chosen because miekg/dns supports it natively — no
// C-backed algorithm support is linked into the pure-client debug package.
func newTestSigner(t *testing.T, name string) *Sig0Signer {
	t.Helper()

	name = dns.Fqdn(name)
	// dns.KEY embeds DNSKEY, which carries the header.
	key := &dns.KEY{DNSKEY: dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
	}}
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = dns.ED25519

	priv, err := key.Generate(256)
	if err != nil {
		t.Fatalf("generating test SIG(0) key for %s: %v", name, err)
	}
	cs, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("generated key for %s is not a crypto.Signer", name)
	}

	return &Sig0Signer{
		Zone:    name,
		KeyName: name,
		sak: &tdns.Sig0ActiveKeys{
			Keys: []*tdns.PrivateKeyCache{{
				CS:        cs,
				K:         priv,
				KeyRR:     *key,
				KeyType:   dns.TypeKEY,
				Algorithm: key.Algorithm,
				KeyId:     key.KeyTag(),
			}},
		},
	}
}

// publicKEY returns the signer's public KEY RR, for verifying responses it signed.
func (s *Sig0Signer) publicKEY() *dns.KEY {
	if s == nil || s.sak == nil || len(s.sak.Keys) == 0 {
		return nil
	}
	k := s.sak.Keys[0].KeyRR
	return &k
}
