/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package algorithms

import (
	"crypto"
)

// signingKey is a DNSKEY or a KEY (which embeds one).
type signingKey interface {
	Generate(bits int) (crypto.PrivateKey, error)
	KeyTag() uint16
}

// generateSigningKey generates k's key pair, again until its key tag is not 0.
// A random key gets tag 0 about once in 65,536 tries, and the dns library will
// not sign with such a key (RRSIG.Sign returns ErrKey, "bad key"), so a test
// that signed with a fresh key failed that often.
func generateSigningKey(k signingKey, bits int) (crypto.PrivateKey, error) {
	for {
		priv, err := k.Generate(bits)
		if err != nil || k.KeyTag() != 0 {
			return priv, err
		}
	}
}
