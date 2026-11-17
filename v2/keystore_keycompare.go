/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Comparing a stored private key with an offered one, for the import
 * paths that must tell "the same key again" from "another key under the
 * same keyid".
 *
 * The keystore column holds PKCS#8 PEM, but not one canonical text of it:
 * a bulk import stores the PEM it was given verbatim, while a JWK import
 * and the single-key import write PrivateKeyToPEM's encoding. One key can
 * therefore sit in the keystore as OpenSSL's ML-DSA seed-plus-expanded
 * form, with CRLF line ends, with 76-column lines, with text before BEGIN,
 * or as an EC key whose inner SEC1 carries a compressed public point, and
 * come back as tdns's own encoding. Comparing the texts reported every one
 * of those as a conflict. Comparing the decoded keys does not.
 */
package tdns

import (
	"crypto"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/johanix/dnssec-algorithms/mldsakey"
	"github.com/miekg/dns"
)

// keyCompare is the verdict of comparePrivateKeyPEM.
type keyCompare int

const (
	// keySame: the same key, whatever the two texts look like.
	keySame keyCompare = iota
	// keyDiffers: another key, or (when either side cannot be decoded by
	// this binary) another text.
	keyDiffers
	// keyStoredWithoutSeed: the same ML-DSA key, but the stored row has
	// no seed and the offered one has. Not "unchanged": the offered row
	// is better (it can be exported as JWK), and --force is how the
	// operator completes the stored one.
	keyStoredWithoutSeed
)

// detail is the diff label for each verdict; key material is
// never part of it.
func (c keyCompare) detail() string {
	switch c {
	case keyDiffers:
		return "privatekey"
	case keyStoredWithoutSeed:
		return "privatekey (stored without seed)"
	}
	return ""
}

// comparePrivateKeyPEM compares two PKCS#8 PEM private keys by what they
// decode to, not by their text.
//
// When either side does not decode in this binary -- an algorithm that is
// not linked, a legacy BIND-format row, a malformed blob -- it falls back
// to comparing the texts, as the import paths did before. That keeps
// pre-load able to restore (and to recognise as unchanged) keys whose
// algorithm this binary does not link; see validateDnssecKeyRR.
func comparePrivateKeyPEM(stored, offered string) keyCompare {
	if stored == offered {
		return keySame
	}
	sk, err := PEMToPrivateKey(stored)
	if err != nil {
		return keyDiffers
	}
	ok, err := PEMToPrivateKey(offered)
	if err != nil {
		return keyDiffers
	}
	if !privateKeysEqual(sk, ok) {
		return keyDiffers
	}
	if mldsaSeedOnlyOffered(stored, offered) {
		return keyStoredWithoutSeed
	}
	return keySame
}

// privateKeysEqual compares key material independent of its encoding.
// Every key type tdns stores has an Equal (the stdlib's RSA, ECDSA and
// Ed25519, CIRCL's Ed448 and ML-DSA); for one that does not, the two keys
// are compared in tdns's own PKCS#8 encoding, which is canonical for a
// given key.
func privateKeysEqual(a, b crypto.PrivateKey) bool {
	type equaler interface {
		Equal(crypto.PrivateKey) bool
	}
	if ea, ok := a.(equaler); ok {
		return ea.Equal(b)
	}
	pa, errA := PrivateKeyToPEM(a)
	pb, errB := PrivateKeyToPEM(b)
	return errA == nil && errB == nil && pa == pb
}

// mldsaSeedOnlyOffered reports whether stored is an ML-DSA key kept
// without its seed (expanded-only or legacy form) while offered carries
// one. CIRCL's Equal ignores the seed, so this is asked separately. A key
// that is not ML-DSA gives false.
func mldsaSeedOnlyOffered(stored, offered string) bool {
	sd, so := pemDER(stored), pemDER(offered)
	if sd == nil || so == nil {
		return false
	}
	_, storedHas, err := mldsakey.Seed(sd)
	if err != nil || storedHas {
		return false
	}
	_, offeredHas, err := mldsakey.Seed(so)
	return err == nil && offeredHas
}

func pemDER(s string) []byte {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil
	}
	return block.Bytes
}

// privateKeyField is the diffFields entry for the private key: it carries
// comparePrivateKeyPEM's verdict rather than the two texts, so that the
// same key in another encoding is not a difference.
func privateKeyField(stored, offered string) (field, keyCompare) {
	c := comparePrivateKeyPEM(stored, offered)
	if c == keySame {
		return field{name: "privatekey"}, c
	}
	return field{name: c.detail(), have: "stored", want: "offered"}, c
}

// sameKeyRRText compares two key RRs in canonical presentation form (so
// whitespace and comments do not count, but TTL does, as it does in the
// bulk import's diff).
func sameKeyRRText(a, b string) bool {
	canon := func(s string) string {
		if rr, err := dns.NewRR(strings.TrimSpace(s)); err == nil && rr != nil {
			return rr.String()
		}
		return strings.TrimSpace(s)
	}
	return canon(a) == canon(b)
}

// keptPrivateKey is the text a replace writes: the stored text when the
// offered key is the same key, so that a forced replace of other fields
// does not churn the PEM; the offered text otherwise, including an ML-DSA
// key that brings the seed the stored row lacks.
func keptPrivateKey(c keyCompare, stored, offered string) string {
	if c == keySame {
		return stored
	}
	return offered
}

// singleKeyAdd is what a single-key import does with a key that may
// already be in the store.
type singleKeyAdd struct {
	write   bool   // false: leave the row alone
	replace bool   // the row exists and is overwritten
	msg     string // what to tell the operator
}

// decideSingleKeyAdd decides a single-key import ("keystore <class> add")
// of a key that is already stored under the same owner and keyid. A
// replacement writes the row afresh, which resets its state to newState
// (an active key goes back to created), so it is never done by accident:
//
//   - the same key and RR: "unchanged", nothing written, the state kept;
//   - anything different: refused, naming the stored state and what
//     differs, unless force;
//   - force: replaced, also when identical (a deliberate reset).
//
// found is false for a key not yet in the store, which is simply added.
func decideSingleKeyAdd(store, zone string, keyid uint16, found bool, curState, curPriv, curRR,
	newState, newPriv, newRR string, force bool) (singleKeyAdd, error) {
	if !found {
		return singleKeyAdd{write: true}, nil
	}
	var diffs []string
	if c := comparePrivateKeyPEM(curPriv, newPriv); c != keySame {
		diffs = append(diffs, c.detail())
	}
	if !sameKeyRRText(curRR, newRR) {
		diffs = append(diffs, "keyrr")
	}
	what := fmt.Sprintf("%s key %s keyid %d", store, zone, keyid)
	switch {
	case len(diffs) == 0 && !force:
		return singleKeyAdd{msg: fmt.Sprintf("Unchanged: %s is already in the keystore (state %s) and is the same key; "+
			"nothing written. --force replaces it and resets its state to %s.", what, curState, newState)}, nil
	case !force:
		return singleKeyAdd{}, fmt.Errorf("%s is already in the keystore in state %s and differs (%s); "+
			"a replacement resets its state to %s. Use --force to replace it.",
			what, curState, strings.Join(diffs, ", "), newState)
	case len(diffs) == 0:
		return singleKeyAdd{write: true, replace: true, msg: fmt.Sprintf("Replaced %s on --force: the same key, "+
			"state reset from %s to %s.", what, curState, newState)}, nil
	}
	return singleKeyAdd{write: true, replace: true, msg: fmt.Sprintf("Replaced %s on --force (differs: %s): "+
		"state reset from %s to %s.", what, strings.Join(diffs, ", "), curState, newState)}, nil
}
