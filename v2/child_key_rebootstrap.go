/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"sync"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// childKeyVerifications holds the child keys a verification is running for in
// this process, so that there is at most one per key.
//
// A re-bootstrap starts verification over (reBootstrapOfKnownKey), which is
// only safe while nothing is verifying the key already: a second verifier would
// race the first to promote or fail the same row, and a re-upload replacing the
// row under a running verifier would reset what that verifier is about to
// write. It also bounds what a child can make the parent do by re-sending its
// upload: one verification at a time, however often it asks.
var childKeyVerifications sync.Map

func childKeyVerificationID(child string, keyid uint16) string {
	return fmt.Sprintf("%s::%d", core.CanonicalizeName(child), keyid)
}

// childKeyVerificationRunning reports whether a verification of child's key
// keyid is under way in this process.
func childKeyVerificationRunning(child string, keyid uint16) bool {
	_, ok := childKeyVerifications.Load(childKeyVerificationID(child, keyid))
	return ok
}

// reBootstrapOfKnownKey recognises a child re-bootstrapping a key the parent
// already holds but does not trust. It returns the signer's key as a
// self-signed upload, which sends the update down the same path as a first
// upload; nil for anything else.
//
// A first upload goes: TrustStore miss, self-signed upload, TRUSTSTORE-UPDATE,
// stored untrusted, verification. Every later upload of the same key hit the
// TrustStore first and stopped there, and TrustUpdate refused it as "known but
// not trusted". Once a verification had run out of attempts that refusal
// carried EDE KEY-VALIDATION-FAILED, whose text tells the child to re-bootstrap
// -- the one thing this made impossible, short of an operator deleting the row.
// A row left "in progress" by a restart was stuck the same way, with nothing
// running that could ever finish it.
//
// Only a genuine re-upload qualifies:
//   - the update is the bootstrap ceremony, and its ADD KEY is the signing key;
//   - that key is the key already stored, byte for byte: a different key under
//     the same tag would replace a row it has no claim to;
//   - the stored key is not trusted, since a trusted key needs no bootstrap;
//   - no verification of it is running: that one will decide, and starting over
//     underneath it would reset the row it is about to write.
func reBootstrapOfKnownKey(ns []dns.RR, sig *dns.SIG, known *Sig0Key) *Sig0Key {
	if known == nil || known.Trusted || sig == nil {
		return nil
	}
	addKey, _, ok := bootstrapCeremony(ns)
	if !ok || addKey.KeyTag() != sig.RRSIG.KeyTag || addKey.Algorithm != sig.RRSIG.Algorithm ||
		!core.EqualNames(addKey.Header().Name, sig.RRSIG.SignerName) {
		return nil
	}
	if addKey.Flags != known.Key.Flags || addKey.Protocol != known.Key.Protocol ||
		addKey.Algorithm != known.Key.Algorithm || addKey.PublicKey != known.Key.PublicKey {
		return nil
	}
	if childKeyVerificationRunning(sig.RRSIG.SignerName, sig.RRSIG.KeyTag) {
		return nil
	}
	reupload := *known
	reupload.Key = *addKey
	reupload.Source = "child-key-upload"
	reupload.ValidationFailed = false
	reupload.ValidationError = ""
	return &reupload
}
