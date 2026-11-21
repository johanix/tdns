/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"sync"
	"time"

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

// childKeyReBootstrapCooldown is how long after a verification of a child key
// ends before a re-bootstrap of that key may start the next one (#677).
//
// A verification that failed tells the child to re-bootstrap, and a child
// that does starts it over. Without a pause a child could have the parent
// repeat its lookups back to back, as fast as it can send the ceremony. The
// child's own re-bootstrap schedule starts above this (childReBootstrapDelay),
// so a well-behaved child never meets it.
const childKeyReBootstrapCooldown = 5 * time.Minute

// childKeyVerificationsEnded holds, per child key, when its last verification
// in this process ended. In memory only: a restart forgets it, and a restart
// is pause enough.
var childKeyVerificationsEnded sync.Map

// noteChildKeyVerificationEnded records that a verification of child's key
// keyid ended at now().
func noteChildKeyVerificationEnded(child string, keyid uint16, now func() time.Time) {
	childKeyVerificationsEnded.Store(childKeyVerificationID(child, keyid), now())
}

// childKeyCoolingDown reports whether a verification of child's key keyid
// ended less than childKeyReBootstrapCooldown before now. An entry older than
// that is removed as it is found.
func childKeyCoolingDown(child string, keyid uint16, now time.Time) bool {
	return childKeyCooldownLeft(child, keyid, now) > 0
}

// childKeyCooldownLeft is how long until a re-bootstrap of child's key keyid
// may start a verification: zero when none ended within
// childKeyReBootstrapCooldown before now.
func childKeyCooldownLeft(child string, keyid uint16, now time.Time) time.Duration {
	id := childKeyVerificationID(child, keyid)
	v, ok := childKeyVerificationsEnded.Load(id)
	if !ok {
		return 0
	}
	if left := childKeyReBootstrapCooldown - now.Sub(v.(time.Time)); left > 0 {
		return left
	}
	childKeyVerificationsEnded.CompareAndDelete(id, v)
	return 0
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
//     underneath it would reset the row it is about to write;
//   - none ended within childKeyReBootstrapCooldown.
func reBootstrapOfKnownKey(ns []dns.RR, sig *dns.SIG, known *Sig0Key) *Sig0Key {
	reupload, _ := reBootstrapDecision(ns, sig, known, time.Now())
	return reupload
}

// reBootstrapDecision is reBootstrapOfKnownKey, and also says how long is left
// of the cooldown when that alone refused a genuine re-upload. The refusal
// then tells the child when to try again (EDESig0ReBootstrapTooSoon) rather
// than to re-bootstrap, which it just did (#1172).
func reBootstrapDecision(ns []dns.RR, sig *dns.SIG, known *Sig0Key, now time.Time) (*Sig0Key, time.Duration) {
	if known == nil || known.Trusted || sig == nil {
		return nil, 0
	}
	addKey, _, ok := bootstrapCeremony(ns)
	if !ok || addKey.KeyTag() != sig.RRSIG.KeyTag || addKey.Algorithm != sig.RRSIG.Algorithm ||
		!core.EqualNames(addKey.Header().Name, sig.RRSIG.SignerName) {
		return nil, 0
	}
	if addKey.Flags != known.Key.Flags || addKey.Protocol != known.Key.Protocol ||
		addKey.Algorithm != known.Key.Algorithm || addKey.PublicKey != known.Key.PublicKey {
		return nil, 0
	}
	if childKeyVerificationRunning(sig.RRSIG.SignerName, sig.RRSIG.KeyTag) {
		return nil, 0
	}
	if left := childKeyCooldownLeft(sig.RRSIG.SignerName, sig.RRSIG.KeyTag, now); left > 0 {
		lgSigner.Info("re-bootstrap of a child key refused: its last verification ended less than the cooldown ago",
			"zone", sig.RRSIG.SignerName, "keyid", sig.RRSIG.KeyTag, "cooldown", childKeyReBootstrapCooldown,
			"left", left.Round(time.Second))
		return nil, left
	}
	reupload := *known
	reupload.Key = *addKey
	reupload.Source = "child-key-upload"
	reupload.ValidationFailed = false
	reupload.ValidationError = ""
	return &reupload, 0
}

// reBootstrapTooSoonText is the EXTRA-TEXT of EDESig0ReBootstrapTooSoon: what
// the child was refused and when the same re-bootstrap will be accepted.
func reBootstrapTooSoonText(keyid uint16, left time.Duration) string {
	if left < time.Second {
		left = time.Second
	}
	return fmt.Sprintf("re-bootstrap of SIG(0) key %d refused: its last verification ended less than %s ago; re-bootstrap again in %s",
		keyid, childKeyReBootstrapCooldown, left.Round(time.Second))
}
