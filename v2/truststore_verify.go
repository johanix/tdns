/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// childKeyQuery looks up the KEY RRset at name for child key verification:
// the child's apex, or one signal name.
//
// Fresh, past the IMR cache (ImrQueryFresh). An attempt is only worth making
// if it can see what changed since the last one, and a KEY published after
// the first attempt would otherwise sit behind that attempt's cached NXDOMAIN
// for the whole negative TTL (#677).
//
// Indirected so a test can see which names are asked, and answer them,
// without standing up an IMR. Production code MUST NOT reassign this. Tests
// reassign it and restore the original via t.Cleanup.
var childKeyQuery = func(ctx context.Context, imr *Imr, name string) (*ImrResponse, error) {
	if imr == nil {
		return nil, errors.New("IMR engine not available")
	}
	return imr.ImrQueryFresh(ctx, name, dns.TypeKEY, dns.ClassINET)
}

// atNsNameservers returns the nameservers at-ns builds its signal names from:
// the NS RRset of childZone's delegation, as parentZone holds it on this server.
//
// Read from the parent's own zone data, never resolved. It used to be the
// child's apex NS RRset, asked of the IMR. That had two faults (#677). A stale
// cached RRset sent every attempt to the old nameservers and never to the one
// holding the key, so a correct, validating KEY failed its bootstrap. And the
// child chose which nameservers were asked for its own key, which is what
// signal names exist to prevent. The parent is authoritative for the
// delegation, so it has nothing to resolve and nothing to validate.
//
// Nameservers inside the child zone are dropped while the parent holds no DS
// for the child. Their signal names lie inside the child zone itself, so the
// child alone controls them, and with no DS nothing there can validate. With a
// DS the child's chain of trust reaches them, and they are kept.
//
// Read at every attempt rather than once, so a delegation update that lands
// after the key upload is seen by the next attempt.
//
// An error means there is nothing to ask: no delegating zone was named, this
// server does not hold it, it holds no NS for the child, or every NS is inside
// the child and there is no DS. Falling back to the child's apex NS would
// reintroduce both faults.
func atNsNameservers(parentZone, childZone string) (*core.RRset, error) {
	if parentZone == "" {
		return nil, fmt.Errorf("no delegating zone known for %s", childZone)
	}
	if core.EqualNames(parentZone, childZone) {
		return nil, fmt.Errorf("%s cannot be its own delegating zone", childZone)
	}
	pzd, ok := Zones.Get(parentZone)
	if !ok {
		return nil, fmt.Errorf("this server is not authoritative for %s, the zone delegating %s", parentZone, childZone)
	}
	child := dns.Fqdn(childZone)
	nsRRset, err := pzd.GetRRset(child, dns.TypeNS)
	if err != nil {
		return nil, fmt.Errorf("cannot read the delegation of %s from %s: %v", childZone, parentZone, err)
	}
	if nsRRset == nil || len(nsRRset.RRs) == 0 {
		return nil, fmt.Errorf("%s holds no NS delegation for %s", parentZone, childZone)
	}
	dsRRset, err := pzd.GetRRset(child, dns.TypeDS)
	if err != nil {
		return nil, fmt.Errorf("cannot read the DS of %s from %s: %v", childZone, parentZone, err)
	}
	if dsRRset != nil && len(dsRRset.RRs) > 0 {
		return nsRRset, nil
	}

	out := &core.RRset{Name: nsRRset.Name, Class: nsRRset.Class, RRtype: nsRRset.RRtype}
	for _, rr := range nsRRset.RRs {
		if ns, ok := rr.(*dns.NS); ok && dns.IsSubDomain(child, ns.Ns) {
			continue
		}
		out.RRs = append(out.RRs, rr)
	}
	if len(out.RRs) == 0 {
		return nil, fmt.Errorf("every NS of %s is inside the child and %s holds no DS for it", childZone, parentZone)
	}
	return out, nil
}

// childKeyVerdict is what one KEY lookup concluded about the offered key.
type childKeyVerdict int

const (
	// childKeyNotFound: no KEY there, or the lookup did not finish. Another
	// attempt may find it.
	childKeyNotFound childKeyVerdict = iota
	// childKeyRejected: a KEY is there and another attempt cannot change the
	// answer. It is bogus, it is not the offered key, or it is in an unsigned
	// zone while the policy requires DNSSEC.
	childKeyRejected
	// childKeyAccepted: the offered key, acceptable under the policy.
	childKeyAccepted
)

func (v childKeyVerdict) String() string {
	switch v {
	case childKeyNotFound:
		return "not-found"
	case childKeyRejected:
		return "rejected"
	case childKeyAccepted:
		return "accepted"
	}
	return fmt.Sprintf("verdict(%d)", int(v))
}

// childKeyFinding is the verdict on one lookup: the child's apex, or one
// signal name.
type childKeyFinding struct {
	verdict childKeyVerdict
	dnssec  bool // accepted, and DNSSEC-validated
	why     string
}

// errChildKeyFinal marks a verification failure that no further attempt can
// change. runChildKeyVerification stops retrying on it.
var errChildKeyFinal = errors.New("a further attempt cannot change this verdict")

type childKeyFinalError struct{ msg string }

func (e *childKeyFinalError) Error() string        { return e.msg }
func (e *childKeyFinalError) Is(target error) bool { return target == errChildKeyFinal }

// judgeChildKeyAnswer turns one KEY lookup at name into a verdict on keyRR.
// There are three cases (#677):
//
//   - No KEY there, or the lookup did not finish: not found, and worth another
//     attempt. A DNSSEC validation that could not be concluded is a lookup
//     that did not finish.
//   - A KEY in a signed zone: DNSSEC decides. Bogus is rejected, and so is a
//     valid KEY that is not the offered key. The offered key, validated, is
//     accepted.
//   - A KEY in an unsigned zone: accepted only where the policy does not
//     require DNSSEC (childKeyAcceptable), rejected otherwise. Another attempt
//     would find the zone just as unsigned.
//
// There is no "published but not yet signed" case: a signed zone serves its
// data signed.
func judgeChildKeyAnswer(name string, resp *ImrResponse, err error, keyRR string, pol DelegationPolicy) childKeyFinding {
	switch {
	case err != nil:
		return childKeyFinding{verdict: childKeyNotFound, why: fmt.Sprintf("KEY lookup at %s failed: %v", name, err)}
	case resp == nil:
		return childKeyFinding{verdict: childKeyNotFound, why: fmt.Sprintf("KEY lookup at %s returned nothing", name)}
	case resp.Error:
		return childKeyFinding{verdict: childKeyNotFound, why: fmt.Sprintf("KEY lookup at %s failed: %s", name, resp.ErrorMsg)}
	case resp.RRset == nil || len(resp.RRset.RRs) == 0:
		return childKeyFinding{verdict: childKeyNotFound, why: fmt.Sprintf("no KEY at %s", name)}
	}

	match := matchKeyRR(resp.RRset.RRs, keyRR)
	state := resp.ValidationState
	if resp.Validated {
		state = cache.ValidationStateSecure
	}
	switch state {
	case cache.ValidationStateBogus:
		return childKeyFinding{verdict: childKeyRejected, why: fmt.Sprintf("the KEY at %s is DNSSEC-bogus", name)}
	case cache.ValidationStateSecure:
		if match {
			return childKeyFinding{verdict: childKeyAccepted, dnssec: true,
				why: fmt.Sprintf("the offered KEY is at %s, DNSSEC-validated", name)}
		}
		return childKeyFinding{verdict: childKeyRejected,
			why: fmt.Sprintf("the KEY at %s is DNSSEC-validated but is not the offered key", name)}
	case cache.ValidationStateInsecure:
		if !match {
			return childKeyFinding{verdict: childKeyRejected, why: fmt.Sprintf("the KEY at %s is not the offered key", name)}
		}
		if childKeyAcceptable(true, false, pol) {
			return childKeyFinding{verdict: childKeyAccepted,
				why: fmt.Sprintf("the offered KEY is at %s, in an unsigned zone", name)}
		}
		return childKeyFinding{verdict: childKeyRejected,
			why: fmt.Sprintf("the offered KEY is at %s, but in an unsigned zone, and require-dnssec is set", name)}
	default:
		if match && childKeyAcceptable(true, false, pol) {
			return childKeyFinding{verdict: childKeyAccepted,
				why: fmt.Sprintf("the offered KEY is at %s, not DNSSEC-validated", name)}
		}
		return childKeyFinding{verdict: childKeyNotFound,
			why: fmt.Sprintf("the KEY at %s could not be DNSSEC-validated (%s)", name, validationStateName(state))}
	}
}

// atNsFindings looks for the offered key at the signal name of each
// nameserver atNsNameservers selects, one finding per name.
//
// With no nameserver to ask, the finding is not-found rather than rejected:
// the delegation the next attempt reads may name one.
func atNsFindings(ctx context.Context, childZone, parentZone, keyRR string, imr *Imr, pol DelegationPolicy) []childKeyFinding {
	nameservers, err := atNsNameservers(parentZone, childZone)
	if err != nil {
		lgSigner.Info("VerifyChildKey: at-ns not tried, no nameserver in the delegation to build signal names from",
			"zone", childZone, "parent", parentZone, "err", err)
		return []childKeyFinding{{verdict: childKeyNotFound, why: err.Error()}}
	}
	var out []childKeyFinding
	for _, rr := range nameservers.RRs {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		// _sig0key.<childzone>._signal.<ns>. -- the same spelling the child
		// side publishes (signal_republish.go).
		name := signalOwnerName(signalPrefixSig0Key, childZone, ns.Ns)
		lgSigner.Debug("VerifyChildKey: querying signal name", "zone", childZone, "name", name)
		resp, err := childKeyQuery(ctx, imr, name)
		out = append(out, judgeChildKeyAnswer(name, resp, err, keyRR, pol))
	}
	return out
}

// VerifyChildKey looks for a child's offered KEY (keyRR) where the policy's
// mechanisms say, and judges every answer on its own (judgeChildKeyAnswer).
// The policy is the caller's: TriggerChildKeyVerification resolves it once
// from the receiving parent zone and passes it here rather than looking it up
// again from the child name. parentZone is that same zone: at-ns reads the
// child's delegation from it (atNsNameservers).
//
// One DNSSEC-validated KEY, at the apex or at any one signal name, is enough,
// and ends the search. A KEY acceptable without validation (require-dnssec
// off) is kept while the remaining mechanisms get the chance to validate it.
//
// When the key is not accepted, reason says why, naming every lookup. It Is
// errChildKeyFinal when every lookup was rejected: nothing another attempt
// could see would change that. If any lookup found nothing, or did not finish,
// it is a plain error, and another attempt may succeed.
func VerifyChildKey(ctx context.Context, childZone, parentZone string, keyRR string, imr *Imr, pol DelegationPolicy) (accepted, dnssecValidated bool, reason error) {
	var findings []childKeyFinding
	for _, mech := range pol.Mechanisms {
		var found []childKeyFinding
		switch mech {
		case "at-apex":
			name := dns.Fqdn(childZone)
			resp, err := childKeyQuery(ctx, imr, name)
			found = []childKeyFinding{judgeChildKeyAnswer(name, resp, err, keyRR, pol)}
		case "at-ns":
			found = atNsFindings(ctx, childZone, parentZone, keyRR, imr, pol)
		default:
			continue // compileDelegationPolicy admits no other mechanism
		}
		for _, f := range found {
			lgSigner.Debug("VerifyChildKey: finding", "zone", childZone, "mechanism", mech,
				"verdict", f.verdict, "why", f.why)
			if f.verdict == childKeyAccepted && f.dnssec {
				lgSigner.Info("VerifyChildKey: key found and DNSSEC-validated",
					"zone", childZone, "mechanism", mech, "why", f.why)
				return true, true, nil
			}
			f.why = mech + ": " + f.why
			findings = append(findings, f)
		}
	}
	return childKeyOutcome(childZone, findings)
}

// childKeyOutcome sums up findings that contain no validated acceptance.
func childKeyOutcome(childZone string, findings []childKeyFinding) (accepted, dnssecValidated bool, reason error) {
	if len(findings) == 0 {
		return false, false, errors.New("no verification mechanism looked for the KEY")
	}
	final := true
	var why []string
	for _, f := range findings {
		switch f.verdict {
		case childKeyAccepted:
			lgSigner.Info("VerifyChildKey: key found, not DNSSEC-validated, and the policy allows that",
				"zone", childZone, "why", f.why)
			return true, false, nil
		case childKeyNotFound:
			final = false
		}
		why = append(why, f.why)
	}
	msg := strings.Join(why, "; ")
	if final {
		return false, false, &childKeyFinalError{msg: msg}
	}
	return false, false, errors.New(msg)
}

// matchKeyRR reports whether any of rrs carries the same KEY as keyRR.
//
// Compares the RDATA -- flags, protocol, algorithm, public key -- rather than
// the rendered record, because the two verification mechanisms fetch the same
// key under DIFFERENT owner names, and with whatever TTL the cache has left on
// it.
//
// at-ns is why. The child publishes its apex KEY re-owned to the RFC 9615
// signal name, _sig0key.<child>._signal.<ns>. -- that re-owning IS the
// mechanism -- while keyRR is the child-apex form the parent was handed. Two
// rendered strings that differ in their owner name by construction never
// compared equal, so at-ns could not verify a key in any configuration, and the
// log said "key not found" about a record that was present and validating
// (#569).
//
// TTL is the same defect one step quieter. Both lookups go through
// imr.ImrQuery, so a record served from a warm cache renders with a decremented
// TTL and stops matching. at-apex worked only for as long as the TTLs happened
// to come back unchanged. The producer side had already settled this for the
// same comparison -- signalRRsEqual is documented as "same set, ignoring TTL".
//
// No identity is given up by ignoring the owner: both lookups are already
// scoped to the child, at-apex by querying it and at-ns by building the signal
// name from it, so the only open question here is whether the key found there
// is the key that was offered.
func matchKeyRR(rrs []dns.RR, keyRR string) bool {
	parsed, err := dns.NewRR(keyRR)
	if err != nil {
		lgSigner.Warn("matchKeyRR: cannot parse the offered key record", "err", err)
		return false
	}
	want, ok := parsed.(*dns.KEY)
	if !ok {
		lgSigner.Warn("matchKeyRR: the offered record is not a KEY",
			"rrtype", dns.TypeToString[parsed.Header().Rrtype])
		return false
	}

	for _, rr := range rrs {
		key, ok := rr.(*dns.KEY)
		if !ok {
			continue
		}
		if key.Flags == want.Flags &&
			key.Protocol == want.Protocol &&
			key.Algorithm == want.Algorithm &&
			key.PublicKey == want.PublicKey {
			return true
		}
	}
	return false
}

// waitOrDone sleeps for d, or returns false the moment ctx is cancelled.
//
// A plain time.Sleep kept the key-verification retry goroutine alive past
// shutdown for as long as the wait had left to run, and with a configured
// retry-interval that could be a long time after everything else had stopped.
func waitOrDone(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// rememberDiscoveredChildKey records a child SIG(0) key that was found in DNS
// as known-but-untrusted, and starts the verification that can promote it.
//
// Without this a key the parent can find AND validate is refused forever.
// TriggerChildKeyVerification had exactly one caller: the TRUSTSTORE-UPDATE arm
// of the updater, after a key has been STORED. The DNS-discovery path in
// ValidateUpdate stores nothing, so it produced no verification, so the key
// stayed untrusted and every update from that child was refused with "known but
// not trusted" -- permanently, with nothing in the log to say what was being
// waited for. Neither delegation policy offered a way out: with unvalidated
// uploads refused nothing is ever stored, and with them allowed a child that
// already holds a key never runs the upload ceremony in the first place (#574).
//
// A row has to exist before the verifier can do anything: promotion is an
// UPDATE of the TrustStore row, so a verification with no row promotes nothing.
// Stored untrusted, which authorises nothing by itself -- the verification is
// what decides, exactly as it does for an uploaded key.
//
// Reached at most once per key. ValidateUpdate consults the TrustStore first
// and returns on a hit whether or not the row is trusted, so the second update
// from this child takes that path instead and no second verification starts.
//
// Best effort: a child that cannot be recorded is refused as it was before,
// which is what would have happened anyway.
//
// Returns the verifier's completion channel, or nil when this call did not
// start one. Nil covers every way that can happen -- not a child, a policy that
// will not verify, a row that was already there, a database failure -- so a
// caller can tell "verification is under way because of me" from "nothing
// happened", and a test can wait for that verifier rather than racing its own
// cleanup against it.
func (zd *ZoneData) rememberDiscoveredChildKey(ctx context.Context, key *Sig0Key) <-chan struct{} {
	if zd == nil || zd.KeyDB == nil || key == nil {
		return nil
	}
	// Only for names this zone actually delegates. Any signer at all can
	// publish a KEY and send us a signed UPDATE; without this that is a way to
	// have rows created for arbitrary names.
	if !zd.IsChildDelegation(key.Name) {
		lgSigner.Debug("not recording a discovered SIG(0) key: not a child delegation of this zone",
			"zone", zd.ZoneName, "signer", key.Name, "keyid", key.Keyid)
		return nil
	}

	// A policy with no mechanisms is an operator declining automatic
	// bootstrap. Storing a row anyway leaves an untrusted entry that nothing
	// will ever promote and no log line explaining why -- the same dead end
	// #574 was, dressed as progress. The update is still refused; it is just
	// refused without pretending a verification is under way.
	if len(zd.boundDelegationPolicy().Mechanisms) == 0 {
		lgSigner.Info("not recording a discovered SIG(0) key: this zone's delegation policy"+
			" has no verification mechanisms, so nothing could promote it",
			"zone", zd.ZoneName, "signer", key.Name, "keyid", key.Keyid)
		return nil
	}

	keyRR := key.Key.String()
	tx, err := zd.KeyDB.Begin("rememberDiscoveredChildKey")
	if err != nil {
		lgSigner.Error("cannot record a discovered child SIG(0) key", "zone", key.Name, "err", err)
		return nil
	}
	resp, err := zd.KeyDB.Sig0TrustMgmt(tx, TruststorePost{
		Command:    "sig0",
		SubCommand: "add",
		Zone:       zd.ZoneName,
		Keyname:    key.Name,
		Keyid:      int(key.Keyid),
		// Validated is what the DNS lookup concluded; trusted is not ours to
		// grant here.
		Validated:       key.Validated,
		DnssecValidated: key.Validated,
		Trusted:         false,
		Src:             "dns",
		KeyRR:           keyRR,
	})
	if err != nil || (resp != nil && resp.Error) {
		_ = tx.Rollback()
		msg := ""
		if resp != nil {
			msg = resp.ErrorMsg
		}
		lgSigner.Error("cannot record a discovered child SIG(0) key",
			"zone", key.Name, "keyid", key.Keyid, "err", err, "resp", msg)
		return nil
	}
	if err := tx.Commit(); err != nil {
		lgSigner.Error("cannot commit a discovered child SIG(0) key",
			"zone", key.Name, "keyid", key.Keyid, "err", err)
		return nil
	}
	if resp != nil && resp.Existed {
		// Already recorded, so a verification is already running or has
		// already concluded. Starting another would re-verify a key that may
		// by now be trusted.
		lgSigner.Debug("discovered child SIG(0) key was already in the truststore",
			"parent", zd.ZoneName, "zone", key.Name, "keyid", key.Keyid)
		return nil
	}

	lgSigner.Info("recorded a child SIG(0) key found in DNS; verifying it",
		"parent", zd.ZoneName, "zone", key.Name, "keyid", key.Keyid, "dnssec_validated", key.Validated)
	return zd.KeyDB.TriggerChildKeyVerification(ctx, key.Name, zd.ZoneName, key.Keyid, keyRR)
}

// TriggerChildKeyVerification starts an async verification of a child KEY
// that was just stored in the TrustStore: DNS lookup, a few spaced retries,
// then trust. ctx is the engine's lifetime context. The verification can be
// asleep between attempts when the process is asked to stop; without ctx the
// goroutine ignores shutdown and the deferred key cleanup it performs runs
// against a database that is closing.
// Returns a channel closed when the verifier goroutine exits, and nil when no
// verification was started. Production ignores it; it exists so a test can wait
// for THIS verifier rather than watching the process-wide goroutine count,
// which an unrelated goroutine starting or stopping makes meaningless in either
// direction. Same shape as deferForImr.
func (kdb *KeyDB) TriggerChildKeyVerification(ctx context.Context, childZone, parentZone string, keyid uint16, keyRR string) <-chan struct{} {
	pol, parentZone := childKeyPolicy(childZone, parentZone)
	if len(pol.Mechanisms) == 0 {
		lgSigner.Info("TriggerChildKeyVerification: policy has empty mechanisms; not verifying",
			"zone", childZone, "keyid", keyid, "policy", pol.Name)
		return nil
	}
	// One verification per key (childKeyVerifications says why). A second
	// request while one runs is not lost: the running one decides the same row.
	id := childKeyVerificationID(childZone, keyid)
	if _, running := childKeyVerifications.LoadOrStore(id, struct{}{}); running {
		lgSigner.Info("TriggerChildKeyVerification: already verifying this key; not starting another",
			"zone", childZone, "keyid", keyid)
		return nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Released before done closes, so a caller that waits on done can
		// start the next verification of the key.
		defer childKeyVerifications.Delete(id)
		// Stamped before the release above (defers run last-in, first-out),
		// so a re-bootstrap never finds the key neither verifying nor cooling
		// down (childKeyCoolingDown).
		defer noteChildKeyVerificationEnded(childZone, keyid, time.Now)
		kdb.runChildKeyVerification(ctx, childZone, keyid, pol, imrChildKeyVerifier(childZone, parentZone, keyRR, pol))
	}()
	return done
}

// childKeyPolicy resolves the delegation policy for verifying childZone's key,
// and the delegating zone at-ns reads the delegation from. Both come from the
// same zone, so the policy and the delegation it is applied to cannot belong
// to different parents.
//
// parentZone is the receiving zone when the caller knows it. When it is not
// held here, the compiled default policy applies and the name is kept:
// atNsNameservers reports it as not authoritative at each attempt, and at-ns is
// not tried. An empty parentZone means the caller does not know it (only tests
// reach this today), and the closest enclosing zone held here is used.
func childKeyPolicy(childZone, parentZone string) (DelegationPolicy, string) {
	if parentZone != "" {
		if pzd, ok := Zones.Get(parentZone); ok {
			return pzd.boundDelegationPolicy(), parentZone
		}
		return compiledDefaultDelegationPolicy(), parentZone
	}
	if pzd := FindParentZone(childZone); pzd != nil {
		return pzd.boundDelegationPolicy(), pzd.ZoneName
	}
	return compiledDefaultDelegationPolicy(), ""
}

// childKeyVerifier makes one verification attempt. accepted means the key may
// be promoted to trusted now; otherwise reason says why not (it becomes the
// persisted ValidationError if every attempt ends this way). Injected so the
// retry/exhaustion engine can be tested without an IMR; the production
// verifier is imrChildKeyVerifier.
type childKeyVerifier func(ctx context.Context) (accepted, dnssecValidated bool, reason error)

// childKeyAcceptable is the trust rule, in one place so it cannot quietly grow
// a third condition.
//
// A child KEY found where the policy allows, and DNSSEC-validated there, is
// SUFFICIENT for promotion to trusted. That is not a convenience: DNSSEC
// validation of the published KEY is the only evidence the at-apex and at-ns
// mechanisms produce, so if it is not enough on its own, neither mechanism can
// ever complete and there is no automatic bootstrap at all.
//
// require-dnssec makes that evidence necessary; nothing makes it insufficient.
// mechanisms are the SCOPE of the search rather than an extra requirement --
// VerifyChildKey only looks where they say -- so "validated" already means
// "validated somewhere this parent agreed to look".
//
// The one thing that is not a cryptographic question: a policy with no
// mechanisms at all is an operator declining automatic bootstrap, and
// TriggerChildKeyVerification returns before reaching here.
func childKeyAcceptable(verified, dnssecValidated bool, pol DelegationPolicy) bool {
	if !verified {
		return false
	}
	return dnssecValidated || !pol.RequireDnssec
}

func imrChildKeyVerifier(childZone, parentZone, keyRR string, pol DelegationPolicy) childKeyVerifier {
	return func(ctx context.Context) (bool, bool, error) {
		imr := Globals.ImrEngine
		if imr == nil {
			return false, false, errors.New("IMR engine not yet available")
		}
		return VerifyChildKey(ctx, childZone, parentZone, keyRR, imr, pol)
	}
}

// runChildKeyVerification is the retry/exhaustion engine behind
// TriggerChildKeyVerification. On acceptance it promotes the key to trusted
// (the "verify" truststore subcommand, which also clears any earlier failure)
// and completes a deferred bootstrap DEL-ANY-KEY.
//
// Attempts are pol.RetryInterval apart, not backed off (#677). A KEY that is
// simply not there yet is worth a few attempts, each of which really asks
// (childKeyQuery bypasses the cache). A longer wait belongs to the child,
// which knows when it asked for its key to be published; the parent keeps no
// goroutine waiting on someone else's schedule. A final verdict
// (errChildKeyFinal) ends the attempts at once.
//
// On a final verdict or exhaustion it RECORDS the failure on the truststore
// row (K-4 code 8): from then on the KeyState inquiry reports
// KEY_VALIDATION_FAILED rather than "in progress", and a signed UPDATE is
// refused with EDE KEY-VALIDATION-FAILED. The reason names every lookup. The
// child's remedy is to re-bootstrap, which starts verification over
// (reBootstrapOfKnownKey), once the cooldown has passed. A shutdown mid-way
// records nothing; the row stays "in progress" and a re-upload starts over.
func (kdb *KeyDB) runChildKeyVerification(ctx context.Context, childZone string, keyid uint16, pol DelegationPolicy, verify childKeyVerifier) bool {
	maxAttempts, retryInterval := pol.RetryMaxAttempts, pol.RetryInterval
	var lastReason error
	attempts := 0

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		attempts = attempt
		lgSigner.Info("verifying child key via DNS",
			"zone", childZone, "keyid", keyid, "attempt", attempt, "max", maxAttempts)

		accepted, dnssecValidated, reason := verify(ctx)
		if accepted {
			// Update TrustStore: mark as validated + trusted.
			tx, err := kdb.Begin("VerifyChildKey")
			if err != nil {
				lgSigner.Error("TriggerChildKeyVerification: failed to begin tx", "err", err)
				return false
			}

			tppost := TruststorePost{
				SubCommand:      "verify",
				Keyname:         childZone,
				Keyid:           int(keyid),
				DnssecValidated: dnssecValidated,
			}
			_, err = kdb.Sig0TrustMgmt(tx, tppost)
			if err != nil {
				lgSigner.Error("TriggerChildKeyVerification: failed to update TrustStore", "err", err)
				tx.Rollback()
				return false
			}
			if err := tx.Commit(); err != nil {
				lgSigner.Error("TriggerChildKeyVerification: failed to commit", "err", err)
				return false
			}

			lgSigner.Info("child key verified and trusted",
				"zone", childZone, "keyid", keyid, "dnssec", dnssecValidated)

			// The key is now trusted; complete any deferred bootstrap
			// DEL-ANY-KEY by removing the child's now-superseded keys.
			kdb.applyPendingKeyReplacement(ctx, childZone, keyid)
			return true
		}

		if reason == nil {
			reason = errors.New("the key was not accepted")
		}
		lastReason = reason
		if errors.Is(reason, errChildKeyFinal) {
			lgSigner.Info("child key verification reached a final verdict; not retrying",
				"zone", childZone, "keyid", keyid, "reason", reason)
			break
		}
		if attempt < maxAttempts {
			lgSigner.Info("child key not yet verifiable, will retry",
				"zone", childZone, "keyid", keyid, "reason", reason, "delay", retryInterval)
			if !waitOrDone(ctx, retryInterval) {
				lgSigner.Info("TriggerChildKeyVerification: shutting down, abandoning verification",
					"zone", childZone, "keyid", keyid)
				return false
			}
		}
	}

	// A cancel that landed inside the last attempt is a shutdown, not a
	// verdict on the key: the loop fell out with a "context canceled" reason,
	// and recording that as a validation failure would tell the child that
	// waiting will not help when nothing was concluded. Same rule as the
	// backoff branch above.
	if ctx.Err() != nil {
		lgSigner.Info("TriggerChildKeyVerification: shutting down during the last attempt, not recording a verdict",
			"zone", childZone, "keyid", keyid)
		return false
	}

	why := fmt.Sprintf("%s via %v: %v", attemptsText(attempts), pol.Mechanisms, lastReason)
	lgSigner.Warn("child key verification failed; recording validation failure",
		"zone", childZone, "keyid", keyid, "reason", why)
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command:         "child-sig0-mgmt",
		SubCommand:      "validation-failed",
		Keyname:         childZone,
		Keyid:           int(keyid),
		ValidationError: why,
	}); err != nil {
		lgSigner.Error("TriggerChildKeyVerification: failed to record validation failure",
			"zone", childZone, "keyid", keyid, "err", err)
	}
	return false
}

func attemptsText(n int) string {
	if n == 1 {
		return "1 attempt"
	}
	return fmt.Sprintf("%d attempts", n)
}
