/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// LookupChildKeyAtApex queries the child zone apex for KEY records via the
// IMR engine. Returns the KEY RRs found, whether the response was DNSSEC-
// validated, and any error.
func LookupChildKeyAtApex(ctx context.Context, childZone string, imr *Imr) ([]dns.RR, bool, error) {
	resp, err := imr.ImrQuery(ctx, dns.Fqdn(childZone), dns.TypeKEY, dns.ClassINET, nil)
	if err != nil {
		return nil, false, fmt.Errorf("IMR query for %s KEY failed: %v", childZone, err)
	}
	if resp.Error {
		return nil, false, fmt.Errorf("IMR query for %s KEY returned error: %s", childZone, resp.ErrorMsg)
	}
	if resp.RRset == nil || len(resp.RRset.RRs) == 0 {
		return nil, false, fmt.Errorf("no KEY records found at apex of %s", childZone)
	}

	return resp.RRset.RRs, resp.Validated, nil
}

// childKeySignalQuery indirects the KEY lookup at one signal name, so a test
// can see which names at-ns asks without standing up an IMR. Which names are
// asked is the thing worth pinning (#677).
//
// Production code MUST NOT reassign this. Tests reassign it and restore the
// original via t.Cleanup.
var childKeySignalQuery = func(ctx context.Context, imr *Imr, name string) (*ImrResponse, error) {
	return imr.ImrQuery(ctx, name, dns.TypeKEY, dns.ClassINET, nil)
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

// LookupChildKeyAtSignal queries _sig0key.<childzone>._signal.<ns>. for KEY
// records, for each NS in nameservers: those of the parent's own delegation
// that atNsNameservers selects (it says why not the child's apex NS). Returns the
// union of KEY RRs found, whether all responses were DNSSEC-validated, and any
// error.
func LookupChildKeyAtSignal(ctx context.Context, childZone string, nameservers *core.RRset, imr *Imr) ([]dns.RR, bool, error) {
	if nameservers == nil || len(nameservers.RRs) == 0 {
		return nil, false, fmt.Errorf("no nameservers to build signal names for %s from", childZone)
	}

	var allKeys []dns.RR
	allValidated := true
	found := false

	for _, rr := range nameservers.RRs {
		nsRR, ok := rr.(*dns.NS)
		if !ok {
			continue
		}

		// _sig0key.<childzone>._signal.<ns>. -- the same spelling the child
		// side publishes (signal_republish.go).
		signalName := signalOwnerName(signalPrefixSig0Key, childZone, nsRR.Ns)
		lgSigner.Debug("LookupChildKeyAtSignal: querying", "name", signalName)

		keyResp, err := childKeySignalQuery(ctx, imr, signalName)
		if err != nil {
			lgSigner.Debug("LookupChildKeyAtSignal: query failed", "name", signalName, "err", err)
			continue
		}
		if keyResp == nil || keyResp.Error || keyResp.RRset == nil || len(keyResp.RRset.RRs) == 0 {
			continue
		}

		found = true
		allKeys = append(allKeys, keyResp.RRset.RRs...)
		if !keyResp.Validated {
			allValidated = false
		}
	}

	if !found {
		return nil, false, fmt.Errorf("no KEY records found at _signal names for %s", childZone)
	}

	return allKeys, allValidated, nil
}

// VerifyChildKey checks whether a child's KEY (identified by keyRR string) can
// be found via the policy's verification mechanisms (at-apex, at-ns). The
// policy is the caller's: TriggerChildKeyVerification resolves it once from
// the receiving parent zone and passes it here rather than looking it up
// again from the child name. parentZone is that same zone: at-ns reads the
// child's delegation from it (atNsNameservers).
func VerifyChildKey(ctx context.Context, childZone, parentZone string, keyRR string, imr *Imr, pol DelegationPolicy) (verified bool, dnssecValidated bool) {
	mechanisms := pol.Mechanisms
	if len(mechanisms) == 0 {
		return false, false
	}

	// Try each mechanism in order. Stop as soon as we have a DNSSEC-validated
	// match. If a mechanism finds the key without DNSSEC validation, remember
	// that but keep trying — a later mechanism may provide validation.
	foundUnvalidated := false

	for _, mech := range mechanisms {
		switch mech {
		case "at-apex":
			keys, validated, err := LookupChildKeyAtApex(ctx, childZone, imr)
			if err != nil {
				lgSigner.Debug("VerifyChildKey: at-apex failed", "zone", childZone, "err", err)
				continue
			}
			if matchKeyRR(keys, keyRR) {
				lgSigner.Info("VerifyChildKey: key found via at-apex", "zone", childZone, "dnssec", validated)
				if validated {
					return true, true
				}
				foundUnvalidated = true
			} else {
				lgSigner.Debug("VerifyChildKey: key not found in at-apex results", "zone", childZone)
			}

		case "at-ns":
			nsRRset, err := atNsNameservers(parentZone, childZone)
			if err != nil {
				lgSigner.Info("VerifyChildKey: at-ns not tried, no nameserver in the delegation to build signal names from",
					"zone", childZone, "parent", parentZone, "err", err)
				continue
			}
			keys, validated, err := LookupChildKeyAtSignal(ctx, childZone, nsRRset, imr)
			if err != nil {
				lgSigner.Debug("VerifyChildKey: at-ns failed", "zone", childZone, "err", err)
				continue
			}
			if matchKeyRR(keys, keyRR) {
				lgSigner.Info("VerifyChildKey: key found via at-ns (_signal)", "zone", childZone, "dnssec", validated)
				if validated {
					return true, true
				}
				foundUnvalidated = true
			} else {
				lgSigner.Debug("VerifyChildKey: key not found in at-ns results", "zone", childZone)
			}
		}
	}

	return foundUnvalidated, false
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
// shutdown for as long as the backoff had left to run -- and the backoff
// doubles, so with a configured retry-interval that could be a long time after
// everything else had stopped.
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
// that was just stored in the TrustStore: DNS lookup, retry with backoff, then
// trust. ctx is the engine's lifetime context. The verification retries with
// exponential backoff and can therefore be sleeping for a long time when the
// process is asked to stop; without it the goroutine ignores shutdown and the
// deferred key cleanup it performs runs against a database that is closing.
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
		verified, dnssecValidated := VerifyChildKey(ctx, childZone, parentZone, keyRR, imr, pol)
		if !verified {
			return false, false, fmt.Errorf("KEY not found via %v", pol.Mechanisms)
		}
		// One predicate, and only one. This used to repeat the require-dnssec
		// condition inline and THEN call the helper, which left the helper
		// unable to reject anything -- so a rule added to it would have had no
		// effect here, which is the opposite of why it was extracted.
		// Compiled policy: absent require-dnssec became true at compile.
		if !childKeyAcceptable(verified, dnssecValidated, pol) {
			return false, false, errors.New(
				"KEY found but not DNSSEC-validated, and require-dnssec is set")
		}
		return true, dnssecValidated, nil
	}
}

// runChildKeyVerification is the retry/exhaustion engine behind
// TriggerChildKeyVerification. On acceptance it promotes the key to trusted
// (the "verify" truststore subcommand, which also clears any earlier failure)
// and completes a deferred bootstrap DEL-ANY-KEY. On exhaustion it RECORDS the
// failure on the truststore row (K-4 code 8): from then on the KeyState
// inquiry reports KEY_VALIDATION_FAILED rather than "in progress", and a
// signed UPDATE is refused with EDE KEY-VALIDATION-FAILED -- the child is told
// that waiting will not help. A shutdown mid-way records nothing; the row
// stays "in progress" and a re-upload starts over.
func (kdb *KeyDB) runChildKeyVerification(ctx context.Context, childZone string, keyid uint16, pol DelegationPolicy, verify childKeyVerifier) bool {
	maxAttempts, retryInterval := pol.RetryMaxAttempts, pol.RetryInterval
	var lastReason error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
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

		lastReason = reason
		if attempt < maxAttempts {
			lgSigner.Info("child key not yet verifiable, will retry",
				"zone", childZone, "keyid", keyid, "reason", reason, "delay", retryInterval)
			if !waitOrDone(ctx, retryInterval) {
				lgSigner.Info("TriggerChildKeyVerification: shutting down, abandoning verification",
					"zone", childZone, "keyid", keyid)
				return false
			}
			retryInterval *= 2 // exponential backoff
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

	why := fmt.Sprintf("%d attempts via %v: %v", maxAttempts, pol.Mechanisms, lastReason)
	lgSigner.Warn("child key verification exhausted all attempts; recording validation failure",
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
