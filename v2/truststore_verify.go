/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"time"

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

// LookupChildKeyAtSignal queries _sig0key.<childzone>._signal.<ns>. for KEY
// records for each NS serving the child zone. Returns the union of KEY RRs
// found, whether all responses were DNSSEC-validated, and any error.
func LookupChildKeyAtSignal(ctx context.Context, childZone string, imr *Imr) ([]dns.RR, bool, error) {
	// First, look up the child zone's NS records.
	nsResp, err := imr.ImrQuery(ctx, dns.Fqdn(childZone), dns.TypeNS, dns.ClassINET, nil)
	if err != nil {
		return nil, false, fmt.Errorf("IMR query for %s NS failed: %v", childZone, err)
	}
	if nsResp.Error || nsResp.RRset == nil || len(nsResp.RRset.RRs) == 0 {
		return nil, false, fmt.Errorf("no NS records found for %s", childZone)
	}

	var allKeys []dns.RR
	allValidated := true
	found := false

	for _, rr := range nsResp.RRset.RRs {
		nsRR, ok := rr.(*dns.NS)
		if !ok {
			continue
		}

		// _sig0key.<childzone>._signal.<ns>. -- the same spelling the child
		// side publishes (signal_republish.go).
		signalName := signalOwnerName(signalPrefixSig0Key, childZone, nsRR.Ns)
		lgSigner.Debug("LookupChildKeyAtSignal: querying", "name", signalName)

		keyResp, err := imr.ImrQuery(ctx, signalName, dns.TypeKEY, dns.ClassINET, nil)
		if err != nil {
			lgSigner.Debug("LookupChildKeyAtSignal: query failed", "name", signalName, "err", err)
			continue
		}
		if keyResp.Error || keyResp.RRset == nil || len(keyResp.RRset.RRs) == 0 {
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
// again from the child name.
func VerifyChildKey(ctx context.Context, childZone string, keyRR string, imr *Imr, pol DelegationPolicy) (verified bool, dnssecValidated bool) {
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
			keys, validated, err := LookupChildKeyAtSignal(ctx, childZone, imr)
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
	var pol DelegationPolicy
	if parentZone != "" {
		if pzd, ok := Zones.Get(parentZone); ok {
			pol = pzd.boundDelegationPolicy()
		} else {
			pol = compiledDefaultDelegationPolicy()
		}
	} else {
		pol = parentDelegationPolicy(childZone)
	}
	if len(pol.Mechanisms) == 0 {
		lgSigner.Info("TriggerChildKeyVerification: policy has empty mechanisms; not verifying",
			"zone", childZone, "keyid", keyid, "policy", pol.Name)
		return nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		kdb.runChildKeyVerification(ctx, childZone, keyid, pol, imrChildKeyVerifier(childZone, keyRR, pol))
	}()
	return done
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

func imrChildKeyVerifier(childZone, keyRR string, pol DelegationPolicy) childKeyVerifier {
	return func(ctx context.Context) (bool, bool, error) {
		imr := Globals.ImrEngine
		if imr == nil {
			return false, false, errors.New("IMR engine not yet available")
		}
		verified, dnssecValidated := VerifyChildKey(ctx, childZone, keyRR, imr, pol)
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
