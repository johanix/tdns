/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// ParentSyncAfterKeyPublication is called asynchronously after onLeaderElected
// publishes the SIG(0) KEY to the combiner. It queries the parent via KeyState
// EDNS(0) to determine if bootstrap is needed, and if so, sends the bootstrap
// UPDATE.
//
// Flow:
//  1. Check HSYNCPARAM parentsync=agent (caller already verified OptParentSync),
//     and again before every inquiry, bootstrap and delegation sync: the
//     poll stops when the zone's owner has taken the sync over
//  2. Query parent via KeyState EDNS(0) inquiry
//  3. KeyStateTrusted → done
//  4. KeyStateUnknown → bootstrap, once the zone's nameservers serve the
//     key (#917)
//  5. KeyStateBootstrapAutoOngoing → poll
//  6. Query failure → retry with backoff
func (conf *Config) ParentSyncAfterKeyPublication(ctx context.Context, zone ZoneName, keyName string, keyid uint16, algorithm uint8) {
	kdb := conf.Internal.KeyDB

	// Wait for IMR to become available (it starts asynchronously).
	var imr *Imr
	for i := 0; i < 10; i++ {
		imr = conf.Internal.ImrEngine
		if imr != nil {
			break
		}
		lgElect.Info("ParentSyncAfterKeyPublication: waiting for IMR engine", "zone", zone, "attempt", i+1)
		if !waitOrDone(ctx, 2*time.Second) {
			lgElect.Info("ParentSyncAfterKeyPublication: shutting down while waiting for the IMR engine",
				"zone", zone)
			return
		}
	}
	if imr == nil {
		lgElect.Error("ParentSyncAfterKeyPublication: IMR engine not available after waiting", "zone", zone)
		return
	}

	// Check HSYNCPARAM parentsync=agent.
	if !ZoneHasParentSyncAgent(zone) {
		lgElect.Info("ParentSyncAfterKeyPublication: parentsync is not 'agent', skipping", "zone", zone)
		return
	}

	// One poll per key, shared with the tdns-auth post-bootstrap poll.
	id := childKeyVerificationID(keyName, keyid)
	st := &childKeyPoll{}
	if _, running := childKeyStatePolls.LoadOrStore(id, st); running {
		lgElect.Info("ParentSyncAfterKeyPublication: already polling the parent for this key",
			"zone", zone, "keyid", keyid)
		return
	}
	defer childKeyStatePolls.Delete(id)

	poll := agentKeyStatePoll(kdb, imr, zone, keyName, keyid, algorithm)
	poll.state = st
	syncErr := conf.pollParentKeyState(ctx, poll)
	if syncErr != nil {
		lgElect.Warn("ParentSyncAfterKeyPublication: gave up (exhausted retries or terminal error)",
			"zone", zone, "keyid", keyid, "err", syncErr)
	}
}

// agentKeyStatePoll is the agent's poll of the parent for its key. The poll
// can run for many minutes, and the zone's owner may take the delegation sync
// over meanwhile, so it asks HSYNCPARAM again before every inquiry, bootstrap
// and delegation sync.
func agentKeyStatePoll(kdb *KeyDB, imr *Imr, zone ZoneName, keyName string, keyid uint16, algorithm uint8) parentKeyStatePoll {
	return parentKeyStatePoll{
		zone:                      zone,
		keyid:                     keyid,
		syncDelegationWhenTrusted: true,
		agentsSync:                func() bool { return ZoneHasParentSyncAgent(zone) },
		query: func(ctx context.Context) (*edns0.KeyStateOption, bool, error) {
			return QueryParentKeyState(ctx, kdb, imr, keyName, keyid)
		},
		record: func(state uint8) { UpdateParentState(kdb, keyName, keyid, state) },
		bootstrap: func(ctx context.Context) error {
			return BootstrapWithParent(ctx, zone, keyName, algorithm)
		},
		served:           sig0KeyServed(kdb, imr, keyName, keyid),
		pollDelay:        delegationSyncInitialDelay,
		wait:             waitOrDone,
		reBootstrapDelay: childReBootstrapDelay,
	}
}

// sig0KeyServed is the look at the zone's nameservers for its SIG(0) key
// keyid (keyServedCheck), the key read from the keystore when it looks. A key
// the keystore does not hold as active cannot be looked for, and does not
// hold the bootstrap. Without a keystore or a resolver there is no look.
func sig0KeyServed(kdb *KeyDB, imr *Imr, zone string, keyid uint16) func(context.Context) (keyServedState, string) {
	if kdb == nil || imr == nil {
		return nil
	}
	return func(ctx context.Context) (keyServedState, string) {
		sak, err := kdb.GetSig0Keys(zone, Sig0StateActive)
		if err != nil || sak == nil {
			return keyServedUnknown, fmt.Sprintf("the keystore cannot be read: %v", err)
		}
		for _, pkc := range sak.Keys {
			if pkc.KeyRR.KeyTag() == keyid {
				return imrKeyServedCheck(imr, zone, pkc.KeyRR.String()).look(ctx)
			}
		}
		return keyServedUnknown, fmt.Sprintf("no active SIG(0) key %d in the keystore", keyid)
	}
}

// childKeyStatePolls holds the child keys a KeyState poll of the parent is
// running for in this process, so that there is at most one per key: the
// agent's (ParentSyncAfterKeyPublication) or the tdns-auth post-bootstrap one
// (pollAfterAcceptedBootstrap). Keyed like childKeyVerifications; the value is
// the poll's *childKeyPoll.
var childKeyStatePolls sync.Map

// childKeyPoll is what a running poll tells others about itself through
// childKeyStatePolls.
type childKeyPoll struct {
	// bootstrapped mirrors the poll's own flag: the poll has sent its
	// bootstrap. From then on a parent that does not know the key is polled
	// again, not sent the key again (onParentKeyState), so a BADKEY
	// re-bootstrap must not leave the upload to this poll (#944).
	bootstrapped atomic.Bool
}

// markBootstrapped records that the poll has sent its bootstrap. A poll run
// outside the registry (a test) has no entry.
func (st *childKeyPoll) markBootstrapped() {
	if st != nil {
		st.bootstrapped.Store(true)
	}
}

// startChildKeyStatePoll runs poll in its own goroutine, unless a poll for
// zone's key keyid is already running. poll gets the key's registry entry. It
// returns a channel closed when the goroutine exits, or nil when none was
// started.
func startChildKeyStatePoll(zone string, keyid uint16, poll func(st *childKeyPoll)) <-chan struct{} {
	id := childKeyVerificationID(zone, keyid)
	st := &childKeyPoll{}
	if _, running := childKeyStatePolls.LoadOrStore(id, st); running {
		return nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer childKeyStatePolls.Delete(id)
		poll(st)
	}()
	return done
}

// pollAfterAcceptedBootstrap polls the parent's KeyState after it accepted a
// tdns-auth child's bootstrap ceremony, the way an agent polls after
// publishing its key (#677). A failed verification then leads to a
// re-bootstrap on the child's schedule, not to silence.
//
// The key is the zone's first active SIG(0) key, the one the ceremony sent
// (bootstrapSig0KeyWithParent). The ceremony has been sent, so a parent that
// still does not know the key is polled again, not bootstrapped again. Unlike
// the agent, this poll does not start a delegation sync when the key is
// trusted: the ceremony runs at every zone load, and so does this poll.
func (conf *Config) pollAfterAcceptedBootstrap(ctx context.Context, kdb *KeyDB, zd *ZoneData, algorithm uint8) <-chan struct{} {
	imr := conf.Internal.ImrEngine
	if imr == nil || kdb == nil {
		lgElect.Warn("pollAfterAcceptedBootstrap: no IMR or keystore; not polling the parent",
			"zone", zd.ZoneName)
		return nil
	}
	sak, err := kdb.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if err != nil || sak == nil || len(sak.Keys) == 0 {
		lgElect.Warn("pollAfterAcceptedBootstrap: no active SIG(0) key to poll the parent about",
			"zone", zd.ZoneName, "err", err)
		return nil
	}
	keyName := zd.ZoneName
	keyid := sak.Keys[0].KeyRR.KeyTag()

	done := startChildKeyStatePoll(keyName, keyid, func(st *childKeyPoll) {
		err := conf.pollParentKeyState(ctx, parentKeyStatePoll{
			zone:         ZoneName(keyName),
			keyid:        keyid,
			state:        st,
			bootstrapped: true,
			query: func(ctx context.Context) (*edns0.KeyStateOption, bool, error) {
				return QueryParentKeyState(ctx, kdb, imr, keyName, keyid)
			},
			record: func(state uint8) { UpdateParentState(kdb, keyName, keyid, state) },
			bootstrap: func(ctx context.Context) error {
				return BootstrapWithParent(ctx, ZoneName(keyName), keyName, algorithm)
			},
			served:           sig0KeyServed(kdb, imr, keyName, keyid),
			pollDelay:        delegationSyncInitialDelay,
			wait:             waitOrDone,
			reBootstrapDelay: childReBootstrapDelay,
		})
		if err != nil {
			lgElect.Warn("pollAfterAcceptedBootstrap: gave up polling the parent",
				"zone", keyName, "keyid", keyid, "err", err)
		}
	})
	if done == nil {
		lgElect.Debug("pollAfterAcceptedBootstrap: already polling the parent for this key",
			"zone", keyName, "keyid", keyid)
	}
	return done
}

// parentKeyStatePoll is what pollParentKeyState needs from the outside world,
// injected so a test can play the parent.
type parentKeyStatePoll struct {
	zone  ZoneName
	keyid uint16
	// bootstrapped: the ceremony has already been sent, so a parent that does
	// not know the key yet is polled again rather than bootstrapped again.
	bootstrapped bool
	// state is the poll's entry in childKeyStatePolls, told when the poll
	// has sent its bootstrap. Nil when the poll is not registered.
	state *childKeyPoll
	// syncDelegationWhenTrusted enqueues a delegation sync once the parent
	// trusts the key.
	syncDelegationWhenTrusted bool
	// agentsSync says whether the zone's delegation sync is still the
	// agents' (HSYNCPARAM parentsync=agent). It is asked before each
	// inquiry, bootstrap and delegation sync, and the poll stops when it
	// says no. Nil for the tdns-auth child's poll, which is the owner's own.
	agentsSync func() bool
	// query asks the parent for our key's state; authenticated says whether
	// the answer was.
	query func(ctx context.Context) (ks *edns0.KeyStateOption, authenticated bool, err error)
	// record stores the parent's answer in the local keystore.
	record func(state uint8)
	// bootstrap sends the bootstrap ceremony to the parent.
	bootstrap func(ctx context.Context) error
	// served looks at what the zone's nameservers serve of the key; a
	// bootstrap waits until they serve it (keyIsServed). Nil: no look.
	served func(ctx context.Context) (keyServedState, string)
	// pollDelay is the first wait between inquiries; it doubles.
	pollDelay time.Duration
	// wait sleeps for d, or returns false when ctx is cancelled.
	wait func(ctx context.Context, d time.Duration) bool
	// reBootstrapDelay is the wait before re-bootstrap round (0-based).
	reBootstrapDelay func(round int) time.Duration
}

// ownerTookOver reports whether the zone's owner has taken the delegation
// sync over since the poll started, in which case the poll stops before
// sending what it was about to send: next names it.
func (p parentKeyStatePoll) ownerTookOver(next string) bool {
	if p.agentsSync == nil || p.agentsSync() {
		return false
	}
	lgElect.Info("ParentSyncAfterKeyPublication: the zone no longer says parentsync=agent: its owner syncs its delegation, and the poll stops",
		"zone", p.zone, "keyid", p.keyid, "withheld", next)
	return true
}

// keyIsServed holds a bootstrap until the zone's nameservers serve the key
// (waitUntilKeyServed, #917). It returns false only when ctx ends first.
func (p parentKeyStatePoll) keyIsServed(ctx context.Context) bool {
	if p.served == nil {
		return true
	}
	return waitUntilKeyServed(ctx, p.zone, p.keyid, p.served, p.wait, keyServedWait)
}

// pollParentKeyState polls the parent's KeyState with the shared
// delegation-sync backoff (5s, 10s, 20s, 40s, then give up), bootstrapping if
// the parent reports our key as unknown.
//
// A parent that reports the key's validation FAILED is not the end (#677). The
// parent looked a few times and keeps no state waiting for us, and what it
// could not find may still appear: typically a KEY our provider has not yet
// published at its signal name. So we wait, re-bootstrap, which has the parent
// verify again, and poll again, up to childReBootstrapRounds times.
func (conf *Config) pollParentKeyState(ctx context.Context, p parentKeyStatePoll) error {
	zone, keyid := p.zone, p.keyid
	bootstrapped := p.bootstrapped
	if bootstrapped {
		p.state.markBootstrapped()
	}
	for round := 0; ; round++ {
		validationFailed := false
		syncErr := retryWithBackoff(ctx, delegationSyncMaxRetries, p.pollDelay, func(attempt int) (bool, error) {
			return conf.onParentKeyState(ctx, p, round, attempt, &bootstrapped, &validationFailed)
		})
		if !validationFailed {
			return syncErr
		}
		if !p.wait(ctx, p.reBootstrapDelay(round)) {
			return fmt.Errorf("shut down while waiting to re-bootstrap: %w", ctx.Err())
		}
		if !p.keyIsServed(ctx) {
			return fmt.Errorf("shut down while waiting for the key to be served: %w", ctx.Err())
		}
		if p.ownerTookOver("the re-bootstrap") {
			return nil
		}
		lgElect.Info("ParentSyncAfterKeyPublication: re-bootstrapping after the parent reported our key's validation failed",
			"zone", zone, "keyid", keyid, "round", round+1, "of", childReBootstrapRounds)
		sent := true
		if err := p.bootstrap(ctx); err != nil {
			if errors.Is(err, errBootstrapManual) {
				lgElect.Info("ParentSyncAfterKeyPublication: parent requires manual SIG(0) bootstrap; waiting for the operator",
					"zone", zone, "keyid", keyid)
				return nil
			}
			// Sent only if it failed after the parent accepted it. One that
			// never went out leaves the poll free to bootstrap when the
			// parent reports the key unknown.
			sent = errors.Is(err, errBootstrapAfterSend)
			// The poll that follows reports where the parent stands.
			lgElect.Warn("ParentSyncAfterKeyPublication: re-bootstrap failed; polling the parent anyway",
				"zone", zone, "keyid", keyid, "sent", sent, "err", err)
		}
		if sent {
			bootstrapped = true
			p.state.markBootstrapped()
		}
	}
}

// onParentKeyState acts on one KeyState inquiry. It returns what
// retryWithBackoff wants: done, and the error that ends or explains the
// attempt. It sets *validationFailed when the parent reports the key's
// validation failed and another re-bootstrap round is due.
func (conf *Config) onParentKeyState(ctx context.Context, p parentKeyStatePoll, round, attempt int,
	bootstrapped, validationFailed *bool) (bool, error) {

	zone, keyid := p.zone, p.keyid
	if p.ownerTookOver("the KeyState inquiry") {
		return true, nil // done
	}
	ks, authenticated, err := p.query(ctx)
	if err != nil {
		lgElect.Warn("ParentSyncAfterKeyPublication: KeyState inquiry failed",
			"zone", zone, "attempt", attempt, "err", err)
		return false, err // retry
	}
	keyState := ks.KeyState
	// authenticated=false here means allow-insecure let an unauthenticated
	// answer through; every transition below says so, so a bootstrap or a
	// "trusted" verdict driven by such an answer is traceable in the log.
	if !authenticated {
		lgElect.Warn("ParentSyncAfterKeyPublication: acting on an UNAUTHENTICATED KeyState answer (allow-insecure)",
			"zone", zone, "keyid", keyid, "state", keyState, "statename", edns0.KeyStateToString(keyState))
	}

	switch keyState {
	case edns0.KeyStateTrusted:
		lgElect.Info("ParentSyncAfterKeyPublication: parent trusts our key",
			"zone", zone, "keyid", keyid, "authenticated", authenticated)
		p.record(keyState)

		// Post-bootstrap: verify delegation data is in sync with parent.
		// Enqueue EXPLICIT-SYNC-DELEGATION which queries the parent and
		// only syncs if there is a real delta.
		if delsyncq := conf.Internal.DelegationSyncQ; delsyncq != nil && p.syncDelegationWhenTrusted &&
			!p.ownerTookOver("the delegation sync") {
			zd, exists := Zones.Get(string(zone))
			if exists {
				lgElect.Info("ParentSyncAfterKeyPublication: enqueuing post-bootstrap delegation verification", "zone", zone)
				delsyncq <- DelegationSyncRequest{
					Command:  "EXPLICIT-SYNC-DELEGATION",
					ZoneName: string(zone),
					ZoneData: zd,
				}
			} else {
				lgElect.Warn("ParentSyncAfterKeyPublication: zone not found, skipping delegation verification", "zone", zone)
			}
		}
		return true, nil // done

	case edns0.KeyStateUnknown:
		if *bootstrapped {
			// Already sent bootstrap, parent hasn't processed it yet — keep polling
			lgElect.Info("ParentSyncAfterKeyPublication: parent still unknown after bootstrap, polling",
				"zone", zone, "keyid", keyid, "attempt", attempt)
			return false, nil // retry
		}
		p.record(keyState)
		if !p.keyIsServed(ctx) {
			return true, fmt.Errorf("shut down while waiting for the key to be served: %w", ctx.Err())
		}
		// The inquiry, and the wait for the key to be served, took their
		// time; the owner may have taken over meanwhile.
		if p.ownerTookOver("the bootstrap") {
			return true, nil // done
		}
		lgElect.Info("ParentSyncAfterKeyPublication: parent does not know our key, bootstrapping",
			"zone", zone, "keyid", keyid, "authenticated", authenticated)
		if err := p.bootstrap(ctx); err != nil {
			if errors.Is(err, errBootstrapManual) {
				// MANUAL-BOOTSTRAP-REQUIRED from the child's side: nothing
				// automatic will change this; the operator has to act.
				lgElect.Info("ParentSyncAfterKeyPublication: parent requires manual SIG(0) bootstrap; waiting for the operator",
					"zone", zone, "keyid", keyid)
				return true, nil // done, not a failure
			}
			if errors.Is(err, errBootstrapAdvertisementLookup) {
				// The parent's SVCB advertisement could not be looked up.
				// Not a verdict on the method set, so not terminal: retry
				// with the same backoff rather than either giving up or
				// guessing.
				lgElect.Warn("ParentSyncAfterKeyPublication: bootstrap deferred, advertisement lookup failed",
					"zone", zone, "attempt", attempt, "err", err)
				return false, err // retry
			}
			lgElect.Error("ParentSyncAfterKeyPublication: bootstrap failed",
				"zone", zone, "err", err)
			return true, err // done (terminal error)
		}
		lgElect.Info("ParentSyncAfterKeyPublication: bootstrap UPDATE sent to parent, will poll for trust",
			"zone", zone, "keyid", keyid)
		*bootstrapped = true
		p.state.markBootstrapped()
		return false, nil // retry

	case edns0.KeyStateBootstrapAutoOngoing:
		lgElect.Info("ParentSyncAfterKeyPublication: parent is verifying key, will poll",
			"zone", zone, "keyid", keyid, "attempt", attempt)
		p.record(keyState)
		return false, nil // retry

	case edns0.KeyStateBootstrapManualRequired:
		// keystate-03 code 10: the parent knows the key but will only
		// trust it after a manual step. Terminal for this poll, and not
		// a failure: the operator has to act. Same treatment as the
		// child-side selection of the manual method above.
		lgElect.Info("ParentSyncAfterKeyPublication: parent requires manual bootstrap for our key; waiting for the operator",
			"zone", zone, "keyid", keyid, "detail", ks.ExtraText)
		p.record(keyState)
		return true, nil // done

	case edns0.KeyStateValidationFail:
		// keystate-03 code 8: the parent tried to verify the key and gave
		// up. Polling will not change that; the EXTRA-TEXT says what the
		// parent could not accept. A re-bootstrap has it verify again, so
		// end this poll and let pollParentKeyState schedule one, until the
		// rounds run out.
		p.record(keyState)
		if round >= childReBootstrapRounds {
			lgElect.Error("ParentSyncAfterKeyPublication: parent still reports our key's validation FAILED"+
				" after every re-bootstrap. Fix the KEY's publication (at-apex / at-ns, DNSSEC if the parent requires it) and re-bootstrap",
				"zone", zone, "keyid", keyid, "rebootstraps", round, "detail", ks.ExtraText)
			return true, fmt.Errorf("parent reports KEY_VALIDATION_FAILED for keyid %d after %d re-bootstraps: %s",
				keyid, round, ks.ExtraText)
		}
		lgElect.Warn("ParentSyncAfterKeyPublication: parent reports our key's validation FAILED; will re-bootstrap",
			"zone", zone, "keyid", keyid, "round", round+1, "of", childReBootstrapRounds,
			"delay", p.reBootstrapDelay(round), "detail", ks.ExtraText)
		*validationFailed = true
		return true, nil

	case edns0.KeyStateTemporaryFailure:
		// keystate-03: the receiver understood the inquiry but is
		// temporarily unable to determine the key's state (e.g. a transient
		// truststore error) — the child MAY retry later. Keep polling with
		// backoff rather than giving up as the default branch would.
		lgElect.Info("ParentSyncAfterKeyPublication: parent reports a temporary failure, will retry",
			"zone", zone, "keyid", keyid, "attempt", attempt)
		p.record(keyState)
		return false, nil // retry

	default:
		// Terminal, and a failure: the child's key is not trusted and no
		// further attempt will change that. Reported at Info it looked like
		// a successful outcome in the logs, and the caller's "gave up"
		// branch never fired because the error was nil.
		lgElect.Error("ParentSyncAfterKeyPublication: parent returned an unexpected key state;"+
			" the child's key is NOT trusted and bootstrap will not complete",
			"zone", zone, "keyid", keyid, "state", keyState,
			"statename", edns0.KeyStateToString(keyState))
		p.record(keyState)
		return true, fmt.Errorf("parent returned unexpected key state %d (%s)",
			keyState, edns0.KeyStateToString(keyState))
	}
}

// QueryParentKeyState sends a SIG(0)-signed KeyState EDNS(0) inquiry for
// (keyName, keyid) to the parent's UPDATE Receiver, found via DSYNC discovery,
// and returns the KeyState option from the response plus whether that response
// was authenticated (see keystate_verify.go). A response that cannot be
// authenticated is an error unless parentsync.update.allow-insecure
// is set, in which case it is returned with authenticated=false; a response
// whose signature is present but wrong is always an error.
func QueryParentKeyState(ctx context.Context, kdb *KeyDB, imr *Imr, keyName string, keyid uint16) (*edns0.KeyStateOption, bool, error) {
	dsyncTarget, err := imr.LookupDSYNCTarget(ctx, keyName, dns.TypeANY, core.SchemeUpdate)
	if err != nil {
		return nil, false, fmt.Errorf("DSYNC lookup failed: %v", err)
	}
	allowInsecure := ParentSyncConfig().Update.AllowInsecure
	return queryKeyState(ctx, kdb, keyName, keyid, dsyncTarget,
		kdb.receiverKeyTrust(), imrReceiverKeyFetcher(imr), allowInsecure)
}

// UpdateParentState persists the parent's KeyState response in the local keystore.
func UpdateParentState(kdb *KeyDB, keyName string, keyid uint16, parentState uint8) {
	tx, err := kdb.Begin("UpdateParentState")
	if err != nil {
		lgElect.Error("UpdateParentState: failed to begin transaction", "err", err)
		return
	}

	kp := KeystorePost{
		Command:     "sig0-mgmt",
		SubCommand:  "setparentstate",
		Keyname:     keyName,
		Keyid:       keyid,
		ParentState: parentState,
	}

	_, err = kdb.Sig0KeyMgmt(tx, kp)
	if err != nil {
		lgElect.Error("UpdateParentState: failed to update parent state", "err", err)
		tx.Rollback()
		return
	}

	if err := tx.Commit(); err != nil {
		lgElect.Error("UpdateParentState: failed to commit", "err", err)
	}
}

// BootstrapWithParent sends a self-signed UPDATE to the parent to bootstrap
// trust for the child's SIG(0) key.
func BootstrapWithParent(ctx context.Context, zone ZoneName, keyName string, algorithm uint8) error {
	lgElect.Info("BootstrapWithParent: starting", "zone", zone, "keyName", keyName, "algorithm", algorithm)

	// Try Zones map first, then FindZone (label-walking).
	zd, ok := Zones.Get(keyName)
	if !ok || zd == nil {
		lgElect.Debug("BootstrapWithParent: zone not in Zones map, trying FindZone", "keyName", keyName)
		zd = FindZone(keyName)
	}
	if zd == nil {
		return fmt.Errorf("zone %s not found (available zones: %v)", keyName, Zones.Keys())
	}

	msg, ur, err := zd.BootstrapSig0KeyWithParent(ctx, algorithm)
	if err != nil {
		return fmt.Errorf("BootstrapSig0KeyWithParent: %s: %w", msg, err)
	}

	lgElect.Info("BootstrapWithParent: success", "zone", zone, "result", msg, "updateResult", ur)
	return nil
}

// ZoneHasParentSyncAgent checks whether the zone's HSYNCPARAM record has
// parentsync=agent. Returns false if HSYNCPARAM is absent or parentsync=owner.
func ZoneHasParentSyncAgent(zone ZoneName) bool {
	zd, ok := Zones.Get(string(zone))
	if !ok || zd == nil {
		return false
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		return false
	}

	hsyncparamRRset, exists := apex.RRtypes.Get(core.TypeHSYNCPARAM)
	if !exists || len(hsyncparamRRset.RRs) == 0 {
		return false
	}

	prr, ok := hsyncparamRRset.RRs[0].(*dns.PrivateRR)
	if !ok {
		return false
	}

	hsyncparam, ok := prr.Data.(*core.HSYNCPARAM)
	if !ok {
		return false
	}

	return hsyncparam.GetParentSync() == core.HsyncParentSyncAgent
}
