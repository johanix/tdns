package tdns

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	rolloverPhaseIdle                 = "idle"
	rolloverPhasePendingChildPublish  = "pending-child-publish"
	rolloverPhasePendingParentPush    = "pending-parent-push"
	rolloverPhasePendingParentObserve = "pending-parent-observe"
	rolloverPhasePushSoftfail         = "parent-push-softfail"
	rolloverPhasePendingChildWithdraw = "pending-child-withdraw"
)

// jitterUpTo returns a random duration in [-d, +d]. Used to spread
// next_push_at across zones sharing a parent so that a parent outage
// doesn't cause every child zone's softfail probe to fire on the same
// hour boundary.
func jitterUpTo(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(2*d))) - d
}

// kskIndexPushNeeded answers "should we push a fresh DS UPDATE to the
// parent right now?" by comparing the engine-computed target DS index
// range to what the parent has actually published.
//
// The comparison is against LastConfirmed* (parent reality) rather
// than LastSubmitted* (our local "I tried"). The two diverge whenever
// a previous attempt got rcode NOERROR back but the DS never actually
// appeared on the parent — silent policy reject, broken update→publish
// pipeline at the parent, etc. Comparing against LastSubmitted* in
// that situation says "we already tried this, nothing to do" and the
// zone gets stuck. Comparing against LastConfirmed* says "the parent
// still doesn't have it, push again."
func kskIndexPushNeeded(row *RolloverZoneRow, low, high int, indexOK bool, haveDS bool) bool {
	if !haveDS {
		return false
	}
	if !indexOK {
		return false
	}
	if row == nil || !row.LastConfirmedLow.Valid || !row.LastConfirmedHigh.Valid {
		return true
	}
	return int(row.LastConfirmedLow.Int64) != low || int(row.LastConfirmedHigh.Int64) != high
}

// RolloverAutomatedTick runs one slice of automated KSK rollover for multi-ds (pipeline fill,
// DS push / observe phase machine). double-signature is not implemented yet.
//
// All dependencies are passed via RolloverEngineDeps so the engine has no
// implicit globals. The orchestrator (KeyStateWorker) iterates its zones,
// builds deps for each, and calls this. deps.PropagationDelay is the
// kasp.propagation_delay used by pending-child-publish.
func RolloverAutomatedTick(ctx context.Context, deps RolloverEngineDeps) error {
	zd := deps.Zone
	if zd == nil {
		return nil
	}
	pol := deps.Policy
	if pol == nil {
		return nil
	}
	if pol.Rollover.Method == RolloverMethodNone {
		return nil
	}
	if pol.Rollover.Method == RolloverMethodDoubleSignature {
		return nil
	}

	conf := deps.Conf
	kdb := deps.KDB
	imr := deps.Imr
	propagationDelay := deps.PropagationDelay
	now := time.Now()
	if deps.Now != nil {
		now = deps.Now()
	}

	zone := dns.Fqdn(zd.ZoneName)

	// Serialize against API mutating handlers (asap, cancel, reset,
	// unstick). Held for the duration of one tick's per-zone work so
	// a CLI-driven write cannot interleave with a phase advance.
	acquire := deps.AcquireLock
	if acquire == nil {
		acquire = defaultAcquireRolloverLock
	}
	release, err := acquire(zone)
	if err != nil {
		// Soft acquisition failure (e.g. tdns-mp's leader-aware
		// acquirer returning ErrNotLeader for a zone owned by
		// another provider). Skip this cycle without escalating.
		lgSigner.Debug("rollover: lock acquisition skipped", "zone", zone, "err", err)
		return nil
	}
	defer release()

	if err := EnsureRolloverZoneRow(kdb, zone); err != nil {
		return err
	}

	// Self-heal: if the zone's active SEP KSK was minted by
	// EnsureActiveDnssecKeys before RegisterBootstrapActiveKSK was wired
	// in (or before active_at existed in the schema), the
	// RolloverKeyState row may be missing or have no active_at. Without
	// active_at, rolloverDue and tNextRoll both fail. Stamp it now using
	// "first observation" semantics — not perfectly accurate (the key may
	// have been active for hours/days already) but recoverable: a
	// scheduled rollover from today is better than no rollover ever.
	healBootstrapActiveAt(kdb, zone, pol)

	// 4D K-step TTL clamp: detect step boundaries and bump SOA serial so
	// secondaries pull AXFR with the new clamp ceiling. No-op for zones
	// with clamping.enabled: false.
	kStepScheduler(zd, kdb, pol, now)

	num := pol.Rollover.NumDS
	for {
		n, err := CountKskInRolloverPipeline(kdb, zone)
		if err != nil {
			return err
		}
		if n >= num {
			break
		}
		kid, _, err := GenerateKskRolloverCreated(kdb, zone, "key-state-worker", pol.Algorithm, pol.Rollover.Method)
		if err != nil {
			lgSigner.Error("rollover: pipeline KSK generation failed", "zone", zone, "err", err)
			break
		}
		lgSigner.Info("rollover: generated pipeline KSK", "zone", zone, "keyid", kid)
	}

	row, err := LoadRolloverZoneRow(kdb, zone)
	if err != nil {
		return err
	}
	if row == nil {
		return nil
	}
	phase := row.RolloverPhase
	if phase == "" {
		phase = rolloverPhaseIdle
	}

	// rollover_due (§8.1): when no rollover is in progress and either the
	// scheduled lifetime has elapsed OR a manual-ASAP request has reached
	// its computed earliest time, fire AtomicRollover. The tick then
	// re-loads phase and continues; the new pending-child-publish phase
	// will be handled below if reached this pass, or on the next tick.
	if phase == rolloverPhaseIdle && !row.RolloverInProgress {
		due, manual, err := rolloverDue(kdb, zone, pol, row, now)
		if err != nil {
			lgSigner.Warn("rollover: rollover_due check failed", "zone", zone, "err", err)
		} else if due {
			if _, _, err := AtomicRollover(conf, kdb, zone); err != nil {
				lgSigner.Warn("rollover: AtomicRollover failed", "zone", zone, "err", err)
			} else {
				if manual {
					if err := ClearManualRolloverRequest(kdb, zone); err != nil {
						lgSigner.Warn("rollover: clear manual_rollover_* failed", "zone", zone, "err", err)
					}
				}
				row, err = LoadRolloverZoneRow(kdb, zone)
				if err != nil {
					return err
				}
				if row != nil {
					phase = row.RolloverPhase
				}
			}
		}
	}

	switch phase {
	case rolloverPhaseIdle:
		// §8.8 idle branch: steady-state pipeline maintenance. Arm the
		// push phase if the target DS RRset differs from what we have
		// submitted. Arming is the single advance on this tick — the
		// actual push happens on the next tick under pending-parent-push.
		ds, low, high, idxOK, err := ComputeTargetDSSetForZone(kdb, zone, uint8(dns.SHA256))
		if err != nil {
			return err
		}
		if kskIndexPushNeeded(row, low, high, idxOK, len(ds) > 0) {
			if err := SetRolloverPhase(kdb, zone, rolloverPhasePendingParentPush); err != nil {
				return err
			}
			lgSigner.Info("rollover: arming DS push", "zone", zone)
		}
	case rolloverPhasePendingChildPublish:
		// §8.8: wait kasp.propagation_delay from rollover_phase_at, then
		// arm the DS push. Real child-secondary observation is post-4
		// future work; here we use a fixed wait.
		if t, ok := parseOptionalTime(row.RolloverPhaseAt); ok {
			if now.Sub(t) < propagationDelay {
				return nil
			}
		} else {
			lgSigner.Warn("rollover: pending-child-publish without rollover_phase_at; arming push immediately", "zone", zone)
		}
		if err := SetRolloverPhase(kdb, zone, rolloverPhasePendingParentPush); err != nil {
			return err
		}
		lgSigner.Info("rollover: pending-child-publish elapsed, arming DS push", "zone", zone)
	case rolloverPhasePendingParentPush:
		// §8.8: send DS UPDATE. Arming the observe phase counts as the
		// advance; the actual parent DS query happens on the next tick
		// under pending-parent-observe.
		if imr == nil {
			lgSigner.Warn("rollover: ImrEngine nil, cannot DS push", "zone", zone)
			handleAttemptFailed(kdb, zone, pol, SoftfailChildConfig, "ImrEngine nil, cannot DS push", now)
			return nil
		}
		_ = setLastAttemptStarted(kdb, zone, now)
		pushCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		res, err := PushDSRRsetForRollover(pushCtx, deps)
		cancel()
		if err != nil {
			cat := res.Category
			if cat == "" {
				cat = SoftfailTransport
			}
			detail := err.Error()
			if res.Detail != "" {
				detail = res.Detail
			}
			lgSigner.Warn("rollover: DS push failed", "zone", zone, "err", err, "category", cat, "detail", detail)
			handleAttemptFailed(kdb, zone, pol, cat, detail, now)
			return nil
		}
		if res.Rcode != dns.RcodeSuccess {
			lgSigner.Warn("rollover: DS push non-NOERROR", "zone", zone, "rcode", dns.RcodeToString[res.Rcode])
			detail := fmt.Sprintf("rcode=%s", dns.RcodeToString[res.Rcode])
			if res.Detail != "" {
				detail = res.Detail
			}
			handleAttemptFailed(kdb, zone, pol, SoftfailParentRejected, detail, now)
			return nil
		}
		if res.Scheme != "" {
			_ = setLastAttemptScheme(kdb, zone, res.Scheme)
		}
		// Schedule the first parent-agent DS query: wait confirm-initial-wait
		// from now, then exponential backoff starting at confirm-initial-wait.
		initial := pol.Rollover.ConfirmInitialWait
		if initial <= 0 {
			initial = defaultConfirmInitialWait
		}
		nextPoll := now.Add(initial)
		if err := setObserveSchedule(kdb, zone, now, nextPoll, int(initial.Seconds())); err != nil {
			lgSigner.Warn("rollover: set observe schedule", "zone", zone, "err", err)
		}
		if err := SetRolloverPhase(kdb, zone, rolloverPhasePendingParentObserve); err != nil {
			return err
		}
		lgSigner.Info("rollover: DS UPDATE accepted, arming observe", "zone", zone, "first_poll_at", nextPoll.Format(time.RFC3339))
		scheduleFastObservePoll(ctx, deps, initial)
	case rolloverPhasePendingParentObserve:
		agent := pol.Rollover.ParentAgent
		if agent == "" {
			lgSigner.Warn("rollover: parent-agent unset, cannot observe", "zone", zone)
			return nil
		}
		expected, low, high, idxOK, err := ComputeTargetDSSetForZone(kdb, zone, uint8(dns.SHA256))
		if err != nil {
			return err
		}
		if len(expected) == 0 {
			// Steady state with no expected DS set; nothing to observe.
			_ = clearObserveSchedule(kdb, zone)
			if err := SetRolloverPhase(kdb, zone, rolloverPhaseIdle); err != nil {
				return err
			}
			return nil
		}

		// Enforce the §7.2 poll schedule: honor next-poll-at; hard-fail
		// past confirm-timeout.
		timeout := pol.Rollover.ConfirmTimeout
		if timeout <= 0 {
			timeout = defaultConfirmTimeout
		}
		pollMax := pol.Rollover.ConfirmPollMax
		if pollMax <= 0 {
			pollMax = defaultConfirmPollMax
		}
		if t, ok := parseOptionalTime(row.ObserveStartedAt); ok {
			if now.Sub(t) >= timeout {
				recordObserveTimeout(kdb, zone, low, high, timeout, pol, now)
				lgSigner.Error("rollover: DS observation timed out; keys marked with last_rollover_error", "zone", zone, "started_at", t.Format(time.RFC3339), "timeout", timeout)
				return nil
			}
		}
		if t, ok := parseOptionalTime(row.ObserveNextPollAt); ok {
			if now.Before(t) {
				// Backoff not yet elapsed; skip this tick.
				return nil
			}
		}

		obs, err := QueryParentAgentDS(ctx, zone, agent)
		_ = setLastPoll(kdb, zone, now)
		if err != nil {
			lgSigner.Debug("rollover: parent-agent DS query failed", "zone", zone, "err", err)
			scheduleNextObservePoll(kdb, zone, row, now, pollMax)
			return nil
		}
		if !ObservedDSSetMatchesExpected(obs, expected) {
			scheduleNextObservePoll(kdb, zone, row, now, pollMax)
			return nil
		}
		if !idxOK {
			lgSigner.Warn("rollover: DS observed but rollover_index incomplete for all KSK rows; cannot advance created→ds-published", "zone", zone)
			_ = clearObserveSchedule(kdb, zone)
			if err := SetRolloverPhase(kdb, zone, rolloverPhaseIdle); err != nil {
				return err
			}
			return nil
		}

		// §9.4: wrap the confirmed-range write, the created→ds-published
		// state transitions, the ds_observed_at timestamps, the
		// observe-schedule clear, and the phase reset to idle in a
		// single transaction.
		advanced, err := confirmDSAndAdvanceCreatedKeysTx(kdb, zone, low, high, now)
		if err != nil {
			return fmt.Errorf("rollover: confirm DS and advance keys: %w", err)
		}
		_ = resetHardfailCount(kdb, zone)
		_ = setLastSuccess(kdb, zone, now)
		// Clear last_attempt_started_at: the attempt window closed
		// successfully, so its expected-by / attempt-timeout deadlines
		// are no longer meaningful. Status output uses the absence of
		// this timestamp to suppress stale window lines.
		_ = setLastAttemptStarted(kdb, zone, time.Time{})
		// Clear last_softfail_*: the previous softfail event is no
		// longer informative now that we're back in sync.
		_ = clearLastSoftfail(kdb, zone)
		if advanced > 0 {
			triggerResign(conf, zone)
		}
		lgSigner.Info("rollover: parent DS observed, advanced created keys", "zone", zone, "advanced", advanced)
	case rolloverPhasePushSoftfail:
		// Long-term mode after the initial flurry exhausted. Two
		// concurrent activities run on every tick:
		//
		//   1. Observe-poll continues at confirm-poll-max cadence so a
		//      parent fix is auto-detected without requiring a probe.
		//      On confirmed observation, the engine transitions
		//      directly to the advance-keys path — skipping the next
		//      probe entirely.
		//   2. Once next_push_at elapses, send ONE probe UPDATE and
		//      schedule the next probe softfail_delay later (with
		//      ±5min jitter to spread thundering-herd against a
		//      shared parent). Probe failures keep the engine in this
		//      phase; we do NOT enter pending-parent-push as a fresh
		//      attempt group.
		expected, low, high, idxOK, err := ComputeTargetDSSetForZone(kdb, zone, uint8(dns.SHA256))
		if err != nil {
			return err
		}
		if len(expected) == 0 {
			// Steady state — nothing to confirm. Return to idle.
			_ = clearObserveSchedule(kdb, zone)
			return SetRolloverPhase(kdb, zone, rolloverPhaseIdle)
		}
		pollMax := pol.Rollover.ConfirmPollMax
		if pollMax <= 0 {
			pollMax = derivedPollMax(pol.Rollover.DsPublishDelay)
		}
		// (a) Observe-poll, if scheduled.
		pollDue := true
		if t, ok := parseOptionalTime(row.ObserveNextPollAt); ok && now.Before(t) {
			pollDue = false
		}
		agent := pol.Rollover.ParentAgent
		if pollDue && agent != "" {
			obs, qerr := QueryParentAgentDS(ctx, zone, agent)
			_ = setLastPoll(kdb, zone, now)
			if qerr == nil && ObservedDSSetMatchesExpected(obs, expected) {
				if !idxOK {
					lgSigner.Warn("rollover: DS observed during softfail but rollover_index incomplete; cannot advance", "zone", zone)
					_ = clearObserveSchedule(kdb, zone)
					return SetRolloverPhase(kdb, zone, rolloverPhaseIdle)
				}
				advanced, terr := confirmDSAndAdvanceCreatedKeysTx(kdb, zone, low, high, now)
				if terr != nil {
					return fmt.Errorf("rollover: confirm DS and advance keys: %w", terr)
				}
				_ = resetHardfailCount(kdb, zone)
				_ = setLastSuccess(kdb, zone, now)
				_ = setLastAttemptStarted(kdb, zone, time.Time{})
				_ = clearLastSoftfail(kdb, zone)
				if advanced > 0 {
					triggerResign(conf, zone)
				}
				lgSigner.Info("rollover: parent recovered during softfail polling, advancing keys", "zone", zone, "advanced", advanced)
				return nil
			}
			scheduleNextObservePoll(kdb, zone, row, now, pollMax)
		}
		// (b) Probe UPDATE side. Fire only if next_push_at elapsed.
		nextPushDue := false
		if t, ok := parseOptionalTime(row.NextPushAt); !ok || !now.Before(t) {
			nextPushDue = true
		}
		if !nextPushDue {
			return nil
		}
		softfailDelay := pol.Rollover.SoftfailDelay
		if softfailDelay <= 0 {
			softfailDelay = derivedSoftfailDelay(pol.Rollover.DsPublishDelay)
		}
		nextPush := now.Add(softfailDelay).Add(jitterUpTo(5 * time.Minute))
		if imr == nil {
			lgSigner.Warn("rollover: ImrEngine nil, cannot softfail probe", "zone", zone)
			_ = setSoftfail(kdb, zone, SoftfailChildConfig, "ImrEngine nil, cannot softfail probe", now, nextPush)
			return nil
		}
		_ = setLastAttemptStarted(kdb, zone, now)
		pushCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		res, perr := PushDSRRsetForRollover(pushCtx, deps)
		cancel()
		if perr != nil {
			cat := res.Category
			if cat == "" {
				cat = SoftfailTransport
			}
			detail := perr.Error()
			if res.Detail != "" {
				detail = res.Detail
			}
			lgSigner.Warn("rollover: softfail probe push failed", "zone", zone, "category", cat, "err", perr, "detail", detail)
			_ = setSoftfail(kdb, zone, cat, detail, now, nextPush)
			return nil
		}
		if res.Rcode != dns.RcodeSuccess {
			detail := fmt.Sprintf("rcode=%s", dns.RcodeToString[res.Rcode])
			if res.Detail != "" {
				detail = res.Detail
			}
			lgSigner.Warn("rollover: softfail probe push non-NOERROR", "zone", zone, "rcode", dns.RcodeToString[res.Rcode], "detail", detail)
			_ = setSoftfail(kdb, zone, SoftfailParentRejected, detail, now, nextPush)
			return nil
		}
		if res.Scheme != "" {
			_ = setLastAttemptScheme(kdb, zone, res.Scheme)
		}
		// Probe accepted at the wire. Restart observe to pick up DS
		// when it appears; bump next_push_at without overwriting the
		// most recent softfail context.
		initial := pol.Rollover.ConfirmInitialWait
		if initial <= 0 {
			initial = defaultConfirmInitialWait
		}
		nextPoll := now.Add(initial)
		_ = setObserveSchedule(kdb, zone, now, nextPoll, int(initial.Seconds()))
		_ = setNextPushAt(kdb, zone, nextPush)
		lgSigner.Info("rollover: softfail probe accepted, observing", "zone", zone, "first_poll_at", nextPoll.Format(time.RFC3339), "next_probe_at", nextPush.Format(time.RFC3339))
		scheduleFastObservePoll(ctx, deps, initial)
	case rolloverPhasePendingChildWithdraw:
		// §8.8: wait effective_margin = max(policy.clamping.margin,
		// max_observed_ttl) from each retired SEP key's retired_at, then
		// advance to removed. When all retired SEP keys for the zone have
		// reached removed, clear rollover_in_progress and return the zone
		// to idle. The next idle tick re-evaluates the DS set and arms a
		// fresh push if the set changed (foreign-DS dropped out).
		eff, err := effectiveMarginForZone(kdb, zone, pol)
		if err != nil {
			lgSigner.Warn("rollover: effective margin lookup failed", "zone", zone, "err", err)
			return nil
		}
		retired, err := GetDnssecKeysByState(kdb, zone, DnskeyStateRetired)
		if err != nil {
			return fmt.Errorf("list retired keys: %w", err)
		}
		var sepRetired []DnssecKeyWithTimestamps
		for i := range retired {
			if retired[i].Flags&dns.SEP != 0 {
				sepRetired = append(sepRetired, retired[i])
			}
		}
		if len(sepRetired) == 0 {
			// All retired SEP keys are gone (or there were none) — wrap up.
			if err := completeRolloverWithdraw(conf, kdb, zone); err != nil {
				return err
			}
			return nil
		}
		stillWaiting := 0
		advanced := 0
		for i := range sepRetired {
			k := &sepRetired[i]
			if k.RetiredAt == nil {
				lgSigner.Warn("rollover: retired SEP key has no retired_at; cannot advance", "zone", zone, "keyid", k.KeyTag)
				stillWaiting++
				continue
			}
			if now.Sub(*k.RetiredAt) < eff {
				stillWaiting++
				continue
			}
			if err := UpdateDnssecKeyState(kdb, zone, k.KeyTag, DnskeyStateRemoved); err != nil {
				lgSigner.Error("rollover: retired→removed failed", "zone", zone, "keyid", k.KeyTag, "err", err)
				stillWaiting++
				continue
			}
			lgSigner.Info("rollover: retired→removed (pending-child-withdraw)", "zone", zone, "keyid", k.KeyTag, "effective_margin", eff)
			advanced++
		}
		if advanced > 0 {
			triggerResign(conf, zone)
		}
		if stillWaiting == 0 {
			if err := completeRolloverWithdraw(conf, kdb, zone); err != nil {
				return err
			}
		}
	default:
		if err := SetRolloverPhase(kdb, zone, rolloverPhaseIdle); err != nil {
			return err
		}
	}
	return nil
}

// confirmDSAndAdvanceCreatedKeysTx performs all post-observation state writes
// in a single transaction: persist last_ds_confirmed_*, advance every created
// SEP key whose rollover_index falls inside [low, high] to ds-published, stamp
// ds_observed_at on each, clear the observe schedule, and reset rollover_phase
// to idle. Returns the number of keys advanced. §9.4 two-store consistency.
func confirmDSAndAdvanceCreatedKeysTx(kdb *KeyDB, zone string, low, high int, now time.Time) (int, error) {
	tx, err := kdb.Begin("confirmDSAndAdvanceCreatedKeysTx")
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	commit := false
	defer func() {
		if !commit {
			tx.Rollback()
		}
	}()

	if err := saveLastDSConfirmedRangeTx(tx, zone, low, high); err != nil {
		return 0, fmt.Errorf("save confirmed range: %w", err)
	}

	created, err := GetDnssecKeysByState(kdb, zone, DnskeyStateCreated)
	if err != nil {
		return 0, fmt.Errorf("list created keys: %w", err)
	}

	advanced := 0
	for i := range created {
		k := &created[i]
		if k.Flags&dns.SEP == 0 {
			continue
		}
		var ri sql.NullInt64
		err := tx.QueryRow(`SELECT rollover_index FROM RolloverKeyState WHERE zone = ? AND keyid = ?`, zone, int(k.KeyTag)).Scan(&ri)
		if err == sql.ErrNoRows || !ri.Valid {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("rollover_index lookup: %w", err)
		}
		idx := int(ri.Int64)
		if idx < low || idx > high {
			continue
		}
		if err := UpdateDnssecKeyStateTx(tx, kdb, zone, k.KeyTag, DnskeyStateDsPublished); err != nil {
			return 0, fmt.Errorf("created→ds-published for keyid %d: %w", k.KeyTag, err)
		}
		if err := setRolloverKeyDsObservedAtTx(tx, zone, k.KeyTag, now); err != nil {
			return 0, fmt.Errorf("ds_observed_at for keyid %d: %w", k.KeyTag, err)
		}
		// A successful DS observation invalidates any prior
		// last_rollover_error (e.g. from a previous DS-observation
		// timeout that has since been resolved). The key is
		// progressing again; the stale error would only confuse
		// operators reading auto-rollover status output.
		if _, err := tx.Exec(`UPDATE RolloverKeyState SET last_rollover_error = NULL WHERE zone = ? AND keyid = ?`, zone, int(k.KeyTag)); err != nil {
			return 0, fmt.Errorf("clear last_rollover_error for keyid %d: %w", k.KeyTag, err)
		}
		advanced++
	}

	// Clear the observe-schedule fields and reset the phase, all inside
	// the same TX as the state advances.
	if _, err := tx.Exec(`UPDATE RolloverZoneState
SET observe_started_at = NULL,
    observe_next_poll_at = NULL,
    observe_backoff_seconds = NULL
WHERE zone = ?`, zone); err != nil {
		return 0, fmt.Errorf("clear observe schedule: %w", err)
	}
	// 4B routing: if a rollover is in progress (set by AtomicRollover),
	// the post-observe path leads to pending-child-withdraw, not idle.
	// Read rollover_in_progress inside this same TX so the read and the
	// phase write are atomic.
	inProgress, err := getRolloverInProgressTx(tx, zone)
	if err != nil {
		return 0, fmt.Errorf("read rollover_in_progress: %w", err)
	}
	nextPhase := rolloverPhaseIdle
	if inProgress {
		nextPhase = rolloverPhasePendingChildWithdraw
	}
	if err := setRolloverPhaseTx(tx, zone, nextPhase); err != nil {
		return 0, fmt.Errorf("reset phase: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	commit = true
	return advanced, nil
}

// scheduleFastObservePoll spawns a one-shot goroutine that fires the
// observe-phase poll exactly initial-wait after a successful UPDATE,
// independent of the worker tick cadence. Without this, the first
// parent-DS query is gated on the next KeyStateWorker tick, which can
// be up to kasp.check_interval seconds away — and if that exceeds
// attempt-timeout (= ds-publish-delay × 1.2 by default), the engine
// declares the attempt timed out before any poll has ever fired.
//
// The goroutine waits initial-wait seconds, then re-runs
// RolloverAutomatedTick for the same zone. RolloverAutomatedTick
// acquires the per-zone lock internally, so concurrent tick + fast-poll
// serialize cleanly. Daemon shutdown via ctx.Done() aborts the goroutine.
//
// Restart safety: if the daemon restarts while the goroutine is
// sleeping, the goroutine is gone but the DB state still carries
// observe_started_at + observe_next_poll_at. The next worker tick
// after restart picks up where this left off (at the cost of being
// bounded by check_interval — same as the pre-fix behavior). No state
// is lost; just slower recovery.
func scheduleFastObservePoll(ctx context.Context, deps RolloverEngineDeps, initial time.Duration) {
	if initial <= 0 {
		initial = defaultConfirmInitialWait
	}
	if deps.Zone == nil {
		return
	}
	zone := deps.Zone.ZoneName
	go func() {
		timer := time.NewTimer(initial)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := RolloverAutomatedTick(ctx, deps); err != nil {
			lgSigner.Debug("rollover: fast-poll tick error", "zone", zone, "err", err)
		}
	}()
}

// recordObserveTimeout stamps a per-key last_rollover_error on every
// SEP key in state=created that was waiting on confirmation of the
// [low, high] range, then delegates to handleAttemptFailed to
// increment the hardfail counter and decide whether to retry
// immediately or enter parent-push-softfail.
//
// Per-key stamping is purely diagnostic — status output renders the
// most recent error per key. The actual phase decision happens in
// handleAttemptFailed.
func recordObserveTimeout(kdb *KeyDB, zone string, low, high int, timeout time.Duration, pol *DnssecPolicy, now time.Time) {
	msg := fmt.Sprintf("DS observation timeout (%s): parent never published expected DS RRset", timeout)
	if low <= high {
		created, err := GetDnssecKeysByState(kdb, zone, DnskeyStateCreated)
		if err == nil {
			for i := range created {
				k := &created[i]
				if k.Flags&dns.SEP == 0 {
					continue
				}
				ri, ok, _ := RolloverIndexForKey(kdb, zone, k.KeyTag)
				if !ok || ri < low || ri > high {
					continue
				}
				_ = setLastRolloverError(kdb, zone, k.KeyTag, msg)
			}
		}
	}
	handleAttemptFailed(kdb, zone, pol, SoftfailParentPublishFailure, msg, now)
}

// handleAttemptFailed is the shared decision point for any failed
// rollover attempt — push error, push non-NOERROR, observe timeout.
// Increments the hardfail counter and decides the next phase:
//
//   - count < max-attempts-before-backoff → stay in / return to
//     pending-parent-push (retry on the very next tick).
//   - count >= max-attempts-before-backoff → enter parent-push-softfail
//     (long-term mode; one probe per softfail-delay forever).
//
// Records the failure category and detail in either case so status
// output can show what went wrong. Errors from the underlying writes
// are logged but not propagated — the caller's tick-level error path
// is for things that prevent the engine from advancing at all.
func handleAttemptFailed(kdb *KeyDB, zone string, pol *DnssecPolicy, category, detail string, now time.Time) {
	n, err := incrementHardfailCount(kdb, zone)
	if err != nil {
		lgSigner.Warn("rollover: increment hardfail_count failed", "zone", zone, "err", err)
		return
	}
	maxAttempts := defaultMaxAttemptsBeforeBackoff
	var softfailDelay time.Duration
	if pol != nil {
		if pol.Rollover.MaxAttemptsBeforeBackoff > 0 {
			maxAttempts = pol.Rollover.MaxAttemptsBeforeBackoff
		}
		softfailDelay = pol.Rollover.SoftfailDelay
		if softfailDelay <= 0 {
			softfailDelay = derivedSoftfailDelay(pol.Rollover.DsPublishDelay)
		}
	} else {
		softfailDelay = defaultSoftfailDelayMinimum
	}
	if n >= maxAttempts {
		nextPush := now.Add(softfailDelay).Add(jitterUpTo(5 * time.Minute))
		if err := setSoftfail(kdb, zone, category, detail, now, nextPush); err != nil {
			lgSigner.Warn("rollover: setSoftfail (entering softfail) failed", "zone", zone, "err", err)
		}
		// Leave observe schedule in place — polling continues during
		// softfail-delay, which is what gives the engine its
		// auto-recovery property when the operator fixes the parent.
		if err := SetRolloverPhase(kdb, zone, rolloverPhasePushSoftfail); err != nil {
			lgSigner.Warn("rollover: set phase parent-push-softfail failed", "zone", zone, "err", err)
		}
		lgSigner.Warn("rollover: initial flurry exhausted, entering softfail long-term mode",
			"zone", zone, "attempts", n, "category", category, "next_probe_at", nextPush.Format(time.RFC3339))
		return
	}
	// Mid-flurry retry: clear observe schedule (the failed attempt's
	// observe state is irrelevant; the next push starts fresh) and
	// transition back to pending-parent-push so the next tick sends
	// a fresh UPDATE.
	if err := setSoftfail(kdb, zone, category, detail, now, time.Time{}); err != nil {
		lgSigner.Warn("rollover: setSoftfail (mid-flurry) failed", "zone", zone, "err", err)
	}
	_ = clearObserveSchedule(kdb, zone)
	if err := SetRolloverPhase(kdb, zone, rolloverPhasePendingParentPush); err != nil {
		lgSigner.Warn("rollover: set phase pending-parent-push failed", "zone", zone, "err", err)
	}
	lgSigner.Warn("rollover: parent push failed, retrying immediately",
		"zone", zone, "attempt", n, "max_attempts", maxAttempts, "category", category)
}

// scheduleNextObservePoll advances the backoff interval for the next parent
// DS query. Doubles the current backoff up to pollMax. Updates
// observe_next_poll_at and observe_backoff_seconds.
func scheduleNextObservePoll(kdb *KeyDB, zone string, row *RolloverZoneRow, now time.Time, pollMax time.Duration) {
	cur := time.Duration(0)
	if row != nil && row.ObserveBackoffSecs.Valid {
		cur = time.Duration(row.ObserveBackoffSecs.Int64) * time.Second
	}
	next := cur * 2
	if next <= 0 {
		next = 2 * time.Second
	}
	if next > pollMax {
		next = pollMax
	}
	started := time.Time{}
	if row != nil {
		if t, ok := parseOptionalTime(row.ObserveStartedAt); ok {
			started = t
		}
	}
	if err := setObserveSchedule(kdb, zone, started, now.Add(next), int(next.Seconds())); err != nil {
		lgSigner.Warn("rollover: set next observe poll", "zone", zone, "err", err)
	}
}

func parseOptionalTime(s sql.NullString) (time.Time, bool) {
	if !s.Valid {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s.String)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// TransitionRolloverKskDsPublishedToStandby advances each SEP key from
// ds-published to standby exactly when its DNSKEY needs to be in the
// served zone for cache-flush safety: T_publish_i = T_roll_i -
// propagationDelay, where T_roll_i = active.active_at + i × KSK.Lifetime
// and i is the key's position in the promotion queue (1 = next-up).
//
// Why not "advance after DS has been observed for propagationDelay
// seconds": that rule unconditionally advances every ds-published key
// shortly after its DS is seen at the parent, which puts the DNSKEY for
// every standby into the zone. For multi-DS the operational intent is
// to keep DNSKEY material *out* of the zone for keys whose rollover is
// far in the future — DS hashes are post-quantum-opaque, but DNSKEYs
// reveal the public key. Pre-publication only has to satisfy the
// cache-flush invariant for the immediately-upcoming rollover; for keys
// further out, leave them in ds-published until their own T_publish
// comes around.
//
// Corner case: when propagationDelay > KSK.Lifetime, T_publish_i for a
// key that's i slots out can land before T_publish_{i-1}'s rollover
// fires, meaning multiple standbys may need DNSKEYs simultaneously.
// The per-promotion-position computation handles this correctly —
// each key is governed by its own T_publish.
func TransitionRolloverKskDsPublishedToStandby(conf *Config, kdb *KeyDB, now time.Time, propagationDelay time.Duration) {
	keys, err := GetDnssecKeysByState(kdb, "", DnskeyStateDsPublished)
	if err != nil {
		lgSigner.Error("rollover: list ds-published keys", "err", err)
		return
	}

	// Group ds-published SEP keys by zone.
	byZone := map[string][]*DnssecKeyWithTimestamps{}
	for i := range keys {
		k := &keys[i]
		if k.Flags&dns.SEP == 0 {
			continue
		}
		byZone[k.ZoneName] = append(byZone[k.ZoneName], k)
	}

	for zoneName, dsPubs := range byZone {
		zd, ok := Zones.Get(zoneName)
		if !ok || zd.DnssecPolicy == nil || zd.DnssecPolicy.Rollover.Method != RolloverMethodMultiDS {
			continue
		}
		pol := zd.DnssecPolicy
		if pol.KSK.Lifetime == 0 {
			continue
		}

		// Anchor T_roll on the active KSK's active_at.
		active, err := GetDnssecKeysByState(kdb, zoneName, DnskeyStateActive)
		if err != nil {
			continue
		}
		var activeKid uint16
		for i := range active {
			if active[i].Flags&dns.SEP != 0 {
				activeKid = active[i].KeyTag
				break
			}
		}
		if activeKid == 0 {
			continue
		}
		activeAt, err := RolloverKeyActiveAt(kdb, zoneName, activeKid)
		if err != nil || activeAt == nil {
			continue
		}

		// Sort ds-published keys by ds_observed_at ascending — this is
		// the promotion order (oldest = next up). Keys with no
		// ds_observed_at (shouldn't happen for state=ds-published, but
		// be defensive) sort to the back.
		sort.SliceStable(dsPubs, func(a, b int) bool {
			ta, _ := RolloverKeyDsObservedAt(kdb, zoneName, dsPubs[a].KeyTag)
			tb, _ := RolloverKeyDsObservedAt(kdb, zoneName, dsPubs[b].KeyTag)
			if ta == nil && tb == nil {
				return dsPubs[a].KeyTag < dsPubs[b].KeyTag
			}
			if ta == nil {
				return false
			}
			if tb == nil {
				return true
			}
			return ta.Before(*tb)
		})

		lifetime := time.Duration(pol.KSK.Lifetime) * time.Second
		for i, k := range dsPubs {
			// Promotion position: i=0 is the next-up (slot 1),
			// i=1 is after that (slot 2), etc.
			tRoll := activeAt.Add(time.Duration(i+1) * lifetime)
			tPublish := tRoll.Add(-propagationDelay)
			if now.Before(tPublish) {
				// Sorted by promotion order; later keys have
				// strictly later tPublish (by exactly `lifetime`).
				// Nothing more to do for this zone this tick.
				break
			}
			if err := UpdateDnssecKeyState(kdb, zoneName, k.KeyTag, DnskeyStateStandby); err != nil {
				lgSigner.Error("rollover: ds-published→standby failed",
					"zone", zoneName, "keyid", k.KeyTag, "err", err)
				continue
			}
			if err := setRolloverKeyStandbyAt(kdb, zoneName, k.KeyTag, now); err != nil {
				lgSigner.Warn("rollover: standby_at stamp failed",
					"zone", zoneName, "keyid", k.KeyTag, "err", err)
			}
			lgSigner.Info("rollover: ds-published→standby",
				"zone", zoneName, "keyid", k.KeyTag,
				"slot", i+1, "t_roll", tRoll.UTC().Format(time.RFC3339),
				"t_publish", tPublish.UTC().Format(time.RFC3339))
			triggerResign(conf, zoneName)
		}
	}
}

// PromoteStandbyKskIfNoActive activates one standby KSK when the zone has none (bootstrap).
func PromoteStandbyKskIfNoActive(conf *Config, kdb *KeyDB, zone string) {
	zone = dns.Fqdn(zone)
	active, err := GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
	if err != nil {
		return
	}
	for i := range active {
		if active[i].Flags&dns.SEP != 0 {
			return
		}
	}
	standby, err := GetDnssecKeysByState(kdb, zone, DnskeyStateStandby)
	if err != nil {
		return
	}
	var best *DnssecKeyWithTimestamps
	for i := range standby {
		k := &standby[i]
		if k.Flags&dns.SEP == 0 {
			continue
		}
		if best == nil || k.KeyTag < best.KeyTag {
			best = k
		}
	}
	if best == nil {
		return
	}
	if err := UpdateDnssecKeyState(kdb, zone, best.KeyTag, DnskeyStateActive); err != nil {
		lgSigner.Error("rollover: standby→active (bootstrap) failed", "zone", zone, "keyid", best.KeyTag, "err", err)
		return
	}
	// Stamp active_at and assign the next active_seq atomically.
	tx, err := kdb.Begin("PromoteStandbyKskIfNoActive")
	if err != nil {
		lgSigner.Warn("rollover: bootstrap promote stamp tx begin failed", "zone", zone, "err", err)
	} else {
		commit := false
		if err := setRolloverKeyActiveAtTx(tx, zone, best.KeyTag, time.Now().UTC()); err != nil {
			lgSigner.Warn("rollover: active_at stamp failed (bootstrap)", "zone", zone, "keyid", best.KeyTag, "err", err)
		} else if seq, err := nextActiveSeqTx(tx, zone); err != nil {
			lgSigner.Warn("rollover: next active_seq failed (bootstrap)", "zone", zone, "err", err)
		} else if err := setRolloverKeyActiveSeqTx(tx, zone, best.KeyTag, seq); err != nil {
			lgSigner.Warn("rollover: active_seq stamp failed (bootstrap)", "zone", zone, "keyid", best.KeyTag, "err", err)
		} else if err := tx.Commit(); err != nil {
			lgSigner.Warn("rollover: bootstrap promote stamp tx commit failed", "zone", zone, "err", err)
		} else {
			commit = true
		}
		if !commit {
			tx.Rollback()
		}
	}
	lgSigner.Info("rollover: promoted standby KSK to active (no active KSK)", "zone", zone, "keyid", best.KeyTag)
	triggerResign(conf, zone)
}

func rolloverAutomatedForAllZones(ctx context.Context, conf *Config, kdb *KeyDB, propagationDelay time.Duration, now time.Time) {
	imr := conf.Internal.ImrEngine
	nowFn := func() time.Time { return now }
	for _, zd := range Zones.Items() {
		if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
			continue
		}
		if zd.Options[OptMultiProvider] {
			continue
		}
		if zd.DnssecPolicy == nil {
			continue
		}
		var notifyq chan NotifyRequest
		if conf.Internal.NotifyQ != nil {
			notifyq = conf.Internal.NotifyQ
		}
		var updateq chan UpdateRequest
		if kdb != nil {
			updateq = kdb.UpdateQ
		}
		deps := RolloverEngineDeps{
			Conf:             conf,
			KDB:              kdb,
			Zone:             zd,
			Imr:              imr,
			NotifyQ:          notifyq,
			InternalUpdateQ:  updateq,
			Policy:           zd.DnssecPolicy,
			AcquireLock:      defaultAcquireRolloverLock,
			Logger:           lgSigner,
			PropagationDelay: propagationDelay,
			Now:              nowFn,
		}
		if err := RolloverAutomatedTick(ctx, deps); err != nil {
			lgSigner.Error("rollover: tick error", "zone", zd.ZoneName, "err", err)
		}
	}
}

// rolloverDue returns (due, manual, err). due == true means the zone should
// fire AtomicRollover this tick. manual == true means the trigger was a
// manual-ASAP request (callers must clear manual_rollover_* on success).
//
// Two independent triggers, OR'd:
//
//  1. Scheduled: active SEP KSK has lived past policy.ksk.lifetime.
//  2. Manual:    operator set manual_rollover_earliest <= now via `rollover asap`.
//
// Both require: no rollover in progress (caller-checked) and a standby SEP
// key exists.
func rolloverDue(kdb *KeyDB, zone string, pol *DnssecPolicy, row *RolloverZoneRow, now time.Time) (due bool, manual bool, err error) {
	if pol == nil || row == nil {
		return false, false, nil
	}

	// At least one standby SEP key must exist for either trigger.
	standby, err := GetDnssecKeysByState(kdb, zone, DnskeyStateStandby)
	if err != nil {
		return false, false, fmt.Errorf("list standby keys: %w", err)
	}
	haveStandby := false
	for i := range standby {
		if standby[i].Flags&dns.SEP != 0 {
			haveStandby = true
			break
		}
	}
	if !haveStandby {
		return false, false, nil
	}

	// Manual-ASAP: take precedence so operator action is honored even when
	// scheduled would also fire.
	if row.ManualRolloverEarliest.Valid && strings.TrimSpace(row.ManualRolloverEarliest.String) != "" {
		if t, e := time.Parse(time.RFC3339, strings.TrimSpace(row.ManualRolloverEarliest.String)); e == nil {
			if !now.Before(t) {
				return true, true, nil
			}
		} else {
			lgSigner.Warn("rollover: invalid manual_rollover_earliest", "zone", zone, "value", row.ManualRolloverEarliest.String, "err", e)
		}
	}

	// Scheduled: KSK.Lifetime == 0 means "never expires."
	if pol.KSK.Lifetime == 0 {
		return false, false, nil
	}
	lifetime := time.Duration(pol.KSK.Lifetime) * time.Second
	active, err := GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
	if err != nil {
		return false, false, fmt.Errorf("list active keys: %w", err)
	}
	var activeKid uint16
	for i := range active {
		if active[i].Flags&dns.SEP != 0 {
			activeKid = active[i].KeyTag
			break
		}
	}
	if activeKid == 0 {
		return false, false, nil
	}
	at, err := RolloverKeyActiveAt(kdb, zone, activeKid)
	if err != nil {
		return false, false, fmt.Errorf("active_at lookup: %w", err)
	}
	if at == nil {
		return false, false, nil
	}
	if now.Sub(*at) >= lifetime {
		return true, false, nil
	}
	return false, false, nil
}

// EffectiveMarginForZone is the exported alias used by the auto-rollover
// status CLI to estimate the next pending-child-withdraw transition.
func EffectiveMarginForZone(kdb *KeyDB, zone string, pol *DnssecPolicy) (time.Duration, error) {
	return effectiveMarginForZone(kdb, zone, pol)
}

// effectiveMarginForZone returns max(policy.clamping.margin, max_observed_ttl)
// for the zone. Used by pending-child-withdraw to bound the wait by both the
// configured margin and the longest-lived RRSIG that could still be cached at
// resolvers. max_observed_ttl is whatever the most recent SignZone pass
// recorded; 0 if the zone has not yet completed a sign pass.
func effectiveMarginForZone(kdb *KeyDB, zone string, pol *DnssecPolicy) (time.Duration, error) {
	margin := pol.Clamping.Margin
	maxTTL, err := LoadZoneSigningMaxTTL(kdb, zone)
	if err != nil {
		return margin, err
	}
	ttlDur := time.Duration(maxTTL) * time.Second
	if ttlDur > margin {
		return ttlDur, nil
	}
	return margin, nil
}

// completeRolloverWithdraw is called when the last retired SEP key has been
// removed: clear rollover_in_progress and return the zone to idle. The next
// idle tick re-evaluates the DS set and arms a fresh push if needed (the
// retired key's DS dropping out is the typical trigger).
func completeRolloverWithdraw(conf *Config, kdb *KeyDB, zone string) error {
	tx, err := kdb.Begin("completeRolloverWithdraw")
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	commit := false
	defer func() {
		if !commit {
			tx.Rollback()
		}
	}()
	if err := setRolloverInProgressTx(tx, zone, false); err != nil {
		return fmt.Errorf("clear rollover_in_progress: %w", err)
	}
	if err := setRolloverPhaseTx(tx, zone, rolloverPhaseIdle); err != nil {
		return fmt.Errorf("reset phase: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	commit = true
	lgSigner.Info("rollover: pending-child-withdraw complete; zone returned to idle", "zone", zone)
	triggerResign(conf, zone)
	return nil
}

// healBootstrapActiveAt is a self-heal pass: if the zone has an active SEP
// KSK with no RolloverKeyState row, no active_at timestamp, OR no active_seq,
// register/backfill it now so rolloverDue, tNextRoll, and the operator-
// facing active_seq counter all work. Best-effort — silent on errors.
//
// active_seq backfill is necessary for active SEP keys promoted by an older
// binary that didn't yet stamp active_seq at AtomicRollover. The row exists
// and active_at is set, but active_seq is NULL. RegisterBootstrapActiveKSK
// is idempotent and only stamps active_seq when it is currently NULL, so
// calling it on already-healed keys is a no-op.
func healBootstrapActiveAt(kdb *KeyDB, zone string, pol *DnssecPolicy) {
	if pol == nil || pol.Rollover.Method == RolloverMethodNone {
		return
	}
	active, err := GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
	if err != nil {
		return
	}
	for i := range active {
		k := &active[i]
		if k.Flags&dns.SEP == 0 {
			continue
		}
		at, atErr := RolloverKeyActiveAt(kdb, zone, k.KeyTag)
		seq, seqErr := RolloverKeyActiveSeq(kdb, zone, k.KeyTag)
		needHeal := atErr != nil || at == nil || seqErr != nil || seq < 0
		if !needHeal {
			continue
		}
		if err := RegisterBootstrapActiveKSK(kdb, zone, k.KeyTag, pol.Rollover.Method, pol.Algorithm); err != nil {
			lgSigner.Warn("rollover: heal active SEP KSK state failed", "zone", zone, "keyid", k.KeyTag, "err", err)
			continue
		}
		lgSigner.Info("rollover: healed active SEP KSK state", "zone", zone, "keyid", k.KeyTag,
			"had_active_at", at != nil, "had_active_seq", seq >= 0)
	}
}

func promoteStandbyKskBootstrapAll(conf *Config, kdb *KeyDB) {
	for zoneName, zd := range Zones.Items() {
		if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
			continue
		}
		if zd.Options[OptMultiProvider] || zd.DnssecPolicy == nil {
			continue
		}
		if zd.DnssecPolicy.Rollover.Method != RolloverMethodMultiDS {
			continue
		}
		PromoteStandbyKskIfNoActive(conf, kdb, zoneName)
	}
}
