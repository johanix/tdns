package tdns

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

const (
	rolloverPhaseIdle                 = "idle"
	rolloverPhasePendingChildPublish  = "pending-child-publish"
	rolloverPhasePendingParentPush    = "pending-parent-push"
	rolloverPhasePendingParentObserve = "pending-parent-observe"
	rolloverPhasePendingChildWithdraw = "pending-child-withdraw"
)

func kskIndexPushNeeded(row *RolloverZoneRow, low, high int, indexOK bool, haveDS bool) bool {
	if !haveDS {
		return false
	}
	if !indexOK {
		return false
	}
	if row == nil || !row.LastSubmittedLow.Valid || !row.LastSubmittedHigh.Valid {
		return true
	}
	return int(row.LastSubmittedLow.Int64) != low || int(row.LastSubmittedHigh.Int64) != high
}

// RolloverAutomatedTick runs one slice of automated KSK rollover for multi-ds (pipeline fill,
// DS push / observe phase machine). double-signature is not implemented yet.
// propagationDelay is the kasp.propagation_delay used by pending-child-publish.
func RolloverAutomatedTick(ctx context.Context, conf *Config, kdb *KeyDB, imr *Imr, zd *ZoneData, propagationDelay time.Duration, now time.Time) error {
	if zd == nil || zd.DnssecPolicy == nil {
		return nil
	}
	pol := zd.DnssecPolicy
	if pol.Rollover.Method == RolloverMethodNone {
		return nil
	}
	if pol.Rollover.Method == RolloverMethodDoubleSignature {
		return nil
	}

	zone := dns.Fqdn(zd.ZoneName)
	if err := EnsureRolloverZoneRow(kdb, zone); err != nil {
		return err
	}

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

	// rollover_due (§8.1): when no rollover is in progress, the active KSK
	// has lived past policy.ksk.lifetime, and a standby SEP exists, fire
	// AtomicRollover. The tick then re-loads phase and continues; the new
	// pending-child-publish phase will be handled below if reached this
	// pass, or on the next tick.
	if phase == rolloverPhaseIdle && !row.RolloverInProgress {
		due, err := rolloverDue(kdb, zone, pol, now)
		if err != nil {
			lgSigner.Warn("rollover: rollover_due check failed", "zone", zone, "err", err)
		} else if due {
			if _, _, err := AtomicRollover(conf, kdb, zone); err != nil {
				lgSigner.Warn("rollover: AtomicRollover failed", "zone", zone, "err", err)
			} else {
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
			return nil
		}
		pushCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		res, err := PushWholeDSRRset(pushCtx, zd, kdb, imr)
		cancel()
		if err != nil {
			lgSigner.Warn("rollover: DS push failed", "zone", zone, "err", err)
			return nil
		}
		if res.Rcode != dns.RcodeSuccess {
			lgSigner.Warn("rollover: DS push non-NOERROR", "zone", zone, "rcode", dns.RcodeToString[res.Rcode])
			return nil
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
				if err := observeHardFail(kdb, zone, low, high, timeout); err != nil {
					return err
				}
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
		if advanced > 0 {
			triggerResign(conf, zone)
		}
		lgSigner.Info("rollover: parent DS observed, advanced created keys", "zone", zone, "advanced", advanced)
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
	if err := setRolloverPhaseTx(tx, zone, rolloverPhaseIdle); err != nil {
		return 0, fmt.Errorf("reset phase: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	commit = true
	return advanced, nil
}

// observeHardFail records last_rollover_error on every SEP key currently in
// state=created that was waiting on confirmation of the [low, high] range,
// then resets the zone to idle. No TX needed: this is a diagnostic write
// path and idempotent retry on the next tick is safe.
func observeHardFail(kdb *KeyDB, zone string, low, high int, timeout time.Duration) error {
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
	_ = clearObserveSchedule(kdb, zone)
	return SetRolloverPhase(kdb, zone, rolloverPhaseIdle)
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

// TransitionRolloverKskDsPublishedToStandby moves SEP keys from ds-published to standby after propagation delay.
func TransitionRolloverKskDsPublishedToStandby(conf *Config, kdb *KeyDB, now time.Time, propagationDelay time.Duration) {
	keys, err := GetDnssecKeysByState(kdb, "", DnskeyStateDsPublished)
	if err != nil {
		lgSigner.Error("rollover: list ds-published keys", "err", err)
		return
	}
	for i := range keys {
		k := &keys[i]
		if k.Flags&dns.SEP == 0 {
			continue
		}
		zd, ok := Zones.Get(k.ZoneName)
		if !ok || zd.DnssecPolicy == nil || zd.DnssecPolicy.Rollover.Method != RolloverMethodMultiDS {
			continue
		}
		dsAt, err := rolloverKeyDsObservedAt(kdb, k.ZoneName, k.KeyTag)
		if err != nil || dsAt == nil {
			continue
		}
		if now.Sub(*dsAt) < propagationDelay {
			continue
		}
		if err := UpdateDnssecKeyState(kdb, k.ZoneName, k.KeyTag, DnskeyStateStandby); err != nil {
			lgSigner.Error("rollover: ds-published→standby failed", "zone", k.ZoneName, "keyid", k.KeyTag, "err", err)
			continue
		}
		if err := setRolloverKeyStandbyAt(kdb, k.ZoneName, k.KeyTag, now); err != nil {
			lgSigner.Warn("rollover: standby_at stamp failed", "zone", k.ZoneName, "keyid", k.KeyTag, "err", err)
		}
		lgSigner.Info("rollover: ds-published→standby", "zone", k.ZoneName, "keyid", k.KeyTag)
		triggerResign(conf, k.ZoneName)
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
	if _, err := kdb.DB.Exec(`UPDATE RolloverKeyState SET active_at = ? WHERE zone = ? AND keyid = ?`,
		time.Now().UTC().Format(time.RFC3339), zone, int(best.KeyTag)); err != nil {
		lgSigner.Warn("rollover: active_at stamp failed (bootstrap)", "zone", zone, "keyid", best.KeyTag, "err", err)
	}
	lgSigner.Info("rollover: promoted standby KSK to active (no active KSK)", "zone", zone, "keyid", best.KeyTag)
	triggerResign(conf, zone)
}

func rolloverAutomatedForAllZones(ctx context.Context, conf *Config, kdb *KeyDB, propagationDelay time.Duration, now time.Time) {
	imr := conf.Internal.ImrEngine
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
		if err := RolloverAutomatedTick(ctx, conf, kdb, imr, zd, propagationDelay, now); err != nil {
			lgSigner.Error("rollover: tick error", "zone", zd.ZoneName, "err", err)
		}
	}
}

// rolloverDue returns true when the zone should fire AtomicRollover: the
// active SEP KSK has lived past policy.ksk.lifetime, no rollover is currently
// in progress (caller-checked), and at least one standby SEP key exists. A
// zero-or-unset KSK lifetime means "never expires" — return false.
func rolloverDue(kdb *KeyDB, zone string, pol *DnssecPolicy, now time.Time) (bool, error) {
	if pol == nil {
		return false, nil
	}
	if pol.KSK.Lifetime == 0 {
		return false, nil
	}
	lifetime := time.Duration(pol.KSK.Lifetime) * time.Second

	// Find the active SEP key.
	active, err := GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
	if err != nil {
		return false, fmt.Errorf("list active keys: %w", err)
	}
	var activeKid uint16
	for i := range active {
		if active[i].Flags&dns.SEP != 0 {
			activeKid = active[i].KeyTag
			break
		}
	}
	if activeKid == 0 {
		return false, nil
	}
	at, err := rolloverKeyActiveAt(kdb, zone, activeKid)
	if err != nil {
		return false, fmt.Errorf("active_at lookup: %w", err)
	}
	if at == nil {
		// No timestamp yet (e.g. legacy zone): cannot fire scheduled rollover.
		return false, nil
	}
	if now.Sub(*at) < lifetime {
		return false, nil
	}

	// At least one standby SEP key must exist.
	standby, err := GetDnssecKeysByState(kdb, zone, DnskeyStateStandby)
	if err != nil {
		return false, fmt.Errorf("list standby keys: %w", err)
	}
	for i := range standby {
		if standby[i].Flags&dns.SEP != 0 {
			return true, nil
		}
	}
	return false, nil
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
