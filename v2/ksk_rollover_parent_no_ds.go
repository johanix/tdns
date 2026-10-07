package tdns

import (
	"fmt"
	"strings"
	"time"
)

// First DS publication against a parent with no DS
// (docs/2026-10-06-first-ds-publication-does-not-block.md).
//
// A multi-DS zone whose parent holds no DS for it -- an insecure
// delegation, which validators may still trust through a configured trust
// anchor -- does not leave the DS push/observe loop: the idle branch arms a
// push of the active KSK's DS, the parent never publishes it, and the engine
// ends up in parent-push-softfail, probing and polling for good. That loop
// is right; the zone keeps asking for a DS at the parent. But it is not a
// rollover, and it must not block what a rollover blocks: a KSK algorithm
// change, by command or by config reload, and the spawn of the algorithm
// roll that carries it.

// parentShowedNoDS reports whether the engine's own most recent parent DS
// poll (QueryParentAgentDS, recorded by setLastDsObserved) answered with no
// DS records at all. A zone that has never polled has learned nothing about
// its parent and does not count.
func parentShowedNoDS(row *RolloverZoneRow) bool {
	if row == nil || !row.LastDsObservedAt.Valid || !row.LastDsObservedKeyids.Valid {
		return false
	}
	return strings.TrimSpace(row.LastDsObservedKeyids.String) == ""
}

// dsRangeEverConfirmed reports whether the engine has ever seen the parent
// publish a DS set for the zone: last_ds_confirmed_* is set at every
// confirm and only an insecure roll's confirm clears it.
func dsRangeEverConfirmed(row *RolloverZoneRow) bool {
	return row != nil && (row.LastConfirmedLow.Valid || row.LastConfirmedHigh.Valid)
}

// firstDSPublicationWithoutParentDS is the non-blocking state: the engine
// is pushing (or retrying, or waiting to observe) the DS set of a zone with
// no rollover of its own in flight, to a parent that held no DS for the zone
// at the engine's last poll and has never been seen to hold one. Nothing at
// the parent depends on the keys, and nothing a validator can have cached
// from the parent does either, so nothing here has to finish before the KSK
// algorithm may change.
//
// A DS push to a parent that does hold DS for the zone -- multi-DS pipeline
// maintenance, say -- is not this state, and still blocks: the parent is
// part way through taking a DS set the zone has committed to. Nor is a push
// to a parent that once held DS for the zone and no longer does: validators
// may still have that DS cached, for up to the parent DS TTL, and no poll of
// the parent can see their caches. An insecure roll from there would remove
// the old KSK on a margin that does not cover it.
func firstDSPublicationWithoutParentDS(row *RolloverZoneRow) bool {
	if row == nil || row.RolloverInProgress || row.AlgRollFromAlg.Valid || dsRangeEverConfirmed(row) {
		return false
	}
	switch row.RolloverPhase {
	case rolloverPhasePendingParentPush, rolloverPhasePendingParentObserve, rolloverPhasePushSoftfail:
		return parentShowedNoDS(row)
	}
	return false
}

// kskAlgRollStartsInsecure is the decision SpawnKskAlgRollover records as
// alg_roll_parent_insecure: the roll starts against a parent with no DS for
// the zone. True from the non-blocking first-DS state, and from idle when
// the engine's last poll showed no DS and no DS set has ever been confirmed
// -- the zone between the end of an earlier insecure roll and the tick that
// re-arms its first DS publication. Both require that no DS was ever
// confirmed (see firstDSPublicationWithoutParentDS).
//
// It is made once, here, so that an empty answer later in a secure roll (a
// lagging parent nameserver, say) can never turn that roll insecure.
func kskAlgRollStartsInsecure(row *RolloverZoneRow) bool {
	if !parentShowedNoDS(row) {
		return false
	}
	if firstDSPublicationWithoutParentDS(row) {
		return true
	}
	phase := row.RolloverPhase
	if phase == "" {
		phase = rolloverPhaseIdle
	}
	return phase == rolloverPhaseIdle && !row.RolloverInProgress && !dsRangeEverConfirmed(row)
}

// kskRolloverPolicyChangeBlock returns "" when the zone's KSK rollover state
// lets a KSK algorithm change through, and otherwise a sentence saying what
// the engine is doing that the change has to wait for. The command path
// refuses with it and the config path logs it.
func kskRolloverPolicyChangeBlock(zone string, row *RolloverZoneRow) string {
	if row == nil {
		return ""
	}
	phase := row.RolloverPhase
	if phase == "" {
		phase = rolloverPhaseIdle
	}
	if phase == rolloverPhaseIdle && !row.RolloverInProgress {
		return ""
	}
	if firstDSPublicationWithoutParentDS(row) {
		return ""
	}
	doing := kskRolloverActivity(row, phase)
	if row.RolloverInProgress || row.AlgRollFromAlg.Valid {
		return fmt.Sprintf("a KSK rollover is already in progress for zone %s (phase %s) and the engine is %s; wait for the rollover to complete",
			zone, phase, doing)
	}
	if !row.LastDsObservedAt.Valid {
		return fmt.Sprintf("a DS push is in flight for zone %s (phase %s) and the engine is %s, but has not polled the parent yet; if the parent holds no DS for the zone, retry once a poll has shown that%s",
			zone, phase, doing, nextPollSuffix(row))
	}
	if parentShowedNoDS(row) && dsRangeEverConfirmed(row) {
		return fmt.Sprintf("a DS push is in flight for zone %s (phase %s) and the engine is %s; %s, but it has held DS for the zone before, and validators may still have that DS cached; wait for the parent to publish the DS set",
			zone, phase, doing, lastParentObservation(row))
	}
	return fmt.Sprintf("a DS push is in flight for zone %s (phase %s) and the engine is %s; %s; wait for the parent to publish it",
		zone, phase, doing, lastParentObservation(row))
}

// kskRolloverActivity names, for an operator, what the engine is waiting
// for in phase.
func kskRolloverActivity(row *RolloverZoneRow, phase string) string {
	switch phase {
	case rolloverPhasePendingChildPublish:
		return "waiting for the new KSK's DNSKEY to propagate before it asks the parent for the DS"
	case rolloverPhasePendingParentPush:
		return "sending the DS set to the parent"
	case rolloverPhasePendingParentObserve:
		return "waiting for the parent to publish the DS set it was sent"
	case rolloverPhasePushSoftfail:
		return "waiting for the parent to publish the DS set it was sent, re-sending it periodically"
	case rolloverPhasePendingChildWithdraw:
		if row != nil && row.AlgRollFromAlg.Valid {
			return "letting cached data signed by the old-algorithm KSK expire before it removes that KSK"
		}
		return "letting cached data signed by the retired KSK expire before it removes that KSK"
	case rolloverPhaseIdle:
		return "finishing a rollover"
	}
	return "in phase " + phase
}

// lastParentObservation describes the engine's last parent DS poll.
func lastParentObservation(row *RolloverZoneRow) string {
	at := strings.TrimSpace(row.LastDsObservedAt.String)
	if parentShowedNoDS(row) {
		return fmt.Sprintf("the parent served no DS at its last poll (%s)", at)
	}
	return fmt.Sprintf("the parent served DS for key tag(s) %s at its last poll (%s)",
		strings.TrimSpace(row.LastDsObservedKeyids.String), at)
}

func nextPollSuffix(row *RolloverZoneRow) string {
	if t, ok := parseOptionalTime(row.ObserveNextPollAt); ok {
		return " (first poll due " + t.UTC().Format(time.RFC3339) + ")"
	}
	return ""
}

// loadRolloverSpawnStateTx reads, inside the spawn's transaction, the
// fields the spawn decides on: whether anything is rolling, the phase, what
// the engine last saw at the parent, and whether a DS set was ever
// confirmed. The rest of the row is left zero.
func loadRolloverSpawnStateTx(tx *Tx, zone string) (*RolloverZoneRow, error) {
	r := RolloverZoneRow{Zone: zone}
	var inProg int
	err := tx.QueryRow(`SELECT rollover_phase, rollover_in_progress, alg_roll_from_alg,
       last_ds_observed_keyids, last_ds_observed_at,
       last_ds_confirmed_index_low, last_ds_confirmed_index_high
FROM RolloverZoneState WHERE zone = ?`, zone).Scan(
		&r.RolloverPhase, &inProg, &r.AlgRollFromAlg,
		&r.LastDsObservedKeyids, &r.LastDsObservedAt,
		&r.LastConfirmedLow, &r.LastConfirmedHigh,
	)
	if err != nil {
		return nil, err
	}
	r.RolloverInProgress = inProg != 0
	return &r, nil
}

// endFirstDSPublicationTx closes the first DS publication's attempt group
// in the transaction that starts an algorithm roll from it. The observe
// schedule, the hardfail count, the softfail context and the next probe
// time all describe a push of the old key set, which the roll's own push
// replaces. Left behind, the roll's first push would inherit a hardfail
// count at the backoff threshold and a probe time already due.
func endFirstDSPublicationTx(tx *Tx, zone string) error {
	if err := clearObserveScheduleTx(tx, zone); err != nil {
		return err
	}
	_, err := tx.Exec(`UPDATE RolloverZoneState
SET hardfail_count = 0,
    next_push_at = NULL,
    last_softfail_at = NULL,
    last_softfail_category = NULL,
    last_softfail_detail = NULL
WHERE zone = ?`, zone)
	return err
}

// clearLastDSConfirmedRangeTx forgets the confirmed DS range on an existing
// TX. Used by the insecure algorithm-roll confirm: the parent has confirmed
// nothing, and with no confirmed range the idle branch arms the first DS
// publication for the new KSK once the roll is done.
func clearLastDSConfirmedRangeTx(tx *Tx, zone string) error {
	_, err := tx.Exec(`UPDATE RolloverZoneState
SET last_ds_confirmed_index_low = NULL,
    last_ds_confirmed_index_high = NULL,
    last_ds_confirmed_at = NULL
WHERE zone = ?`, zone)
	return err
}
