package tdns

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// KSK algorithm rollover: the spawn and its trigger predicate.
//
// The engine that carries a KSK algorithm rollover is the existing per-zone
// phase machine (RolloverAutomatedTick); what an algorithm roll adds is one
// alternate ordering through it. Instead of pre-positioning a DS for a
// standby key and promoting later (multi-DS), the new-algorithm KSK is
// minted straight into active so it signs the apex DNSKEY RRset BEFORE its
// DS is pushed -- double-signature -- and the old-algorithm KSK stays active,
// still signing, until the parent has confirmed the mixed DS RRset and a
// full drain window has elapsed. See
// docs/2026-09-08-ksk-alg-rollover-implementation-plan.md (§2, §5.2, A2).
//
// Sequence, mapped onto the phases the machine already has:
//
//	spawn (this file)              → pending-child-publish
//	wait propagation + DNSKEY_TTL  → pending-child-publish handler
//	push {DS(A), DS(B)}            → pending-parent-push
//	observe until both confirmed   → pending-parent-observe
//	confirm ⇒ start A's clock      → pending-child-withdraw
//	hold margin, remove A          → pending-child-withdraw (alg-roll arm)
//	DS shrinks to {DS(B)}          → a final push, then idle

// kskAlgRollNeeded is the trigger predicate the tick evaluates on an idle
// zone with no roll in flight. mismatch reports that the zone has exactly
// one active SEP key and its algorithm differs from the bound policy's
// KSK algorithm -- a bind has happened that the engine has not carried
// yet. blocked reports that the spawn must wait: a ZSK algorithm rollover
// is still draining (one role at a time, D-11). The (from, to) pair is
// what the spawn should use.
//
// A mismatch that is blocked is not an error: the bind succeeded and the
// KSK roll waits its turn. The tick re-evaluates every pass, and while it
// waits it neither fills the pipeline nor arms a push -- both would act
// on the new algorithm ahead of the spawn.
func kskAlgRollNeeded(kdb *KeyDB, zone string, pol *DnssecPolicy) (fromAlg, toAlg uint8, mismatch, blocked bool, err error) {
	if pol == nil || pol.Mode == DnssecPolicyModeCSK || pol.KSKAlgorithm == 0 {
		return 0, 0, false, false, nil
	}
	active, err := GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
	if err != nil {
		return 0, 0, false, false, fmt.Errorf("kskAlgRollNeeded: list active keys: %w", err)
	}
	var seps []DnssecKeyWithTimestamps
	for i := range active {
		if active[i].Flags&dns.SEP != 0 {
			seps = append(seps, active[i])
		}
	}
	if len(seps) != 1 {
		// Zero: bootstrap territory (EnsureActiveDnssecKeys mints on the
		// policy algorithm, nothing to roll). Two or more: either an
		// algorithm roll already in progress (the caller checks the
		// marker first) or a broken invariant; neither is ours to start.
		return 0, 0, false, false, nil
	}
	if seps[0].Algorithm == pol.KSKAlgorithm {
		return 0, 0, false, false, nil
	}
	fromAlg, toAlg = seps[0].Algorithm, pol.KSKAlgorithm
	if pol.ZSKAlgorithm != 0 {
		zst, err := zskAlgRollInFlight(kdb, zone, pol.ZSKAlgorithm)
		if err != nil {
			return 0, 0, false, false, err
		}
		if zst.InFlight {
			lgRollover.Debug("rollover: KSK algorithm change bound but a ZSK algorithm rollover is draining; waiting (one role at a time)",
				"zone", zone,
				"ksk_have", dns.AlgorithmToString[fromAlg], "ksk_want", dns.AlgorithmToString[toAlg],
				"zsk_from", dns.AlgorithmToString[zst.FromAlg], "zsk_to", dns.AlgorithmToString[zst.ToAlg])
			return fromAlg, toAlg, true, true, nil
		}
	}
	return fromAlg, toAlg, true, false, nil
}

// SpawnKskAlgRollover starts a KSK algorithm rollover for a zone whose
// bound policy KSK algorithm differs from its active KSK's. One
// transaction; on commit the zone has two active KSKs, one per algorithm,
// and the next re-sign double-signs the apex DNSKEY RRset.
//
// In the transaction:
//
//  1. re-check that no rollover of any kind is in flight;
//  2. identify A, the single active SEP key of fromAlg, and refuse if an
//     active SEP key of toAlg already exists;
//  3. mint B straight into active with the next rollover_index and
//     active_seq -- the same four writes AtomicRollover makes for the key
//     it promotes;
//  4. freeze the old FIFO: every non-active SEP key of an algorithm other
//     than toAlg goes to removed. None of them has ever signed, so there
//     are no RRSIGs to orphan, and removed drops them from both the
//     DNSKEY RRset and the DS target set. A itself is untouched;
//  5. set rollover_in_progress and the pending-child-publish phase --
//     in THIS transaction, so the idle branch can never see the enlarged
//     DS target set and arm a push before B has propagated;
//  6. record the roll (alg_roll_* columns).
//
// Post-commit: republish the signing-keys snapshot and trigger the
// re-sign that puts RRSIG(B) on the wire.
func SpawnKskAlgRollover(conf *Config, kdb *KeyDB, zone string, fromAlg, toAlg uint8) (newKid uint16, err error) {
	zone = dns.Fqdn(strings.TrimSpace(zone))
	if zone == "." || zone == "" {
		return 0, fmt.Errorf("SpawnKskAlgRollover: empty zone")
	}
	if fromAlg == toAlg {
		return 0, fmt.Errorf("SpawnKskAlgRollover: zone %s: from and to algorithm are both %s", zone, dns.AlgorithmToString[toAlg])
	}
	if err := EnsureRolloverZoneRow(kdb, zone); err != nil {
		return 0, fmt.Errorf("ensure rollover zone row: %w", err)
	}

	tx, err := kdb.Begin("SpawnKskAlgRollover")
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	commit := false
	defer func() {
		if !commit {
			tx.Rollback()
		}
	}()

	now := time.Now().UTC()

	// 1. Nothing else may be rolling. Read inside the TX so two callers
	// cannot both spawn.
	inProgress, err := getRolloverInProgressTx(tx, zone)
	if err != nil {
		return 0, fmt.Errorf("read rollover_in_progress: %w", err)
	}
	if inProgress {
		return 0, fmt.Errorf("SpawnKskAlgRollover: zone %s already has a rollover in progress", zone)
	}
	var fromCol *int64
	if err := tx.QueryRow(`SELECT alg_roll_from_alg FROM RolloverZoneState WHERE zone = ?`, zone).Scan(&fromCol); err != nil {
		return 0, fmt.Errorf("read alg_roll_from_alg: %w", err)
	}
	if fromCol != nil {
		return 0, fmt.Errorf("SpawnKskAlgRollover: zone %s already has a KSK algorithm rollover in progress", zone)
	}

	// 2. A is the old-algorithm head; there must be no new-algorithm head yet.
	oldKid, err := pickActiveSEPByAlgTx(tx, zone, fromAlg)
	if err != nil {
		return 0, fmt.Errorf("pick active %s KSK: %w", dns.AlgorithmToString[fromAlg], err)
	}
	if oldKid == 0 {
		return 0, fmt.Errorf("SpawnKskAlgRollover: zone %s has no active %s KSK to roll from", zone, dns.AlgorithmToString[fromAlg])
	}
	if kid, err := pickActiveSEPByAlgTx(tx, zone, toAlg); err != nil {
		return 0, fmt.Errorf("pick active %s KSK: %w", dns.AlgorithmToString[toAlg], err)
	} else if kid != 0 {
		return 0, fmt.Errorf("SpawnKskAlgRollover: zone %s already has an active %s KSK (%d); refusing to mint a second",
			zone, dns.AlgorithmToString[toAlg], kid)
	}

	// 3. Mint B straight into active.
	ri, err := nextRolloverIndexTx(tx, zone)
	if err != nil {
		return 0, fmt.Errorf("next rollover_index: %w", err)
	}
	pkc, _, err := kdb.GenerateKeypair(zone, "ksk-alg-roll", DnskeyStateActive, dns.TypeDNSKEY, toAlg, "KSK", tx)
	if err != nil {
		return 0, fmt.Errorf("generate %s KSK: %w", dns.AlgorithmToString[toAlg], err)
	}
	newKid = pkc.KeyId
	if err := insertRolloverKeyStateTx(tx, zone, newKid, ri, RolloverMethodDoubleSignature); err != nil {
		return 0, fmt.Errorf("rollover state for keyid %d: %w", newKid, err)
	}
	if err := setRolloverKeyActiveAtTx(tx, zone, newKid, now); err != nil {
		return 0, fmt.Errorf("active_at (keyid %d): %w", newKid, err)
	}
	seq, err := nextActiveSeqTx(tx, zone)
	if err != nil {
		return 0, fmt.Errorf("next active_seq: %w", err)
	}
	if err := setRolloverKeyActiveSeqTx(tx, zone, newKid, seq); err != nil {
		return 0, fmt.Errorf("active_seq (keyid %d): %w", newKid, err)
	}
	if err := stampRolloverStateAtTx(tx, zone, newKid, now); err != nil {
		return 0, fmt.Errorf("rollover_state_at (keyid %d): %w", newKid, err)
	}

	// 4. Freeze the old FIFO.
	frozen, err := freezeNonActiveSEPKeysTx(tx, kdb, zone, toAlg, now)
	if err != nil {
		return 0, fmt.Errorf("freeze old-algorithm pipeline: %w", err)
	}

	// 5. Mark the zone mid-rollover and arm pending-child-publish.
	if err := setRolloverInProgressTx(tx, zone, true); err != nil {
		return 0, fmt.Errorf("set rollover_in_progress: %w", err)
	}
	if err := setRolloverPhaseTx(tx, zone, rolloverPhasePendingChildPublish); err != nil {
		return 0, fmt.Errorf("set rollover_phase: %w", err)
	}

	// 6. Record the roll.
	if err := setKskAlgRollTx(tx, zone, KskAlgRollState{
		FromAlg: fromAlg, ToAlg: toAlg, StartedAt: now,
		NewHeadKeyID: newKid, OldHeadKeyID: oldKid,
	}); err != nil {
		return 0, fmt.Errorf("record algorithm roll: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	commit = true

	// GenerateKeypair and UpdateDnssecKeyStateTx ran on an external TX; the
	// signing-keys snapshot is republished here, after the commit (R1).
	if rerr := republishSigningKeysForZone(kdb, zone); rerr != nil {
		return newKid, fmt.Errorf("SpawnKskAlgRollover: republish signing keys: %w", rerr)
	}

	lgRollover.Info("rollover: KSK algorithm rollover spawned; zone now double-signs its DNSKEY RRset",
		"zone", zone,
		"from", dns.AlgorithmToString[fromAlg], "to", dns.AlgorithmToString[toAlg],
		"old_head", oldKid, "new_head", newKid,
		"frozen", frozen, "phase", rolloverPhasePendingChildPublish)

	triggerResign(conf, zone)
	return newKid, nil
}

// freezeNonActiveSEPKeysTx moves every non-active, non-terminal SEP key of
// an algorithm other than keepAlg to removed and returns how many. These
// are the old-algorithm FIFO's created / ds-published / published /
// standby members (and any stray leftover of a third algorithm): none has
// ever signed, so removal orphans nothing, and removed takes them out of
// both the served DNSKEY RRset and the DS target set. Retired keys are
// left alone -- they may still have signatures on the wire and are the
// withdraw phase's to drain.
func freezeNonActiveSEPKeysTx(tx *Tx, kdb *KeyDB, zone string, keepAlg uint8, now time.Time) (int, error) {
	rows, err := tx.Query(`
SELECT keyid, algorithm, state FROM DnssecKeyStore
WHERE zonename = ? AND (flags & 1) = 1
  AND state IN ('created','ds-published','published','standby')
ORDER BY keyid ASC`, zone)
	if err != nil {
		return 0, err
	}
	type victim struct {
		kid   uint16
		alg   string
		state string
	}
	var victims []victim
	for rows.Next() {
		var kid int
		var algName, state string
		if err := rows.Scan(&kid, &algName, &state); err != nil {
			rows.Close()
			return 0, err
		}
		if alg, ok := dns.StringToAlgorithm[algName]; ok && alg == keepAlg {
			continue
		}
		victims = append(victims, victim{kid: uint16(kid), alg: algName, state: state})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	for _, v := range victims {
		if err := UpdateDnssecKeyStateTx(tx, kdb, zone, v.kid, DnskeyStateRemoved); err != nil {
			return 0, fmt.Errorf("%s→removed (keyid %d): %w", v.state, v.kid, err)
		}
		if err := stampRolloverStateAtTx(tx, zone, v.kid, now); err != nil {
			return 0, fmt.Errorf("rollover_state_at (keyid %d): %w", v.kid, err)
		}
		lgRollover.Info("rollover: froze old-algorithm pipeline KSK", "zone", zone, "keyid", v.kid, "algorithm", v.alg, "was", v.state)
	}
	return len(victims), nil
}

// AbortKskAlgRollover cancels an in-flight KSK algorithm rollover before
// the parent has confirmed the mixed DS RRset (D-12). Until then nobody
// relies on DS(B): abort means strip B's signatures, mark B removed, clear
// the roll marker, and return the zone to idle; the next idle tick pushes
// the shrunken DS set if a push had gone out. After confirmation "abort"
// would be a reverse algorithm rollover -- refused, with the guidance to
// let the roll finish and then change policy back.
//
// Returns a one-line description of what was done for the operator.
func AbortKskAlgRollover(conf *Config, kdb *KeyDB, zone string) (string, error) {
	zone = dns.Fqdn(strings.TrimSpace(zone))
	row, err := LoadRolloverZoneRow(kdb, zone)
	if err != nil {
		return "", fmt.Errorf("read rollover state: %w", err)
	}
	algRoll := kskAlgRollFromRow(row)
	if algRoll == nil {
		return "", fmt.Errorf("no KSK algorithm rollover is in progress")
	}
	if algRoll.OldHeadRetireAt != nil || row.RolloverPhase == rolloverPhasePendingChildWithdraw {
		return "", fmt.Errorf("the parent has already confirmed the mixed DS RRset (%s -> %s); aborting now would be a reverse algorithm rollover -- let it finish, then change policy back",
			dns.AlgorithmToString[algRoll.FromAlg], dns.AlgorithmToString[algRoll.ToAlg])
	}

	// B has signed the apex DNSKEY RRset since the spawn: strip its
	// signatures before it goes, or they dangle (F2).
	if zd, ok := Zones.Get(zone); ok && zd != nil {
		if _, err := zd.StripZoneRRSIGs(context.Background(), func(s *dns.RRSIG) bool {
			return s.KeyTag == algRoll.NewHeadKeyID
		}); err != nil {
			return "", fmt.Errorf("strip the new-algorithm KSK's signatures: %w", err)
		}
	}

	tx, err := kdb.Begin("AbortKskAlgRollover")
	if err != nil {
		return "", fmt.Errorf("begin: %w", err)
	}
	commit := false
	defer func() {
		if !commit {
			tx.Rollback()
		}
	}()
	if err := UpdateDnssecKeyStateTx(tx, kdb, zone, algRoll.NewHeadKeyID, DnskeyStateRemoved); err != nil {
		return "", fmt.Errorf("remove new-algorithm KSK %d: %w", algRoll.NewHeadKeyID, err)
	}
	if err := stampRolloverStateAtTx(tx, zone, algRoll.NewHeadKeyID, time.Now().UTC()); err != nil {
		return "", fmt.Errorf("rollover_state_at (keyid %d): %w", algRoll.NewHeadKeyID, err)
	}
	if err := clearKskAlgRollTx(tx, zone); err != nil {
		return "", fmt.Errorf("clear algorithm-roll state: %w", err)
	}
	if err := clearObserveScheduleTx(tx, zone); err != nil {
		return "", fmt.Errorf("clear observe schedule: %w", err)
	}
	if err := setRolloverInProgressTx(tx, zone, false); err != nil {
		return "", fmt.Errorf("clear rollover_in_progress: %w", err)
	}
	if err := setRolloverPhaseTx(tx, zone, rolloverPhaseIdle); err != nil {
		return "", fmt.Errorf("reset phase: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit: %w", err)
	}
	commit = true

	if rerr := republishSigningKeysForZone(kdb, zone); rerr != nil {
		return "", fmt.Errorf("republish signing keys: %w", rerr)
	}
	lgRollover.Warn("rollover: KSK algorithm rollover ABORTED before DS confirmation",
		"zone", zone, "from", dns.AlgorithmToString[algRoll.FromAlg], "to", dns.AlgorithmToString[algRoll.ToAlg],
		"removed_new_head", algRoll.NewHeadKeyID, "kept_old_head", algRoll.OldHeadKeyID)
	triggerResign(conf, zone)

	detail := fmt.Sprintf("aborted the %s -> %s KSK algorithm rollover: removed the %s KSK %d, kept the %s KSK %d active; the zone is idle again",
		dns.AlgorithmToString[algRoll.FromAlg], dns.AlgorithmToString[algRoll.ToAlg],
		dns.AlgorithmToString[algRoll.ToAlg], algRoll.NewHeadKeyID,
		dns.AlgorithmToString[algRoll.FromAlg], algRoll.OldHeadKeyID)
	if row.LastSubmittedHigh.Valid {
		detail += "; a DS push had been sent, so the next tick pushes the DS RRset without the removed key"
	}
	detail += ". The bound policy still names the new algorithm: change policy back, or the engine will start the roll again on its next tick."
	return detail, nil
}
