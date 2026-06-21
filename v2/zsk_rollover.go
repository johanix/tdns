/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Automated ZSK rollover: age-based pre-publish roll driven by ZSK.Lifetime.
 */

package tdns

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// zskRollDue reports whether a ZSK roll is due, and whether it was triggered
// manually. A roll is due when either:
//  1. an operator `asap --zsk` request's earliest moment has been reached
//     (manualEarliest, RFC3339; "" when none), OR
//  2. the active ZSK has lived past policy.ZSK.Lifetime (scheduled cadence).
//
// Manual takes precedence and bypasses the lifetime gate (operator override).
func zskRollDue(now time.Time, activeAt *time.Time, lifetimeSec uint32, manualEarliest string) (due bool, manual bool) {
	if s := strings.TrimSpace(manualEarliest); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			if !now.Before(t) {
				return true, true
			}
		} else {
			lgSigner.Warn("zsk rollover: invalid manual_rollover_earliest", "value", manualEarliest, "err", err)
		}
	}
	if lifetimeSec == 0 || activeAt == nil {
		return false, false
	}
	lifetime := time.Duration(lifetimeSec) * time.Second
	return now.Sub(*activeAt) >= lifetime, false
}

// healZskActiveSeqAndActiveAt stamps a missing active_at (and active_seq) on
// the active ZSK, so the lifetime-driven roll becomes decidable
// (zskRollDue reads ActiveAt) and the operator-facing roll counter has a
// value. The ZSK analog of healBootstrapActiveAt (KSK). Simpler: ZSK state
// lives directly in DnssecKeyStore, so this is a direct stamp — no
// RolloverKeyState. First-observation semantics: stamp `now` only when the
// field is currently NULL (never overwrite a real timestamp, or every
// restart would push the roll forward).
func healZskActiveAt(kdb *KeyDB, zone string, activeZSK *DnssecKeyWithTimestamps) {
	if activeZSK == nil {
		return
	}
	needAt := activeZSK.ActiveAt == nil
	needSeq := activeZSK.ActiveSeq == nil
	if !needAt && !needSeq {
		return
	}
	tx, err := kdb.Begin("healZskActiveAt")
	if err != nil {
		lgSigner.Warn("zsk rollover: heal begin tx failed", "zone", zone, "keyid", activeZSK.KeyTag, "err", err)
		return
	}
	commit := false
	defer func() {
		if commit {
			tx.Commit()
		} else {
			tx.Rollback()
		}
	}()
	if needAt {
		now := time.Now().UTC().Format(time.RFC3339)
		if _, err := tx.Exec(`UPDATE DnssecKeyStore SET active_at=? WHERE zonename=? AND keyid=? AND (active_at IS NULL OR active_at='')`,
			now, zone, int(activeZSK.KeyTag)); err != nil {
			lgSigner.Warn("zsk rollover: heal active_at failed", "zone", zone, "keyid", activeZSK.KeyTag, "err", err)
			return
		}
	}
	if needSeq {
		seq, serr := nextZskActiveSeqTx(tx, zone)
		if serr != nil {
			lgSigner.Warn("zsk rollover: heal active_seq compute failed", "zone", zone, "keyid", activeZSK.KeyTag, "err", serr)
			return
		}
		if _, err := tx.Exec(`UPDATE DnssecKeyStore SET active_seq=? WHERE zonename=? AND keyid=? AND active_seq IS NULL`,
			seq, zone, int(activeZSK.KeyTag)); err != nil {
			lgSigner.Warn("zsk rollover: heal active_seq failed", "zone", zone, "keyid", activeZSK.KeyTag, "err", err)
			return
		}
	}
	commit = true
	lgSigner.Info("zsk rollover: healed active ZSK state", "zone", zone, "keyid", activeZSK.KeyTag,
		"healed_active_at", needAt, "healed_active_seq", needSeq)
}

// nextZskActiveSeqTx returns the next ZSK active_seq for a zone:
// MAX(active_seq)+1 over the zone's ZSK rows (flags=256) in DnssecKeyStore,
// or 0 if no ZSK has ever been active. This is the operator-facing
// "n-th active ZSK in this zone's history" counter — the ZSK analog of
// the KSK active_seq in RolloverKeyState, but sourced from DnssecKeyStore
// since ZSK rollover keeps no RolloverKeyState rows.
//
// Purge semantics: MAX+1 survives normal purges (retired→removed and
// policy-cleanup delete the OLDEST, lowest-seq keys, never the newest, so
// MAX stays held by the most-recent key). It resets only when ALL ZSK rows
// are deleted (`clear`), which is the intended "wipe and start over."
func nextZskActiveSeqTx(tx *Tx, zone string) (int, error) {
	var max sql.NullInt64
	// flags=256 = real ZSK (ZONE bit set, SEP clear), matching how the rest
	// of zsk_rollover.go identifies ZSKs. KSK/CSK (flags=257) are excluded,
	// so the ZSK and KSK active_seq counters are independent.
	err := tx.QueryRow(
		`SELECT MAX(active_seq) FROM DnssecKeyStore WHERE zonename=? AND CAST(flags AS INTEGER)=256`,
		zone).Scan(&max)
	if err != nil {
		return 0, err
	}
	if !max.Valid {
		return 0, nil
	}
	return int(max.Int64) + 1, nil
}

// setZskActiveSeqTx stamps active_seq for one ZSK on an existing TX.
func setZskActiveSeqTx(tx *Tx, zone string, keyid uint16, seq int) error {
	_, err := tx.Exec(`UPDATE DnssecKeyStore SET active_seq=? WHERE zonename=? AND keyid=?`,
		seq, zone, int(keyid))
	return err
}

// ZskManualRollover holds the per-zone manual ZSK-rollover request read
// from ZskRolloverState. Earliest is "" when no request is pending.
type ZskManualRollover struct {
	RequestedAt string
	Earliest    string
}

// EnsureZskRolloverRow creates the per-zone ZskRolloverState row if absent.
func EnsureZskRolloverRow(kdb *KeyDB, zone string) error {
	zone = strings.TrimSpace(zone)
	if zone == "" {
		return fmt.Errorf("EnsureZskRolloverRow: empty zone")
	}
	_, err := kdb.DB.Exec(
		`INSERT INTO ZskRolloverState (zone) VALUES (?) ON CONFLICT(zone) DO NOTHING`, zone)
	return err
}

// SetZskManualRolloverRequest stamps a manual ZSK-rollover request. Mirrors
// the KSK SetManualRolloverRequest, on ZskRolloverState.
func SetZskManualRolloverRequest(kdb *KeyDB, zone string, requestedAt, earliest time.Time) error {
	if err := EnsureZskRolloverRow(kdb, zone); err != nil {
		return err
	}
	_, err := kdb.DB.Exec(`UPDATE ZskRolloverState
SET manual_rollover_requested_at = ?,
    manual_rollover_earliest = ?
WHERE zone = ?`,
		requestedAt.UTC().Format(time.RFC3339),
		earliest.UTC().Format(time.RFC3339),
		zone)
	return err
}

// ClearZskManualRolloverRequest nulls the manual-request columns. Called by
// `cancel --zsk` and after a manual ZSK roll commits.
func ClearZskManualRolloverRequest(kdb *KeyDB, zone string) error {
	_, err := kdb.DB.Exec(`UPDATE ZskRolloverState
SET manual_rollover_requested_at = NULL,
    manual_rollover_earliest = NULL
WHERE zone = ?`, zone)
	return err
}

// LoadZskManualRollover returns the pending manual ZSK-rollover request for a
// zone (zero value when none / no row).
func LoadZskManualRollover(kdb *KeyDB, zone string) (ZskManualRollover, error) {
	zone = strings.TrimSpace(zone)
	var requestedAt, earliest sql.NullString
	err := kdb.DB.QueryRow(
		`SELECT manual_rollover_requested_at, manual_rollover_earliest FROM ZskRolloverState WHERE zone = ?`,
		zone).Scan(&requestedAt, &earliest)
	if err == sql.ErrNoRows {
		return ZskManualRollover{}, nil
	}
	if err != nil {
		return ZskManualRollover{}, err
	}
	out := ZskManualRollover{}
	if requestedAt.Valid {
		out.RequestedAt = requestedAt.String
	}
	if earliest.Valid {
		out.Earliest = earliest.String
	}
	return out, nil
}

// ZskAlgRollState describes an in-flight relaxed-mode ZSK algorithm rollover.
// FromAlg is an old algorithm still present in the pipeline; ToAlg is the
// target (effective-policy) ZSK algorithm. Done/Total give a coarse progress
// count for the operator (promotions of target-alg keys / total live ZSK
// pipeline members of any algorithm).
type ZskAlgRollState struct {
	InFlight bool
	FromAlg  uint8
	ToAlg    uint8
	Done     int
	Total    int
}

// zskAlgRollInFlight reports whether a ZSK algorithm rollover toward targetZSKAlg
// is in flight for a zone, using the FULLER drain-window predicate (the spec's
// re-entrancy / status notion of "in progress", §8.3): a ZSK of an algorithm
// other than targetZSKAlg present in any of standby / active / retired. This is
// stricter than "active ZSK alg ≠ policy alg" (D4) — it stays true through the
// drain window, after the new-alg key has been promoted to active while an
// old-alg ZSK is still retired/draining. Both the change-policy re-entrancy
// guard and the status display derive "in flight" from this one function.
func zskAlgRollInFlight(kdb *KeyDB, zone string, targetZSKAlg uint8) (ZskAlgRollState, error) {
	zone = dns.Fqdn(zone)
	var out ZskAlgRollState
	var fromAlg uint8
	for _, state := range []string{DnskeyStateStandby, DnskeyStateActive, DnskeyStateRetired} {
		keys, err := GetDnssecKeysByState(kdb, zone, state)
		if err != nil {
			return out, fmt.Errorf("zskAlgRollInFlight: list %s keys for zone %s: %w", state, zone, err)
		}
		for _, k := range keys {
			if k.Flags != 256 {
				continue
			}
			out.Total++
			if k.Algorithm == targetZSKAlg {
				out.Done++
			} else {
				out.InFlight = true
				if fromAlg == 0 {
					fromAlg = k.Algorithm
				}
			}
		}
	}
	if out.InFlight {
		out.FromAlg = fromAlg
		out.ToAlg = targetZSKAlg
	}
	return out, nil
}

// zskRemovalMargin is the hold time before a retired ZSK may be removed:
// propagationDelay + max observed signing TTL (sum, not max).
func zskRemovalMargin(propagationDelay time.Duration, maxObservedTTL uint32) time.Duration {
	margin := propagationDelay
	if maxObservedTTL > 0 {
		margin += time.Duration(maxObservedTTL) * time.Second
	}
	return margin
}

// rolloverZsksForAllZones runs automated ZSK rollover for every eligible zone.
// Invoked from KeyStateWorker after published→standby and before retired→removed.
func rolloverZsksForAllZones(ctx context.Context, conf *Config, kdb *KeyDB, propagationDelay time.Duration, now time.Time) {
	for _, zd := range Zones.Items() {
		if ctx.Err() != nil {
			return
		}
		if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
			continue
		}
		if zd.Options[OptMultiProvider] {
			continue
		}
		pol := zd.DnssecPolicy
		if pol == nil || pol.Mode != DnssecPolicyModeKSKZSK || pol.ZSK.Lifetime == 0 {
			continue
		}
		if err := rolloverZskForZone(ctx, conf, kdb, zd, propagationDelay, now); err != nil {
			lgSigner.Error("zsk rollover: tick error", "zone", zd.ZoneName, "err", err)
		}
	}
}

func rolloverZskForZone(ctx context.Context, conf *Config, kdb *KeyDB, zd *ZoneData, propagationDelay time.Duration, now time.Time) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	pol := zd.DnssecPolicy
	zone := dns.Fqdn(zd.ZoneName)

	release, err := defaultAcquireRolloverLock(zone)
	if err != nil {
		lgSigner.Debug("zsk rollover: lock acquisition skipped", "zone", zone, "err", err)
		return nil
	}
	defer release()

	activeKeys, err := GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
	if err != nil {
		return fmt.Errorf("list active keys: %w", err)
	}
	var activeZSK *DnssecKeyWithTimestamps
	for i := range activeKeys {
		if activeKeys[i].Flags == 256 {
			activeZSK = &activeKeys[i]
			break
		}
	}
	if activeZSK == nil {
		return nil
	}

	// Self-heal a missing active_at / active_seq so the roll is decidable
	// and the operator-facing counter has a value. Re-read the active ZSK
	// afterward if anything was stamped.
	if activeZSK.ActiveAt == nil || activeZSK.ActiveSeq == nil {
		healZskActiveAt(kdb, zone, activeZSK)
		delete(kdb.KeystoreDnskeyCache, zone+"+"+DnskeyStateActive)
		activeKeys, err = GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
		if err != nil {
			return fmt.Errorf("re-list active keys after heal: %w", err)
		}
		activeZSK = nil
		for i := range activeKeys {
			if activeKeys[i].Flags == 256 {
				activeZSK = &activeKeys[i]
				break
			}
		}
		if activeZSK == nil {
			return nil
		}
	}

	manual, err := LoadZskManualRollover(kdb, zone)
	if err != nil {
		return fmt.Errorf("load manual zsk request: %w", err)
	}

	due, isManual := zskRollDue(now, activeZSK.ActiveAt, pol.ZSK.Lifetime, manual.Earliest)
	if !due {
		return nil
	}

	standbyKeys, err := GetDnssecKeysByState(kdb, zone, DnskeyStateStandby)
	if err != nil {
		return fmt.Errorf("list standby keys: %w", err)
	}
	haveStandby := false
	for i := range standbyKeys {
		if standbyKeys[i].Flags == 256 {
			haveStandby = true
			break
		}
	}
	if !haveStandby {
		// Roll is due but no standby yet. Do NOT clear a manual request
		// here — it must persist until the roll actually commits, so the
		// trigger fires when a standby appears (e.g. a fresh key still
		// propagating). Just wait for the next tick.
		lgSigner.Warn("zsk rollover: roll due but no standby ZSK available", "zone", zone, "active_keyid", activeZSK.KeyTag, "manual", isManual)
		return nil
	}

	oldActive, newActive, err := kdb.RolloverKey(zone, "ZSK", nil)
	if err != nil {
		return fmt.Errorf("RolloverKey: %w", err)
	}
	// Clear the manual request only after the roll has committed (mirrors
	// the KSK path: clear on fire, not on the no-standby no-op above).
	if isManual {
		if cerr := ClearZskManualRolloverRequest(kdb, zone); cerr != nil {
			lgSigner.Warn("zsk rollover: clear manual request failed", "zone", zone, "err", cerr)
		}
	}
	lgSigner.Info("zsk rollover: completed", "zone", zone, "old_active", oldActive, "new_active", newActive, "manual", isManual)
	triggerResign(conf, zd.ZoneName)
	return nil
}
