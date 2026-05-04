/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"sort"
	"time"
)

// populateNextTransitions fills NextTransition / NextTransitionAt /
// NextTransitionNote on every KSK entry in out.KSKs. Best-effort: a
// missing prerequisite (no active key, no policy, no observation)
// leaves the fields empty for the affected entry, never blocks the
// status response.
//
// The math mirrors transitionDsPublishedToStandbyForZone (W1) and
// transitionRetiredToRemoved: ds-published → standby uses
// T_publish = T_roll - child_prop - DNSKEY_TTL, retired → removed
// uses RetiredAt + effective_margin. standby → active and active →
// retired use T_roll = active_at + slot × KSK.Lifetime.
//
// Multi-standby caveat: only the next-up standby has a "soft-confirmed"
// promotion time (active_at + 1 × Lifetime). Subsequent standbys are
// projected at active_at + (slot+1) × Lifetime; that's the engine's
// current intent and shifts when an asap fires. The renderer is
// guidance, not contract.
func populateNextTransitions(out *RolloverStatus, kdb *KeyDB, zone string, pol *DnssecPolicy, propagationDelay time.Duration, now time.Time) {
	if pol == nil || pol.Rollover.Method == RolloverMethodNone || pol.KSK.Lifetime == 0 {
		return
	}
	lifetime := time.Duration(pol.KSK.Lifetime) * time.Second

	// Anchor: active KSK's active_at. Without it we can't time any
	// of the standby/active/retired transitions.
	var activeAt *time.Time
	for _, e := range out.KSKs {
		if e.State != DnskeyStateActive {
			continue
		}
		t, err := RolloverKeyActiveAt(kdb, zone, e.KeyID)
		if err == nil && t != nil {
			activeAt = t
		}
		break
	}

	// Slot ordering for ds-published keys. confirmDSAndAdvanceCreatedKeysTx
	// stamps the same ds_observed_at on a batch, so tie-break by
	// rollover_index — same comparator as the engine.
	dsPubKids := []uint16{}
	for _, e := range out.KSKs {
		if e.State == DnskeyStateDsPublished {
			dsPubKids = append(dsPubKids, e.KeyID)
		}
	}
	sort.SliceStable(dsPubKids, func(a, b int) bool {
		ta, _ := RolloverKeyDsObservedAt(kdb, zone, dsPubKids[a])
		tb, _ := RolloverKeyDsObservedAt(kdb, zone, dsPubKids[b])
		if ta == nil && tb == nil {
			return dsPubsRolloverIndexLess(kdb, zone, dsPubKids[a], dsPubKids[b])
		}
		if ta == nil {
			return false
		}
		if tb == nil {
			return true
		}
		if !ta.Equal(*tb) {
			return ta.Before(*tb)
		}
		return dsPubsRolloverIndexLess(kdb, zone, dsPubKids[a], dsPubKids[b])
	})

	// Slot ordering for standby keys. AtomicRollover picks oldest
	// standby_at first; renderer mirrors that selection.
	standbyKids := []uint16{}
	for _, e := range out.KSKs {
		if e.State == DnskeyStateStandby {
			standbyKids = append(standbyKids, e.KeyID)
		}
	}
	sort.SliceStable(standbyKids, func(a, b int) bool {
		ta, _ := RolloverKeyStandbyAt(kdb, zone, standbyKids[a])
		tb, _ := RolloverKeyStandbyAt(kdb, zone, standbyKids[b])
		if ta == nil && tb == nil {
			return standbyKids[a] < standbyKids[b]
		}
		if ta == nil {
			return false
		}
		if tb == nil {
			return true
		}
		if !ta.Equal(*tb) {
			return ta.Before(*tb)
		}
		return standbyKids[a] < standbyKids[b]
	})

	// E12 served DNSKEY TTL for the ds-published → standby formula.
	dnskeyTTL, dnskeyTTLKnown := effectiveServedDnskeyTTL(kdb, zone, pol)

	// retirement_period for retired → removed. Mirror
	// effectiveMarginForZone: max(clamping.margin, max_observed_TTL).
	margin := pol.Clamping.Margin
	if maxTTL, err := LoadZoneSigningMaxTTL(kdb, zone); err == nil && maxTTL > 0 {
		obs := time.Duration(maxTTL) * time.Second
		if obs > margin {
			margin = obs
		}
	}

	// Apply per-entry. Mutate in place.
	for i := range out.KSKs {
		e := &out.KSKs[i]
		switch e.State {
		case DnskeyStateCreated:
			e.NextTransition = "created → ds-published"
			e.NextTransitionNote = "after parent observes DS"

		case DnskeyStateDsPublished:
			e.NextTransition = "ds-published → standby"
			if activeAt == nil {
				e.NextTransitionNote = "no active key — bootstrap pending"
				break
			}
			if !dnskeyTTLKnown {
				e.NextTransitionNote = "after first SignZone records DNSKEY TTL"
				break
			}
			// Slot accounting: ds-published keys queue *after* any
			// existing standby keys (each standby occupies one of
			// the next promotion slots). Match the engine's
			// transitionDsPublishedToStandbyForZone slot calculation
			// so renderer and engine agree.
			pos := slotFromKid(dsPubKids, e.KeyID) // 1-based within ds-published
			if pos == 0 {
				break
			}
			slot := len(standbyKids) + pos
			tRoll := activeAt.Add(time.Duration(slot) * lifetime)
			tPublish := tRoll.Add(-(propagationDelay + dnskeyTTL))
			e.NextTransitionAt = tPublish.UTC().Format(time.RFC3339)
			if pos > 1 {
				// ds-published key behind another ds-published key:
				// its T_publish depends on the prior key's promotion
				// completing first. Shifts on asap. Mark as projected.
				e.NextTransitionEstimate = true
			}

		case DnskeyStateStandby:
			e.NextTransition = "standby → active"
			if activeAt == nil {
				e.NextTransitionNote = "no active key — bootstrap pending"
				break
			}
			slot := slotFromKid(standbyKids, e.KeyID) // 1-based; 1 = next-up
			if slot == 0 {
				break
			}
			tActivate := activeAt.Add(time.Duration(slot) * lifetime)
			e.NextTransitionAt = tActivate.UTC().Format(time.RFC3339)
			if slot > 1 {
				// Projected: depends on the next-up standby promoting
				// first. An asap shifts the schedule. Short tag so
				// the column doesn't wrap.
				e.NextTransitionEstimate = true
			}

		case DnskeyStateActive:
			e.NextTransition = "active → retired"
			if activeAt == nil {
				break
			}
			tRetire := activeAt.Add(lifetime)
			e.NextTransitionAt = tRetire.UTC().Format(time.RFC3339)

		case DnskeyStateRetired:
			e.NextTransition = "retired → removed"
			if margin == 0 {
				e.NextTransitionNote = "awaiting effective_margin computation"
				break
			}
			ts, ok := parseRFC3339(e.StateSince)
			if !ok {
				e.NextTransitionNote = "awaiting retired_at"
				break
			}
			e.NextTransitionAt = ts.Add(margin).UTC().Format(time.RFC3339)

		case DnskeyStateRemoved:
			// Terminal. Leave fields empty.

		case DnskeyStatePublished:
			// ZSK lifecycle path; not exercised on KSKs here. The
			// generic transition is published → standby after
			// propagationDelay.
			e.NextTransition = "published → standby"
			if propagationDelay > 0 {
				if ts, ok := parseRFC3339(e.StateSince); ok {
					e.NextTransitionAt = ts.Add(propagationDelay).UTC().Format(time.RFC3339)
				}
			}
		}
	}
}

// slotFromKid returns the 1-based slot index of kid in ordered.
// Returns 0 when kid is not in the slice (defensive).
func slotFromKid(ordered []uint16, kid uint16) int {
	for i, k := range ordered {
		if k == kid {
			return i + 1
		}
	}
	return 0
}

func parseRFC3339(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
