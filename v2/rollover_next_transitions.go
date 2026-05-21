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
	populateZskNextTransitions(out, kdb, zone, pol, propagationDelay)
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

	// Slot ordering for keys whose DNSKEY is in the served zone —
	// both published (propagation incomplete) and standby (genuine,
	// propagated). AtomicRollover and the published→standby
	// transition both order by published_at, so combining them into
	// one queue gives the renderer the canonical promotion order.
	dnskeyInZoneKids := []uint16{}
	for _, e := range out.KSKs {
		if e.State == DnskeyStatePublished || e.State == DnskeyStateStandby {
			dnskeyInZoneKids = append(dnskeyInZoneKids, e.KeyID)
		}
	}
	sort.SliceStable(dnskeyInZoneKids, func(a, b int) bool {
		ta, _ := RolloverKeyPublishedAt(kdb, zone, dnskeyInZoneKids[a])
		tb, _ := RolloverKeyPublishedAt(kdb, zone, dnskeyInZoneKids[b])
		if ta == nil && tb == nil {
			return dnskeyInZoneKids[a] < dnskeyInZoneKids[b]
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
		return dnskeyInZoneKids[a] < dnskeyInZoneKids[b]
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
			// Post-C18 the engine fires ds-published → published
			// (DNSKEY enters served zone but propagation still in
			// flight). The published → standby transition follows
			// later — see the published case below for that gate.
			e.NextTransition = "ds-published → published"
			if activeAt == nil {
				e.NextTransitionNote = "no active key — bootstrap pending"
				break
			}
			if !dnskeyTTLKnown {
				e.NextTransitionNote = "after first SignZone records DNSKEY TTL"
				break
			}
			// Slot accounting: ds-published keys queue *after* any
			// keys whose DNSKEY is already in the zone (published
			// or genuine-standby). Each of those occupies one of
			// the next promotion slots; the new ds-published
			// promotion joins after them. Match the engine's
			// transitionDsPublishedToPublishedForZone slot
			// calculation so renderer and engine agree.
			pos := slotFromKid(dsPubKids, e.KeyID) // 1-based within ds-published
			if pos == 0 {
				break
			}
			slot := len(dnskeyInZoneKids) + pos
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
			slot := slotFromKid(dnskeyInZoneKids, e.KeyID) // 1-based; 1 = next-up
			if slot == 0 {
				break
			}
			// For slot 1 (the next-up standby), the rollover fires at
			// max(active_at + lifetime, standby_at + standby_time) —
			// the rolloverDue gate. For deeper slots, project natural
			// cadence (active_at + slot*lifetime) and mark as
			// estimated; the standby_time pause for those keys
			// applies to a *future* rollover that hasn't started.
			tActivate := activeAt.Add(time.Duration(slot) * lifetime)
			if slot == 1 {
				if standbyAt, err := RolloverKeyStandbyAt(kdb, zone, e.KeyID); err == nil && standbyAt != nil {
					gated := standbyAt.Add(pol.Rollover.StandbyTime)
					if gated.After(tActivate) {
						tActivate = gated
					}
				}
			}
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
			// active → retired and standby → active fire as a
			// single atomic event (AtomicRollover). The actual
			// fire time is max(active_at + lifetime,
			// projected_standby_at + standby_time) where
			// projected_standby_at is the eventual genuine-standby
			// moment of the next-up key — possibly itself a
			// projection if that key is currently in published or
			// ds-published.
			tRetire := activeAt.Add(lifetime)
			if t, ok := projectedNextUpStandbyAt(out, kdb, zone, pol, lifetime, dnskeyTTLKnown, dnskeyTTL, propagationDelay, now, dnskeyInZoneKids, dsPubKids); ok {
				gated := t.Add(pol.Rollover.StandbyTime)
				if gated.After(tRetire) {
					tRetire = gated
				}
			}
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
			// KSK published → standby fires when both:
			//   T_published + child_prop + DNSKEY_TTL ≤ now
			//   T_ds_observed + parent_prop + DS_TTL ≤ now
			//
			// Pick the later of the two for the "Expected at"
			// column. ZSK keys also use this state but for them the
			// child-side gate is the only one (no DS); the same
			// computation gives the right answer (no T_ds_observed
			// → DS gate evaluates to zero time).
			e.NextTransition = "published → standby"
			ts, ok := parseRFC3339(e.StateSince)
			if !ok {
				e.NextTransitionNote = "awaiting published_at"
				break
			}
			if !dnskeyTTLKnown {
				e.NextTransitionNote = "awaiting DNSKEY TTL observation"
				break
			}
			dnskeyReady := ts.Add(propagationDelay + dnskeyTTL)
			// Parent-side gate. Both DS TTL and a recorded DS
			// observation are required — the transition won't fire
			// until both are present (see
			// transitionPublishedToStandbyForZone).
			zd, ok := Zones.Get(zone)
			if !ok || zd == nil {
				e.NextTransitionNote = "awaiting zone data"
				break
			}
			dsTTL, dsTTLKnown := resolveDSTTL(zd, pol)
			if !dsTTLKnown {
				e.NextTransitionNote = "awaiting DS TTL observation"
				break
			}
			dsObs, err := RolloverKeyDsObservedAt(kdb, zone, e.KeyID)
			if err != nil || dsObs == nil {
				e.NextTransitionNote = "awaiting DS observation at parent"
				break
			}
			dsReady := dsObs.Add(pol.Rollover.DsPublishDelay + dsTTL)
			latest := dnskeyReady
			if dsReady.After(latest) {
				latest = dsReady
			}
			e.NextTransitionAt = latest.UTC().Format(time.RFC3339)
		}
	}

}

// projectedNextUpStandbyAt returns the projected moment when the
// next-up SEP key will reach the genuine standby state. Promotion
// order:
//
//  1. A key already in standby — return its actual standby_at.
//  2. The oldest-published_at key in published — project to
//     max(T_published + child_prop + DNSKEY_TTL,
//     T_ds_observed + parent_prop + DS_TTL).
//  3. The oldest-ds_observed_at key in ds-published — project to
//     now + child_prop + DNSKEY_TTL (engine hasn't moved DNSKEY
//     into zone yet; assume immediate publish for the projection)
//     unioned with the DS-side gate above.
//
// Returns (zero, false) when no candidate exists or the math is
// indeterminate (missing TTL data).
//
// Used by the active→retired projection so that the "next rollover"
// time agrees with the next-up key's actual readiness path. Without
// chaining through these states, the active row could project a time
// earlier than the next-up key can possibly be ready.
func projectedNextUpStandbyAt(out *RolloverStatus, kdb *KeyDB, zone string, pol *DnssecPolicy, lifetime time.Duration, dnskeyTTLKnown bool, dnskeyTTL time.Duration, propagationDelay time.Duration, now time.Time, dnskeyInZoneKids []uint16, dsPubKids []uint16) (time.Time, bool) {
	// 1. Already in genuine standby.
	for _, kid := range dnskeyInZoneKids {
		state := ""
		for _, ke := range out.KSKs {
			if ke.KeyID == kid {
				state = ke.State
				break
			}
		}
		if state != DnskeyStateStandby {
			continue
		}
		if t, err := RolloverKeyStandbyAt(kdb, zone, kid); err == nil && t != nil {
			return *t, true
		}
	}

	// 2. Published — project to max(child-side, parent-side) gate.
	for _, kid := range dnskeyInZoneKids {
		state := ""
		for _, ke := range out.KSKs {
			if ke.KeyID == kid {
				state = ke.State
				break
			}
		}
		if state != DnskeyStatePublished {
			continue
		}
		if !dnskeyTTLKnown {
			return time.Time{}, false
		}
		tPub, err := RolloverKeyPublishedAt(kdb, zone, kid)
		if err != nil || tPub == nil {
			continue
		}
		latest := tPub.Add(propagationDelay + dnskeyTTL)
		if zd, ok := Zones.Get(zone); ok && zd != nil {
			if dsTTL, dsTTLKnown := resolveDSTTL(zd, pol); dsTTLKnown {
				if tDsObs, err := RolloverKeyDsObservedAt(kdb, zone, kid); err == nil && tDsObs != nil {
					dsReady := tDsObs.Add(pol.Rollover.DsPublishDelay + dsTTL)
					if dsReady.After(latest) {
						latest = dsReady
					}
				}
			}
		}
		return latest, true
	}

	// 3. ds-published — project assuming "publish now" plus
	// propagation. This is the operator-override (asap) timeline,
	// not the natural cadence. For the active→retired projection
	// we want the natural cadence, which means: when would the
	// engine *naturally* publish this key? The engine fires
	// ds-published→published at T_publish_i = T_roll_i - child_prop
	// - DNSKEY_TTL where T_roll_i = active_at + slot * lifetime.
	// Then propagation takes another child_prop + DNSKEY_TTL. Net:
	// T_standby = T_roll_i. So the natural-cadence published_at
	// projection collapses to the slot's T_roll.
	if len(dsPubKids) > 0 && dnskeyTTLKnown {
		// dsPubKids[0] is the next-up ds-published key (caller
		// sorted by ds_observed_at). Its slot number includes any
		// published+standby keys ahead of it — but section 1+2
		// above already returned for those, so when we get here
		// dnskeyInZoneKids is empty in steady state. Slot accounting
		// uses len(dnskeyInZoneKids) as the offset to be safe in
		// any transient state.
		activeAt := findActiveAt(out, kdb, zone)
		if activeAt == nil {
			return time.Time{}, false
		}
		offset := len(dnskeyInZoneKids)
		slot := offset + 1
		tRoll := activeAt.Add(time.Duration(slot) * lifetime)
		return tRoll, true
	}

	return time.Time{}, false
}

// findActiveAt is a small helper that returns the active KSK's
// active_at, or nil when no active key exists.
func findActiveAt(out *RolloverStatus, kdb *KeyDB, zone string) *time.Time {
	for _, e := range out.KSKs {
		if e.State != DnskeyStateActive {
			continue
		}
		t, err := RolloverKeyActiveAt(kdb, zone, e.KeyID)
		if err == nil && t != nil {
			return t
		}
		break
	}
	return nil
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

// populateZskNextTransitions fills NextTransition fields on ZSK entries
// for ksk-zsk mode zones with a configured ZSK.Lifetime.
func populateZskNextTransitions(out *RolloverStatus, kdb *KeyDB, zone string, pol *DnssecPolicy, propagationDelay time.Duration) {
	if pol == nil || pol.Mode != DnssecPolicyModeKSKZSK || pol.ZSK.Lifetime == 0 {
		return
	}
	lifetime := time.Duration(pol.ZSK.Lifetime) * time.Second

	var activeAt *time.Time
	for i := range out.ZSKs {
		if out.ZSKs[i].State != DnskeyStateActive {
			continue
		}
		if t, ok := parseRFC3339(out.ZSKs[i].StateSince); ok {
			activeAt = &t
		}
		break
	}

	maxTTL, _ := LoadZoneSigningMaxTTL(kdb, zone)
	removalMargin := zskRemovalMargin(propagationDelay, maxTTL)

	for i := range out.ZSKs {
		e := &out.ZSKs[i]
		switch e.State {
		case DnskeyStateActive:
			if activeAt == nil {
				e.NextTransitionNote = "no active_at — roll timing unknown"
				break
			}
			e.NextTransition = "ZSK roll (standby → active)"
			t := activeAt.Add(lifetime)
			e.NextTransitionAt = t.UTC().Format(time.RFC3339)
		case DnskeyStateStandby:
			if activeAt != nil {
				e.NextTransition = "promote on ZSK roll"
				e.NextTransitionAt = activeAt.Add(lifetime).UTC().Format(time.RFC3339)
			}
		case DnskeyStateRetired:
			if t, ok := parseRFC3339(e.StateSince); ok {
				e.NextTransition = "retired → removed"
				e.NextTransitionAt = t.Add(removalMargin).UTC().Format(time.RFC3339)
			}
		case DnskeyStatePublished:
			e.NextTransition = "published → standby"
			if t, ok := parseRFC3339(e.StateSince); ok {
				e.NextTransitionAt = t.Add(propagationDelay).UTC().Format(time.RFC3339)
			}
		}
	}
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
