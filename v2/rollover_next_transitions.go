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
			// standby_at + standby_time) — same gate as the
			// rolloverDue check. Without taking standby_time into
			// account, the renderer shows a "(N ago)" projection
			// that confuses operators when the natural T_roll has
			// passed but the engine is still waiting on the pause.
			tRetire := activeAt.Add(lifetime)
			// Find the next-up genuine standby key (mirrors
			// pickEarliestStandbySEP — state=standby, oldest
			// published_at first).
			for _, kid := range dnskeyInZoneKids {
				inStandby := false
				for _, ke := range out.KSKs {
					if ke.KeyID == kid && ke.State == DnskeyStateStandby {
						inStandby = true
						break
					}
				}
				if !inStandby {
					continue
				}
				if standbyAt, err := RolloverKeyStandbyAt(kdb, zone, kid); err == nil && standbyAt != nil {
					gated := standbyAt.Add(pol.Rollover.StandbyTime)
					if gated.After(tRetire) {
						tRetire = gated
					}
				}
				break
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
			var dnskeyReady time.Time
			if dnskeyTTLKnown {
				dnskeyReady = ts.Add(propagationDelay + dnskeyTTL)
			} else {
				dnskeyReady = ts.Add(propagationDelay)
			}
			latest := dnskeyReady
			if zd, ok := Zones.Get(zone); ok && zd != nil {
				if dsTTL, dsTTLKnown := resolveDSTTL(zd, pol); dsTTLKnown {
					if dsObs, err := RolloverKeyDsObservedAt(kdb, zone, e.KeyID); err == nil && dsObs != nil {
						dsReady := dsObs.Add(pol.Rollover.DsPublishDelay + dsTTL)
						if dsReady.After(latest) {
							latest = dsReady
						}
					}
				}
			}
			e.NextTransitionAt = latest.UTC().Format(time.RFC3339)
		}
	}

	// Synthetic "future key" row: a visual cue that the engine will
	// generate one more KSK on the next pipeline-fill tick. Inserted
	// at the front of the KSK list (sorted top = latest-to-roll).
	// Has IsSynthetic=true so the renderer can distinguish it from
	// real keystore entries (renders the keyid as "-----" rather
	// than a number).
	//
	// Conditions:
	//   - rollover.method = multi-ds (only multi-DS pipeline-fills
	//     to a target N; double-signature has no continuous fill).
	//   - active key present (otherwise we have no anchor).
	//   - count of in-pipeline SEP keys ≥ NumDS (we're at parent's
	//     desired set; the next thing the engine does is generate
	//     for the cycle after this one).
	//
	// The expected_at timestamp is when the engine will notice the
	// pipeline is short and generate. That happens immediately after
	// the next rollover fires (current standby promotes to active,
	// pipeline depth drops by one). So expected_at = T_roll of the
	// current active key.
	if pol.Rollover.Method == RolloverMethodMultiDS && activeAt != nil && pol.Rollover.NumDS > 0 {
		inPipeline := 0
		for _, e := range out.KSKs {
			switch e.State {
			case DnskeyStateCreated, DnskeyStateDsPublished, DnskeyStateStandby,
				DnskeyStatePublished, DnskeyStateActive, DnskeyStateRetired:
				inPipeline++
			}
		}
		if inPipeline >= pol.Rollover.NumDS {
			tNext := activeAt.Add(lifetime)
			out.KSKs = append([]RolloverKeyEntry{
				{
					KeyID:                  0, // sentinel for "synthetic"
					IsSynthetic:            true,
					State:                  "-",
					Published:              "none",
					NextTransition:         "→ created",
					NextTransitionAt:       tNext.UTC().Format(time.RFC3339),
					NextTransitionEstimate: true,
				},
			}, out.KSKs...)
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
