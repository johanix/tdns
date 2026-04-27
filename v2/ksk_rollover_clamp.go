package tdns

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// ClampParams carries the current TTL-clamp inputs into SignRRset. A non-nil
// value means at least one clamp is active for this sign pass:
//
//   - K-step rollover clamp (K, Margin, TRoll): active near a scheduled
//     rollover; ceiling = K * Margin.
//   - Steady-state TTL ceiling (MaxServedTTL): always-on cap from policy
//     ttls.max_served; ceiling = MaxServedTTL.
//
// SignRRset takes the minimum of (UnclampedTTL, K*Margin if K>0,
// MaxServedTTL if >0) and writes that to every RR header TTL before
// generating the RRSIG.
//
// nil means no clamp at all (zone has clamping.enabled: false AND no
// max_served set AND no rollover scheduled).
type ClampParams struct {
	K            int
	Margin       time.Duration
	TRoll        time.Time // for the validity invariant check
	MaxServedTTL uint32    // 0 = no steady-state ceiling
}

// CeilingTTL returns the K * margin ceiling in seconds.
func (c *ClampParams) CeilingTTL() uint32 {
	if c == nil || c.K <= 0 || c.Margin <= 0 {
		return 0
	}
	secs := int64(c.Margin.Seconds()) * int64(c.K)
	if secs < 0 {
		return 0
	}
	if secs > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(secs)
}

// tNextRoll returns the time of the next scheduled KSK rollover for the
// zone. Returns ok=false when clamping should be inactive (no policy, no
// active KSK, mid-rollover, or KSK.Lifetime == 0).
//
// Same source-of-truth as rolloverDue and ComputeEarliestRollover.
func tNextRoll(kdb *KeyDB, zone string, pol *DnssecPolicy) (time.Time, bool, error) {
	if pol == nil || pol.Rollover.Method == RolloverMethodNone {
		return time.Time{}, false, nil
	}
	row, err := LoadRolloverZoneRow(kdb, zone)
	if err != nil {
		return time.Time{}, false, err
	}
	if row != nil && row.RolloverInProgress {
		// Mid-rollover: clamp inactive.
		return time.Time{}, false, nil
	}

	// Manual-ASAP takes precedence (operator action honored).
	if row != nil && row.ManualRolloverEarliest.Valid {
		s := strings.TrimSpace(row.ManualRolloverEarliest.String)
		if s != "" {
			if t, e := time.Parse(time.RFC3339, s); e == nil {
				return t, true, nil
			}
		}
	}

	// Scheduled.
	if pol.KSK.Lifetime == 0 {
		return time.Time{}, false, nil
	}
	active, err := GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
	if err != nil {
		return time.Time{}, false, err
	}
	var activeKid uint16
	for i := range active {
		if active[i].Flags&dns.SEP != 0 {
			activeKid = active[i].KeyTag
			break
		}
	}
	if activeKid == 0 {
		return time.Time{}, false, nil
	}
	at, err := RolloverKeyActiveAt(kdb, zone, activeKid)
	if err != nil {
		return time.Time{}, false, err
	}
	if at == nil {
		return time.Time{}, false, nil
	}
	return at.Add(time.Duration(pol.KSK.Lifetime) * time.Second), true, nil
}

// kMaxForPolicy returns K_max = ksk.lifetime / margin. Returns 0 when
// clamping is disabled or inputs are invalid.
func kMaxForPolicy(pol *DnssecPolicy) int {
	if pol == nil || !pol.Clamping.Enabled {
		return 0
	}
	margin := pol.Clamping.Margin
	if margin <= 0 || pol.KSK.Lifetime == 0 {
		return 0
	}
	lifetime := time.Duration(pol.KSK.Lifetime) * time.Second
	k := int(lifetime / margin)
	if k < 1 {
		return 1
	}
	return k
}

// currentClampK returns the K value for the zone at `now`. Returns 0 to
// signal "clamp inactive". K ∈ [1, K_max] otherwise.
func currentClampK(pol *DnssecPolicy, tRoll, now time.Time) int {
	kMax := kMaxForPolicy(pol)
	if kMax < 1 {
		return 0
	}
	margin := pol.Clamping.Margin

	r := tRoll.Sub(now)
	if r <= 0 {
		// Past T_roll without the rollover firing yet (between
		// rolloverDue=true and the next AtomicRollover): K_max. The next
		// AtomicRollover advances T_roll.
		return kMax
	}
	if r >= time.Duration(kMax)*margin {
		return kMax
	}
	// R ∈ [(k−1)·margin, k·margin) → K = k. Floor of (R / margin) + 1.
	k := int(r/margin) + 1
	if k < 1 {
		k = 1
	}
	if k > kMax {
		k = kMax
	}
	return k
}

// ClampParamsForZone builds a *ClampParams for the zone at `now`, or nil
// if no clamp is active (neither rollover K-step nor steady-state max_served).
// Called by SignZone before each sign pass on a clamping zone.
func ClampParamsForZone(kdb *KeyDB, zone string, pol *DnssecPolicy, now time.Time) (*ClampParams, error) {
	if pol == nil {
		return nil, nil
	}
	maxServed := pol.TTLS.MaxServed

	// No K-step clamp by default. Only set if rollover machinery is
	// active for this zone.
	var k int
	var margin time.Duration
	var tRoll time.Time
	if pol.Clamping.Enabled && pol.Clamping.Margin > 0 {
		t, ok, err := tNextRoll(kdb, zone, pol)
		if err != nil {
			return nil, err
		}
		if ok {
			kk := currentClampK(pol, t, now)
			if kk > 0 {
				k = kk
				margin = pol.Clamping.Margin
				tRoll = t
			}
		}
	}

	// If neither clamp source is active, return nil so SignRRset takes
	// the no-op fast path.
	if k <= 0 && maxServed == 0 {
		return nil, nil
	}
	return &ClampParams{
		K:            k,
		Margin:       margin,
		TRoll:        tRoll,
		MaxServedTTL: maxServed,
	}, nil
}

// clampLastK persists the last-observed K per zone in memory. Used by the
// K-step scheduler to detect step boundaries (current K decreased since
// last tick) and trigger SOA bumps. Restart re-derives from tNextRoll on
// first observation; the first observation does not bump SOA (we don't
// know if it's steady-state K_max or a re-start mid-clamp).
var clampLastK sync.Map // map[zone]int

func loadLastK(zone string) (int, bool) {
	v, ok := clampLastK.Load(zone)
	if !ok {
		return 0, false
	}
	k, ok := v.(int)
	return k, ok
}

func storeLastK(zone string, k int) {
	clampLastK.Store(zone, k)
}

// kStepScheduler is invoked from RolloverAutomatedTick on every clamping
// zone. It detects K-step boundaries (current K decreased since last
// observed) and bumps the SOA serial to trigger AXFR. Returns true if a
// SOA bump was performed.
func kStepScheduler(zd *ZoneData, kdb *KeyDB, pol *DnssecPolicy, now time.Time) bool {
	if zd == nil || pol == nil || !pol.Clamping.Enabled {
		return false
	}
	tRoll, ok, err := tNextRoll(kdb, zd.ZoneName, pol)
	if err != nil {
		lgSigner.Warn("clamp: tNextRoll failed", "zone", zd.ZoneName, "err", err)
		return false
	}
	if !ok {
		// No clamp active; reset memory so the first step after the next
		// rollover schedule is detected freshly.
		clampLastK.Delete(zd.ZoneName)
		return false
	}
	k := currentClampK(pol, tRoll, now)
	if k <= 0 {
		return false
	}
	prev, hadPrev := loadLastK(zd.ZoneName)
	if !hadPrev {
		storeLastK(zd.ZoneName, k)
		lgSigner.Info("clamp: K-step initial observation",
			"zone", zd.ZoneName, "K", k, "T_roll", tRoll.Format(time.RFC3339))
		return false
	}
	if k >= prev {
		// K rose (post-rollover reset to K_max) or unchanged. Reset
		// memory; no SOA bump needed (rollover itself already triggered
		// re-sign in AtomicRollover).
		storeLastK(zd.ZoneName, k)
		return false
	}
	// k < prev: crossed at least one step boundary.
	storeLastK(zd.ZoneName, k)
	atomic.AddUint64(&clampStepCounter, 1)
	lgSigner.Info("clamp: K-step",
		"zone", zd.ZoneName, "K_old", prev, "K_new", k,
		"T_roll", tRoll.Format(time.RFC3339))
	if _, err := zd.BumpSerial(); err != nil {
		lgSigner.Warn("clamp: SOA bump failed", "zone", zd.ZoneName, "err", err)
		return false
	}
	return true
}

// Telemetry counters.
var (
	clampStepCounter        uint64 // total K-step boundaries observed
	clampDecisionsClamped   uint64 // SignRRset calls where TTL was lowered
	clampDecisionsUnclamped uint64 // SignRRset calls with clamp == nil or no-op
	clampValidityViolations uint64 // RRSIG validity < R + margin at sign time
)

// ClampMetrics returns a snapshot of the clamp telemetry counters.
func ClampMetrics() (steps, clamped, unclamped, violations uint64) {
	return atomic.LoadUint64(&clampStepCounter),
		atomic.LoadUint64(&clampDecisionsClamped),
		atomic.LoadUint64(&clampDecisionsUnclamped),
		atomic.LoadUint64(&clampValidityViolations)
}

// applyClampToRRset is called from SignRRset before generating the RRSIG
// when clamp != nil. Captures UnclampedTTL on first encounter, then
// rewrites every RR header TTL to:
//
//	min(UnclampedTTL, K*margin if K>0, MaxServedTTL if >0)
//
// The K*margin source is the rollover-time K-step clamp; the MaxServedTTL
// source is the steady-state policy ttls.max_served ceiling. Either, both,
// or neither may be in effect.
func applyClampToRRset(rrset *core.RRset, clamp *ClampParams) {
	if clamp == nil || len(rrset.RRs) == 0 {
		atomic.AddUint64(&clampDecisionsUnclamped, 1)
		return
	}

	// Compute the effective ceiling from whichever clamp sources are active.
	var ceiling uint32 = ^uint32(0) // "no ceiling" sentinel
	if c := clamp.CeilingTTL(); c > 0 && c < ceiling {
		ceiling = c
	}
	if clamp.MaxServedTTL > 0 && clamp.MaxServedTTL < ceiling {
		ceiling = clamp.MaxServedTTL
	}
	if ceiling == ^uint32(0) {
		atomic.AddUint64(&clampDecisionsUnclamped, 1)
		return
	}

	if rrset.UnclampedTTL == 0 {
		rrset.UnclampedTTL = rrset.RRs[0].Header().Ttl
	}
	target := rrset.UnclampedTTL
	if ceiling < target {
		target = ceiling
	}
	changed := false
	for i := range rrset.RRs {
		if rrset.RRs[i].Header().Ttl != target {
			rrset.RRs[i].Header().Ttl = target
			changed = true
		}
	}
	if changed {
		atomic.AddUint64(&clampDecisionsClamped, 1)
	} else {
		atomic.AddUint64(&clampDecisionsUnclamped, 1)
	}
}

// checkValidityInvariant logs a warning if RRSIG validity is shorter than
// R + margin (signatures would expire mid-rollover). Warn-only; doesn't
// refuse to sign. The signer uses operator-configured SigValidity which
// clamping does not modify — this is a "your config is unsafe" advisory.
func checkValidityInvariant(zone string, rrsig *dns.RRSIG, clamp *ClampParams, now time.Time) {
	if clamp == nil || clamp.TRoll.IsZero() {
		return
	}
	r := clamp.TRoll.Sub(now)
	if r < 0 {
		r = 0
	}
	required := r + clamp.Margin
	expiration := time.Unix(int64(rrsig.Expiration), 0)
	validity := time.Until(expiration)
	if validity < required {
		atomic.AddUint64(&clampValidityViolations, 1)
		lgSigner.Warn("clamp invariant: RRSIG validity below R+margin",
			"zone", zone, "keyid", rrsig.KeyTag,
			"validity", validity.Truncate(time.Second),
			"required", required.Truncate(time.Second))
	}
}
