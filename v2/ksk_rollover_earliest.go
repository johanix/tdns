package tdns

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// EarliestRolloverGate names a constraint that contributed to t_earliest.
// One of: "now", "max-ttl-expiry", "ds-ready".
type EarliestRolloverGate struct {
	Name string
	At   time.Time
}

// EarliestRolloverStatus distinguishes the two operationally distinct
// "rollover not yet" cases plus the ready and policy-blocked states:
//
//   - Ready: rollover can be queued at Earliest (Case 2 cache-flush
//     wait already factored in). asap honors the operator override
//     and queues; CLI shows the gate list.
//   - WaitingForParent (Case 1): no usable standby SEP key — DS for
//     the next key isn't observed at the parent yet, so promotion
//     can't happen at any time. Engine cannot satisfy asap;
//     refuse with the blocker diagnostic.
//   - PolicyBlocked: zone has an auto-rollover-impacting error
//     (E5/E10 violation or RolloverParentBlocker); engine
//     intentionally suspended.
type EarliestRolloverStatus int

const (
	EarliestStatusReady EarliestRolloverStatus = iota
	EarliestStatusWaitingForParent
	EarliestStatusPolicyBlocked
)

// EarliestRolloverBlocker explains why Earliest is unavailable when
// status != Ready. KeyID is the active key the engine wants to roll
// FROM (when meaningful); ToHint identifies the next-up key target
// (or 0 when no candidate exists). Detail is human-readable.
type EarliestRolloverBlocker struct {
	Reason string // e.g. "no standby SEP key in pipeline"
	Cause  string // sub-cause from RolloverZoneRow (last_softfail_*, etc.)
	KeyID  uint16 // active key (0 when not meaningful)
	Detail string // free-form additional info
}

// EarliestRolloverResult is the output of ComputeEarliestRollover.
// FromKID/ToKID identify the active SEP KSK and its scheduled standby
// successor by keyid; FromIdx/ToIdx are the corresponding rollover_index
// values, retained for callers that persist scheduling state under that
// identifier.
type EarliestRolloverResult struct {
	Earliest time.Time
	FromKID  uint16
	ToKID    uint16
	FromIdx  int
	ToIdx    int
	Gates    []EarliestRolloverGate
	Status   EarliestRolloverStatus
	Blocker  *EarliestRolloverBlocker
}

// ComputeEarliestRollover returns the earliest moment a rollover can safely
// fire for the zone, the active KSK and its scheduled successor, and the
// constraints that produced the result. Side-effect free.
//
//	t_earliest = max(now, max_ttl_expiry, ds_ready_at)
//
// where:
//   - max_ttl_expiry = now + max_published_ttl_in_zone(z) - margin
//   - ds_ready_at = 0 if next_ksk is in standby, else
//     next_ksk.ds_observed_at + ds_ttl + margin
//
// Returns an error if a rollover cannot be scheduled (no active KSK, or
// no standby SEP key). Does NOT refuse based on RolloverInProgress:
// callers that need to gate on that (e.g. APIRolloverAsap) must check
// separately. ComputeRolloverWhen handles the in-progress case via
// projection rather than refusal so the operator can still see when the
// next rollover after the current one is scheduled.
//
// Why no max-rrsig-validity gate: the operationally-relevant cache-flush
// bound for "all validators have fresh DNSKEY state" is min(TTL,
// remaining-RRSIG-validity), which is bounded above by TTL whenever
// TTL <= SigValidity (the typical regime — zones publish TTLs of hours
// while SigValidity is days to weeks). Adding RRSIG validity as an
// independent gate is therefore over-conservative; the TTL gate alone
// is the right bound. If the unusual TTL > SigValidity regime ever
// becomes operationally relevant, tracking observed RRSIG signing time
// (currently absent — only max_observed_ttl is tracked) will let us
// compute the tighter "remaining-validity" bound. Until then, the
// design assumes TTL <= SigValidity.
//
// ds_ready_at uses next_ksk's standby state as the "ready now" signal.
// The non-standby branch is exercised by manual-ASAP only when the
// pipeline isn't fully primed yet, which the gate set will surface.
func ComputeEarliestRollover(kdb *KeyDB, zone string, pol *DnssecPolicy, now time.Time) (*EarliestRolloverResult, error) {
	zone = dns.Fqdn(strings.TrimSpace(zone))
	if zone == "" {
		return nil, fmt.Errorf("ComputeEarliestRollover: empty zone")
	}
	if pol == nil {
		return nil, fmt.Errorf("ComputeEarliestRollover: nil policy")
	}
	if pol.Rollover.Method == RolloverMethodNone {
		return nil, fmt.Errorf("zone %s: rollover method is none", zone)
	}

	// Policy-blocked first: caller wants the engine status BEFORE the
	// "is the pipeline ready" question, since policy errors mean we
	// shouldn't be rolling at all. ComputeEarliestRollover is read-only;
	// the engine's rollover ticks have their own gate
	// (HasAutoRolloverImpactingError early-return).
	if zd, ok := Zones.Get(zone); ok && zd != nil && zd.HasAutoRolloverImpactingError() {
		var blocker EarliestRolloverBlocker
		var msgs []string
		hasParentBlocker := false
		hasPolicyViolation := false
		for _, e := range zd.ErrorList() {
			if !isAutoRolloverImpactingError(e.Type) {
				continue
			}
			msgs = append(msgs, e.Msg)
			switch e.Type {
			case RolloverParentBlocker:
				hasParentBlocker = true
			case RolloverPolicyViolation:
				hasPolicyViolation = true
			}
		}
		switch {
		case hasParentBlocker && hasPolicyViolation:
			blocker.Reason = "automated rollover suspended by parent blocker and policy violation"
		case hasParentBlocker:
			blocker.Reason = "automated rollover suspended by parent blocker"
		default:
			blocker.Reason = "automated rollover suspended by policy violation"
		}
		blocker.Detail = strings.Join(msgs, "; ")
		return &EarliestRolloverResult{
			Status:  EarliestStatusPolicyBlocked,
			Blocker: &blocker,
		}, nil
	}

	// Active SEP KSK.
	active, err := GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
	if err != nil {
		return nil, fmt.Errorf("list active keys: %w", err)
	}
	var fromKid uint16
	for i := range active {
		if active[i].Flags&dns.SEP != 0 {
			fromKid = active[i].KeyTag
			break
		}
	}
	if fromKid == 0 {
		return nil, fmt.Errorf("zone %s: no active SEP key", zone)
	}
	fromIdx, _, err := RolloverIndexForKey(kdb, zone, fromKid)
	if err != nil {
		return nil, fmt.Errorf("rollover_index for active keyid %d: %w", fromKid, err)
	}

	// Pick the next-up key across all "DNSKEY material exists" states:
	// standby (genuinely ready), published (DNSKEY in zone, propagation
	// in flight), ds-published (DS at parent, DNSKEY not in zone yet).
	// Search in promote-order — standby first, then published, then
	// ds-published. The chosen key plus its "earliest moment ready"
	// drives the rollover schedule.
	toKid, toState, toIdx, err := pickNextUpKeyWithState(kdb, zone)
	if err != nil {
		return nil, fmt.Errorf("pick next-up key: %w", err)
	}
	if toKid == 0 {
		// No suitable key exists in any pre-active state. This is
		// the rare "engine has no pipeline yet" case — bootstrap
		// failure or empty zone. Surface as waiting-for-parent so
		// the operator sees structured diagnostics.
		blocker := diagnoseEarliestBlocker(kdb, zone, fromKid)
		return &EarliestRolloverResult{
			FromKID: fromKid,
			FromIdx: fromIdx,
			Status:  EarliestStatusWaitingForParent,
			Blocker: blocker,
		}, nil
	}

	// Compute the earliest moment toKid could become active under
	// the operator-override (asap) timeline: skip standby_time pause
	// but honor cache-flush propagation (which is mandatory for
	// E3 correctness).
	zd, _ := Zones.Get(zone)
	var gates []EarliestRolloverGate
	earliest := now
	advance := func(name string, t time.Time) {
		gates = append(gates, EarliestRolloverGate{Name: name, At: t})
		if t.After(earliest) {
			earliest = t
		}
	}

	// Per-state "key ready" gate: when the key reaches the genuine
	// standby state. Includes whatever propagation it still needs.
	switch toState {
	case DnskeyStateStandby:
		// Already there. asap can fire immediately.
	case DnskeyStatePublished:
		// Needs DNSKEY-side propagation (and DS-side, if we have a
		// DS observation gating; usually elapsed earlier).
		if tPub, err := RolloverKeyPublishedAt(kdb, zone, toKid); err == nil && tPub != nil {
			child := pol.Rollover.DsPublishDelay // not the right knob — see below
			_ = child
			// child_prop comes from kasp.propagation_delay, not the
			// policy. ComputeEarliestRollover doesn't currently take
			// it as a parameter; use a conservative observed proxy
			// via the DNSKEY TTL alone. The runtime engine reads
			// kasp.propagation_delay directly via deps.PropagationDelay
			// when transitioning published → standby. For ASAP-time
			// math the dominant term in typical configs is DNSKEY_TTL.
			if dnskeyTTL, ok := effectiveServedDnskeyTTL(kdb, zone, pol); ok {
				advance("dnskey-propagation", tPub.Add(dnskeyTTL))
			}
		}
		// DS-side gate (if known).
		if dsTTL, dsTTLKnown := resolveDSTTL(zd, pol); dsTTLKnown {
			if tDsObs, err := RolloverKeyDsObservedAt(kdb, zone, toKid); err == nil && tDsObs != nil {
				advance("ds-propagation", tDsObs.Add(pol.Rollover.DsPublishDelay+dsTTL))
			}
		}
	case DnskeyStateDsPublished:
		// Has not yet had its DNSKEY published. asap-time lower
		// bound: publish now, propagate over DNSKEY_TTL, then DS-side
		// gate independent.
		if dnskeyTTL, ok := effectiveServedDnskeyTTL(kdb, zone, pol); ok {
			advance("dnskey-propagation", now.Add(dnskeyTTL))
		}
		if dsTTL, dsTTLKnown := resolveDSTTL(zd, pol); dsTTLKnown {
			if tDsObs, err := RolloverKeyDsObservedAt(kdb, zone, toKid); err == nil && tDsObs != nil {
				advance("ds-propagation", tDsObs.Add(pol.Rollover.DsPublishDelay+dsTTL))
			}
		}
	}

	margin := pol.Clamping.Margin

	// Constraint: max published TTL must expire (minus one margin, since
	// records published just before the roll receive TTL=margin).
	maxTTL, err := LoadZoneSigningMaxTTL(kdb, zone)
	if err != nil {
		return nil, fmt.Errorf("load max_observed_ttl: %w", err)
	}
	maxTTLDur := time.Duration(maxTTL) * time.Second
	if maxTTLDur > 0 {
		advance("max-ttl-expiry", now.Add(maxTTLDur-margin))
	}

	gates = append(gates, EarliestRolloverGate{Name: "now", At: now})

	return &EarliestRolloverResult{
		Earliest: earliest,
		FromKID:  fromKid,
		ToKID:    toKid,
		FromIdx:  fromIdx,
		ToIdx:    toIdx,
		Gates:    gates,
		Status:   EarliestStatusReady,
	}, nil
}

// pickNextUpKeyWithState returns the next-up SEP key, its current
// state, and its rollover_index. Search order: standby → published →
// ds-published. Within each state, oldest published_at first
// (mirroring AtomicRollover's selection for standby and the engine's
// promotion order for published / ds-published).
//
// Returns (0, "", 0, nil) when no suitable key exists.
func pickNextUpKeyWithState(kdb *KeyDB, zone string) (uint16, string, int, error) {
	for _, st := range []string{DnskeyStateStandby, DnskeyStatePublished, DnskeyStateDsPublished} {
		kid, err := pickEarliestSEPInState(kdb, zone, st)
		if err != nil {
			return 0, "", 0, err
		}
		if kid != 0 {
			idx, _, err := RolloverIndexForKey(kdb, zone, kid)
			if err != nil {
				return 0, "", 0, err
			}
			return kid, st, idx, nil
		}
	}
	return 0, "", 0, nil
}

// pickEarliestSEPInState returns the SEP keyid in the given state
// with the oldest published_at (or, for ds-published, oldest
// ds_observed_at). Tie-break by rollover_index then keytag.
func pickEarliestSEPInState(kdb *KeyDB, zone string, state string) (uint16, error) {
	orderCol := "r.published_at"
	if state == DnskeyStateDsPublished {
		orderCol = "r.ds_observed_at"
	}
	q := `
SELECT d.keyid
FROM DnssecKeyStore d
LEFT JOIN RolloverKeyState r ON r.zone = d.zonename AND r.keyid = d.keyid
WHERE d.zonename = ? AND d.state = ? AND (CAST(d.flags AS INTEGER) & 1) = 1
ORDER BY (` + orderCol + ` IS NULL OR ` + orderCol + ` = '') ASC,
         ` + orderCol + ` ASC,
         (r.rollover_index IS NULL) ASC,
         r.rollover_index ASC,
         d.keyid ASC`
	rows, err := kdb.DB.Query(q, zone, state)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, rows.Err()
	}
	var kid int
	if err := rows.Scan(&kid); err != nil {
		return 0, err
	}
	return uint16(kid), nil
}

// diagnoseEarliestBlocker reads RolloverZoneRow softfail / observe
// state to explain why no standby SEP key is available. Returns a
// best-effort populated blocker — never nil, since the caller has
// already determined Case 1.
func diagnoseEarliestBlocker(kdb *KeyDB, zone string, activeKid uint16) *EarliestRolloverBlocker {
	out := &EarliestRolloverBlocker{
		Reason: "no standby SEP key in pipeline (parent DS for upcoming key not yet observed)",
		KeyID:  activeKid,
	}
	row, err := LoadRolloverZoneRow(kdb, zone)
	if err != nil || row == nil {
		out.Cause = "no rollover-zone state recorded yet"
		return out
	}
	if row.LastSoftfailCategory.Valid && row.LastSoftfailCategory.String != "" {
		cause := row.LastSoftfailCategory.String
		switch cause {
		case "child-config:waiting-for-parent":
			out.Cause = "parent advertises no DSYNC scheme matching policy"
		case "transport":
			out.Cause = "parent unreachable (last attempt: transport failure)"
		case "parent-rejected":
			out.Cause = "parent rejected last DS push (parent-rejected)"
		case "child-config:local-error":
			out.Cause = "child-side configuration error preventing DS push"
		default:
			out.Cause = fmt.Sprintf("last softfail category: %s", cause)
		}
		if row.LastSoftfailDetail.Valid && row.LastSoftfailDetail.String != "" {
			out.Detail = row.LastSoftfailDetail.String
		}
		return out
	}
	if row.NextPushAt.Valid && row.NextPushAt.String != "" {
		out.Cause = fmt.Sprintf("DS push pending; next attempt %s", row.NextPushAt.String)
		return out
	}
	out.Cause = "DS push not yet attempted in current pipeline window"
	return out
}

// pickEarliestStandbySEP returns the keyid of the standby SEP key that
// AtomicRollover would promote: oldest published_at, tie-break by
// rollover_index ascending then keytag ascending. Returns 0 if no standby
// SEP key exists.
//
// published_at (added in C16) replaces what the old single-state code
// called standby_at: the moment the engine moved the DNSKEY into the
// served zone. C18 adds a genuine "standby" transition with its own
// timestamp; until then "oldest published_at" remains the right
// promotion-order signal.
func pickEarliestStandbySEP(kdb *KeyDB, zone string) (uint16, error) {
	rows, err := kdb.DB.Query(`
SELECT d.keyid, r.published_at, r.rollover_index
FROM DnssecKeyStore d
LEFT JOIN RolloverKeyState r ON r.zone = d.zonename AND r.keyid = d.keyid
WHERE d.zonename = ? AND d.state = ? AND (d.flags & 1) = 1
ORDER BY (r.published_at IS NULL OR r.published_at = '') ASC,
         r.published_at ASC,
         (r.rollover_index IS NULL) ASC,
         r.rollover_index ASC,
         d.keyid ASC`,
		zone, DnskeyStateStandby)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, rows.Err()
	}
	var kid int
	var sa sql.NullString
	var ri sql.NullInt64
	if err := rows.Scan(&kid, &sa, &ri); err != nil {
		return 0, err
	}
	return uint16(kid), nil
}
