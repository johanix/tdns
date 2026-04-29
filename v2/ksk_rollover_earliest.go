package tdns

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// EarliestRolloverGate names a constraint that contributed to t_earliest.
// One of: "now", "max-ttl-expiry", "max-rrsig-validity", "ds-ready".
type EarliestRolloverGate struct {
	Name string
	At   time.Time
}

// EarliestRolloverResult is the output of ComputeEarliestRollover.
type EarliestRolloverResult struct {
	Earliest time.Time
	FromIdx  int
	ToIdx    int
	Gates    []EarliestRolloverGate
}

// ComputeEarliestRollover returns the earliest moment a rollover can safely
// fire for the zone, the rollover_index of the active KSK and its scheduled
// successor, and the constraints that produced the result. Side-effect free.
//
// Per §8.5:
//
//	t_earliest = max(now, max_ttl_expiry, max_sig_expiry, ds_ready_at)
//
// where:
//   - max_ttl_expiry = now + max_published_ttl_in_zone(z) - margin
//   - max_sig_expiry = now + max_published_rrsig_validity(z) - margin
//   - ds_ready_at = 0 if next_ksk is in standby, else
//     next_ksk.ds_observed_at + ds_ttl + margin
//
// Returns an error if a rollover cannot be scheduled (rollover already in
// progress, no active KSK, or no standby SEP key).
//
// Implementation notes for v1:
//   - max_published_rrsig_validity uses the policy's max SigValidity across
//     KSK/ZSK/CSK as a conservative upper bound on currently published RRSIG
//     validity. A future enhancement could track observed validity in
//     ZoneSigningState alongside max_observed_ttl.
//   - ds_ready_at uses next_ksk's standby state as the "ready now" signal.
//     The non-standby branch is exercised by manual-ASAP only when the
//     pipeline isn't fully primed yet, which the gate set will surface.
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

	row, err := LoadRolloverZoneRow(kdb, zone)
	if err != nil {
		return nil, fmt.Errorf("load rollover zone row: %w", err)
	}
	if row != nil && row.RolloverInProgress {
		return nil, fmt.Errorf("zone %s: rollover already in progress", zone)
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

	// Next SEP KSK: oldest standby (matches AtomicRollover's selection).
	standbyKid, err := pickEarliestStandbySEP(kdb, zone)
	if err != nil {
		return nil, fmt.Errorf("pick standby: %w", err)
	}
	if standbyKid == 0 {
		return nil, fmt.Errorf("zone %s: no standby SEP key (pipeline not ready)", zone)
	}
	toIdx, _, err := RolloverIndexForKey(kdb, zone, standbyKid)
	if err != nil {
		return nil, fmt.Errorf("rollover_index for standby keyid %d: %w", standbyKid, err)
	}

	margin := pol.Clamping.Margin

	// Constraint: max published TTL must expire (minus one margin, since
	// records published just before the roll receive TTL=margin).
	var gates []EarliestRolloverGate
	maxTTL, err := LoadZoneSigningMaxTTL(kdb, zone)
	if err != nil {
		return nil, fmt.Errorf("load max_observed_ttl: %w", err)
	}
	maxTTLDur := time.Duration(maxTTL) * time.Second
	maxTTLExpiry := now.Add(maxTTLDur - margin)
	if maxTTLDur > 0 {
		gates = append(gates, EarliestRolloverGate{Name: "max-ttl-expiry", At: maxTTLExpiry})
	}

	// Constraint: max published RRSIG validity must expire. v1 uses the
	// policy's largest SigValidity across KSK/ZSK/CSK as a conservative
	// upper bound on currently-published validity.
	maxSigDur := maxPublishedRRSIGValidity(pol)
	maxSigExpiry := now.Add(maxSigDur - margin)
	if maxSigDur > 0 {
		gates = append(gates, EarliestRolloverGate{Name: "max-rrsig-validity", At: maxSigExpiry})
	}

	// Constraint: standby KSK is fully published / DS observed at parent.
	// Standby state implies "DS observed + propagation already elapsed";
	// for non-standby successors (not reached in v1's selection), we'd need
	// ds_observed_at + ds_ttl + margin. Selected key is in standby by
	// construction, so this constraint is satisfied at `now`.
	dsReadyAt := now
	gates = append(gates, EarliestRolloverGate{Name: "ds-ready", At: dsReadyAt})

	earliest := now
	for _, g := range gates {
		if g.At.After(earliest) {
			earliest = g.At
		}
	}
	gates = append(gates, EarliestRolloverGate{Name: "now", At: now})

	return &EarliestRolloverResult{
		Earliest: earliest,
		FromIdx:  fromIdx,
		ToIdx:    toIdx,
		Gates:    gates,
	}, nil
}

// pickEarliestStandbySEP returns the keyid of the standby SEP key that
// AtomicRollover would promote: oldest standby_at, tie-break by
// rollover_index ascending then keytag ascending. Returns 0 if no standby
// SEP key exists.
func pickEarliestStandbySEP(kdb *KeyDB, zone string) (uint16, error) {
	rows, err := kdb.DB.Query(`
SELECT d.keyid, r.standby_at, r.rollover_index
FROM DnssecKeyStore d
LEFT JOIN RolloverKeyState r ON r.zone = d.zonename AND r.keyid = d.keyid
WHERE d.zonename = ? AND d.state = ? AND (d.flags & 1) = 1
ORDER BY (r.standby_at IS NULL OR r.standby_at = '') ASC,
         r.standby_at ASC,
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

// maxPublishedRRSIGValidity returns the maximum SigValidity across the
// policy's KSK/ZSK/CSK lifetimes. Used as a conservative upper bound on
// currently-published RRSIG validity for ComputeEarliestRollover.
func maxPublishedRRSIGValidity(pol *DnssecPolicy) time.Duration {
	var max uint32
	if pol.KSK.SigValidity > max {
		max = pol.KSK.SigValidity
	}
	if pol.ZSK.SigValidity > max {
		max = pol.ZSK.SigValidity
	}
	if pol.CSK.SigValidity > max {
		max = pol.CSK.SigValidity
	}
	return time.Duration(max) * time.Second
}
