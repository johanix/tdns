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
		FromKID:  fromKid,
		ToKID:    standbyKid,
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
