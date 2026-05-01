package tdns

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// KSKDSPushResult is the outcome of PushDSRRsetForRollover (rcode and wire diagnostics).
// Category is empty on success (rcode NOERROR + persisted submitted range);
// otherwise it is one of the SoftfailXxx constants from
// ksk_rollover_categories.go and the engine's caller uses it to record a
// softfail event via setSoftfail.
//
// Scheme reflects which scheme(s) actually completed at the wire level
// for this attempt. Comma-joined when a parallel send had at least one
// path return NOERROR ("UPDATE", "NOTIFY", or "UPDATE,NOTIFY").
// Persisted to RolloverZoneState.last_attempt_scheme for status display.
//
// Detail concatenates per-path diagnostics from failures (rcode, EDE,
// transport error). Read by status output to render the cause of a
// parent-rejected or transport softfail.
type KSKDSPushResult struct {
	Rcode        int
	UpdateResult UpdateResult
	Category     string
	Scheme       string
	Detail       string
}

// BuildChildWholeDSUpdate builds a DNS UPDATE for the parent zone that replaces the
// child's entire DS RRset (DEL ANY DS at the delegation owner, then ADD the given set).
func BuildChildWholeDSUpdate(parent, child string, newDS []dns.RR) (*dns.Msg, error) {
	parent = dns.Fqdn(parent)
	child = dns.Fqdn(child)
	if parent == "." || parent == "" {
		return nil, fmt.Errorf("BuildChildWholeDSUpdate: parent zone empty")
	}
	if child == "." || child == "" {
		return nil, fmt.Errorf("BuildChildWholeDSUpdate: child zone empty")
	}

	m := new(dns.Msg)
	m.SetUpdate(parent)

	rrDS := new(dns.DS)
	rrDS.Hdr = dns.RR_Header{Name: child, Rrtype: dns.TypeDS, Class: dns.ClassANY, Ttl: 0}
	m.RemoveRRset([]dns.RR{rrDS})

	if len(newDS) > 0 {
		m.Insert(newDS)
	}
	m.SetEdns0(1232, true)
	return m, nil
}

type kskForDSRow struct {
	keyid uint16
	flags uint16
	keyrr string
	ri    sql.NullInt64
}

// loadTargetKSKsForRollover is the canonical SQL query for "the keys
// belonging in the rollover-target DS RRset." Per §6.1: one row per
// KSK (SEP) in states created, ds-published, standby, published,
// active, retired (created is included for multi-DS pre-publish DS at
// the parent). Two callers wrap it: ComputeTargetDSSetForZone (for DS)
// and ComputeTargetCDSSetForZone (for CDS, see Phase 4). Both must
// derive their target set from the same key rows; if they diverged, a
// NOTIFY-pushed CDS would not match the UPDATE-pushed DS.
//
// indexLow/indexHigh are min/max rollover_index when every contributing
// key has a RolloverKeyState row; otherwise indexRangeKnown is false
// and callers must not treat the indices as authoritative.
func loadTargetKSKsForRollover(kdb *KeyDB, childZone string) (rows []kskForDSRow, indexLow, indexHigh int, indexRangeKnown bool, err error) {
	childZone = dns.Fqdn(childZone)
	const q = `
SELECT k.keyid, k.flags, k.keyrr, r.rollover_index
FROM DnssecKeyStore k
LEFT JOIN RolloverKeyState r ON k.zonename = r.zone AND k.keyid = r.keyid
WHERE k.zonename = ? AND k.state IN ('created','ds-published','standby','published','active','retired')
  AND (CAST(k.flags AS INTEGER) & ?) != 0
ORDER BY COALESCE(r.rollover_index, 2147483646) ASC, k.keyid ASC`

	sqlRows, err := kdb.Query(q, childZone, int(dns.SEP))
	if err != nil {
		return nil, 0, 0, false, fmt.Errorf("loadTargetKSKsForRollover: %w", err)
	}
	defer sqlRows.Close()

	for sqlRows.Next() {
		var keyid, flags int
		var keyrr string
		var ri sql.NullInt64
		if err := sqlRows.Scan(&keyid, &flags, &keyrr, &ri); err != nil {
			return nil, 0, 0, false, fmt.Errorf("loadTargetKSKsForRollover scan: %w", err)
		}
		rows = append(rows, kskForDSRow{
			keyid: uint16(keyid),
			flags: uint16(flags),
			keyrr: keyrr,
			ri:    ri,
		})
	}
	if err := sqlRows.Err(); err != nil {
		return nil, 0, 0, false, err
	}

	indexRangeKnown = len(rows) > 0
	for _, row := range rows {
		if !row.ri.Valid {
			indexRangeKnown = false
			break
		}
	}

	if indexRangeKnown {
		for i, row := range rows {
			v := int(row.ri.Int64)
			if i == 0 {
				indexLow, indexHigh = v, v
			} else {
				if v < indexLow {
					indexLow = v
				}
				if v > indexHigh {
					indexHigh = v
				}
			}
		}
	}
	return rows, indexLow, indexHigh, indexRangeKnown, nil
}

// ComputeTargetDSSetForZone returns the DS RRset the parent should publish for this child,
// per §6.1: one DS per KSK (SEP) in states created, ds-published, standby, published, active, retired
// (created included for multi-DS pre-publish DS at parent).
// Digest is SHA-256 only in this phase. DS owner names use child as FQDN.
// indexLow/indexHigh are min/max rollover_index when every contributing key has a
// RolloverKeyState row; otherwise indexRangeKnown is false and callers must not treat
// the indices as authoritative for RolloverZoneState.
func ComputeTargetDSSetForZone(kdb *KeyDB, childZone string, digest uint8) (ds []dns.RR, indexLow, indexHigh int, indexRangeKnown bool, err error) {
	childZone = dns.Fqdn(childZone)
	rows, low, high, idxOK, err := loadTargetKSKsForRollover(kdb, childZone)
	if err != nil {
		return nil, 0, 0, false, err
	}
	for _, row := range rows {
		rr, err := dns.NewRR(row.keyrr)
		if err != nil {
			return nil, 0, 0, false, fmt.Errorf("ComputeTargetDSSetForZone: parse DNSKEY keyid=%d: %w", row.keyid, err)
		}
		dk, ok := rr.(*dns.DNSKEY)
		if !ok {
			return nil, 0, 0, false, fmt.Errorf("ComputeTargetDSSetForZone: keyid %d is not DNSKEY", row.keyid)
		}
		dsRR := dk.ToDS(digest)
		if dsRR == nil {
			return nil, 0, 0, false, fmt.Errorf("ComputeTargetDSSetForZone: ToDS failed for keyid %d", row.keyid)
		}
		dsRR.Hdr.Name = childZone
		if dsRR.Hdr.Ttl == 0 {
			dsRR.Hdr.Ttl = 3600
		}
		ds = append(ds, dsRR)
	}
	return ds, low, high, idxOK, nil
}

// PushDSRRsetForRollover is the public dispatcher entry point for the
// rollover engine's DS push. It consults the parent's DSYNC RRset and
// the policy's dsync-scheme-preference, dispatches one or more
// per-scheme push functions (in parallel when "auto" matches both
// schemes), and aggregates per-path wire-level results.
//
// Aggregation rules:
//   - Any path returned NOERROR → push succeeds. Scheme is
//     comma-joined for the paths that returned NOERROR.
//   - All paths failed → push fails. Category is the most-actionable:
//     parent-rejected > transport > child-config:local-error.
//     Detail concatenates per-path diagnostics.
//   - "no usable scheme" from pickRolloverSchemes (parent advertises
//     nothing the policy will accept) → child-config:waiting-for-parent
//     (Phase 6) without dispatching any path. Recovery is automatic
//     when the parent restores DSYNC advertisement.
//
// Single-scheme degenerate case: when only one scheme runs, the
// aggregate is just that path's result; no special-case path.
//
// Note: when the policy has no DsyncSchemePreference set (e.g. the
// CLI offline ds-push call constructs deps without policy on a stub
// zd), the dispatcher falls through to the legacy UPDATE-only path
// to preserve existing CLI behavior.
func PushDSRRsetForRollover(ctx context.Context, deps RolloverEngineDeps) (KSKDSPushResult, error) {
	if deps.Policy == nil {
		return pushDSRRsetViaUpdate(ctx, deps)
	}
	if deps.Imr == nil {
		return pushDSRRsetViaUpdate(ctx, deps)
	}

	choices, err := pickRolloverSchemes(ctx, deps.Zone, deps.Imr, deps.Policy)
	if err != nil {
		// Trigger 2 cleanup (err branch): if we still own a CDS RRset
		// and the parent has lost the ability to consume it, unpublish
		// best-effort. Otherwise CDS sits orphaned for the duration of
		// the parent-side outage.
		cleanupCdsAfterConfirm(deps.Zone, deps.KDB)
		// "No usable scheme" maps to child-config:waiting-for-parent
		// in Phase 6. Phase 4 emits SoftfailChildConfig — the
		// subcategorization commit will introduce the new constant
		// and update this site to use it.
		return KSKDSPushResult{
			Category: SoftfailChildConfig,
			Detail:   "pickRolloverSchemes: " + err.Error(),
		}, fmt.Errorf("PushDSRRsetForRollover: %w", err)
	}

	// Trigger 2 cleanup (UPDATE-only branch): if the chosen schemes
	// don't include NOTIFY but we currently own a CDS RRset, that CDS
	// will not be republished by this attempt. Unpublish before
	// dispatch so it doesn't sit stale through the rollover.
	if !schemesContainNotify(choices) {
		cleanupCdsAfterConfirm(deps.Zone, deps.KDB)
	}

	results := make([]pathResultLite, len(choices))

	if len(choices) == 1 {
		// Single-path degenerate case: avoid goroutine overhead.
		ch := choices[0]
		switch ch.Scheme {
		case core.SchemeUpdate:
			res, perr := pushDSRRsetViaUpdate(ctx, deps)
			results[0] = pathResultLite{scheme: "UPDATE", res: res, err: perr}
		case core.SchemeNotify:
			res, perr := pushDSRRsetViaNotify(ctx, deps, ch.Target)
			results[0] = pathResultLite{scheme: "NOTIFY", res: res, err: perr}
		default:
			return KSKDSPushResult{
				Category: SoftfailChildConfig,
				Detail:   fmt.Sprintf("unknown scheme %d", ch.Scheme),
			}, fmt.Errorf("PushDSRRsetForRollover: unknown scheme %d", ch.Scheme)
		}
	} else {
		// Parallel: one goroutine per scheme. Each writes its slot in
		// the pre-allocated results slice; no shared mutation.
		var wg sync.WaitGroup
		for i, ch := range choices {
			wg.Add(1)
			go func(i int, ch schemeChoice) {
				defer wg.Done()
				switch ch.Scheme {
				case core.SchemeUpdate:
					res, perr := pushDSRRsetViaUpdate(ctx, deps)
					results[i] = pathResultLite{scheme: "UPDATE", res: res, err: perr}
				case core.SchemeNotify:
					res, perr := pushDSRRsetViaNotify(ctx, deps, ch.Target)
					results[i] = pathResultLite{scheme: "NOTIFY", res: res, err: perr}
				default:
					results[i] = pathResultLite{
						scheme: schemeName(ch.Scheme),
						res:    KSKDSPushResult{Category: SoftfailChildConfig, Detail: fmt.Sprintf("unknown scheme %d", ch.Scheme)},
						err:    fmt.Errorf("unknown scheme %d", ch.Scheme),
					}
				}
			}(i, ch)
		}
		wg.Wait()
	}

	return aggregateRolloverPushResults(results), nil
}

// aggregateRolloverPushResults applies the dispatcher's any-success-wins
// policy to the per-path results and returns the engine-functional
// aggregate KSKDSPushResult. Helper kept separate for clarity (and so
// future tests can drive it directly without spinning up Imr/UpdateQ).
func aggregateRolloverPushResults(results []pathResultLite) KSKDSPushResult {
	var ok []string
	var failParts []string
	failedCat := ""
	failedRcode := 0
	for _, r := range results {
		if r.err == nil && r.res.Rcode == dns.RcodeSuccess {
			ok = append(ok, r.scheme)
			continue
		}
		// Failed path. Aggregate its diagnostics + category.
		detail := r.scheme + ":"
		if r.res.Detail != "" {
			detail += " " + r.res.Detail
		} else if r.err != nil {
			detail += " " + r.err.Error()
		} else if r.res.Rcode != 0 {
			detail += " rcode=" + dns.RcodeToString[r.res.Rcode]
		}
		failParts = append(failParts, detail)
		// Most-actionable category wins.
		failedCat = mergeFailureCategory(failedCat, r.res.Category)
		if r.res.Rcode != 0 && failedRcode == 0 {
			failedRcode = r.res.Rcode
		}
	}
	if len(ok) > 0 {
		return KSKDSPushResult{
			Rcode:  dns.RcodeSuccess,
			Scheme: strings.Join(ok, ","),
			Detail: strings.Join(failParts, " | "),
		}
	}
	return KSKDSPushResult{
		Rcode:    failedRcode,
		Category: failedCat,
		Detail:   strings.Join(failParts, " | "),
	}
}

// pathResultLite is the trimmed shape aggregateRolloverPushResults
// consumes — just the scheme name and the per-path result.
type pathResultLite struct {
	scheme string
	res    KSKDSPushResult
	err    error
}

// schemesContainNotify reports whether any chosen scheme is NOTIFY.
// Used by the dispatcher's Trigger 2 cleanup decision: when NOTIFY
// is not in the dispatch set, any CDS the engine previously published
// will not be re-published this attempt and should be cleaned up
// preemptively.
func schemesContainNotify(choices []schemeChoice) bool {
	for _, c := range choices {
		if c.Scheme == core.SchemeNotify {
			return true
		}
	}
	return false
}

// mergeFailureCategory picks the more-actionable of two failure
// categories. Order: parent-rejected > transport > child-config.
// Empty strings are treated as least-actionable.
func mergeFailureCategory(a, b string) string {
	rank := func(s string) int {
		switch s {
		case SoftfailParentRejected:
			return 3
		case SoftfailTransport:
			return 2
		case SoftfailChildConfig:
			return 1
		default:
			return 0
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// pushDSRRsetViaUpdate computes the target DS RRset from the keystore, builds a
// whole-RRset replacement UPDATE to the parent, signs with the child's active
// SIG(0) key, and sends it. On rcode NOERROR, updates
// last_ds_submitted_index_* when indexRangeKnown from
// ComputeTargetDSSetForZone.
func pushDSRRsetViaUpdate(ctx context.Context, deps RolloverEngineDeps) (KSKDSPushResult, error) {
	var out KSKDSPushResult
	zd := deps.Zone
	kdb := deps.KDB
	imr := deps.Imr
	if zd == nil || kdb == nil || imr == nil {
		out.Category = SoftfailChildConfig
		return out, fmt.Errorf("pushDSRRsetViaUpdate: nil argument")
	}
	child := dns.Fqdn(zd.ZoneName)
	parent := dns.Fqdn(zd.Parent)
	if parent == "" || parent == "." {
		var err error
		parent, err = imr.ParentZone(child)
		if err != nil {
			out.Category = SoftfailTransport
			return out, fmt.Errorf("pushDSRRsetViaUpdate: parent zone: %w", err)
		}
		parent = dns.Fqdn(parent)
	}

	dsSet, low, high, idxOK, err := ComputeTargetDSSetForZone(kdb, child, uint8(dns.SHA256))
	if err != nil {
		out.Category = SoftfailChildConfig
		return out, err
	}
	if len(dsSet) == 0 {
		out.Category = SoftfailChildConfig
		return out, fmt.Errorf("pushDSRRsetViaUpdate: no DS records to publish for zone %s", child)
	}

	msg, err := BuildChildWholeDSUpdate(parent, child, dsSet)
	if err != nil {
		out.Category = SoftfailChildConfig
		return out, err
	}

	sak, err := kdb.GetSig0Keys(child, Sig0StateActive)
	if err != nil {
		out.Category = SoftfailChildConfig
		return out, fmt.Errorf("pushDSRRsetViaUpdate: GetSig0Keys: %w", err)
	}
	if len(sak.Keys) == 0 {
		out.Category = SoftfailChildConfig
		return out, fmt.Errorf("pushDSRRsetViaUpdate: no active SIG(0) key for zone %s", child)
	}

	smsg, err := SignMsg(*msg, child, sak)
	if err != nil {
		out.Category = SoftfailChildConfig
		return out, fmt.Errorf("pushDSRRsetViaUpdate: SignMsg: %w", err)
	}

	dsyncTarget, err := imr.LookupDSYNCTarget(ctx, child, dns.TypeDS, core.SchemeUpdate)
	if err != nil {
		dsyncTarget, err = imr.LookupDSYNCTarget(ctx, child, dns.TypeANY, core.SchemeUpdate)
		if err != nil {
			out.Category = SoftfailTransport
			return out, fmt.Errorf("pushDSRRsetViaUpdate: DSYNC target: %w", err)
		}
	}

	rcode, ur, err := SendUpdate(smsg, parent, dsyncTarget.Addresses)
	out.Rcode = rcode
	out.UpdateResult = ur
	if err != nil {
		// SendUpdate's err is a network-layer failure: i/o timeout,
		// no route to host, conn refused, etc. Rcode-level rejections
		// from the parent come back via rcode without err.
		out.Category = SoftfailTransport
		return out, err
	}
	if rcode != dns.RcodeSuccess {
		out.Category = SoftfailParentRejected
		return out, nil
	}

	if idxOK {
		if err := saveLastDSSubmittedRange(kdb, child, low, high); err != nil {
			out.Category = SoftfailChildConfig
			return out, fmt.Errorf("pushDSRRsetViaUpdate: persist submitted range: %w", err)
		}
	} else {
		// Contributors didn't all have authoritative rollover_index
		// values, so this push has no meaningful range to record.
		// Clear any stale range from a prior push instead of leaving
		// stale persisted columns that describe an older submission.
		if err := clearLastDSSubmittedRange(kdb, child); err != nil {
			return out, fmt.Errorf("pushDSRRsetViaUpdate: clear stale submitted range: %w", err)
		}
	}
	out.Scheme = "UPDATE"
	return out, nil
}

// ComputeTargetCDSSetForZone returns the CDS RRset that mirrors the
// rollover engine's target DS set, derived from the same KSK rows
// that ComputeTargetDSSetForZone uses. Both functions share
// loadTargetKSKsForRollover so an UPDATE-pushed DS RRset and a
// NOTIFY-pushed CDS RRset always describe the same set of keys.
// Digest is SHA-256 only in this phase. CDS owner names use child
// as FQDN; TTL is 120s to match ops_cds.go.
//
// indexLow/indexHigh / indexRangeKnown are the engine's claim of
// CDS-RRset ownership for cleanup-time comparison
// (RolloverZoneState.last_published_cds_index_low/high). The same
// caveat as ComputeTargetDSSetForZone applies: indexRangeKnown is
// false when not every contributing key has a RolloverKeyState row,
// in which case the caller must not persist the range.
func ComputeTargetCDSSetForZone(kdb *KeyDB, childZone string) (cds []dns.RR, indexLow, indexHigh int, indexRangeKnown bool, err error) {
	childZone = dns.Fqdn(childZone)
	rows, low, high, idxOK, err := loadTargetKSKsForRollover(kdb, childZone)
	if err != nil {
		return nil, 0, 0, false, err
	}
	for _, row := range rows {
		rr, err := dns.NewRR(row.keyrr)
		if err != nil {
			return nil, 0, 0, false, fmt.Errorf("ComputeTargetCDSSetForZone: parse DNSKEY keyid=%d: %w", row.keyid, err)
		}
		dk, ok := rr.(*dns.DNSKEY)
		if !ok {
			return nil, 0, 0, false, fmt.Errorf("ComputeTargetCDSSetForZone: keyid %d is not DNSKEY", row.keyid)
		}
		ds := dk.ToDS(uint8(dns.SHA256))
		if ds == nil {
			return nil, 0, 0, false, fmt.Errorf("ComputeTargetCDSSetForZone: ToDS failed for keyid %d", row.keyid)
		}
		c := &dns.CDS{DS: *ds}
		c.Hdr = dns.RR_Header{
			Name:   childZone,
			Rrtype: dns.TypeCDS,
			Class:  dns.ClassINET,
			Ttl:    120,
		}
		cds = append(cds, c)
	}
	return cds, low, high, idxOK, nil
}

func saveLastDSSubmittedRange(kdb *KeyDB, zone string, low, high int) error {
	const q = `
INSERT INTO RolloverZoneState (zone, last_ds_submitted_index_low, last_ds_submitted_index_high, last_ds_submitted_at, rollover_phase, rollover_in_progress, next_rollover_index)
VALUES (?, ?, ?, ?, 'idle', 0, 0)
ON CONFLICT(zone) DO UPDATE SET
  last_ds_submitted_index_low = excluded.last_ds_submitted_index_low,
  last_ds_submitted_index_high = excluded.last_ds_submitted_index_high,
  last_ds_submitted_at = excluded.last_ds_submitted_at`
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := kdb.DB.Exec(q, zone, low, high, now)
	return err
}

// clearLastDSSubmittedRange wipes the persisted submitted-range columns
// when a successful push had incomplete rollover_index contributors,
// so subsequent range-based decisions and operator status output don't
// keep showing values from an older submission.
func clearLastDSSubmittedRange(kdb *KeyDB, zone string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	const q = `UPDATE RolloverZoneState
SET last_ds_submitted_index_low = NULL,
    last_ds_submitted_index_high = NULL,
    last_ds_submitted_at = ?
WHERE zone = ?`
	_, err := kdb.DB.Exec(q, now, zone)
	return err
}
