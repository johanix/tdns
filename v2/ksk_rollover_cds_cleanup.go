package tdns

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// cleanupCdsAfterConfirm releases the rollover engine's CDS-RRset
// ownership on the child zone, with compare-on-cleanup to avoid
// unpublishing CDS that another caller (general delegation-sync) has
// taken over. Called from three trigger sites:
//
//  1. confirmed observation in pending-parent-observe — primary path
//     for steady-state NOTIFY-pushed rollovers (publish, observe,
//     confirm, clean up).
//  2. start of any push attempt that won't republish CDS — handles
//     parent-side scheme transitions mid-rollover (NOTIFY→UPDATE-only
//     flips, DSYNC withdrawn, ...) so CDS doesn't sit orphaned for
//     the duration of an outage.
//  3. terminal hardfail — to be wired when the rollover state machine
//     adds a terminal-hardfail site. Today the post-overhaul model is
//     indefinite softfail; no such site exists yet.
//
// Behavior:
//   - last_published_cds_index_low/high NULL → no-op (we own no CDS).
//   - Reload the KSK rows referenced by the saved range. Re-derive
//     the expected CDS RRset from those rows (same path as
//     ComputeTargetCDSSetForZone — the rows' state may have advanced
//     since publish, but the key material is what defines a CDS).
//   - Read the current CDS RRset from the in-memory zone. Compare
//     expected vs current as a set of (KeyTag, Algorithm, DigestType,
//     Digest) tuples — TTL, ownername case, and order are immaterial.
//   - Equal sets → queue UnpublishCdsRRs (anti-CDS ClassANY delete);
//     clear last_published_cds_index_low/high.
//   - Unequal sets → another caller has taken ownership; log INFO,
//     clear last_published_cds_index_low/high (so we don't retry next
//     cycle), leave CDS on the wire untouched.
//
// All three triggers are best-effort: on any error, log WARN and
// return without escalating. CDS RRset is not on any rollover-critical
// path; an orphaned CDS will eventually be replaced by the general
// delegation-sync path or by another rollover attempt.
func cleanupCdsAfterConfirm(zd *ZoneData, kdb *KeyDB) {
	if zd == nil || kdb == nil {
		return
	}
	zone := dns.Fqdn(zd.ZoneName)

	row, err := LoadRolloverZoneRow(kdb, zone)
	if err != nil {
		lgSigner.Warn("rollover: cleanupCdsAfterConfirm: load row", "zone", zone, "err", err)
		return
	}
	if row == nil {
		return
	}
	if !row.LastPublishedCdsIndexLow.Valid || !row.LastPublishedCdsIndexHigh.Valid {
		return
	}
	low := int(row.LastPublishedCdsIndexLow.Int64)
	high := int(row.LastPublishedCdsIndexHigh.Int64)

	// Re-derive the expected CDS set from KSK rows whose
	// rollover_index falls in [low, high]. State may have advanced
	// since we published, but key material is what defines a CDS
	// tuple — only the digest matters for comparison.
	expected, err := expectedCdsTuplesForRange(kdb, zone, low, high)
	if err != nil {
		lgSigner.Warn("rollover: cleanupCdsAfterConfirm: re-derive expected CDS",
			"zone", zone, "low", low, "high", high, "err", err)
		// Treat as "unequal" — clear range, leave CDS in place. The
		// stored range is no longer authoritative for cleanup.
		_ = clearPublishedCdsRange(kdb, zone)
		return
	}

	current, err := currentCdsTuples(zd)
	if err != nil {
		lgSigner.Warn("rollover: cleanupCdsAfterConfirm: read current CDS",
			"zone", zone, "err", err)
		_ = clearPublishedCdsRange(kdb, zone)
		return
	}

	if !cdsTupleSetsEqual(expected, current) {
		lgSigner.Info("rollover: CDS no longer matches last push, leaving in place",
			"zone", zone, "expected_count", len(expected), "current_count", len(current))
		_ = clearPublishedCdsRange(kdb, zone)
		return
	}

	// Equal — we still own this CDS RRset. Unpublish.
	if err := zd.UnpublishCdsRRs(); err != nil {
		lgSigner.Warn("rollover: cleanupCdsAfterConfirm: UnpublishCdsRRs",
			"zone", zone, "err", err)
		// Don't clear the range yet — we'll retry on the next trigger.
		return
	}
	if err := clearPublishedCdsRange(kdb, zone); err != nil {
		lgSigner.Warn("rollover: cleanupCdsAfterConfirm: clearPublishedCdsRange",
			"zone", zone, "err", err)
		return
	}
	lgSigner.Info("rollover: CDS cleanup complete", "zone", zone)
}

// cdsTuple is the comparison key for compare-on-cleanup. RFC 4034
// §5.1 defines a DS by these four fields; CDS shares the same shape.
// TTL, ownername case, and slice order are intentionally excluded so
// incidental differences (re-canonicalization on re-signing, TTL
// adjustments) don't cause false-mismatch.
type cdsTuple struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string
}

// expectedCdsTuplesForRange recomputes the CDS tuples from the KSK
// rows whose rollover_index is within [low, high]. Mirrors
// ComputeTargetCDSSetForZone but filtered by index range and
// returning tuples instead of RRs.
func expectedCdsTuplesForRange(kdb *KeyDB, zone string, low, high int) (map[cdsTuple]struct{}, error) {
	if kdb == nil {
		return nil, fmt.Errorf("nil kdb")
	}
	rows, _, _, _, err := loadTargetKSKsForRollover(kdb, zone)
	if err != nil {
		return nil, err
	}
	out := make(map[cdsTuple]struct{}, len(rows))
	for _, row := range rows {
		if !row.ri.Valid {
			continue
		}
		idx := int(row.ri.Int64)
		if idx < low || idx > high {
			continue
		}
		rr, err := dns.NewRR(row.keyrr)
		if err != nil {
			return nil, fmt.Errorf("parse DNSKEY keyid=%d: %w", row.keyid, err)
		}
		dk, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		ds := dk.ToDS(uint8(dns.SHA256))
		if ds == nil {
			continue
		}
		out[cdsTuple{
			KeyTag:     ds.KeyTag,
			Algorithm:  ds.Algorithm,
			DigestType: ds.DigestType,
			Digest:     ds.Digest,
		}] = struct{}{}
	}
	return out, nil
}

// currentCdsTuples reads the CDS RRset from the in-memory zone apex
// and returns its DS-identifying tuples. Returns an empty map if the
// zone has no CDS RRset.
func currentCdsTuples(zd *ZoneData) (map[cdsTuple]struct{}, error) {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return nil, fmt.Errorf("GetOwner: %w", err)
	}
	out := make(map[cdsTuple]struct{})
	if apex == nil {
		return out, nil
	}
	rrset, exists := apex.RRtypes.Get(dns.TypeCDS)
	if !exists {
		return out, nil
	}
	for _, rr := range rrset.RRs {
		c, ok := rr.(*dns.CDS)
		if !ok {
			continue
		}
		out[cdsTuple{
			KeyTag:     c.DS.KeyTag,
			Algorithm:  c.DS.Algorithm,
			DigestType: c.DS.DigestType,
			Digest:     c.DS.Digest,
		}] = struct{}{}
	}
	return out, nil
}

func cdsTupleSetsEqual(a, b map[cdsTuple]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// cleanupCdsAfterHardfail is the Trigger 3 hook for terminal hardfail.
// Today the rollover state machine has no terminal-hardfail state
// (post-overhaul model is indefinite softfail with one probe per
// softfail-delay forever). This function exists so a future
// rollover-state-machine extension that introduces a terminal-hardfail
// transition can call it without re-discovering the cleanup helper.
//
//nolint:unused // wired by the future terminal-hardfail commit.
func cleanupCdsAfterHardfail(zd *ZoneData, kdb *KeyDB, _ time.Time) {
	cleanupCdsAfterConfirm(zd, kdb)
}
