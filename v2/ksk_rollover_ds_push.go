package tdns

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// KSKDSPushResult is the outcome of PushWholeDSRRset (rcode and wire diagnostics).
// Category is empty on success (rcode NOERROR + persisted submitted range);
// otherwise it is one of the SoftfailXxx constants from
// ksk_rollover_categories.go and the engine's caller uses it to record a
// softfail event via setSoftfail.
type KSKDSPushResult struct {
	Rcode        int
	UpdateResult UpdateResult
	Category     string
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

// ComputeTargetDSSetForZone returns the DS RRset the parent should publish for this child,
// per §6.1: one DS per KSK (SEP) in states created, ds-published, standby, published, active, retired
// (created included for multi-DS pre-publish DS at parent).
// Digest is SHA-256 only in this phase. DS owner names use child as FQDN.
// indexLow/indexHigh are min/max rollover_index when every contributing key has a
// RolloverKeyState row; otherwise indexRangeKnown is false and callers must not treat
// the indices as authoritative for RolloverZoneState.
func ComputeTargetDSSetForZone(kdb *KeyDB, childZone string, digest uint8) (ds []dns.RR, indexLow, indexHigh int, indexRangeKnown bool, err error) {
	childZone = dns.Fqdn(childZone)
	const q = `
SELECT k.keyid, k.flags, k.keyrr, r.rollover_index
FROM DnssecKeyStore k
LEFT JOIN RolloverKeyState r ON k.zonename = r.zone AND k.keyid = r.keyid
WHERE k.zonename = ? AND k.state IN ('created','ds-published','standby','published','active','retired')
  AND (CAST(k.flags AS INTEGER) & ?) != 0
ORDER BY COALESCE(r.rollover_index, 2147483646) ASC, k.keyid ASC`

	rows, err := kdb.Query(q, childZone, int(dns.SEP))
	if err != nil {
		return nil, 0, 0, false, fmt.Errorf("ComputeTargetDSSetForZone: %w", err)
	}
	defer rows.Close()

	var rowsOut []kskForDSRow
	for rows.Next() {
		var keyid, flags int
		var keyrr string
		var ri sql.NullInt64
		if err := rows.Scan(&keyid, &flags, &keyrr, &ri); err != nil {
			return nil, 0, 0, false, fmt.Errorf("ComputeTargetDSSetForZone scan: %w", err)
		}
		rowsOut = append(rowsOut, kskForDSRow{
			keyid: uint16(keyid),
			flags: uint16(flags),
			keyrr: keyrr,
			ri:    ri,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, 0, 0, false, err
	}

	indexRangeKnown = len(rowsOut) > 0
	for _, row := range rowsOut {
		if !row.ri.Valid {
			indexRangeKnown = false
			break
		}
	}

	for _, row := range rowsOut {
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

	if indexRangeKnown {
		for i, row := range rowsOut {
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
	return ds, indexLow, indexHigh, indexRangeKnown, nil
}

// PushWholeDSRRset computes the target DS RRset from the keystore, builds a whole-RRset
// replacement UPDATE to the parent, signs with the child's active SIG(0) key, and sends it.
// On rcode NOERROR, updates last_ds_submitted_index_* when indexRangeKnown from ComputeTargetDSSetForZone.
func PushWholeDSRRset(ctx context.Context, zd *ZoneData, kdb *KeyDB, imr *Imr) (KSKDSPushResult, error) {
	var out KSKDSPushResult
	if zd == nil || kdb == nil || imr == nil {
		out.Category = SoftfailChildConfig
		return out, fmt.Errorf("PushWholeDSRRset: nil argument")
	}
	child := dns.Fqdn(zd.ZoneName)
	parent := dns.Fqdn(zd.Parent)
	if parent == "" || parent == "." {
		var err error
		parent, err = imr.ParentZone(child)
		if err != nil {
			out.Category = SoftfailTransport
			return out, fmt.Errorf("PushWholeDSRRset: parent zone: %w", err)
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
		return out, fmt.Errorf("PushWholeDSRRset: no DS records to publish for zone %s", child)
	}

	msg, err := BuildChildWholeDSUpdate(parent, child, dsSet)
	if err != nil {
		out.Category = SoftfailChildConfig
		return out, err
	}

	sak, err := kdb.GetSig0Keys(child, Sig0StateActive)
	if err != nil {
		out.Category = SoftfailChildConfig
		return out, fmt.Errorf("PushWholeDSRRset: GetSig0Keys: %w", err)
	}
	if len(sak.Keys) == 0 {
		out.Category = SoftfailChildConfig
		return out, fmt.Errorf("PushWholeDSRRset: no active SIG(0) key for zone %s", child)
	}

	smsg, err := SignMsg(*msg, child, sak)
	if err != nil {
		out.Category = SoftfailChildConfig
		return out, fmt.Errorf("PushWholeDSRRset: SignMsg: %w", err)
	}

	dsyncTarget, err := imr.LookupDSYNCTarget(ctx, child, dns.TypeDS, core.SchemeUpdate)
	if err != nil {
		dsyncTarget, err = imr.LookupDSYNCTarget(ctx, child, dns.TypeANY, core.SchemeUpdate)
		if err != nil {
			out.Category = SoftfailTransport
			return out, fmt.Errorf("PushWholeDSRRset: DSYNC target: %w", err)
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
			return out, fmt.Errorf("PushWholeDSRRset: persist submitted range: %w", err)
		}
	} else {
		// Contributors didn't all have authoritative rollover_index
		// values, so this push has no meaningful range to record.
		// Clear any stale range from a prior push instead of leaving
		// stale persisted columns that describe an older submission.
		if err := clearLastDSSubmittedRange(kdb, child); err != nil {
			return out, fmt.Errorf("PushWholeDSRRset: clear stale submitted range: %w", err)
		}
	}
	return out, nil
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
