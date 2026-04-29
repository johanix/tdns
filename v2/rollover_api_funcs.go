package tdns

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ComputeRolloverStatus reads the rollover state for one zone and
// returns the operator-facing status struct. Pure read, no DB writes.
// Side-effect free; safe to call from API handlers without taking
// the per-zone lock (sqlite WAL gives snapshot reads while writers
// are in flight, and the response is "best-effort current state at
// response time" by API contract).
//
// pol may be nil for zones that don't have a DNSSEC policy attached;
// the function still returns a valid struct (Headline=OK, no policy
// summary, no derived timing fields).
func ComputeRolloverStatus(kdb *KeyDB, zone string, pol *DnssecPolicy, now time.Time) (*RolloverStatus, error) {
	zone = dns.Fqdn(strings.TrimSpace(zone))
	if zone == "." || zone == "" {
		return nil, fmt.Errorf("ComputeRolloverStatus: empty zone")
	}

	out := &RolloverStatus{
		Zone:        zone,
		CurrentTime: now.UTC().Format(time.RFC3339),
		Phase:       rolloverPhaseIdle,
		KSKs:        []RolloverKeyEntry{},
		ZSKs:        []RolloverKeyEntry{},
	}

	row, err := LoadRolloverZoneRow(kdb, zone)
	if err != nil {
		return nil, fmt.Errorf("LoadRolloverZoneRow: %w", err)
	}
	if row != nil {
		populateFromZoneRow(out, row)
	}

	out.Headline = headlineForPhase(out.Phase)
	out.Hint = hintForState(out.Phase, row, pol, now)

	if pol != nil {
		populateAttemptTiming(out, row, pol)
		out.Policy = policySummary(pol)
	}

	var hiddenRemoved int
	out.KSKs, hiddenRemoved = loadRolloverKeyEntries(kdb, zone, true)
	out.HiddenRemovedKskCount = hiddenRemoved
	out.ZSKs, _ = loadRolloverKeyEntries(kdb, zone, false)

	if err := populateDSKeyidsForStatus(kdb, zone, out); err != nil {
		return nil, fmt.Errorf("ComputeRolloverStatus: %w", err)
	}

	return out, nil
}

func populateDSKeyidsForStatus(kdb *KeyDB, zone string, out *RolloverStatus) error {
	if out.Submitted != nil {
		ids, err := RolloverKeyidsByIndexRange(kdb, zone, int64(out.Submitted.Low), int64(out.Submitted.High))
		if err != nil {
			return fmt.Errorf("submitted keyids: %w", err)
		}
		out.SubmittedKeyIDs = ids
	}
	if out.Confirmed != nil {
		ids, err := RolloverKeyidsByIndexRange(kdb, zone, int64(out.Confirmed.Low), int64(out.Confirmed.High))
		if err != nil {
			return fmt.Errorf("confirmed keyids: %w", err)
		}
		out.ConfirmedKeyIDs = ids
	}
	return nil
}

// ComputeRolloverWhen wraps ComputeEarliestRollover into wire-friendly
// types. Returns the earliest moment a rollover can safely fire plus
// the gates that produced the result.
func ComputeRolloverWhen(kdb *KeyDB, zone string, pol *DnssecPolicy, now time.Time) (*RolloverWhenResponse, error) {
	zone = dns.Fqdn(strings.TrimSpace(zone))
	if zone == "." || zone == "" {
		return nil, fmt.Errorf("ComputeRolloverWhen: empty zone")
	}
	if pol == nil {
		return nil, fmt.Errorf("ComputeRolloverWhen: zone %s has no DNSSEC policy", zone)
	}
	res, err := ComputeEarliestRollover(kdb, zone, pol, now)
	if err != nil {
		return nil, err
	}
	out := &RolloverWhenResponse{
		Zone:     zone,
		Earliest: res.Earliest.UTC().Format(time.RFC3339),
		FromIdx:  res.FromIdx,
		ToIdx:    res.ToIdx,
		Gates:    make([]RolloverWhenGateEntry, 0, len(res.Gates)),
	}
	for _, g := range res.Gates {
		out.Gates = append(out.Gates, RolloverWhenGateEntry{
			Name: g.Name,
			At:   g.At.UTC().Format(time.RFC3339),
		})
	}
	return out, nil
}

// populateFromZoneRow copies fields from the persisted row into the
// status struct. Translation of sql.NullString → string ("" when
// absent) and the two index ranges → *DSRange (nil when absent).
func populateFromZoneRow(out *RolloverStatus, row *RolloverZoneRow) {
	out.Phase = row.RolloverPhase
	if out.Phase == "" {
		out.Phase = rolloverPhaseIdle
	}
	if row.RolloverPhaseAt.Valid {
		out.PhaseAt = row.RolloverPhaseAt.String
	}
	out.InProgress = row.RolloverInProgress

	if row.LastSubmittedLow.Valid && row.LastSubmittedHigh.Valid {
		out.Submitted = &DSRange{
			Low:  int(row.LastSubmittedLow.Int64),
			High: int(row.LastSubmittedHigh.Int64),
		}
	}
	if row.LastConfirmedLow.Valid && row.LastConfirmedHigh.Valid {
		out.Confirmed = &DSRange{
			Low:  int(row.LastConfirmedLow.Int64),
			High: int(row.LastConfirmedHigh.Int64),
		}
	}

	if row.ManualRolloverRequestedAt.Valid {
		out.ManualRequestedAt = row.ManualRolloverRequestedAt.String
	}
	if row.ManualRolloverEarliest.Valid {
		out.ManualEarliest = row.ManualRolloverEarliest.String
	}

	if row.LastAttemptStartedAt.Valid {
		out.LastUpdate = row.LastAttemptStartedAt.String
		out.LastAttemptStarted = row.LastAttemptStartedAt.String
	}

	out.HardfailCount = row.HardfailCount
	if row.NextPushAt.Valid {
		out.NextPushAt = row.NextPushAt.String
	}
	if row.LastSoftfailAt.Valid {
		out.LastSoftfailAt = row.LastSoftfailAt.String
	}
	if row.LastSoftfailCategory.Valid {
		out.LastSoftfailCat = row.LastSoftfailCategory.String
	}
	if row.LastSoftfailDetail.Valid {
		out.LastSoftfailDetail = row.LastSoftfailDetail.String
	}

	if row.LastPollAt.Valid {
		out.LastPoll = row.LastPollAt.String
	}
	if row.ObserveNextPollAt.Valid {
		out.NextPoll = row.ObserveNextPollAt.String
	}
	if row.LastSuccessAt.Valid {
		out.LastSuccess = row.LastSuccessAt.String
	}
}

// populateAttemptTiming computes ExpectedBy and AttemptTimeout from
// LastUpdate + policy durations, and AttemptIndex/AttemptMax from the
// counter and policy. Only meaningful with a policy attached.
func populateAttemptTiming(out *RolloverStatus, row *RolloverZoneRow, pol *DnssecPolicy) {
	if row != nil && row.LastAttemptStartedAt.Valid {
		if t, err := time.Parse(time.RFC3339, row.LastAttemptStartedAt.String); err == nil {
			if pol.Rollover.DsPublishDelay > 0 {
				out.ExpectedBy = t.Add(pol.Rollover.DsPublishDelay).UTC().Format(time.RFC3339)
			}
			if pol.Rollover.ConfirmTimeout > 0 {
				out.AttemptTimeout = t.Add(pol.Rollover.ConfirmTimeout).UTC().Format(time.RFC3339)
			}
		}
	}
	out.AttemptMax = pol.Rollover.MaxAttemptsBeforeBackoff
	// AttemptIndex is the operator-facing 1-based number for the
	// current group of N attempts. During the initial flurry,
	// hardfail_count after attempt n shows as n (incremented at
	// failure), so the running attempt is hardfail_count+1.
	// During softfail the counter is at-or-above max and the index
	// is no longer meaningful; surface 0 there.
	if out.Phase != rolloverPhasePushSoftfail && row != nil {
		if row.HardfailCount < out.AttemptMax {
			out.AttemptIndex = row.HardfailCount + 1
		}
	}
}

// headlineForPhase maps the engine's phase string to the operator-
// facing one-word headline. OK = idle / steady-state. ACTIVE = an
// attempt is in flight. SOFTFAIL = long-term retry mode.
func headlineForPhase(phase string) string {
	switch phase {
	case rolloverPhasePushSoftfail:
		return "SOFTFAIL"
	case rolloverPhasePendingChildPublish,
		rolloverPhasePendingParentPush,
		rolloverPhasePendingParentObserve,
		rolloverPhasePendingChildWithdraw:
		return "ACTIVE"
	default:
		return "OK"
	}
}

// hintForState returns a plain-English diagnosis line keyed off the
// current phase plus the elapsed time relative to the policy's
// ds-publish-delay and confirm-timeout. Empty for steady states.
func hintForState(phase string, row *RolloverZoneRow, pol *DnssecPolicy, now time.Time) string {
	switch phase {
	case rolloverPhasePushSoftfail:
		return "parent fix will be auto-detected — polling never stops"
	case rolloverPhasePendingParentObserve:
		if row == nil || pol == nil || !row.LastAttemptStartedAt.Valid {
			return ""
		}
		t, err := time.Parse(time.RFC3339, row.LastAttemptStartedAt.String)
		if err != nil {
			return ""
		}
		elapsed := now.Sub(t)
		dsDelay := pol.Rollover.DsPublishDelay
		if dsDelay <= 0 || elapsed < dsDelay {
			return "within expected publish window — polling continues"
		}
		return "past expected publish time, polling continues — approaching timeout"
	default:
		return ""
	}
}

// policySummary projects the operator-relevant slice of DnssecPolicy
// for status output.
func policySummary(pol *DnssecPolicy) *PolicySummary {
	out := &PolicySummary{
		Name:                     pol.Name,
		Algorithm:                dns.AlgorithmToString[pol.Algorithm],
		KskLifetime:              (time.Duration(pol.KSK.Lifetime) * time.Second).String(),
		DsPublishDelay:           pol.Rollover.DsPublishDelay.String(),
		MaxAttemptsBeforeBackoff: pol.Rollover.MaxAttemptsBeforeBackoff,
		SoftfailDelay:            pol.Rollover.SoftfailDelay.String(),
	}
	if pol.Clamping.Margin > 0 {
		out.ClampingMargin = pol.Clamping.Margin.String()
	}
	return out
}

// rolloverStatusRemovedDisplayCap limits how many SEP keys in state
// "removed" appear in RolloverStatus.KSKs (most recent by active_seq
// first). Matches historical auto-rollover status CLI behavior.
const rolloverStatusRemovedDisplayCap = 3

// loadRolloverKeyEntries returns one RolloverKeyEntry per DNSSEC key
// for the zone, filtered by SEP flag. SEP keys go in KSKs; non-SEP in
// ZSKs. State, KeyID, and lifecycle timestamps come from
// DnssecKeyStore; ActiveSeq and LastRolloverErr come from
// RolloverKeyState.
//
// For SEP keys in "removed", only the first rolloverStatusRemovedDisplayCap
// rows after sorting by active_seq (descending; keys without seq sink to
// the bottom) are returned. The second return value is how many additional
// removed SEP keys were omitted (0 when wantSEP is false).
func loadRolloverKeyEntries(kdb *KeyDB, zone string, wantSEP bool) ([]RolloverKeyEntry, int) {
	out := []RolloverKeyEntry{}
	hiddenRemoved := 0
	states := []string{
		DnskeyStateCreated,
		DnskeyStateDsPublished,
		DnskeyStatePublished,
		DnskeyStateStandby,
		DnskeyStateActive,
		DnskeyStateRetired,
		DnskeyStateRemoved,
	}
	for _, st := range states {
		keys, err := GetDnssecKeysByState(kdb, zone, st)
		if err != nil {
			// Partial status is better than no status; log and skip
			// this state so the operator at least sees an entry in
			// the daemon log instead of the keystore failure being
			// silently swallowed.
			lgSigner.Debug("loadRolloverKeyEntries: GetDnssecKeysByState failed", "zone", zone, "state", st, "err", err)
			continue
		}
		var batch []RolloverKeyEntry
		for i := range keys {
			k := &keys[i]
			isSEP := k.Flags&dns.SEP != 0
			if isSEP != wantSEP {
				continue
			}
			batch = append(batch, rolloverKeyEntryFromKeystoreKey(kdb, zone, k, wantSEP))
		}
		if st == DnskeyStateRemoved && wantSEP {
			sort.SliceStable(batch, func(i, j int) bool {
				si := rolloverActiveSeqSortKey(batch[i].ActiveSeq)
				sj := rolloverActiveSeqSortKey(batch[j].ActiveSeq)
				if (si < 0) != (sj < 0) {
					return si >= 0
				}
				return si > sj
			})
			if len(batch) > rolloverStatusRemovedDisplayCap {
				hiddenRemoved = len(batch) - rolloverStatusRemovedDisplayCap
				batch = batch[:rolloverStatusRemovedDisplayCap]
			}
		}
		out = append(out, batch...)
	}
	return out, hiddenRemoved
}

func rolloverActiveSeqSortKey(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}

func rolloverKeyEntryFromKeystoreKey(kdb *KeyDB, zone string, k *DnssecKeyWithTimestamps, wantSEP bool) RolloverKeyEntry {
	entry := RolloverKeyEntry{
		KeyID: k.KeyTag,
		State: k.State,
	}
	if wantSEP {
		entry.Published = DnskeyRolloverPublishLabel(k.State)
	} else if k.PublishedAt != nil && !k.PublishedAt.IsZero() {
		entry.Published = k.PublishedAt.UTC().Format(time.RFC3339)
	}
	if ts := StateSinceForDnssecKey(kdb, zone, k); !ts.IsZero() {
		entry.StateSince = ts.UTC().Format(time.RFC3339)
	}
	seq, err := RolloverKeyActiveSeq(kdb, zone, k.KeyTag)
	if err == nil && seq >= 0 {
		v := seq
		entry.ActiveSeq = &v
	}
	if msg, _ := LoadLastRolloverError(kdb, zone, k.KeyTag); msg != "" {
		entry.LastRolloverErr = msg
	}
	return entry
}
