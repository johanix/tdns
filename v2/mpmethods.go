/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 *
 * MP methods: methods on types defined in mptypes.go.
 * Relocated from legacy_* files to enable incremental
 * removal of MP functions from tdns.
 */
package tdns

import (
	"fmt"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// --- Agent methods ---

// IsAnyTransportOperational returns true if at least one transport layer
// (DNS or API) is in the OPERATIONAL state. DNS is checked first as it is
// the primary (and currently only fully implemented) transport.
func (a *Agent) IsAnyTransportOperational() bool {
	if a.DnsDetails != nil && a.DnsDetails.State == AgentStateOperational {
		return true
	}
	if a.ApiDetails != nil && a.ApiDetails.State == AgentStateOperational {
		return true
	}
	return false
}

// EffectiveState returns the most relevant transport-layer state.
// DNS is checked first as it is the primary transport.
// Falls back to the top-level aggregate state if no transport is operational.
func (a *Agent) EffectiveState() AgentState {
	if a.DnsDetails != nil && a.DnsDetails.State == AgentStateOperational {
		return AgentStateOperational
	}
	if a.ApiDetails != nil && a.ApiDetails.State == AgentStateOperational {
		return AgentStateOperational
	}
	return a.State
}

// --- AgentId / ZoneName methods ---

func (id AgentId) String() string {
	return string(id)
}

func (name ZoneName) String() string {
	return string(name)
}

// --- AgentRepo methods ---

func (ar *AgentRepo) Get(agentId AgentId) (*OwnerData, bool) {
	return ar.Data.Get(agentId)
}

func (ar *AgentRepo) Set(agentId AgentId, ownerData *OwnerData) {
	ar.Data.Set(agentId, ownerData)
}

// --- ZoneDataRepo methods ---

func (zdr *ZoneDataRepo) Get(zone ZoneName) (*AgentRepo, bool) {
	return zdr.Repo.Get(zone)
}

func (zdr *ZoneDataRepo) Set(zone ZoneName, agentRepo *AgentRepo) {
	zdr.Repo.Set(zone, agentRepo)
}

// AddConfirmedRR adds a single RR to the repo and tracking as RRStateAccepted.
// Used to hydrate the SDE with pre-confirmed data from the combiner (RFI EDITS).
func (zdr *ZoneDataRepo) AddConfirmedRR(zone ZoneName, agentID AgentId, rr dns.RR) {
	// Get or create AgentRepo for this zone
	nar, ok := zdr.Get(zone)
	if !ok {
		nar, _ = NewAgentRepo()
		zdr.Set(zone, nar)
	}

	// Get or create OwnerData for this agent
	nod, ok := nar.Get(agentID)
	if !ok {
		nod = NewOwnerData(string(zone))
		nar.Set(agentID, nod)
	}

	// Add RR to the RRTypeStore
	rrtype := rr.Header().Rrtype
	cur, ok := nod.RRtypes.Get(rrtype)
	if !ok {
		cur = core.RRset{
			Name:   rr.Header().Name,
			RRtype: rrtype,
		}
	}
	cur.Add(rr)
	nod.RRtypes.Set(rrtype, cur)

	// Add tracking entry as RRStateAccepted
	ts := zdr.getOrCreateTracking(zone, agentID, rrtype)
	ts.Tracked = append(ts.Tracked, TrackedRR{
		RR:        rr,
		State:     RRStateAccepted,
		UpdatedAt: time.Now(),
	})
}

// getOrCreateTracking returns (or creates) the TrackedRRset for the given zone/agent/rrtype.
func (zdr *ZoneDataRepo) getOrCreateTracking(zone ZoneName, agent AgentId, rrtype uint16) *TrackedRRset {
	if zdr.Tracking[zone] == nil {
		zdr.Tracking[zone] = make(map[AgentId]map[uint16]*TrackedRRset)
	}
	if zdr.Tracking[zone][agent] == nil {
		zdr.Tracking[zone][agent] = make(map[uint16]*TrackedRRset)
	}
	if zdr.Tracking[zone][agent][rrtype] == nil {
		zdr.Tracking[zone][agent][rrtype] = &TrackedRRset{}
	}
	return zdr.Tracking[zone][agent][rrtype]
}

func (zdr *ZoneDataRepo) SendUpdate(update *SynchedDataUpdate) error {
	// 1. Send the update to the combiner.
	lgEngine.Debug("sending update to combiner (NYI)")
	return nil
}

// removeTracking removes all tracking for a zone/agent/rrtype (used on ClassANY deletion).
func (zdr *ZoneDataRepo) removeTracking(zone ZoneName, agent AgentId, rrtype uint16) {
	if zdr.Tracking[zone] != nil && zdr.Tracking[zone][agent] != nil {
		delete(zdr.Tracking[zone][agent], rrtype)
	}
}

// removeTrackedRR removes a specific tracked RR by its string representation (used on ClassNONE deletion).
func (zdr *ZoneDataRepo) removeTrackedRR(zone ZoneName, agent AgentId, rrtype uint16, rrStr string) {
	if zdr.Tracking[zone] == nil || zdr.Tracking[zone][agent] == nil {
		return
	}
	tracked := zdr.Tracking[zone][agent][rrtype]
	if tracked == nil {
		return
	}
	for i := range tracked.Tracked {
		if tracked.Tracked[i].RR.String() == rrStr {
			tracked.Tracked = append(tracked.Tracked[:i], tracked.Tracked[i+1:]...)
			return
		}
	}
}

// MarkRRsPending marks all RRs in a ZoneUpdate as pending with the given distribution ID.
// Called after successful enqueue for combiner delivery.
// recipients is the list of expected confirmation sources (combiner + agents) for this distID.
// The RR transitions to accepted only after ALL recipients have confirmed.
//
// For ClassINET RRs: marks as RRStatePending (addition awaiting confirmation).
// For ClassNONE RRs: finds the matching existing tracked RR and marks it as RRStatePendingRemoval.
// For ClassANY RRs: marks all tracked RRs for the rrtype as RRStatePendingRemoval.
func (zdr *ZoneDataRepo) MarkRRsPending(zone ZoneName, agent AgentId, update *ZoneUpdate, distID string, recipients []string) {
	now := time.Now()

	// Handle Operations first — REPLACE operations define the full set and
	// take precedence over the delta in RRsets/RRs for tracking purposes.
	// Track which rrtypes were handled by Operations so we don't double-track.
	opsHandled := map[uint16]bool{}
	for _, op := range update.Operations {
		rrtype, ok := dns.StringToType[op.RRtype]
		if !ok {
			continue
		}
		switch op.Operation {
		case "replace":
			// REPLACE: create tracking for ALL records in the replacement set.
			// The delta in RRsets/RRs only has adds/removes, but we need tracking
			// for the complete set so confirmations can match every record.
			// Removals are implicit (absent from the set) — processReplaceOp
			// already cleaned up tracking for removed keys.
			tracked := zdr.getOrCreateTracking(zone, agent, rrtype)
			for _, rrStr := range op.Records {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					continue
				}
				zdr.markAddPending(tracked, rr, distID, now)
			}
			opsHandled[rrtype] = true

		case "add":
			tracked := zdr.getOrCreateTracking(zone, agent, rrtype)
			for _, rrStr := range op.Records {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					continue
				}
				zdr.markAddPending(tracked, rr, distID, now)
			}
			opsHandled[rrtype] = true

		case "delete":
			tracked := zdr.getOrCreateTracking(zone, agent, rrtype)
			for _, rrStr := range op.Records {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					continue
				}
				zdr.markDeletePending(tracked, rr, distID, now)
			}
			opsHandled[rrtype] = true
		}
	}

	// Handle RRsets (remote updates) — skip rrtypes already handled by Operations
	for rrtype, rrset := range update.RRsets {
		if opsHandled[rrtype] {
			continue
		}
		tracked := zdr.getOrCreateTracking(zone, agent, rrtype)
		for _, rr := range rrset.RRs {
			switch rr.Header().Class {
			case dns.ClassINET:
				zdr.markAddPending(tracked, rr, distID, now)
			case dns.ClassNONE:
				zdr.markDeletePending(tracked, rr, distID, now)
			case dns.ClassANY:
				zdr.markAllDeletePending(tracked, distID, now)
			}
		}
	}

	// Handle individual RRs (local updates) — skip rrtypes already handled by Operations
	for _, rr := range update.RRs {
		rrtype := rr.Header().Rrtype
		if opsHandled[rrtype] {
			continue
		}
		tracked := zdr.getOrCreateTracking(zone, agent, rrtype)
		switch rr.Header().Class {
		case dns.ClassINET:
			zdr.markAddPending(tracked, rr, distID, now)
		case dns.ClassNONE:
			zdr.markDeletePending(tracked, rr, distID, now)
		case dns.ClassANY:
			zdr.markAllDeletePending(tracked, distID, now)
		}
	}

	// Set ExpectedRecipients on all TrackedRRs that now carry this distID.
	// This tells ProcessConfirmation who must confirm before state can transition.
	if len(recipients) > 0 {
		zdr.setExpectedRecipients(zone, agent, distID, recipients)
	}
}

// markAddPending marks a ClassINET RR as pending (addition awaiting confirmation).
func (zdr *ZoneDataRepo) markAddPending(tracked *TrackedRRset, rr dns.RR, distID string, now time.Time) {
	rrStr := rr.String()
	for i := range tracked.Tracked {
		if tracked.Tracked[i].RR.String() == rrStr {
			if tracked.Tracked[i].State == RRStateAccepted {
				lgEngine.Debug("markAddPending: RR already accepted, skipping", "rr", rrStr)
				return
			}
			tracked.Tracked[i].State = RRStatePending
			tracked.Tracked[i].Reason = ""
			tracked.Tracked[i].DistributionID = distID
			tracked.Tracked[i].UpdatedAt = now
			return
		}
	}
	tracked.Tracked = append(tracked.Tracked, TrackedRR{
		RR:             rr,
		State:          RRStatePending,
		DistributionID: distID,
		UpdatedAt:      now,
	})
}

// markDeletePending finds the existing tracked RR matching the ClassNONE RR and
// transitions it to RRStatePendingRemoval. Matching is done by comparing the RR
// string with class normalized to ClassINET, since tracked RRs were stored with ClassINET.
func (zdr *ZoneDataRepo) markDeletePending(tracked *TrackedRRset, rr dns.RR, distID string, now time.Time) {
	// Create a ClassINET copy for matching against tracked RRs
	matchRR := dns.Copy(rr)
	matchRR.Header().Class = dns.ClassINET
	matchStr := matchRR.String()

	for i := range tracked.Tracked {
		if tracked.Tracked[i].RR.String() == matchStr {
			tracked.Tracked[i].State = RRStatePendingRemoval
			tracked.Tracked[i].Reason = ""
			tracked.Tracked[i].DistributionID = distID
			tracked.Tracked[i].UpdatedAt = now
			lgEngine.Debug("marked RR as pending-removal", "rr", matchStr, "distID", distID)
			return
		}
	}
	lgEngine.Warn("markDeletePending: no matching tracked RR found", "rr", matchStr)
}

// markAllDeletePending marks all tracked RRs in the RRset as RRStatePendingRemoval (ClassANY delete).
func (zdr *ZoneDataRepo) markAllDeletePending(tracked *TrackedRRset, distID string, now time.Time) {
	transitioned := 0
	for i := range tracked.Tracked {
		if tracked.Tracked[i].State == RRStateAccepted || tracked.Tracked[i].State == RRStatePending {
			tracked.Tracked[i].State = RRStatePendingRemoval
			tracked.Tracked[i].Reason = ""
			tracked.Tracked[i].DistributionID = distID
			tracked.Tracked[i].UpdatedAt = now
			transitioned++
		}
	}
	if transitioned == 0 && len(tracked.Tracked) > 0 {
		lgEngine.Debug("markAllDeletePending: no RRs eligible for transition", "total", len(tracked.Tracked))
	}
}

// evictStaleTracking removes TrackedRR entries in terminal states (accepted, rejected,
// removed) that have not been updated within maxAge. This prevents unbounded growth of
// the Tracking map.
func (zdr *ZoneDataRepo) evictStaleTracking(maxAge time.Duration) {
	evicted := 0
	for zone, agentMap := range zdr.Tracking {
		for agent, rrtypeMap := range agentMap {
			for rrtype, trackedRRset := range rrtypeMap {
				remaining := trackedRRset.Tracked[:0]
				for _, tr := range trackedRRset.Tracked {
					if (tr.State == RRStateAccepted || tr.State == RRStateRejected || tr.State == RRStateRemoved) && time.Since(tr.UpdatedAt) > maxAge {
						evicted++
						continue
					}
					remaining = append(remaining, tr)
				}
				trackedRRset.Tracked = remaining
				// Clean up empty entries
				if len(trackedRRset.Tracked) == 0 {
					delete(rrtypeMap, rrtype)
				}
			}
			if len(rrtypeMap) == 0 {
				delete(agentMap, agent)
			}
		}
		if len(agentMap) == 0 {
			delete(zdr.Tracking, zone)
		}
	}
	if evicted > 0 {
		lgEngine.Info("evicted stale tracking entries", "count", evicted)
	}
}

// setExpectedRecipients sets the ExpectedRecipients on all TrackedRRs matching a given distID.
func (zdr *ZoneDataRepo) setExpectedRecipients(zone ZoneName, agent AgentId, distID string, recipients []string) {
	if zdr.Tracking[zone] == nil || zdr.Tracking[zone][agent] == nil {
		return
	}
	for _, trackedRRset := range zdr.Tracking[zone][agent] {
		for i := range trackedRRset.Tracked {
			if trackedRRset.Tracked[i].DistributionID == distID {
				trackedRRset.Tracked[i].ExpectedRecipients = recipients
			}
		}
	}
}

// ProcessConfirmation updates tracked RR states based on combiner confirmation feedback.
// For additions: Pending -> Accepted or Rejected.
// For deletions: PendingRemoval -> Removed (and the RR is actually deleted from the ZoneDataRepo).
// If a PendingRemoval RR appears in the rejected list, it transitions back to Accepted.
func (zdr *ZoneDataRepo) ProcessConfirmation(detail *ConfirmationDetail, msgQs *MsgQs) {
	now := time.Now()
	source := detail.Source
	if source == "" {
		source = "unknown"
	}
	// Reject sources with suspicious characters (prevent log injection)
	if strings.ContainsAny(source, "\n\r\t") {
		lgEngine.Warn("ProcessConfirmation: source contains control characters, sanitizing", "rawSource", source)
		source = strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == '\t' {
				return '_'
			}
			return r
		}, source)
	}

	// Helper to record per-recipient confirmation on a TrackedRR.
	setConfirmation := func(tr *TrackedRR, status, reason string) {
		if tr.Confirmations == nil {
			tr.Confirmations = make(map[string]RRConfirmation)
		}
		tr.Confirmations[source] = RRConfirmation{
			Status:    status,
			Reason:    reason,
			Timestamp: now,
		}
	}

	// First NOTIFY in two-phase protocol: status="PENDING" means the remote peer
	// received the sync and is processing it. Record per-recipient pending status.
	if detail.Status == "PENDING" {
		lgEngine.Debug("pending confirmation (delivery confirmed, awaiting final response)", "source", source, "distID", detail.DistributionID, "zone", detail.Zone)
		zoneTracking := zdr.Tracking[detail.Zone]
		for _, agentTracking := range zoneTracking {
			for _, trackedRRset := range agentTracking {
				for i := range trackedRRset.Tracked {
					tr := &trackedRRset.Tracked[i]
					if tr.DistributionID == detail.DistributionID {
						setConfirmation(tr, "pending", "")
					}
				}
			}
		}
		return
	}

	// Build a set of applied RR strings for fast lookup
	appliedSet := make(map[string]bool, len(detail.AppliedRecords))
	for _, rr := range detail.AppliedRecords {
		appliedSet[rr] = true
	}

	// Build a set of removed RR strings for fast lookup
	removedSet := make(map[string]bool, len(detail.RemovedRecords))
	for _, rr := range detail.RemovedRecords {
		removedSet[rr] = true
	}

	// Build a map of rejected RR strings -> reason
	rejectedMap := make(map[string]string, len(detail.RejectedItems))
	for _, ri := range detail.RejectedItems {
		rejectedMap[ri.Record] = ri.Reason
	}

	// Walk all tracked RRs for this zone and match by distribution ID + RR string
	zoneTracking := zdr.Tracking[detail.Zone]
	if zoneTracking == nil {
		lgEngine.Warn("no tracking data for zone", "source", source, "zone", detail.Zone)
		return
	}

	matched := 0
	removed := 0
	for agentId, agentTracking := range zoneTracking {
		for rrtype, trackedRRset := range agentTracking {
			for i := range trackedRRset.Tracked {
				tr := &trackedRRset.Tracked[i]
				if tr.DistributionID != detail.DistributionID {
					continue // Wrong distribution
				}
				rrStr := tr.RR.String()

				switch tr.State {
				case RRStatePending:
					// Addition confirmation
					if appliedSet[rrStr] {
						setConfirmation(tr, "accepted", "")
						tr.UpdatedAt = now
						matched++
						// Only transition to Accepted if ALL expected recipients have confirmed.
						if allRecipientsConfirmed(tr) {
							tr.State = RRStateAccepted
							tr.Reason = ""
						}
					} else if reason, rejected := rejectedMap[rrStr]; rejected {
						setConfirmation(tr, "rejected", reason)
						// Any rejection immediately transitions to Rejected
						tr.State = RRStateRejected
						tr.Reason = reason
						tr.UpdatedAt = now
						matched++
					}
					// If truncated and RR not in either list, leave as pending

				case RRStatePendingRemoval:
					if removedSet[rrStr] {
						setConfirmation(tr, "removed", "")
						tr.UpdatedAt = now
						matched++
						// Only transition to Removed and delete from repo if ALL expected recipients confirmed.
						if allRecipientsConfirmed(tr) {
							zdr.deleteRRFromRepo(detail.Zone, agentId, rrtype, tr.RR)
							tr.State = RRStateRemoved
							tr.Reason = ""
							removed++
							lgEngine.Info("RR removed (all confirmed)", "source", source, "rr", rrStr)
						}
					} else if reason, rejected := rejectedMap[rrStr]; rejected {
						// Combiner rejected the delete — RR is still live, revert to Accepted
						setConfirmation(tr, "rejected", reason)
						tr.State = RRStateAccepted
						tr.Reason = fmt.Sprintf("delete rejected: %s", reason)
						tr.UpdatedAt = now
						matched++
						lgEngine.Warn("delete rejected for RR", "source", source, "rr", rrStr, "reason", reason)
					}
					// If truncated and RR not in either list, leave as pending-removal

				case RRStateAccepted:
					// Already accepted — record this recipient's confirmation
					if appliedSet[rrStr] {
						setConfirmation(tr, "accepted", "")
						matched++
					}

				case RRStateRemoved:
					// Already removed — record this recipient's confirmation
					if removedSet[rrStr] {
						setConfirmation(tr, "removed", "")
						matched++
					}
				}
			}
		}
	}

	lgEngine.Info("confirmation processed", "source", source, "distID", detail.DistributionID, "zone", detail.Zone, "matched", matched, "applied", len(detail.AppliedRecords), "removed", removed, "rejected", len(detail.RejectedItems), "truncated", detail.Truncated)

	// Check if this confirmation corresponds to a remote update we forwarded to our combiner.
	// If so, send the final confirmation back to the originating agent.
	zdr.mu.Lock()
	prc, hasPRC := zdr.PendingRemoteConfirms[detail.DistributionID]
	zdr.mu.Unlock()

	if hasPRC {
		appliedRecords := detail.AppliedRecords

		// If the combiner returned SUCCESS but with no AppliedRecords (no-op),
		// reconstruct from our local repo so the originating agent can match.
		if len(appliedRecords) == 0 && (detail.Status == "SUCCESS" || detail.Status == "ok") {
			agentId := AgentId(prc.OriginatingSender)
			if agentRepo, ok := zdr.Repo.Get(prc.Zone); ok {
				if nod, ok := agentRepo.Get(agentId); ok {
					for _, rrtype := range nod.RRtypes.Keys() {
						rrset, exists := nod.RRtypes.Get(rrtype)
						if !exists {
							continue
						}
						for _, rr := range rrset.RRs {
							appliedRecords = append(appliedRecords, rr.String())
						}
					}
					lgEngine.Debug("reconstructed applied records from repo for relay",
						"zone", prc.Zone, "agent", agentId, "records", len(appliedRecords))
				}
			}
		}

		lgEngine.Info("triggering remote confirmation", "source", source, "originDistID", prc.OriginatingDistID, "to", prc.OriginatingSender, "applied", len(appliedRecords))
		remoteDetail := &RemoteConfirmationDetail{
			OriginatingDistID: prc.OriginatingDistID,
			OriginatingSender: prc.OriginatingSender,
			Zone:              prc.Zone,
			Status:            detail.Status,
			Message:           detail.Message,
			AppliedRecords:    appliedRecords,
			RemovedRecords:    detail.RemovedRecords,
			RejectedItems:     detail.RejectedItems,
			Truncated:         detail.Truncated,
		}
		if msgQs != nil && msgQs.OnRemoteConfirmationReady != nil {
			msgQs.OnRemoteConfirmationReady(remoteDetail)
		}
		zdr.mu.Lock()
		delete(zdr.PendingRemoteConfirms, detail.DistributionID)
		zdr.mu.Unlock()
	}
}

// deleteRRFromRepo deletes a specific RR from the active ZoneDataRepo.
// Called when a PendingRemoval RR is confirmed as removed by the combiner.
func (zdr *ZoneDataRepo) deleteRRFromRepo(zone ZoneName, agent AgentId, rrtype uint16, rr dns.RR) {
	nar, ok := zdr.Repo.Get(zone)
	if !ok {
		return
	}
	nod, ok := nar.Get(agent)
	if !ok {
		return
	}
	curRRset, ok := nod.RRtypes.Get(rrtype)
	if !ok {
		return
	}
	curRRset.Delete(rr)
	nod.RRtypes.Set(rrtype, curRRset)
}

// --- RRState methods ---

func (s RRState) String() string {
	switch s {
	case RRStatePending:
		return "pending"
	case RRStateAccepted:
		return "accepted"
	case RRStateRejected:
		return "rejected"
	case RRStatePendingRemoval:
		return "pending-removal"
	case RRStateRemoved:
		return "removed"
	default:
		return "unknown"
	}
}
