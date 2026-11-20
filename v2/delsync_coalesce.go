/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"slices"
	"time"
)

// delegationSyncLook is the request a stored change becomes when it is not
// sent at once: a compare of the zone with its parent, which sends whatever
// differs then. ok is false for a request that is not a stored change.
//
// A stored change is SYNC-DELEGATION, the difference between two versions of
// the zone, or PROXY-SYNC, what a transfer changed. Either is right only while
// the parent holds what the zone held before the change. Sent at once it is,
// and it is sent at once (RunDelegationSyncLanes). Kept for later it may not
// be: the parent may have missed an earlier change, the zone may have changed
// again, and nobody knows when the queue will reach it. A compare made when it
// runs is right whenever that is, and two of them waiting do what one does.
// So the parent's queue holds compares, never stored changes, and a stored
// change whose send fails is retried as a compare too (lookAgainLater).
//
//   - SYNC-DELEGATION becomes EXPLICIT-SYNC-DELEGATION: the zone's NS, glue
//     and DS against the parent's (AnalyseZoneDelegation), the difference sent
//     through the parent's scheme. tdns-mp's syncher retries a leader's failed
//     sync the same way.
//   - PROXY-SYNC becomes PROXY-UPDATE-SETUP: the proxy's own compare
//     (ProxyStartupReconcile), the one it makes at load.
//
// A request someone waits on is kept as it is: the answer is theirs.
func delegationSyncLook(ds DelegationSyncRequest) (DelegationSyncRequest, bool) {
	if ds.Response != nil || ds.DSResponse != nil {
		return ds, false
	}
	var cmd string
	switch ds.Command {
	case "SYNC-DELEGATION":
		cmd = "EXPLICIT-SYNC-DELEGATION"
	case "PROXY-SYNC":
		cmd = "PROXY-UPDATE-SETUP"
	default:
		return ds, false
	}
	return DelegationSyncRequest{
		Command:  cmd,
		ZoneName: ds.ZoneName,
		ZoneData: ds.ZoneData,
		Attempt:  ds.Attempt,
		FailedAt: ds.FailedAt,
	}, true
}

// mergeDelegationSyncRequests merges next, a request that has just arrived,
// into waiting, a request for the same zone with the same command that still
// waits in the parent's queue, and reports whether the two could be merged.
//
// This is what bounds a parent's queue without dropping a request or making a
// sender wait (#1002): a zone has at most one waiting request of each command
// that merges, however often the zone changes while its parent is slow, so a
// queue grows with the zones behind the parent, not with their changes.
//
// Only requests that work from the zone and the parent as they are when they
// run merge: EXPLICIT-SYNC-DELEGATION, REFRESH-SYNC-DELEGATION,
// DELEGATION-SYNC-SETUP, SIGNALS-EDITED, PROXY-UPDATE-SETUP and
// PROXY-UPDATE-GATE. The waiting one runs after next arrived, so it sees
// whatever next was queued for, and the two are one. SIGNALS-EDITED keeps the
// union of the edited types, which say what the run looks at.
//
// A stored change (SYNC-DELEGATION, PROXY-SYNC) never waits in the queue: it
// is sent at once or queued as a compare (delegationSyncLook). A request
// someone waits on (Response, DSResponse) is never merged: each waiter gets its
// own answer. Nor is SYNC-DNSKEY-RRSET, whose key sets are a snapshot of a
// multi-signer exchange, or a command not listed above.
//
// Nor are two requests for different instances of the zone: a retry for a
// copy that has since been replaced, and a compare of the replacement. The
// merged request would run on one of them, and the other's run would be lost.
// The lane still pins both to one lane by name, so they do not run at once.
//
// The merged request keeps the fresher retry counts of the two: a new trigger
// that joins a retry gives the zone its shortest wait again, as it would have
// had if queued on its own. Its FailedAt is apart from that: see
// mergedFailedAt.
func mergeDelegationSyncRequests(waiting, next DelegationSyncRequest) (DelegationSyncRequest, bool) {
	if waiting.Command != next.Command || !delegationSyncMerges(waiting) || !delegationSyncMerges(next) {
		return waiting, false
	}
	if waiting.ZoneData != nil && next.ZoneData != nil && waiting.ZoneData != next.ZoneData {
		return waiting, false
	}
	merged := waiting
	if next.ZoneData != nil {
		merged.ZoneData = next.ZoneData
	}
	if next.Command == "SIGNALS-EDITED" {
		merged.SignalTypes = unionSignalTypes(waiting.SignalTypes, next.SignalTypes)
	}
	merged.Attempt = min(waiting.Attempt, next.Attempt)
	merged.FailedAt = mergedFailedAt(waiting, next)
	if next.ReBootstrapRound < merged.ReBootstrapRound {
		merged.ReBootstrapRound = next.ReBootstrapRound
	}
	return merged, true
}

// mergedFailedAt is the FailedAt of the request that merges a and b. A retry
// is dropped when a sync of the zone has succeeded since the failure it
// retries (delegationSyncRetrySuperseded). The merged request stands for both,
// so it may be dropped only when both would have been: it keeps the later
// failure. A fresh trigger in the merge (Attempt 0) is never dropped, and
// neither is the merged request, which has its Attempt 0.
//
// It used to take the FailedAt of the request with fewer attempts, and the
// waiting one's on a tie. A refresh that failed, then a sync that succeeded,
// then a refresh that failed after a glue change: the two retries, each at
// attempt 1, merged into one with the first failure's time, which the success
// supersedes, and the glue change was never retried.
func mergedFailedAt(a, b DelegationSyncRequest) time.Time {
	if a.Attempt == 0 || b.Attempt == 0 {
		return time.Time{}
	}
	if b.FailedAt.After(a.FailedAt) {
		return b.FailedAt
	}
	return a.FailedAt
}

// delegationSyncMayBeOvertaken reports whether ds, waiting in its zone's queue,
// may have a later request of the zone merged into one ahead of it: ds then
// runs after what that request brought instead of before it
// (delegationSyncLane.merge). Only a live reconciliation may.
// EXPLICIT-SYNC-DELEGATION, REFRESH-SYNC-DELEGATION and SIGNALS-EDITED read
// the zone, its keys and the parent when they run, and do what those call for
// then, so running later only means they see more.
//
// Nothing else may be overtaken. Not a request a caller waits on: it answers
// what it finds when it runs, and the zone's requests that arrived before it
// run before it, those after it after. That is run order, not a view of the
// zone as it was when the request arrived: a compare reads the zone as it is
// when it runs, so one that runs before a status request may send a change
// that arrived after it, and the status then reports the parent with it. And
// not a setup (DELEGATION-SYNC-SETUP,
// PROXY-UPDATE-SETUP, PROXY-UPDATE-GATE): what is moved ahead of it could go
// to the parent before the key it needs is in place.
func delegationSyncMayBeOvertaken(ds DelegationSyncRequest) bool {
	if ds.Response != nil || ds.DSResponse != nil {
		return false
	}
	switch ds.Command {
	case "EXPLICIT-SYNC-DELEGATION", "REFRESH-SYNC-DELEGATION", "SIGNALS-EDITED":
		return true
	}
	return false
}

// delegationSyncMerges reports whether ds is a request that may be merged
// with another of its command (mergeDelegationSyncRequests).
func delegationSyncMerges(ds DelegationSyncRequest) bool {
	if ds.Response != nil || ds.DSResponse != nil {
		return false
	}
	switch ds.Command {
	case "EXPLICIT-SYNC-DELEGATION", "REFRESH-SYNC-DELEGATION",
		"DELEGATION-SYNC-SETUP", "SIGNALS-EDITED",
		"PROXY-UPDATE-SETUP", "PROXY-UPDATE-GATE":
		return true
	}
	return false
}

func unionSignalTypes(a, b []uint16) []uint16 {
	out := slices.Clone(a)
	for _, t := range b {
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}
