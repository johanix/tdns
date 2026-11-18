/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"slices"
	"time"

	"github.com/miekg/dns"
)

// mergeDelegationSyncRequests merges next, a request that has just arrived,
// into waiting, a request for the same zone with the same command that still
// waits in the parent's queue, and reports whether the two could be merged.
//
// This is what bounds a parent's queue without dropping a request or making a
// sender wait (#1002): a zone has at most one waiting request of each command
// that merges, however often the zone changes while its parent is slow, so a
// queue grows with the zones behind the parent, not with their changes. The
// merged request does what running the two, one after the other, would have
// done:
//
//   - A command that works from the zone and the parent as they are when it
//     runs carries nothing to merge: the waiting request runs after next
//     arrived, so it sees whatever next was queued for. These are
//     EXPLICIT-SYNC-DELEGATION, REFRESH-SYNC-DELEGATION,
//     DELEGATION-SYNC-SETUP, PROXY-UPDATE-SETUP and PROXY-UPDATE-GATE.
//   - SYNC-DELEGATION carries a difference: two merge only when neither
//     removes a record (mergeDelegationSyncDiffs).
//   - SIGNALS-EDITED takes the union of the edited types, and PROXY-SYNC the
//     union of the changed dimensions, its differences merged as for
//     SYNC-DELEGATION.
//
// A request someone waits on (Response, DSResponse) is never merged: each
// waiter gets its own answer. Nor is SYNC-DNSKEY-RRSET, whose key sets are a
// snapshot of a multi-signer exchange, or a command not listed above.
//
// The merged request keeps the fresher retry counts of the two: a new trigger
// that joins a retry close to its limit gives the zone its full retries again,
// as it would have had if queued on its own. Its FailedAt is apart from that
// budget: see mergedFailedAt.
func mergeDelegationSyncRequests(waiting, next DelegationSyncRequest) (DelegationSyncRequest, bool) {
	if waiting.Command != next.Command || !delegationSyncMerges(waiting) || !delegationSyncMerges(next) {
		return waiting, false
	}
	merged := waiting
	if next.ZoneData != nil {
		merged.ZoneData = next.ZoneData
	}
	switch next.Command {
	case "SYNC-DELEGATION":
		diff, ok := mergeDelegationSyncDiffs(waiting.SyncStatus, next.SyncStatus)
		if !ok {
			return waiting, false
		}
		merged.SyncStatus = diff
	case "SIGNALS-EDITED":
		merged.SignalTypes = unionSignalTypes(waiting.SignalTypes, next.SignalTypes)
	case "PROXY-SYNC":
		analysis, ok := mergeProxyAnalyses(waiting.ProxyAnalysis, next.ProxyAnalysis)
		if !ok {
			return waiting, false
		}
		merged.ProxyAnalysis = analysis
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
// what it finds when it runs. Not one that carries what it sends
// (SYNC-DELEGATION, PROXY-SYNC): its state was taken when it was queued, and
// sent after newer state it would put the older back. A live reconciliation
// merged ahead of a SYNC-DELEGATION would send the DS the keys call for now,
// and the stored DS after it. And not a setup (DELEGATION-SYNC-SETUP,
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
	case "SYNC-DELEGATION", "EXPLICIT-SYNC-DELEGATION", "REFRESH-SYNC-DELEGATION",
		"DELEGATION-SYNC-SETUP", "SIGNALS-EDITED",
		"PROXY-SYNC", "PROXY-UPDATE-SETUP", "PROXY-UPDATE-GATE":
		return true
	}
	return false
}

// mergeDelegationSyncDiffs is one difference that does what sending older and
// then newer does, and reports whether there is one: only when neither
// removes anything. Two that only add merge into the union of what they add,
// and a parent holds after the merged one what it would after the two.
//
// A difference that removes a record (an exact deletion, class NONE) is never
// merged with another (ok false), and the two are sent one after the other. A
// tdns parent refuses an UPDATE that deletes a record it does not hold, and
// nothing in it is applied (absentChildDeletesLocked, #843). Merged, the
// deletion and everything the other difference carries would go in one UPDATE,
// and a deletion the parent refuses would take the rest with it, though the
// rest would have been applied on its own. That holds for both orders: a
// record older adds and newer removes would be a deletion sent to a parent that
// never had older, since a request that waits has not been sent; and an
// addition merged into a request that also deletes is lost if the parent does
// not hold what is deleted. A retry sends the same UPDATE and fares no better.
//
// Whether a difference goes out as such a delta is decided when it is sent:
// by the transport the parent sync plan picks, and for UPDATE by the
// parent-update option (the API scheme and replace mode send whole RRsets). It
// is not known where the queue merges, so a deletion is not merged whatever
// the mode; that costs a queue entry, nothing else.
//
// The complete new delegation (replace mode) is newer's: it is computed from
// the zone as it was when newer was made. The exception is DS when newer has
// no opinion about it (NewDSKnown unset): older's DS then stands, as it would
// have after both were sent.
func mergeDelegationSyncDiffs(older, newer DelegationSyncStatus) (DelegationSyncStatus, bool) {
	if removesARecord(older) || removesARecord(newer) {
		return older, false
	}
	m := newer
	m.Adds = unionRecords(older.Adds, newer.Adds)
	m.NsAdds = unionRecords(older.NsAdds, newer.NsAdds)
	m.AAdds = unionRecords(older.AAdds, newer.AAdds)
	m.AAAAAdds = unionRecords(older.AAAAAdds, newer.AAAAAdds)
	m.DNSKEYAdds = unionRecords(older.DNSKEYAdds, newer.DNSKEYAdds)
	m.DSAdds = unionRecords(older.DSAdds, newer.DSAdds)
	if !newer.NewDSKnown {
		m.NewDS, m.NewDSKnown = older.NewDS, older.NewDSKnown
	}
	m.InSync = older.InSync && newer.InSync
	m.Unread = older.Unread
	for _, u := range newer.Unread {
		if !slices.Contains(m.Unread, u) {
			m.Unread = append(m.Unread, u)
		}
	}
	return m, true
}

// removesARecord reports whether a difference removes anything.
func removesARecord(d DelegationSyncStatus) bool {
	return len(d.Removes)+len(d.NsRemoves)+len(d.ARemoves)+len(d.AAAARemoves)+
		len(d.DNSKEYRemoves)+len(d.DSRemoves) > 0
}

// unionRecords is older's records that newer does not also have, then newer's.
func unionRecords(older, newer []dns.RR) []dns.RR {
	var out []dns.RR
	for _, rr := range older {
		if !slices.ContainsFunc(newer, func(x dns.RR) bool { return sameRecord(x, rr) }) {
			out = append(out, rr)
		}
	}
	return append(out, newer...)
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

// mergeProxyAnalyses is the union of two PROXY-SYNC analyses: a dimension
// changed if either saw it change. ok is false when their differences are
// kept apart (mergeDelegationSyncDiffs).
func mergeProxyAnalyses(older, newer *ProxyDelegationAnalysis) (*ProxyDelegationAnalysis, bool) {
	if older == nil {
		return newer, true
	}
	if newer == nil {
		return older, true
	}
	diff, ok := mergeDelegationSyncDiffs(older.DelegationStatus, newer.DelegationStatus)
	if !ok {
		return older, false
	}
	m := *newer
	m.CdsChanged = older.CdsChanged || newer.CdsChanged
	m.CsyncChanged = older.CsyncChanged || newer.CsyncChanged
	m.NsOrGlueChanged = older.NsOrGlueChanged || newer.NsOrGlueChanged
	m.DnskeyChanged = older.DnskeyChanged || newer.DnskeyChanged
	m.KeyChanged = older.KeyChanged || newer.KeyChanged
	m.DelegationStatus = diff
	return &m, true
}
