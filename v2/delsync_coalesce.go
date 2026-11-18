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
//   - SYNC-DELEGATION carries a difference: see mergeDelegationSyncDiffs,
//     which keeps two apart when one difference would not do what the two
//     do.
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
// then newer does, and reports whether there is one. For each record the
// later of the two operations wins. A record older removes and newer adds is
// an addition: the parent held it before older, and adding a record the parent
// holds changes nothing in an UPDATE (RFC 2136 §3.4.2.2).
//
// A record older adds and newer removes is not merged (ok false), and the two
// are sent one after the other. The merged difference would carry the
// removal without the addition, to a parent that has not had older, since a
// request that waits has not been sent. The parent does not hold the record,
// and a tdns parent refuses an UPDATE that deletes a record it does not hold,
// with everything else in it (absentChildDeletesLocked, #843): what newer adds
// beside the removal would never reach it.
//
// The complete new delegation (replace mode) is newer's: it is computed from
// the zone as it was when newer was made. The exception is DS when newer has
// no opinion about it (NewDSKnown unset): older's DS then stands, as it would
// have after both were sent.
func mergeDelegationSyncDiffs(older, newer DelegationSyncStatus) (DelegationSyncStatus, bool) {
	for _, p := range [][2][]dns.RR{
		{older.Adds, newer.Removes}, {older.NsAdds, newer.NsRemoves},
		{older.AAdds, newer.ARemoves}, {older.AAAAAdds, newer.AAAARemoves},
		{older.DNSKEYAdds, newer.DNSKEYRemoves}, {older.DSAdds, newer.DSRemoves},
	} {
		if removesAnAddition(p[0], p[1]) {
			return older, false
		}
	}
	m := newer
	m.Adds, m.Removes = laterOperationWins(older.Adds, older.Removes, newer.Adds, newer.Removes)
	m.NsAdds, m.NsRemoves = laterOperationWins(older.NsAdds, older.NsRemoves, newer.NsAdds, newer.NsRemoves)
	m.AAdds, m.ARemoves = laterOperationWins(older.AAdds, older.ARemoves, newer.AAdds, newer.ARemoves)
	m.AAAAAdds, m.AAAARemoves = laterOperationWins(older.AAAAAdds, older.AAAARemoves, newer.AAAAAdds, newer.AAAARemoves)
	m.DNSKEYAdds, m.DNSKEYRemoves = laterOperationWins(older.DNSKEYAdds, older.DNSKEYRemoves, newer.DNSKEYAdds, newer.DNSKEYRemoves)
	m.DSAdds, m.DSRemoves = laterOperationWins(older.DSAdds, older.DSRemoves, newer.DSAdds, newer.DSRemoves)
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

// removesAnAddition reports whether a record in removes is one in adds.
func removesAnAddition(adds, removes []dns.RR) bool {
	for _, rr := range removes {
		if slices.ContainsFunc(adds, func(x dns.RR) bool { return sameRecord(x, rr) }) {
			return true
		}
	}
	return false
}

// laterOperationWins merges two add/remove lists, older first: a record that
// newer adds or removes takes newer's operation, any other keeps older's.
func laterOperationWins(oldAdds, oldRemoves, newAdds, newRemoves []dns.RR) (adds, removes []dns.RR) {
	touched := func(rr dns.RR) bool {
		same := func(x dns.RR) bool { return sameRecord(x, rr) }
		return slices.ContainsFunc(newAdds, same) || slices.ContainsFunc(newRemoves, same)
	}
	for _, rr := range oldAdds {
		if !touched(rr) {
			adds = append(adds, rr)
		}
	}
	adds = append(adds, newAdds...)
	for _, rr := range oldRemoves {
		if !touched(rr) {
			removes = append(removes, rr)
		}
	}
	removes = append(removes, newRemoves...)
	return adds, removes
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
