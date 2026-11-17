/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"slices"

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
//   - SYNC-DELEGATION carries a difference: see mergeDelegationSyncDiffs.
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
// as it would have had if queued on its own.
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
		merged.SyncStatus = mergeDelegationSyncDiffs(waiting.SyncStatus, next.SyncStatus)
	case "SIGNALS-EDITED":
		merged.SignalTypes = unionSignalTypes(waiting.SignalTypes, next.SignalTypes)
	case "PROXY-SYNC":
		merged.ProxyAnalysis = mergeProxyAnalyses(waiting.ProxyAnalysis, next.ProxyAnalysis)
	}
	if next.Attempt < merged.Attempt {
		merged.Attempt, merged.FailedAt = next.Attempt, next.FailedAt
	}
	if next.ReBootstrapRound < merged.ReBootstrapRound {
		merged.ReBootstrapRound = next.ReBootstrapRound
	}
	return merged, true
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
// then newer does. For each record the later of the two operations wins:
// added in older and removed in newer is a removal, removed and then added is
// an addition. Adding a record the parent has, or removing one it lacks,
// changes nothing in an UPDATE (RFC 2136), so the merge leaves the parent as
// the two would have.
//
// The complete new delegation (replace mode) is newer's: it is computed from
// the zone as it was when newer was made. The exception is DS when newer has
// no opinion about it (NewDSKnown unset): older's DS then stands, as it would
// have after both were sent.
func mergeDelegationSyncDiffs(older, newer DelegationSyncStatus) DelegationSyncStatus {
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
	return m
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
// changed if either saw it change.
func mergeProxyAnalyses(older, newer *ProxyDelegationAnalysis) *ProxyDelegationAnalysis {
	if older == nil {
		return newer
	}
	if newer == nil {
		return older
	}
	m := *newer
	m.CdsChanged = older.CdsChanged || newer.CdsChanged
	m.CsyncChanged = older.CsyncChanged || newer.CsyncChanged
	m.NsOrGlueChanged = older.NsOrGlueChanged || newer.NsOrGlueChanged
	m.DnskeyChanged = older.DnskeyChanged || newer.DnskeyChanged
	m.KeyChanged = older.KeyChanged || newer.KeyChanged
	m.DelegationStatus = mergeDelegationSyncDiffs(older.DelegationStatus, newer.DelegationStatus)
	return &m
}
