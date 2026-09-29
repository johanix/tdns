/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"sort"
	"time"

	core "github.com/johanix/tdns/v2/core"
)

// AuthServerStats is one AuthServer instance's transport-usage counters, with
// what is needed to read them per server rather than per zone.
//
// The counters live on the instance, and there is one shared instance per
// nameserver name (AuthServerMap) whatever the number of zones it serves. So a
// per-zone listing repeats the same counters under every zone; this is the
// listing that shows each of them once. A stub zone's servers are the
// exception: each is a private instance (see AddStub), counted apart from the
// shared instance of the same name, and reported as its own entry.
type AuthServerStats struct {
	Name    string
	Src     string                   // "answer", "glue", "hint", "priming", "stub", ...
	Shared  bool                     // the AuthServerMap instance, shared by every zone the name serves
	Zones   []string                 // the zones whose ServerMap lists this instance, sorted
	Weights map[core.Transport]uint8 // the transport signal; nil when there was none
	TransportStats
}

// AuthServerStats snapshots the transport-usage counters of every AuthServer
// instance, once each, and returns them sorted by name with the start of the
// counting period. With reset, each instance's counters are cleared in the same
// step as its snapshot and a new period starts: all of them, always -- the
// counters the per-zone listings show are the same ones.
func (rrcache *RRsetCacheT) AuthServerStats(reset bool) (time.Time, []AuthServerStats) {
	rrcache.statsMu.Lock()
	defer rrcache.statsMu.Unlock()

	type entry struct {
		as     *AuthServer
		shared bool
		zones  []string
	}
	byInstance := map[*AuthServer]*entry{}
	var order []*AuthServer
	add := func(as *AuthServer) *entry {
		e, ok := byInstance[as]
		if !ok {
			e = &entry{as: as}
			byInstance[as] = e
			order = append(order, as)
		}
		return e
	}
	// The shared instances first, so that one no zone lists any more (its
	// ServerMap entry expired) is still reported: its counters are still there.
	for item := range rrcache.AuthServerMap.IterBuffered() {
		if item.Val != nil {
			add(item.Val).shared = true
		}
	}
	for item := range rrcache.ServerMap.IterBuffered() {
		for _, as := range item.Val {
			if as != nil {
				e := add(as)
				e.zones = append(e.zones, item.Key)
			}
		}
	}

	since := rrcache.statsSince
	out := make([]AuthServerStats, 0, len(order))
	for _, as := range order {
		e := byInstance[as]
		sort.Strings(e.zones)
		s := AuthServerStats{
			Name:    as.Name,
			Src:     as.GetSrc(),
			Shared:  e.shared,
			Zones:   e.zones,
			Weights: as.GetTransportWeights(),
		}
		if reset {
			s.TransportStats = as.TakeTransportStats()
		} else {
			s.TransportStats = as.SnapshotTransportStats()
		}
		out = append(out, s)
	}
	if reset {
		rrcache.statsSince = time.Now()
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Shared && !out[j].Shared
	})
	return since, out
}
