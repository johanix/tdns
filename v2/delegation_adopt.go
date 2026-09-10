/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"sort"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A delegation store that starts empty is a live hazard. The scanner reads a
// child's CURRENT delegation from the store, not from the zone (scanner.go,
// the DS read and the NS/glue read), precisely so that a parent handing its
// delegation data out of process still computes correct diffs. On a fresh
// parent with a db or zonefile backend the store holds nothing for a child
// that has had a delegation for years, so the first CSYNC or CDS diff runs
// against an empty current state: every record the child serves is an add,
// and nothing is ever a remove. The code has said for some time that the
// backend is mandatory for exactly this reason; nothing seeded it.
//
// The adoption pass closes that. Once, for every delegation point the served
// zone carries, if the store has no rows for that child, what the zone holds
// is written in -- marked origin=observed, so a later audit can tell what this
// server saw from what a child asserted. A child that already has rows is left
// alone: the store is the intended state, and an observation must never
// overwrite an assertion.
//
// Design: docs/2026-09-08-childsync-proxy.md D-3 and C-0.

// DelegationAdopter is implemented by delegation stores that can record what
// the served zone holds for a child they have no rows for. The direct backend
// does not implement it: the served zone IS its store.
type DelegationAdopter interface {
	// AdoptChildDelegation inserts rrs for childZone, marked origin=observed,
	// if and only if the store holds no rows for that child. Returns the
	// number of rows inserted; 0 means the child already had rows and nothing
	// was written.
	AdoptChildDelegation(parentZone, childZone string, rrs []dns.RR) (int, error)
}

// AdoptServedDelegations seeds this zone's delegation store from the served
// zone. Reports how many children were adopted and how many rows that took.
// Idempotent: a child with rows is never touched, so every run after the first
// is a no-op.
func (zd *ZoneData) AdoptServedDelegations() (children, rows int, err error) {
	if zd == nil || zd.DelegationBackend == nil {
		return 0, 0, nil
	}
	adopter, ok := zd.DelegationBackend.(DelegationAdopter)
	if !ok {
		lg.Debug("AdoptServedDelegations: the backend keeps no store of its own, nothing to seed",
			"zone", zd.ZoneName, "backend", zd.DelegationBackend.Name())
		return 0, 0, nil
	}
	if !zd.HasPublishedData() {
		return 0, 0, nil
	}

	// Read under the lock, write outside it: the store is a database, and a
	// database round trip is not something to hold the zone's lock across.
	type observed struct {
		child string
		rrs   []dns.RR
	}
	var todo []observed
	zd.mu.Lock()
	names, err := zd.servedDelegationChildrenLocked()
	if err == nil {
		for _, child := range delegationPoints(names) {
			data, derr := zd.servedDelegationDataLocked(child, adoptableDelegationRR(child))
			if derr != nil {
				err = derr
				break
			}
			todo = append(todo, observed{child: child, rrs: flattenDelegationData(data)})
		}
	}
	zd.mu.Unlock()
	if err != nil {
		return 0, 0, fmt.Errorf("reading the served delegations of %s: %w", zd.ZoneName, err)
	}

	for _, o := range todo {
		n, aerr := adopter.AdoptChildDelegation(zd.ZoneName, o.child, o.rrs)
		if aerr != nil {
			return children, rows, fmt.Errorf("adopting %s: %w", o.child, aerr)
		}
		if n == 0 {
			continue
		}
		children++
		rows += n
		lg.Info("adopted a delegation from the served zone into the delegation store",
			"zone", zd.ZoneName, "child", o.child, "rows", n)
	}
	return children, rows, nil
}

// adoptableDelegationRR is what the parent holds FOR a child: NS and DS at the
// delegation point, and address records at or below it (glue). Anything else
// below a cut is occluded data the parent does not serve and is not the
// authority for.
func adoptableDelegationRR(child string) func(owner string, rrtype uint16) bool {
	return func(owner string, rrtype uint16) bool {
		switch rrtype {
		case dns.TypeNS, dns.TypeDS:
			return core.EqualNames(owner, child)
		case dns.TypeA, dns.TypeAAAA:
			return true
		}
		return false
	}
}

// delegationPoints drops every name that lies below another name in the set.
// An NS RRset under an existing cut is occluded: it belongs to that child's
// zone, and adopting it would record a delegation this parent does not make.
func delegationPoints(names []string) []string {
	byDepth := append([]string(nil), names...)
	sort.SliceStable(byDepth, func(i, j int) bool {
		return dns.CountLabel(byDepth[i]) < dns.CountLabel(byDepth[j])
	})
	var out []string
	for _, n := range byDepth {
		occluded := false
		for _, cut := range out {
			if !core.EqualNames(n, cut) && dns.IsSubDomain(cut, n) {
				occluded = true
				break
			}
		}
		if !occluded {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// flattenDelegationData turns the per-owner, per-type map into one slice in a
// stable order, so what gets written -- and what a test sees -- does not
// depend on map iteration.
func flattenDelegationData(data map[string]map[uint16][]dns.RR) []dns.RR {
	owners := make([]string, 0, len(data))
	for o := range data {
		owners = append(owners, o)
	}
	sort.Strings(owners)
	var out []dns.RR
	for _, o := range owners {
		types := make([]int, 0, len(data[o]))
		for t := range data[o] {
			types = append(types, int(t))
		}
		sort.Ints(types)
		for _, t := range types {
			out = append(out, data[o][uint16(t)]...)
		}
	}
	return out
}

const delegationSeedWarningPrefix = "the delegation store could not be seeded from the served zone: "

// seedDelegationStore is the adoption pass as SetupZoneSync runs it. A failure
// is an operator-visible warning on the zone rather than a reason not to bring
// the rest of delegation sync up, and a later success clears exactly that
// warning and no other.
func (zd *ZoneData) seedDelegationStore() {
	children, rows, err := zd.AdoptServedDelegations()
	if err != nil {
		lg.Error("SetupZoneSync: could not seed the delegation store from the served zone",
			"zone", zd.ZoneName, "err", err)
		zd.SetError(DelegationSyncWarning, "%s%v", delegationSeedWarningPrefix, err)
		return
	}
	zd.clearDelegationSeedWarning()
	if children > 0 {
		lg.Info("SetupZoneSync: seeded the delegation store from the served zone",
			"zone", zd.ZoneName, "backend", zd.DelegationBackend.Name(), "children", children, "rows", rows)
	}
}

// clearDelegationSeedWarning clears the seed warning, and only the seed
// warning: DelegationSyncWarning is one category shared by several sources,
// and a success here says nothing about the others.
func (zd *ZoneData) clearDelegationSeedWarning() {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if ze, ok := zd.Errors[DelegationSyncWarning]; ok && strings.HasPrefix(ze.Msg, delegationSeedWarningPrefix) {
		zd.clearErrorLocked(DelegationSyncWarning)
	}
}
