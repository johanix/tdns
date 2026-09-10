/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"sort"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// What the SERVED zone holds for its delegations. This is the read half that
// DirectDelegationBackend has always done, factored out so that the adoption
// pass (delegation_adopt.go) -- and, in time, the childsync-proxy reconciler --
// can ask the same question of a zone this server does not author. Both
// helpers assume the caller holds zd.mu, as the direct backend does.

// servedDelegationChildrenLocked lists the names below the apex that carry an
// NS RRset, sorted. Occlusion is the caller's business: an NS RRset under an
// existing cut is listed too, as it always was here.
func (zd *ZoneData) servedDelegationChildrenLocked() ([]string, error) {
	ownerNames, err := zd.GetOwnerNames()
	if err != nil {
		return nil, fmt.Errorf("GetOwnerNames: %w", err)
	}
	var children []string
	for _, ownerName := range ownerNames {
		if core.EqualNames(ownerName, zd.ZoneName) {
			continue
		}
		owner, err := zd.GetOwner(ownerName)
		if err != nil {
			lg.Warn("servedDelegationChildrenLocked: cannot read an owner, skipping it", "zone", zd.ZoneName, "owner", ownerName, "err", err)
			continue
		}
		if owner == nil {
			continue
		}
		if _, ok := owner.RRtypes.Get(dns.TypeNS); ok {
			children = append(children, ownerName)
		}
	}
	sort.Strings(children)
	return children, nil
}

// servedDelegationDataLocked collects what the zone holds at and below
// childZone, keeping the RRs want accepts, grouped by owner and type.
func (zd *ZoneData) servedDelegationDataLocked(childZone string, want func(owner string, rrtype uint16) bool) (map[string]map[uint16][]dns.RR, error) {
	result := map[string]map[uint16][]dns.RR{}
	ownerNames, err := zd.GetOwnerNames()
	if err != nil {
		return nil, fmt.Errorf("GetOwnerNames: %w", err)
	}
	for _, ownerName := range ownerNames {
		// dns.IsSubDomain is true for the child name itself.
		if !dns.IsSubDomain(childZone, ownerName) {
			continue
		}
		owner, err := zd.GetOwner(ownerName)
		if err != nil {
			lg.Warn("servedDelegationDataLocked: cannot read an owner, skipping it", "zone", zd.ZoneName, "owner", ownerName, "err", err)
			continue
		}
		if owner == nil {
			continue
		}
		for _, rrtype := range owner.RRtypes.Keys() {
			if !want(ownerName, rrtype) {
				continue
			}
			rrset, ok := owner.RRtypes.Get(rrtype)
			if !ok || len(rrset.RRs) == 0 {
				continue
			}
			if result[ownerName] == nil {
				result[ownerName] = map[uint16][]dns.RR{}
			}
			result[ownerName][rrtype] = append(result[ownerName][rrtype], rrset.RRs...)
		}
	}
	return result, nil
}
