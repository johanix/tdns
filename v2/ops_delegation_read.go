/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"sort"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// ApiZoneGetDelegation answers "what does this parent currently hold for this
// child" over the management API.
//
// With no child named it answers the question that comes first: which children
// this parent has delegation data for. A client reconciling its own store
// against the server needs both -- the list to know what to ask about, and the
// per-child data to compare -- and both have to come from the same
// authenticated channel as the writes, or the comparison is against a
// different view of the world.
//
// The answer comes from the zone's DelegationBackend rather than from the zone
// data directly, so it reports what the SERVER considers current. Those differ
// on purpose for a backend that records delegations somewhere other than the
// served zone, and a client that reads the zone instead would silently get the
// wrong answer there.
func (zd *ZoneData) ApiZoneGetDelegation(zp ZonePost) (*ChildDelegationReport, error) {
	backend := zd.DelegationBackend
	if backend == nil {
		// Not an internal error: a zone that does not accept child updates has
		// no delegation backend by design, and saying so is more useful than
		// an empty result that reads as "this child has no delegation".
		return nil, fmt.Errorf("zone %s has no delegation backend"+
			" (it does not accept child updates)", zd.ZoneName)
	}

	child := dns.Fqdn(strings.TrimSpace(zp.ChildZone))
	if child == "." {
		children, err := backend.ListChildren(zd.ZoneName)
		if err != nil {
			return nil, fmt.Errorf("listing children of %s: %w", zd.ZoneName, err)
		}
		sort.Strings(children)
		out := &ChildDelegationReport{
			Parent:  zd.ZoneName,
			Backend: backend.Name(),
			RRsets:  map[string]map[string][]string{},
		}
		for _, c := range children {
			out.RRsets[c] = nil
		}
		return out, nil
	}

	if !dns.IsSubDomain(zd.ZoneName, child) {
		return nil, fmt.Errorf("%s is not below %s", child, zd.ZoneName)
	}
	if core.EqualNames(child, zd.ZoneName) {
		return nil, fmt.Errorf("%s is the zone apex, not a delegated child", child)
	}

	raw, err := backend.GetDelegationData(zd.ZoneName, child)
	if err != nil {
		return nil, err
	}

	out := &ChildDelegationReport{
		Parent:  zd.ZoneName,
		Child:   child,
		Backend: backend.Name(),
		RRsets:  make(map[string]map[string][]string, len(raw)),
	}
	for owner, byType := range raw {
		for rrtype, rrs := range byType {
			if len(rrs) == 0 {
				continue
			}
			name := dns.TypeToString[rrtype]
			if name == "" {
				name = fmt.Sprintf("TYPE%d", rrtype)
			}
			if out.RRsets[owner] == nil {
				out.RRsets[owner] = map[string][]string{}
			}
			strs := make([]string, 0, len(rrs))
			for _, rr := range rrs {
				if rr != nil {
					strs = append(strs, rr.String())
				}
			}
			// Sorted so two reads of unchanged data compare equal. A client
			// diffing its own store against this should not see a difference
			// that is only map iteration order.
			sort.Strings(strs)
			out.RRsets[owner][name] = strs
		}
	}
	return out, nil
}
