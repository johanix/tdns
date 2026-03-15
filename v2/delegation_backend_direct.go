/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * DirectDelegationBackend applies child UPDATEs directly to in-memory zone data.
 * This is the original behavior for Primary zones.
 */
package tdns

import (
	"fmt"

	"github.com/miekg/dns"
)

type DirectDelegationBackend struct {
	zd  *ZoneData
	kdb *KeyDB
}

func (b *DirectDelegationBackend) Name() string { return "direct" }

func (b *DirectDelegationBackend) ApplyChildUpdate(parentZone string, ur UpdateRequest) error {
	_, err := b.zd.ApplyChildUpdateToZoneData(ur, b.kdb)
	return err
}

func (b *DirectDelegationBackend) GetDelegationData(parentZone, childZone string) (map[string]map[uint16][]dns.RR, error) {
	result := map[string]map[uint16][]dns.RR{}

	b.zd.mu.Lock()
	defer b.zd.mu.Unlock()

	ownerNames, err := b.zd.GetOwnerNames()
	if err != nil {
		return nil, fmt.Errorf("GetOwnerNames: %w", err)
	}

	// Walk all owners that are at or below the child zone name
	for _, ownerName := range ownerNames {
		if !dns.IsSubDomain(childZone, ownerName) && ownerName != childZone {
			continue
		}
		owner, err := b.zd.GetOwner(ownerName)
		if err != nil || owner == nil {
			continue
		}
		for _, rrtype := range owner.RRtypes.Keys() {
			// Only delegation-relevant types
			switch rrtype {
			case dns.TypeNS, dns.TypeDS, dns.TypeA, dns.TypeAAAA, dns.TypeCDS, dns.TypeKEY:
			default:
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

	if len(result) == 0 {
		return nil, fmt.Errorf("no delegation data for %s in zone %s", childZone, parentZone)
	}
	return result, nil
}

func (b *DirectDelegationBackend) ListChildren(parentZone string) ([]string, error) {
	children := map[string]bool{}

	b.zd.mu.Lock()
	defer b.zd.mu.Unlock()

	ownerNames, err := b.zd.GetOwnerNames()
	if err != nil {
		return nil, fmt.Errorf("GetOwnerNames: %w", err)
	}

	for _, ownerName := range ownerNames {
		if ownerName == b.zd.ZoneName {
			continue // skip apex
		}
		owner, err := b.zd.GetOwner(ownerName)
		if err != nil || owner == nil {
			continue
		}
		if _, ok := owner.RRtypes.Get(dns.TypeNS); ok {
			children[ownerName] = true
		}
	}

	var result []string
	for child := range children {
		result = append(result, child)
	}
	return result, nil
}
