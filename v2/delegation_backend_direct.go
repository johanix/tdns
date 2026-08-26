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
	updated, err := b.zd.ApplyChildUpdateToZoneData(ur, b.kdb)
	if err != nil {
		return err
	}
	if !updated {
		return nil
	}
	// The change is already durable: ApplyChildUpdateToZoneData publishes,
	// and the publish path persists a delta (Phase 2 — see the wsPersistDelta
	// assignment there, and PersistZoneDelta in publishWorkingSetLocked). The
	// journal is what carries a child update across a restart, exactly as it
	// does for every other kind of change.
	//
	// So writing the zone file here is not persistence, it is an eager FOLD of
	// that journal: WriteZone rewrites the whole file and deletes the deltas
	// up to that serial. On a parent that accepts delegation updates at any
	// rate, that is a full zone-file rewrite per update, and it defeats the
	// mechanism the journal exists to provide. Folding is "zone sync"'s job,
	// on the operator's schedule.
	//
	// Two cases still want the eager write, and they are the same two the
	// ZONE-UPDATE path uses (see the apiPrimary write in zone_updater.go,
	// which calls itself the mirror of this one):
	//
	//   - an API-managed primary, whose content has no other on-disk home;
	//   - no journal to carry it — `journal: active: false`, or no keystore —
	//     where memory really would be the only copy.
	if b.zd.Zonefile == "" {
		lg.Debug("DirectDelegationBackend: no source zonefile, skipping persist", "zone", b.zd.ZoneName)
		return nil
	}
	b.zd.mu.Lock()
	apiManaged := b.zd.Options[OptApiManagedZone]
	b.zd.mu.Unlock()
	if !apiManaged && JournalActive() && b.kdb != nil {
		lg.Debug("DirectDelegationBackend: change is in the journal; leaving the zone file to 'zone sync'",
			"zone", b.zd.ZoneName, "file", b.zd.Zonefile)
		return nil
	}
	msg, werr := b.zd.WriteZone(true, false)
	if werr != nil {
		// Propagate the persistence failure. The in-memory state did
		// receive the update, but the zonefile didn't — and if the
		// daemon restarts before the next successful update lands, the
		// change is lost on reload and the scanner will rediscover the
		// "missing" delegation and re-accumulate. Surface the error
		// upstream so operators see it and can act.
		lg.Warn("DirectDelegationBackend: failed to persist zone after CHILD-UPDATE", "zone", b.zd.ZoneName, "file", b.zd.Zonefile, "error", werr)
		return fmt.Errorf("persist zone after CHILD-UPDATE: %w", werr)
	}
	lg.Info("DirectDelegationBackend: persisted zone after CHILD-UPDATE", "zone", b.zd.ZoneName, "msg", msg)
	return nil
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
