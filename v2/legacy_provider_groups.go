package tdns

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

var lgProviderGroup = Logger("provider-group")

// ProviderGroup represents a set of providers that together serve a group of zones.
// The group is identified by a hash of the sorted member identities.
type ProviderGroup struct {
	GroupHash    string             // truncated SHA-256 of sorted member identities
	Name         string             // human-friendly name (resolved via naming protocol)
	Members      []string           // sorted provider identities (FQDNs)
	Zones        []ZoneName         // zones served by this exact set of providers
	NameProposal *GroupNameProposal // our proposal for this group's name
}

// GroupNameProposal is a name proposed by a provider for a group.
type GroupNameProposal struct {
	GroupHash  string    `json:"group_hash"`
	Name       string    `json:"name"`
	Proposer   string    `json:"proposer"`    // provider identity that chose the name
	ProposedAt time.Time `json:"proposed_at"` // when the name was chosen
}

// ProviderGroupManager manages provider group computation and naming.
type ProviderGroupManager struct {
	mu      sync.RWMutex
	Groups  map[string]*ProviderGroup // key: group hash
	LocalID string                    // our own identity
}

// NewProviderGroupManager creates a new provider group manager.
func NewProviderGroupManager(localIdentity string) *ProviderGroupManager {
	return &ProviderGroupManager{
		Groups:  make(map[string]*ProviderGroup),
		LocalID: localIdentity,
	}
}

// ComputeGroupHash computes a deterministic hash from a sorted,
// deduplicated list of provider identities. Uses length-prefixed
// encoding to prevent collisions (e.g., ["a","bb"] vs ["ab","b"]).
func ComputeGroupHash(identities []string) string {
	sorted := make([]string, len(identities))
	copy(sorted, identities)
	slices.Sort(sorted)
	// Deduplicate
	deduped := sorted[:0]
	for i, id := range sorted {
		if i == 0 || id != sorted[i-1] {
			deduped = append(deduped, id)
		}
	}
	h := sha256.New()
	for _, id := range deduped {
		// Length-prefix each identity to prevent concatenation collisions
		binary.Write(h, binary.BigEndian, uint16(len(id)))
		h.Write([]byte(id))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// RecomputeGroups scans all loaded zones, extracts HSYNC3 identity sets,
// and rebuilds the provider group map. This is a pure function of zone data.
func (pgm *ProviderGroupManager) RecomputeGroups() {
	// Step 1: For each zone, collect the set of provider identities from HSYNC3
	// Map: sorted identity set (as joined string) → list of zones
	type zoneGroup struct {
		identities []string
		zones      []ZoneName
	}
	groupMap := make(map[string]*zoneGroup) // key: joined sorted identities

	for zname, zd := range Zones.Items() {
		if !zd.Ready {
			continue
		}
		apex, err := zd.GetOwner(zd.ZoneName)
		if err != nil || apex == nil {
			lgProviderGroup.Warn("skipping zone due to apex lookup failure", "zone", zd.ZoneName, "err", err)
			continue
		}

		hsyncRRset := apex.RRtypes.GetOnlyRRSet(core.TypeHSYNC3)
		if len(hsyncRRset.RRs) == 0 {
			continue
		}

		// Extract identities from HSYNC3 records
		var identities []string
		for _, rr := range hsyncRRset.RRs {
			prr, ok := rr.(*dns.PrivateRR)
			if !ok {
				continue
			}
			h3, ok := prr.Data.(*core.HSYNC3)
			if !ok {
				continue
			}
			if h3.State == 0 { // OFF
				continue
			}
			identities = append(identities, h3.Identity)
		}

		if len(identities) < 2 {
			// Need at least 2 providers for a group
			continue
		}

		slices.Sort(identities)
		key := strings.Join(identities, ",")

		if zg, exists := groupMap[key]; exists {
			zg.zones = append(zg.zones, ZoneName(zname))
		} else {
			groupMap[key] = &zoneGroup{
				identities: identities,
				zones:      []ZoneName{ZoneName(zname)},
			}
		}
	}

	// Step 2: Build provider groups
	newGroups := make(map[string]*ProviderGroup)
	for _, zg := range groupMap {
		hash := ComputeGroupHash(zg.identities)

		// Sort zones for deterministic output
		sort.Slice(zg.zones, func(i, j int) bool {
			return zg.zones[i] < zg.zones[j]
		})

		pg := &ProviderGroup{
			GroupHash: hash,
			Members:   zg.identities,
			Zones:     zg.zones,
			Name:      hash[:8], // default: truncated hash until naming resolves
		}

		// Preserve existing name proposal if we had one
		newGroups[hash] = pg
	}

	// Step 3: Merge with existing groups (preserve name proposals)
	pgm.mu.Lock()
	defer pgm.mu.Unlock()

	for hash, pg := range newGroups {
		if existing, ok := pgm.Groups[hash]; ok {
			pg.NameProposal = existing.NameProposal
			pg.Name = existing.Name
		}
	}
	pgm.Groups = newGroups
}

// ProposeGroupName sets our name proposal for a group.
func (pgm *ProviderGroupManager) ProposeGroupName(groupHash, name string) {
	pgm.mu.Lock()
	defer pgm.mu.Unlock()

	pg, ok := pgm.Groups[groupHash]
	if !ok {
		return
	}
	pg.NameProposal = &GroupNameProposal{
		GroupHash:  groupHash,
		Name:       name,
		Proposer:   pgm.LocalID,
		ProposedAt: time.Now(),
	}
	pg.Name = name
}

// cloneProviderGroup returns a deep copy of a ProviderGroup.
func cloneProviderGroup(pg *ProviderGroup) *ProviderGroup {
	if pg == nil {
		return nil
	}
	cp := *pg
	cp.Members = append([]string(nil), pg.Members...)
	cp.Zones = append([]ZoneName(nil), pg.Zones...)
	if pg.NameProposal != nil {
		np := *pg.NameProposal
		cp.NameProposal = &np
	}
	return &cp
}

// GetGroups returns a snapshot of all current provider groups.
func (pgm *ProviderGroupManager) GetGroups() []*ProviderGroup {
	pgm.mu.RLock()
	defer pgm.mu.RUnlock()

	groups := make([]*ProviderGroup, 0, len(pgm.Groups))
	for _, pg := range pgm.Groups {
		groups = append(groups, cloneProviderGroup(pg))
	}

	sort.Slice(groups, func(i, j int) bool {
		return groups[i].GroupHash < groups[j].GroupHash
	})
	return groups
}

// GetGroup returns a specific provider group by hash.
func (pgm *ProviderGroupManager) GetGroup(groupHash string) *ProviderGroup {
	pgm.mu.RLock()
	defer pgm.mu.RUnlock()
	return cloneProviderGroup(pgm.Groups[groupHash])
}

// GetGroupByName returns a provider group by its human-friendly name.
func (pgm *ProviderGroupManager) GetGroupByName(name string) *ProviderGroup {
	pgm.mu.RLock()
	defer pgm.mu.RUnlock()
	for _, pg := range pgm.Groups {
		if pg.Name == name {
			return cloneProviderGroup(pg)
		}
	}
	return nil
}

// GetGroupsForIdentity returns all groups that include the given identity.
func (pgm *ProviderGroupManager) GetGroupsForIdentity(identity string) []*ProviderGroup {
	pgm.mu.RLock()
	defer pgm.mu.RUnlock()

	var result []*ProviderGroup
	for _, pg := range pgm.Groups {
		for _, member := range pg.Members {
			if member == identity {
				result = append(result, cloneProviderGroup(pg))
				break
			}
		}
	}
	return result
}

// GetGroupForZone returns the provider group that contains the given zone.
func (pgm *ProviderGroupManager) GetGroupForZone(zone ZoneName) *ProviderGroup {
	pgm.mu.RLock()
	defer pgm.mu.RUnlock()
	for _, pg := range pgm.Groups {
		for _, z := range pg.Zones {
			if z == zone {
				return cloneProviderGroup(pg)
			}
		}
	}
	return nil
}

// GroupSummary returns a compact string representation for logging.
func (pg *ProviderGroup) GroupSummary() string {
	memberStr := strings.Join(pg.Members, ", ")
	return fmt.Sprintf("group %s (%s): %d zones, members: [%s]",
		pg.Name, pg.GroupHash[:8], len(pg.Zones), memberStr)
}
