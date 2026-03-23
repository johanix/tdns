/*
*
 */

package tdns

import (
	"fmt"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Named presets for allowed RRtypes. Hardcoded for safety.
// "apex-combiner": manages DNSKEY, CDS, CSYNC, NS, KEY at the zone apex.
// "delegation-combiner": (future) manages NS, DS, GLUE at delegation points.
var AllowedRRtypePresets = map[string]map[uint16]bool{
	"apex-combiner": {
		dns.TypeDNSKEY: true,
		dns.TypeCDS:    true,
		dns.TypeCSYNC:  true,
		dns.TypeNS:     true,
		dns.TypeKEY:    true,
	},
	// "delegation-combiner": { dns.TypeNS: true, dns.TypeDS: true, ... },
}

// AllowedLocalRRtypes is the active preset. Default: "apex-combiner".
var AllowedLocalRRtypes = AllowedRRtypePresets["apex-combiner"]

// providerZoneRRtypes caches the parsed allowed-RRtype map for each provider zone.
// Populated during config parsing via RegisterProviderZoneRRtypes.
var providerZoneRRtypes = map[string]map[uint16]bool{}

// RegisterProviderZoneRRtypes parses a ProviderZoneConf and registers its allowed
// RRtype map for use by the combiner policy engine.
func RegisterProviderZoneRRtypes(pz ProviderZoneConf) {
	zone := dns.Fqdn(pz.Zone)
	m := make(map[uint16]bool)
	for _, s := range pz.AllowedRRtypes {
		if t, ok := dns.StringToType[s]; ok {
			m[t] = true
		}
	}
	providerZoneRRtypes[zone] = m
}

// GetProviderZoneRRtypes returns the allowed RRtype map for a provider zone,
// or nil if the zone is not configured as a provider zone.
func GetProviderZoneRRtypes(zone string) map[uint16]bool {
	return providerZoneRRtypes[dns.Fqdn(zone)]
}

// Returns true if the zone data was modified.
func (zd *ZoneData) CombineWithLocalChanges() (bool, error) {
	modified := false
	if zd.CombinerData == nil {
		zd.Logger.Printf("CombineWithLocalChanges: Zone %s: No combiner data to apply", zd.ZoneName)
		return false, nil
	}

	switch zd.ZoneStore {
	case SliceZone:
		// TODO: Implement this
	case XfrZone:
		// TODO: Implement this
	case MapZone:
		// Determine RRtype whitelist: provider zones use their own, MP zones use the default.
		allowedRRtypes := AllowedLocalRRtypes
		isProvider := GetProviderZoneRRtypes(zd.ZoneName) != nil
		if isProvider {
			allowedRRtypes = GetProviderZoneRRtypes(zd.ZoneName)
		}

		// Iterate over all owners in the CombinerData
		for item := range zd.CombinerData.IterBuffered() {
			ownerName := item.Key
			newOwnerData := item.Val

			// MP zones: only apex records. Provider zones: any owner within the zone.
			if !isProvider && ownerName != zd.ZoneName {
				zd.Logger.Printf("CombineWithLocalChanges: Zone %s: LocalChanges outside apex (%s). Ignored", zd.ZoneName, ownerName)
				continue
			}

			// Get or create the owner in the main zone data
			existingOwnerData, exists := zd.Data.Get(ownerName)
			if !exists {
				existingOwnerData = OwnerData{
					Name:    ownerName,
					RRtypes: NewRRTypeStore(),
				}
			}

			// Apply RRsets for all RRtypes that exist in the combiner data
			for _, rrtype := range newOwnerData.RRtypes.Keys() {
				if zd.Debug {
					zd.Logger.Printf("CombineWithLocalChanges: Zone %s: Processing local change to owner %q RRtype %s", zd.ZoneName, ownerName, dns.TypeToString[rrtype])
				}
				if !allowedRRtypes[rrtype] {
					zd.Logger.Printf("CombineWithLocalChanges: Zone %s: RRtype %s is not allowed. Ignored", zd.ZoneName, dns.TypeToString[rrtype])
					continue
				}
				newRRset, _ := newOwnerData.RRtypes.Get(rrtype)
				if additiveRRtype(rrtype) && ownerName == zd.ZoneName {
					// ADD semantics: merge agent contributions on top of zone file baseline
					merged := zd.mergeWithUpstream(ownerName, rrtype, newRRset)
					existingOwnerData.RRtypes.Set(rrtype, merged)
				} else {
					// REPLACE semantics (existing behavior): DNSKEY, KEY, etc.
					existingOwnerData.RRtypes.Set(rrtype, newRRset)
				}
				modified = true
			}

			// Update the main zone data with the modified owner data
			zd.Data.Set(ownerName, existingOwnerData)
		}
		return modified, nil
	}

	return false, fmt.Errorf("not implemented")
}

// additiveRRtype returns true for RR types where agent contributions should be
// ADDED on top of the zone file baseline rather than REPLACING it.
func additiveRRtype(rrtype uint16) bool {
	return rrtype == dns.TypeNS
}

// mergeWithUpstream merges agent-contributed RRs on top of the zone file baseline
// from UpstreamData. Deduplicates by rr.String() (same approach as InjectSignatureTXT).
// If no upstream baseline exists, returns the agent RRset as-is.
func (zd *ZoneData) mergeWithUpstream(owner string, rrtype uint16, agentRRset core.RRset) core.RRset {
	merged := core.RRset{
		Name:   agentRRset.Name,
		RRtype: agentRRset.RRtype,
	}

	// Start with upstream baseline if available
	if zd.UpstreamData != nil {
		if upstreamOd, ok := zd.UpstreamData.Get(owner); ok {
			if baselineRRset, exists := upstreamOd.RRtypes.Get(rrtype); exists {
				merged.RRs = make([]dns.RR, len(baselineRRset.RRs))
				copy(merged.RRs, baselineRRset.RRs)
			}
		}
	}

	// Append agent contributions, dedup by rr.String()
	for _, rr := range agentRRset.RRs {
		rrStr := rr.String()
		alreadyPresent := false
		for _, existing := range merged.RRs {
			if existing.String() == rrStr {
				alreadyPresent = true
				break
			}
		}
		if !alreadyPresent {
			merged.RRs = append(merged.RRs, rr)
		}
	}

	return merged
}

// AddCombinerData adds or updates local RRsets for the zone from a specific agent.
// Contributions are stored per-agent so that updates from different agents are
// accumulated (not replaced). The merged result is then written to CombinerData.
// senderID identifies the contributing agent (use "local" for CLI-originated data).
//
// TODO: Add local/remote isolation policy. The policy must work at the individual RR
// level (not owner+rrtype), because multiple agents legitimately contribute to the
// same owner+rrtype (e.g. NS records from different providers at the apex).
// A local change must not delete or modify an RR contributed by a remote agent,
// and vice versa. The per-agent storage in AgentContributions already provides
// structural isolation; policy enforcement needs to happen at the RR level.
func (zd *ZoneData) AddCombinerData(senderID string, data map[string][]core.RRset) (bool, error) {
	zd.mu.Lock()
	defer zd.mu.Unlock()

	if zd.CombinerData == nil {
		zd.CombinerData = core.NewCmap[OwnerData]()
	}
	if zd.AgentContributions == nil {
		zd.AgentContributions = make(map[string]map[string]map[uint16]core.RRset)
	}

	if senderID == "" {
		senderID = "local"
	}

	// Initialize per-agent map if needed
	if zd.AgentContributions[senderID] == nil {
		zd.AgentContributions[senderID] = make(map[string]map[uint16]core.RRset)
	}

	// Merge this agent's contributions into existing data (accumulate, don't replace).
	// Each sync may carry only a delta, so we must add new RRs to any existing
	// contribution from the same agent rather than overwriting.
	changed := false
	for owner, rrsets := range data {
		if zd.AgentContributions[senderID][owner] == nil {
			zd.AgentContributions[senderID][owner] = make(map[uint16]core.RRset)
		}
		for _, rrset := range rrsets {
			if len(rrset.RRs) == 0 {
				continue
			}
			rrtype := rrset.RRs[0].Header().Rrtype
			existing, ok := zd.AgentContributions[senderID][owner][rrtype]
			if !ok {
				// First contribution for this agent/owner/rrtype
				zd.AgentContributions[senderID][owner][rrtype] = rrset
				changed = true
			} else {
				// Merge: add new RRs (deduplicated) into the existing contribution
				for _, rr := range rrset.RRs {
					prevLen := len(existing.RRs)
					existing.Add(rr)
					if len(existing.RRs) > prevLen {
						changed = true
					}
				}
				zd.AgentContributions[senderID][owner][rrtype] = existing
			}
		}
	}

	if !changed {
		return false, nil
	}

	// Rebuild CombinerData by merging contributions from ALL agents
	zd.rebuildCombinerData()

	// Persist this agent's contributions to the snapshot table
	if zd.PersistContributions != nil {
		if err := zd.PersistContributions(zd.ZoneName, senderID, zd.AgentContributions[senderID]); err != nil {
			zd.Logger.Printf("AddCombinerData: Zone %q: failed to persist contributions for %s: %v", zd.ZoneName, senderID, err)
			return changed, fmt.Errorf("persist contributions: %w", err)
		}
	}

	modified, err := zd.CombineWithLocalChanges()
	if err != nil {
		return changed, err
	}
	if modified {
		zd.Logger.Printf("AddCombinerData: Zone %q: Local changes applied immediately (from %s)", zd.ZoneName, senderID)
	}

	// Inject combiner signature TXT if configured
	if zd.InjectSignatureTXT(Conf.MultiProvider) {
		zd.Logger.Printf("AddCombinerData: Zone %q: Signature TXT injected", zd.ZoneName)
	}

	return true, nil
}

// rebuildCombinerData merges all per-agent contributions into CombinerData.
// For each owner/rrtype, RRs from all agents are combined into a single RRset,
// with deduplication based on the string representation of each RR.
func (zd *ZoneData) rebuildCombinerData() {
	if zd.CombinerData == nil {
		zd.CombinerData = core.NewCmap[OwnerData]()
	}

	// Collect all RRs per owner per rrtype from all agents
	// merged[owner][rrtype] → []dns.RR (deduplicated)
	type ownerRRtypes map[uint16][]dns.RR
	merged := make(map[string]ownerRRtypes)

	for agentID, ownerMap := range zd.AgentContributions {
		for owner, rrtypeMap := range ownerMap {
			if merged[owner] == nil {
				merged[owner] = make(ownerRRtypes)
			}
			for rrtype, rrset := range rrtypeMap {
				merged[owner][rrtype] = append(merged[owner][rrtype], rrset.RRs...)
				if zd.Debug {
					zd.Logger.Printf("rebuildCombinerData: Zone %s: agent %s contributes %d %s RRs for owner %q",
						zd.ZoneName, agentID, len(rrset.RRs), dns.TypeToString[rrtype], owner)
				}
			}
		}
	}

	// Build deduplicated CombinerData from merged contributions
	// Clear existing CombinerData
	zd.CombinerData = core.NewCmap[OwnerData]()

	for owner, rrtypeRRs := range merged {
		ownerData := OwnerData{
			Name:    owner,
			RRtypes: NewRRTypeStore(),
		}
		for rrtype, rrs := range rrtypeRRs {
			// Deduplicate RRs by their string representation
			seen := make(map[string]bool)
			var dedupRRs []dns.RR
			for _, rr := range rrs {
				key := rr.String()
				if !seen[key] {
					seen[key] = true
					dedupRRs = append(dedupRRs, rr)
				}
			}
			ownerData.RRtypes.Set(rrtype, core.RRset{
				Name:   owner,
				RRtype: rrtype,
				RRs:    dedupRRs,
			})
		}
		zd.CombinerData.Set(owner, ownerData)
	}

	if zd.Debug {
		// Log summary
		for owner, rrtypeRRs := range merged {
			for rrtype, rrs := range rrtypeRRs {
				zd.Logger.Printf("rebuildCombinerData: Zone %s: merged %s for %q: %d RRs from %d agents",
					zd.ZoneName, dns.TypeToString[rrtype], owner, len(rrs), len(zd.AgentContributions))
			}
		}
	}
}

// GetCombinerData retrieves all local combiner data for the zone
func (zd *ZoneData) GetCombinerData() (map[string][]core.RRset, error) {
	if zd.CombinerData == nil {
		return nil, fmt.Errorf("no local data exists for zone %s", zd.ZoneName)
	}

	result := make(map[string][]core.RRset)

	// Iterate over all owners in CombinerData
	for item := range zd.CombinerData.IterBuffered() {
		owner := item.Key
		ownerData := item.Val

		// Get all RRsets for this owner
		var rrsets []core.RRset
		for _, rrtype := range ownerData.RRtypes.Keys() {
			if rrset, ok := ownerData.RRtypes.Get(rrtype); ok {
				rrsets = append(rrsets, rrset)
			}
		}

		if len(rrsets) > 0 {
			result[owner] = rrsets
		}
	}

	return result, nil
}

// AddCombinerDataNG adds or updates local RRsets for the zone from a specific agent.
// The input map keys are owner names and values are slices of RR strings.
// senderID identifies the contributing agent (use "" for CLI-originated data).
func (zd *ZoneData) AddCombinerDataNG(senderID string, data map[string][]string) (bool, error) {
	// Convert string RRs to dns.RR objects and group them into RRsets
	rrsetData := make(map[string][]core.RRset)
	for owner, rrStrings := range data {
		var rrs []dns.RR
		for _, rrString := range rrStrings {
			rr, err := dns.NewRR(rrString)
			if err != nil {
				return false, fmt.Errorf("error parsing RR string %q: %v", rrString, err)
			}
			rrs = append(rrs, rr)
		}

		// Group RRs by type into RRsets
		rrsByType := make(map[uint16][]dns.RR)
		for _, rr := range rrs {
			rrtype := rr.Header().Rrtype
			rrsByType[rrtype] = append(rrsByType[rrtype], rr)
		}

		// Create RRsets
		var rrsets []core.RRset
		for rrtype, typeRRs := range rrsByType {
			rrsets = append(rrsets, core.RRset{
				Name:   owner,
				RRtype: rrtype,
				RRs:    typeRRs,
			})
		}
		rrsetData[owner] = rrsets
	}

	// Use the existing AddCombinerData method to store the data
	return zd.AddCombinerData(senderID, rrsetData)
}

// GetCombinerDataNG returns the combiner data in string format suitable for JSON marshaling
func (zd *ZoneData) GetCombinerDataNG() map[string][]RRsetString {
	responseData := make(map[string][]RRsetString)

	if zd.CombinerData == nil {
		return responseData
	}

	for owner, ownerData := range zd.CombinerData.Items() {
		var rrsets []RRsetString
		if ownerData.RRtypes != nil {
			for _, rrtype := range ownerData.RRtypes.Keys() {
				rrset, ok := ownerData.RRtypes.Get(rrtype)
				if !ok {
					continue
				}

				// Convert RRs to strings
				rrStrings := make([]string, len(rrset.RRs))
				for i, rr := range rrset.RRs {
					rrStrings[i] = rr.String()
				}

				// Convert RRSIGs to strings if present
				var rrsigStrings []string
				if len(rrset.RRSIGs) > 0 {
					rrsigStrings = make([]string, len(rrset.RRSIGs))
					for i, rrsig := range rrset.RRSIGs {
						rrsigStrings[i] = rrsig.String()
					}
				}

				rrsets = append(rrsets, RRsetString{
					Name:   rrset.Name,
					RRtype: rrtype,
					RRs:    rrStrings,
					RRSIGs: rrsigStrings,
				})
			}
		}
		responseData[owner] = rrsets
	}

	return responseData
}

// RemoveCombinerDataNG removes specific RRs from the agent's contributions.
// Input: senderID identifies the agent, data maps owner → RR strings (ClassINET format).
// Returns the list of RR strings that were actually removed. If an RR was already
// absent, it is not included in the returned list (true no-op detection).
func (zd *ZoneData) RemoveCombinerDataNG(senderID string, data map[string][]string) ([]string, error) {
	zd.mu.Lock()
	defer zd.mu.Unlock()

	if zd.AgentContributions == nil {
		return nil, nil
	}

	if senderID == "" {
		senderID = "local"
	}

	agentData, ok := zd.AgentContributions[senderID]
	if !ok {
		return nil, nil
	}

	var removedRecords []string

	for owner, rrStrings := range data {
		ownerMap, ok := agentData[owner]
		if !ok {
			continue
		}

		for _, rrStr := range rrStrings {
			// Parse to get the rrtype
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				zd.Logger.Printf("RemoveCombinerDataNG: Zone %s: Failed to parse RR %q: %v", zd.ZoneName, rrStr, err)
				continue
			}
			rrtype := rr.Header().Rrtype
			existing, ok := ownerMap[rrtype]
			if !ok {
				continue
			}

			// Remove the specific RR by string match
			var kept []dns.RR
			found := false
			for _, existingRR := range existing.RRs {
				if existingRR.String() == rrStr {
					found = true
					continue // Skip (remove) this one
				}
				kept = append(kept, existingRR)
			}

			if found {
				removedRecords = append(removedRecords, rrStr)
			}

			if len(kept) == 0 {
				delete(ownerMap, rrtype)
			} else {
				existing.RRs = kept
				ownerMap[rrtype] = existing
			}
		}

		// Clean up empty owner maps
		if len(ownerMap) == 0 {
			delete(agentData, owner)
		}
	}

	if len(removedRecords) == 0 {
		return nil, nil
	}

	// Rebuild merged CombinerData and apply to zone
	zd.rebuildCombinerData()

	// Persist this agent's contributions to the snapshot table
	if zd.PersistContributions != nil {
		if err := zd.PersistContributions(zd.ZoneName, senderID, zd.AgentContributions[senderID]); err != nil {
			zd.Logger.Printf("RemoveCombinerDataNG: Zone %q: failed to persist contributions for %s: %v", zd.ZoneName, senderID, err)
			return removedRecords, fmt.Errorf("persist contributions: %w", err)
		}
	}

	modified, err := zd.CombineWithLocalChanges()
	if err != nil {
		return removedRecords, err
	}
	if modified {
		zd.Logger.Printf("RemoveCombinerDataNG: Zone %q: Local changes applied after removal (from %s)", zd.ZoneName, senderID)
	}

	// Clean up rrtypes with no remaining agent contributions
	zd.cleanupRemovedRRtypes(data)

	if zd.InjectSignatureTXT(Conf.MultiProvider) {
		zd.Logger.Printf("RemoveCombinerDataNG: Zone %q: Signature TXT injected", zd.ZoneName)
	}

	return removedRecords, nil
}

// RemoveCombinerDataByRRtype removes all RRs of a given type from an agent's contributions
// for a specific owner. Used for ClassANY delete semantics.
// Returns the list of RR strings that were removed.
func (zd *ZoneData) RemoveCombinerDataByRRtype(senderID string, owner string, rrtype uint16) ([]string, error) {
	zd.mu.Lock()
	defer zd.mu.Unlock()

	if senderID == "" {
		senderID = "local"
	}

	var removedRecords []string

	if zd.AgentContributions == nil {
		return removedRecords, nil
	}

	agentData, ok := zd.AgentContributions[senderID]
	if !ok {
		return removedRecords, nil
	}

	ownerMap, ok := agentData[owner]
	if !ok {
		return removedRecords, nil
	}

	existing, ok := ownerMap[rrtype]
	if !ok {
		return removedRecords, nil
	}

	// Collect all RRs being removed
	for _, rr := range existing.RRs {
		removedRecords = append(removedRecords, rr.String())
	}

	// Remove the entire RRtype entry
	delete(ownerMap, rrtype)
	if len(ownerMap) == 0 {
		delete(agentData, owner)
	}

	// Rebuild merged CombinerData and apply to zone
	zd.rebuildCombinerData()

	// Persist this agent's contributions to the snapshot table
	if zd.PersistContributions != nil {
		if err := zd.PersistContributions(zd.ZoneName, senderID, zd.AgentContributions[senderID]); err != nil {
			zd.Logger.Printf("RemoveCombinerDataByRRtype: Zone %q: failed to persist contributions for %s: %v", zd.ZoneName, senderID, err)
			return removedRecords, fmt.Errorf("persist contributions: %w", err)
		}
	}

	modified, err := zd.CombineWithLocalChanges()
	if err != nil {
		return removedRecords, err
	}
	if modified {
		zd.Logger.Printf("RemoveCombinerDataByRRtype: Zone %q: Local changes applied after removal (from %s)", zd.ZoneName, senderID)
	}

	// Clean up if this rrtype has no remaining contributions from any agent
	zd.cleanupRemovedRRtype(owner, rrtype)

	if zd.InjectSignatureTXT(Conf.MultiProvider) {
		zd.Logger.Printf("RemoveCombinerDataByRRtype: Zone %q: Signature TXT injected", zd.ZoneName)
	}

	return removedRecords, nil
}

// ReplaceCombinerDataByRRtype atomically replaces an agent's contributions for a
// specific owner+rrtype with a new set of RRs. Returns the lists of actually
// added and removed RR strings, plus whether any change occurred.
// Used for "replace" operation semantics at the combiner level.
func (zd *ZoneData) ReplaceCombinerDataByRRtype(senderID, owner string, rrtype uint16, newRRs []dns.RR) (applied []string, removed []string, changed bool, err error) {
	zd.mu.Lock()
	defer zd.mu.Unlock()

	return zd.replaceCombinerDataByRRtypeLocked(senderID, owner, rrtype, newRRs)
}

func (zd *ZoneData) replaceCombinerDataByRRtypeLocked(senderID, owner string, rrtype uint16, newRRs []dns.RR) (applied []string, removed []string, changed bool, err error) {
	if senderID == "" {
		senderID = "local"
	}

	if zd.AgentContributions == nil {
		zd.AgentContributions = make(map[string]map[string]map[uint16]core.RRset)
	}
	if zd.AgentContributions[senderID] == nil {
		zd.AgentContributions[senderID] = make(map[string]map[uint16]core.RRset)
	}
	if zd.AgentContributions[senderID][owner] == nil {
		zd.AgentContributions[senderID][owner] = make(map[uint16]core.RRset)
	}

	oldRRset, hadOld := zd.AgentContributions[senderID][owner][rrtype]

	// Empty replacement set = delete entire RRset for this agent/owner/rrtype
	if len(newRRs) == 0 {
		if hadOld && len(oldRRset.RRs) > 0 {
			for _, rr := range oldRRset.RRs {
				removed = append(removed, rr.String())
			}
			delete(zd.AgentContributions[senderID][owner], rrtype)
			if len(zd.AgentContributions[senderID][owner]) == 0 {
				delete(zd.AgentContributions[senderID], owner)
			}
			changed = true
		}
		if !changed {
			return
		}
	} else {
		// Diff old vs new
		newSet := core.RRset{Name: owner, RRtype: rrtype, RRs: newRRs}

		// Find removed: in old but not in new
		if hadOld {
			for _, oldRR := range oldRRset.RRs {
				found := false
				for _, newRR := range newRRs {
					if dns.IsDuplicate(oldRR, newRR) {
						found = true
						break
					}
				}
				if !found {
					removed = append(removed, oldRR.String())
					changed = true
				}
			}
		}

		// Find added: in new but not in old
		for _, newRR := range newRRs {
			found := false
			if hadOld {
				for _, oldRR := range oldRRset.RRs {
					if dns.IsDuplicate(oldRR, newRR) {
						found = true
						break
					}
				}
			}
			if !found {
				applied = append(applied, newRR.String())
				changed = true
			}
		}

		if !changed {
			return
		}

		zd.AgentContributions[senderID][owner][rrtype] = newSet
	}

	// Rebuild merged CombinerData and apply to zone
	if zd.CombinerData == nil {
		zd.CombinerData = core.NewCmap[OwnerData]()
	}
	zd.rebuildCombinerData()

	if zd.PersistContributions != nil {
		if err = zd.PersistContributions(zd.ZoneName, senderID, zd.AgentContributions[senderID]); err != nil {
			zd.Logger.Printf("ReplaceCombinerDataByRRtype: Zone %q: failed to persist contributions for %s: %v", zd.ZoneName, senderID, err)
		}
	}

	modified, combErr := zd.CombineWithLocalChanges()
	if combErr != nil {
		err = combErr
		return
	}
	if modified {
		zd.Logger.Printf("ReplaceCombinerDataByRRtype: Zone %q: Local changes applied after replace (from %s)", zd.ZoneName, senderID)
	}

	// Clean up if no contributions remain for this rrtype
	zd.cleanupRemovedRRtype(owner, rrtype)

	if zd.InjectSignatureTXT(Conf.MultiProvider) {
		zd.Logger.Printf("ReplaceCombinerDataByRRtype: Zone %q: Signature TXT injected", zd.ZoneName)
	}

	return
}

// InjectSignatureTXT adds a combiner signature TXT record to the zone data.
// The record is placed at "hsync-signature.{zone}" to avoid conflicts with apex TXT records.
// Returns true if the signature was injected.
func (zd *ZoneData) InjectSignatureTXT(conf *MultiProviderConf) bool {
	if conf == nil || !conf.CombinerOptions[CombinerOptAddSignature] || conf.Signature == "" {
		return false
	}

	// Template expansion
	sig := strings.ReplaceAll(conf.Signature, "{identity}", conf.Identity)
	sig = strings.ReplaceAll(sig, "{zone}", zd.ZoneName)

	// Build the TXT RR at hsync-signature.{zone}
	ownerName := "hsync-signature." + zd.ZoneName
	rrStr := fmt.Sprintf("%s 300 IN TXT %q", ownerName, sig)
	rr, err := dns.NewRR(rrStr)
	if err != nil {
		zd.Logger.Printf("InjectSignatureTXT: Zone %s: Failed to parse TXT RR: %v", zd.ZoneName, err)
		return false
	}

	// Insert directly into zone data (bypasses CombinerData/apex-only filters)
	ownerData, exists := zd.Data.Get(ownerName)
	if !exists {
		ownerData = OwnerData{
			Name:    ownerName,
			RRtypes: NewRRTypeStore(),
		}
	}
	existing, hasExisting := ownerData.RRtypes.Get(dns.TypeTXT)
	if hasExisting {
		// Check if this exact RR is already present (avoid duplicates on repeated calls)
		rrStr := rr.String()
		alreadyPresent := false
		for _, existingRR := range existing.RRs {
			if existingRR.String() == rrStr {
				alreadyPresent = true
				break
			}
		}
		if !alreadyPresent {
			existing.RRs = append(existing.RRs, rr)
		}
	} else {
		existing = core.RRset{
			Name:   ownerName,
			RRtype: dns.TypeTXT,
			RRs:    []dns.RR{rr},
		}
	}
	ownerData.RRtypes.Set(dns.TypeTXT, existing)
	zd.Data.Set(ownerName, ownerData)
	return true
}

// snapshotUpstreamData captures the current apex RRsets for AllowedLocalRRtypes
// from zd.Data into zd.UpstreamData. Called after zone load/refresh, before
// CombineWithLocalChanges applies agent contributions.
func (zd *ZoneData) snapshotUpstreamData() {
	zd.UpstreamData = core.NewCmap[OwnerData]()

	// Only snapshot the apex owner (agent contributions only apply at apex)
	if apexOd, ok := zd.Data.Get(zd.ZoneName); ok {
		snapshotOd := OwnerData{
			Name:    zd.ZoneName,
			RRtypes: NewRRTypeStore(),
		}
		for _, rrtype := range apexOd.RRtypes.Keys() {
			if AllowedLocalRRtypes[rrtype] {
				rrset, _ := apexOd.RRtypes.Get(rrtype)
				// Deep copy the RR slice to avoid sharing references
				copiedRRs := make([]dns.RR, len(rrset.RRs))
				copy(copiedRRs, rrset.RRs)
				snapshotOd.RRtypes.Set(rrtype, core.RRset{
					Name:   rrset.Name,
					RRtype: rrset.RRtype,
					RRs:    copiedRRs,
				})
			}
		}
		zd.UpstreamData.Set(zd.ZoneName, snapshotOd)
	}
}

// restoreUpstreamRRset restores an rrtype from UpstreamData back into the zone.
// Used when all agent contributions for a mandatory rrtype (e.g. NS) are removed.
func (zd *ZoneData) restoreUpstreamRRset(owner string, rrtype uint16) {
	if zd.UpstreamData == nil {
		zd.Logger.Printf("restoreUpstreamRRset: Zone %q: No upstream data, cannot restore %s",
			zd.ZoneName, dns.TypeToString[rrtype])
		return
	}
	if od, ok := zd.UpstreamData.Get(owner); ok {
		if rrset, exists := od.RRtypes.Get(rrtype); exists {
			if zoneOd, ok := zd.Data.Get(owner); ok {
				zoneOd.RRtypes.Set(rrtype, rrset)
				zd.Data.Set(owner, zoneOd)
				zd.Logger.Printf("restoreUpstreamRRset: Zone %q: Restored original %s for %q (%d records)",
					zd.ZoneName, dns.TypeToString[rrtype], owner, len(rrset.RRs))
				return
			}
		}
	}
	zd.Logger.Printf("restoreUpstreamRRset: Zone %q: No upstream %s found for %q",
		zd.ZoneName, dns.TypeToString[rrtype], owner)
}

// cleanupRemovedRRtypes checks each owner+rrtype in data for remaining agent contributions.
// If no contributions remain: for NS at the apex, restore from upstream; otherwise delete from zone.
func (zd *ZoneData) cleanupRemovedRRtypes(data map[string][]string) {
	for owner, rrStrings := range data {
		for _, rrStr := range rrStrings {
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				continue
			}
			zd.cleanupRemovedRRtype(owner, rr.Header().Rrtype)
		}
	}
}

// cleanupRemovedRRtype checks if a single owner+rrtype still has agent contributions.
// If not: for NS at the apex, restore from upstream; otherwise delete from zone data.
func (zd *ZoneData) cleanupRemovedRRtype(owner string, rrtype uint16) {
	stillExists := false
	if zd.CombinerData != nil {
		if od, ok := zd.CombinerData.Get(owner); ok {
			if _, exists := od.RRtypes.Get(rrtype); exists {
				stillExists = true
			}
		}
	}
	if stillExists {
		return
	}
	if rrtype == dns.TypeNS && owner == zd.ZoneName {
		zd.restoreUpstreamRRset(owner, rrtype)
	} else {
		if od, ok := zd.Data.Get(owner); ok {
			od.RRtypes.Delete(rrtype)
			zd.Data.Set(owner, od)
			zd.Logger.Printf("cleanupRemovedRRtype: Zone %q: Removed %s from %q (no remaining contributions)",
				zd.ZoneName, dns.TypeToString[rrtype], owner)
		}
	}
}

// combinerReapplyContributions reloads contributions from the database and
// re-applies them to zone data. Works for both MP zones (contributions snapshot)
// and provider zones (contributions + publish instructions).
func combinerReapplyContributions(zone string, kdb *KeyDB) (string, error) {
	zd, ok := Zones.Get(zone)
	if !ok {
		return "", fmt.Errorf("zone %q not found", zone)
	}

	isProvider := GetProviderZoneRRtypes(zone) != nil
	var parts []string

	// 1. Reload AgentContributions from the CombinerContributions snapshot.
	allContribs, err := kdb.LoadAllContributions()
	if err != nil {
		return "", fmt.Errorf("failed to load contributions: %w", err)
	}

	zd.mu.Lock()
	if zoneContribs, ok := allContribs[zone]; ok {
		zd.AgentContributions = make(map[string]map[string]map[uint16]core.RRset)
		for senderID, ownerMap := range zoneContribs {
			zd.AgentContributions[senderID] = ownerMap
		}
		zd.rebuildCombinerData()
		parts = append(parts, fmt.Sprintf("loaded contributions from %d agent(s)", len(zoneContribs)))
	} else {
		zd.AgentContributions = make(map[string]map[string]map[uint16]core.RRset)
		parts = append(parts, "no contributions in snapshot")
	}

	// 2. For provider zones: re-apply _signal KEY records from publish instructions.
	if isProvider {
		allInstr, err := kdb.LoadAllPublishInstructions()
		if err != nil {
			zd.mu.Unlock()
			return "", fmt.Errorf("failed to load publish instructions: %w", err)
		}
		keyCount := 0
		for childZone, senders := range allInstr {
			for senderID, stored := range senders {
				if !containsString(stored.Locations, "at-ns") || len(stored.KEYRRs) == 0 {
					continue
				}
				for _, ns := range stored.PublishedNS {
					ownerName := Sig0KeyOwnerName(childZone, ns)
					providerZone := findProviderZoneForOwner(ownerName)
					if providerZone != zone {
						continue
					}
					var parsedRRs []dns.RR
					for _, rrStr := range stored.KEYRRs {
						rr, err := dns.NewRR(rrStr)
						if err != nil {
							continue
						}
						rr.Header().Name = ownerName
						parsedRRs = append(parsedRRs, rr)
					}
					zd.replaceCombinerDataByRRtypeLocked(senderID, ownerName, dns.TypeKEY, parsedRRs)
					keyCount++
				}
			}
		}
		if keyCount > 0 {
			parts = append(parts, fmt.Sprintf("applied %d _signal KEY record(s)", keyCount))
		}
	}

	// 3. For MP zones: re-apply at-apex KEY from publish instructions.
	if !isProvider {
		allInstr, err := kdb.LoadAllPublishInstructions()
		if err != nil {
			zd.mu.Unlock()
			return "", fmt.Errorf("failed to load publish instructions: %w", err)
		}
		if senders, ok := allInstr[zone]; ok {
			for senderID, stored := range senders {
				if !containsString(stored.Locations, "at-apex") || len(stored.KEYRRs) == 0 {
					continue
				}
				var parsedRRs []dns.RR
				for _, rrStr := range stored.KEYRRs {
					rr, err := dns.NewRR(rrStr)
					if err != nil {
						continue
					}
					parsedRRs = append(parsedRRs, rr)
				}
				zd.replaceCombinerDataByRRtypeLocked(senderID, zone, dns.TypeKEY, parsedRRs)
				parts = append(parts, fmt.Sprintf("applied at-apex KEY from %s", senderID))
			}
		}
	}
	zd.mu.Unlock()

	// 4. Apply to zone data.
	modified, err := zd.CombineWithLocalChanges()
	if err != nil {
		return "", fmt.Errorf("CombineWithLocalChanges failed: %w", err)
	}
	if modified {
		bumperResp, err := zd.BumpSerialOnly()
		if err != nil {
			parts = append(parts, "serial bump failed")
		} else {
			parts = append(parts, fmt.Sprintf("serial %d→%d", bumperResp.OldSerial, bumperResp.NewSerial))
		}
	}

	return fmt.Sprintf("Reapplied contributions for %s: %s", zone, strings.Join(parts, "; ")), nil
}
