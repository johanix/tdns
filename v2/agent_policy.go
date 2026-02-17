/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"log"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func (zdr *ZoneDataRepo) EvaluateUpdate(synchedDataUpdate *SynchedDataUpdate) (bool, string, error) {
	log.Printf("SynchedDataEngine: Evaluating update for zone %q from %q", synchedDataUpdate.Zone, synchedDataUpdate.AgentId)
	// 1. Evaluate the update for applicability (valid zone, etc)
	// 2. Evaluate the update according to policy.

	switch synchedDataUpdate.UpdateType {
	case "remote":
		for _, rrset := range synchedDataUpdate.Update.RRsets {
			for _, rr := range rrset.RRs {
				if !AllowedLocalRRtypes[rr.Header().Rrtype] {
					log.Printf("SynchedDataEngine: Invalid RR type: %s", rr.String())
					return false, fmt.Sprintf("Update for zone %q from %q: Invalid RR type: %s",
						synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rr.String()), nil
				}
				if !strings.EqualFold(rr.Header().Name, string(synchedDataUpdate.Zone)) {
					log.Printf("SynchedDataEngine: Invalid RR name (outside apex): %s", rr.String())
					return false, fmt.Sprintf("Update for zone %q from %q: Invalid RR name (outside apex): %s",
						synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rr.String()), nil
				}
			}
		}

	case "local":
		rrs := append([]dns.RR{}, synchedDataUpdate.Update.RRs...)

		// Check HSYNC nsmgmt policy for NS record operations
		hasNS := false
		for _, rr := range rrs {
			if rr.Header().Rrtype == dns.TypeNS {
				hasNS = true
				break
			}
		}
		if hasNS {
			zd, exists := Zones.Get(string(synchedDataUpdate.Zone))
			if !exists {
				return false, fmt.Sprintf("Local update for zone %q: zone not found", synchedDataUpdate.Zone), nil
			}
			apex, err := zd.GetOwner(zd.ZoneName)
			if err != nil {
				return false, fmt.Sprintf("Local update for zone %q: cannot get apex: %v", synchedDataUpdate.Zone, err), nil
			}
			hsyncRRset, exists := apex.RRtypes.Get(core.TypeHSYNC)
			if !exists || len(hsyncRRset.RRs) == 0 {
				return false, fmt.Sprintf("Local update for zone %q: no HSYNC record (NS management not configured)",
					synchedDataUpdate.Zone), nil
			}
			hsync := hsyncRRset.RRs[0].(*dns.PrivateRR).Data.(*core.HSYNC)
			if hsync.NSmgmt != core.HsyncNSmgmtAGENT {
				return false, fmt.Sprintf("Local update for zone %q: HSYNC nsmgmt=%s, NS management not delegated to agents",
					synchedDataUpdate.Zone, core.HsyncNSmgmtToString[hsync.NSmgmt]), nil
			}
		}

		// Must check for (at least): approved RRtype, apex of zone and zone with us in the HSYNC RRset
		for _, rr := range rrs {
			if !AllowedLocalRRtypes[rr.Header().Rrtype] {
				log.Printf("SynchedDataEngine: Invalid RR type: %s", rr.String())
				return false, fmt.Sprintf("Local update for zone %q from mgmt API: Invalid RR type: %s",
					synchedDataUpdate.Zone, rr.String()), nil
			}
			if !strings.EqualFold(rr.Header().Name, string(synchedDataUpdate.Zone)) {
				log.Printf("SynchedDataEngine: Invalid RR name (outside apex): %s", rr.String())
				return false, fmt.Sprintf("Local update for zone %q from mgmt API: Invalid RR name (outside apex): %s",
					synchedDataUpdate.Zone, rr.String()), nil
			}

			// For local deletes, verify the RR belongs to this agent
			if rr.Header().Class == dns.ClassNONE {
				agentRepo, ok := zdr.Get(synchedDataUpdate.Zone)
				if ok {
					nod, ok := agentRepo.Get(synchedDataUpdate.AgentId)
					if ok {
						rrset, ok := nod.RRtypes.Get(rr.Header().Rrtype)
						if ok {
							checkRR := dns.Copy(rr)
							checkRR.Header().Class = dns.ClassINET
							found := false
							for _, existingRR := range rrset.RRs {
								if dns.IsDuplicate(existingRR, checkRR) {
									found = true
									break
								}
							}
							if !found {
								return false, fmt.Sprintf("Local delete for zone %q: RR not owned by this agent (%s)",
									synchedDataUpdate.Zone, rr.String()), nil
							}
						} else {
							return false, fmt.Sprintf("Local delete for zone %q: no %s RRset owned by this agent",
								synchedDataUpdate.Zone, dns.TypeToString[rr.Header().Rrtype]), nil
						}
					} else {
						return false, fmt.Sprintf("Local delete for zone %q: no data owned by this agent",
							synchedDataUpdate.Zone), nil
					}
				}
			}
		}
	}
	return true, "", nil
}

// Returns change (true/false), msg (string), error (error)
func (zdr *ZoneDataRepo) ProcessUpdate(synchedDataUpdate *SynchedDataUpdate) (bool, string, error) {
	var msg string
	var changed bool
	log.Printf("SynchedDataEngine: Processing update for zone %q from %q", synchedDataUpdate.Zone, synchedDataUpdate.AgentId)
	var nar *AgentRepo
	var err error
	var ok bool
	if nar, ok = zdr.Get(synchedDataUpdate.Zone); !ok {
		log.Printf("SynchedDataEngine: Creating new agent repo for zone %q", synchedDataUpdate.Zone)
		nar, err = NewAgentRepo()
		log.Printf("SynchedDataEngine: New agent repo created: %+v", nar)
		if err != nil {
			return false, "", err
		}
		log.Printf("SynchedDataEngine: Setting new agent repo for zone %q", synchedDataUpdate.Zone)
		zdr.Set(synchedDataUpdate.Zone, nar)
	}

	log.Printf("SynchedDataEngine: Agent repo for zone %q should now exist", synchedDataUpdate.Zone)
	// Initialize agent data if it doesn't exist
	var nod *OwnerData
	log.Printf("SynchedDataEngine: Getting owner data for zone %q from %q", synchedDataUpdate.Zone, synchedDataUpdate.AgentId)
	if nod, ok = nar.Get(synchedDataUpdate.AgentId); !ok {
		log.Printf("SynchedDataEngine: Creating new owner data for zone %q from %q", synchedDataUpdate.Zone, synchedDataUpdate.AgentId)
		nod = NewOwnerData(string(synchedDataUpdate.Zone))
		nar.Set(synchedDataUpdate.AgentId, nod)
	}

	isLocal := synchedDataUpdate.UpdateType == "local"

	// Iterate through RRsets in the update and only replace those with data
	log.Printf("SynchedDataEngine: Iterating through RRsets in the update")
	for rrtype, rrset := range synchedDataUpdate.Update.RRsets {
		if len(rrset.RRs) > 0 {
			log.Printf("SynchedDataEngine: Adding %s %s RRset to agent %s",
				synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId)
			// XXX: If there are new RRs, then we just replace the existing RRset.
			// nar.Get(update.AgentId).RRtypes.Set(rrtype, rrset)
			cur_rrset, ok := nod.RRtypes.Get(rrtype)
			for _, rr := range rrset.RRs {
				switch rr.Header().Class {
				case dns.ClassANY:
					// ANY = delete entire RRset
					if !ok {
						msg = fmt.Sprintf("Removing %s %s RRset from agent %q: RRset does not exist",
							synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId)
						log.Printf("SynchedDataEngine: %s", msg)
					} else if isLocal {
						// Local delete: don't remove yet — mark as changed so the
						// delete is sent to combiner/agents. The actual removal
						// happens when the combiner confirms.
						msg = fmt.Sprintf("Requesting removal of %s %s RRset from agent %q (pending combiner confirmation)",
							synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId)
						log.Printf("SynchedDataEngine: %s", msg)
						changed = true
					} else {
						// Remote delete: apply immediately (remote agent mirrors
						// originating agent's intent, doesn't own lifecycle).
						msg = fmt.Sprintf("Removing %s %s RRset from agent %q",
							synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId)
						log.Printf("SynchedDataEngine: %s", msg)
						nod.RRtypes.Delete(rrtype)
						// Remove tracking for this entire RRtype
						zdr.removeTracking(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rrtype)
						changed = true
					}
				case dns.ClassNONE:
					// NONE = delete this RR from the RRset
					if !ok {
						msg = fmt.Sprintf("Removing %s RR %q from agent %q: RRset does not exist",
							synchedDataUpdate.Zone, rr.String(), synchedDataUpdate.AgentId)
						log.Printf("SynchedDataEngine: %s", msg)
					} else if isLocal {
						// Local delete: don't remove from repo yet. Keep the RR
						// with ClassNONE intact in the ZoneUpdate so transport
						// sends the delete intent to combiner/agents. The actual
						// removal from the repo happens on combiner confirmation.
						msg = fmt.Sprintf("Requesting removal of %s RR from agent %q (pending combiner confirmation)",
							synchedDataUpdate.Zone, synchedDataUpdate.AgentId)
						log.Printf("SynchedDataEngine: %s", msg)
						changed = true
					} else {
						// Remote delete: copy the RR before mutating class for
						// local Delete(). The original RR keeps ClassNONE for
						// forwarding to this agent's combiner.
						msg = fmt.Sprintf("Removing %s RR from agent %q (remote)",
							synchedDataUpdate.Zone, synchedDataUpdate.AgentId)
						log.Printf("SynchedDataEngine: %s", msg)
						delRR := dns.Copy(rr)
						delRR.Header().Class = dns.ClassINET
						cur_rrset.Delete(delRR)
						zdr.removeTrackedRR(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rrtype, delRR.String())
						nod.RRtypes.Set(rrtype, cur_rrset)
						changed = true
					}
				case dns.ClassINET:
					// IN = add this RR to the RRset
					if !ok {
						msg = fmt.Sprintf("Adding %s %s RRset to agent %q",
							synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId)
						log.Printf("SynchedDataEngine: %s", msg)
						cur_rrset = *rrset.Clone()
						changed = true
					} else {
						for _, rr := range rrset.RRs {
							prevLen := len(cur_rrset.RRs)
							cur_rrset.Add(rr)
							if len(cur_rrset.RRs) > prevLen {
								msg = fmt.Sprintf("Adding RR: %s to RRset", rr.String())
								log.Printf("SynchedDataEngine: %s", msg)
								changed = true
							} else if synchedDataUpdate.Force {
								log.Printf("SynchedDataEngine: RR already present but --force set, marking changed: %s", rr.String())
								changed = true
							} else {
								log.Printf("SynchedDataEngine: RR already present, skipping: %s", rr.String())
							}
						}
					}
					nod.RRtypes.Set(rrtype, cur_rrset)
				}
			}
			rrset, ok = nod.RRtypes.Get(rrtype)
			if !ok {
				log.Printf("SynchedDataEngine: %s %s RRset does not exist",
					synchedDataUpdate.Zone, dns.TypeToString[rrtype])
			} else {
				log.Printf("SynchedDataEngine: %s %s RRset after addition/deletion:\n%v",
					synchedDataUpdate.Zone, dns.TypeToString[rrtype], rrset.RRs)
			}
		}
	}
	log.Printf("SynchedDataEngine: Setting owner data for zone %q from %q", synchedDataUpdate.Zone, synchedDataUpdate.AgentId)
	nar.Set(synchedDataUpdate.AgentId, nod)
	log.Printf("SynchedDataEngine: Setting agent repo for zone %q", synchedDataUpdate.Zone)
	zdr.Set(synchedDataUpdate.Zone, nar)
	return changed, msg, nil
}
