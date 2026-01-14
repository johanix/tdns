/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
)

var validRRtype = map[uint16]bool{
	dns.TypeDNSKEY: true,
	dns.TypeCDS:    true,
	dns.TypeCSYNC:  true,
	dns.TypeNS:     true,
	// dns.TypeKEY: true,
}

func (zdr *ZoneDataRepo) EvaluateUpdate(synchedDataUpdate *SynchedDataUpdate) (bool, string, error) {
	log.Printf("SynchedDataEngine: Evaluating update for zone %q from %q", synchedDataUpdate.Zone, synchedDataUpdate.AgentId)
	// 1. Evaluate the update for applicability (valid zone, etc)
	// 2. Evaluate the update according to policy.

	switch synchedDataUpdate.UpdateType {
	case "remote":
		for _, rrset := range synchedDataUpdate.Update.RRsets {
			for _, rr := range rrset.RRs {
				if !validRRtype[rr.Header().Rrtype] {
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

		// Must check for (at least): approved RRtype, apex of zone and zone with us in the HSYNC RRset
		for _, rr := range rrs {
			if !validRRtype[rr.Header().Rrtype] {
				log.Printf("SynchedDataEngine: Invalid RR type: %s", rr.String())
				return false, fmt.Sprintf("Local update for zone %q from mgmt API: Invalid RR type: %s",
					synchedDataUpdate.Zone, rr.String()), nil
			}
			if !strings.EqualFold(rr.Header().Name, string(synchedDataUpdate.Zone)) {
				log.Printf("SynchedDataEngine: Invalid RR name (outside apex): %s", rr.String())
				return false, fmt.Sprintf("Local update for zone %q from mgmt API: Invalid RR name (outside apex): %s",
					synchedDataUpdate.Zone, rr.String()), nil
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
					} else {
						msg = fmt.Sprintf("Removing %s %s RRset from agent %q",
							synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId)
						log.Printf("SynchedDataEngine: %s", msg)
						nod.RRtypes.Delete(rrtype)
						changed = true
					}
				case dns.ClassNONE:
					// NONE = delete this RR from the RRset
					if !ok {
						msg = fmt.Sprintf("Removing %s RR %q from agent %q: RRset does not exist",
							synchedDataUpdate.Zone, rr.String(), synchedDataUpdate.AgentId)
						log.Printf("SynchedDataEngine: %s", msg)
					} else {
						msg = fmt.Sprintf("Removing %s RR %q from agent %q",
							synchedDataUpdate.Zone, rr.String(), synchedDataUpdate.AgentId)
						log.Printf("SynchedDataEngine: %s", msg)
						rr.Header().Class = dns.ClassINET
						cur_rrset.Delete(rr)
						changed = true
					}
					nod.RRtypes.Set(rrtype, cur_rrset)
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
							msg = fmt.Sprintf("Adding RR: %s to RRset\n%v", rr.String(), cur_rrset.RRs)
							log.Printf("SynchedDataEngine: %s", msg)
							cur_rrset.Add(rr)
							changed = true
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
