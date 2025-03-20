/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"log"

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
	for _, rrset := range synchedDataUpdate.Update.RRsets {
		for _, rr := range rrset.RRs {
			if !validRRtype[rr.Header().Rrtype] {
				log.Printf("SynchedDataEngine: Invalid RR type: %s", rr.String())
				return false, fmt.Sprintf("Update for zone %q from %q: Invalid RR type: %s",
					synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rr.String()), nil
			}
			if rr.Header().Name != string(synchedDataUpdate.Zone) {
				log.Printf("SynchedDataEngine: Invalid RR name (outside apex): %s", rr.String())
				return false, fmt.Sprintf("Update for zone %q from %q: Invalid RR name (outside apex): %s",
					synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rr.String()), nil
			}
		}
	}
	return true, "", nil
}

func (zdr *ZoneDataRepo) ProcessUpdate(synchedDataUpdate *SynchedDataUpdate) error {
	log.Printf("SynchedDataEngine: Processing update for zone %q from %q", synchedDataUpdate.Zone, synchedDataUpdate.AgentId)
	var nar *AgentRepo
	var err error
	var ok bool
	if nar, ok = zdr.Get(synchedDataUpdate.Zone); !ok {
		log.Printf("SynchedDataEngine: Creating new agent repo for zone %q", synchedDataUpdate.Zone)
		nar, err = NewAgentRepo()
		log.Printf("SynchedDataEngine: New agent repo created: %+v", nar)
		if err != nil {
			return err
		}
		log.Printf("SynchedDataEngine: Setting new agent repo for zone %q", synchedDataUpdate.Zone)
		zdr.Set(synchedDataUpdate.Zone, nar)
	}

	log.Printf("SynchedDataEngine: Agent repo should now exist: %+v", nar)
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
			log.Printf("SynchedDataEngine: Adding %s %s RRset to agent %s", synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId)
			// XXX: If there are new RRs, then we just replace the existing RRset.
			// nar.Get(update.AgentId).RRtypes.Set(rrtype, rrset)
			nod.RRtypes.Set(rrtype, rrset)
		}
	}
	log.Printf("SynchedDataEngine: Setting owner data for zone %q from %q", synchedDataUpdate.Zone, synchedDataUpdate.AgentId)
	nar.Set(synchedDataUpdate.AgentId, nod)
	log.Printf("SynchedDataEngine: Setting agent repo for zone %q", synchedDataUpdate.Zone)
	zdr.Set(synchedDataUpdate.Zone, nar)
	return nil
}
