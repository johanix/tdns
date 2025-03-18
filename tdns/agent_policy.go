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

func (zdr *ZoneDataRepo) EvaluateUpdate(combu *CombUpdate) (bool, string, error) {
	log.Printf("CombinerUpdater: Evaluating update for zone %q from %q", combu.Zone, combu.AgentId)
	// 1. Evaluate the update for applicability (valid zone, etc)
	// 2. Evaluate the update according to policy.
	for _, rrset := range combu.Update.RRsets {
		for _, rr := range rrset.RRs {
			if !validRRtype[rr.Header().Rrtype] {
				log.Printf("CombinerUpdater: Invalid RR type: %s", rr.String())
				return false, fmt.Sprintf("Update for zone %q from %q: Invalid RR type: %s",
					combu.Zone, combu.AgentId, rr.String()), nil
			}
			if rr.Header().Name != string(combu.Zone) {
				log.Printf("CombinerUpdater: Invalid RR name (outside apex): %s", rr.String())
				return false, fmt.Sprintf("Update for zone %q from %q: Invalid RR name (outside apex): %s",
					combu.Zone, combu.AgentId, rr.String()), nil
			}
		}
	}
	return true, "", nil
}

func (zdr *ZoneDataRepo) ProcessUpdate(combu *CombUpdate) error {
	log.Printf("CombinerUpdater: Processing update for zone %q from %q", combu.Zone, combu.AgentId)
	var nar *AgentRepo
	var err error
	var ok bool
	if nar, ok = zdr.Get(combu.Zone); !ok {
		log.Printf("CombinerUpdater: Creating new agent repo for zone %q", combu.Zone)
		nar, err = NewAgentRepo()
		log.Printf("CombinerUpdater: New agent repo created: %+v", nar)
		if err != nil {
			return err
		}
		log.Printf("CombinerUpdater: Setting new agent repo for zone %q", combu.Zone)
		zdr.Set(combu.Zone, nar)
	}

	log.Printf("CombinerUpdater: Agent repo should now exist: %+v", nar)
	// Initialize agent data if it doesn't exist
	var nod *OwnerData
	log.Printf("CombinerUpdater: Getting owner data for zone %q from %q", combu.Zone, combu.AgentId)
	if nod, ok = nar.Get(combu.AgentId); !ok {
		log.Printf("CombinerUpdater: Creating new owner data for zone %q from %q", combu.Zone, combu.AgentId)
		nod = NewOwnerData(string(combu.Zone))
		nar.Set(combu.AgentId, nod)
	}

	// Iterate through RRsets in the update and only replace those with data
	log.Printf("CombinerUpdater: Iterating through RRsets in the update")
	for rrtype, rrset := range combu.Update.RRsets {
		if len(rrset.RRs) > 0 {
			log.Printf("CombinerUpdater: Adding %s %s RRset to agent %s", combu.Zone, dns.TypeToString[rrtype], combu.AgentId)
			// XXX: If there are new RRs, then we just replace the existing RRset.
			// nar.Get(update.AgentId).RRtypes.Set(rrtype, rrset)
			nod.RRtypes.Set(rrtype, rrset)
		}
	}
	log.Printf("CombinerUpdater: Setting owner data for zone %q from %q", combu.Zone, combu.AgentId)
	nar.Set(combu.AgentId, nod)
	log.Printf("CombinerUpdater: Setting agent repo for zone %q", combu.Zone)
	zdr.Set(combu.Zone, nar)
	return nil
}
