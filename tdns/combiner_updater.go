/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/spf13/viper"
)

type CombUpdate struct {
	Zone     ZoneName
	AgentId  AgentId
	Update   ZoneUpdate
	Response chan *CombResponse
}

type CombResponse struct {
	Zone     ZoneName
	AgentId  AgentId
	Msg      string
	Error    bool
	ErrorMsg string
}

type ZoneUpdate struct {
	Zone    ZoneName
	AgentId AgentId
	Data    map[uint16]RRset
}

type AgentId string

func (id AgentId) String() string {
	return string(id)
}

type ZoneName string

func (name ZoneName) String() string {
	return string(name)
}

// XXX: this was likely the wrong idea
// type AgentDataRepo struct {
// 	// Repo map[ZoneName]ZoneRepo // map[zonename]ZoneRepo
// 	Repo cmap.ConcurrentMap[ZoneName, ZoneRepo] // map[zonename]ZoneRepo
// }

type ZoneDataRepo struct {
	// Repo map[ZoneName]ZoneRepo // map[zonename]ZoneRepo
	Repo cmap.ConcurrentMap[ZoneName, *AgentRepo] // map[zonename]ZoneRepo
}

// XXX: this was also wrong
//
//	type ZoneRepo struct {
//		// Data map[AgentId]OwnerData // map[agentid]data
//		Data cmap.ConcurrentMap[AgentId, OwnerData] // map[agentid]data
//	}
type AgentRepo struct {
	// Data map[AgentId]OwnerData // map[agentid]data
	Data cmap.ConcurrentMap[AgentId, *OwnerData] // map[agentid]data
}

func (ar *AgentRepo) Get(agentId AgentId) (*OwnerData, bool) {
	return ar.Data.Get(agentId)
}

func (ar *AgentRepo) Set(agentId AgentId, ownerData *OwnerData) {
	ar.Data.Set(agentId, ownerData)
}

func NewAgentRepo() (*AgentRepo, error) {
	return &AgentRepo{
		Data: cmap.NewStringer[AgentId, *OwnerData](),
	}, nil
}

// func (conf *Config) NewAgentDataRepo() (*AgentDataRepo, error) {
// 	return &AgentDataRepo{
// 		Repo: cmap.NewStringer[ZoneName, ZoneRepo](),
// 	}, nil
// }

func NewZoneDataRepo() (*ZoneDataRepo, error) {
	return &ZoneDataRepo{
		Repo: cmap.NewStringer[ZoneName, *AgentRepo](),
	}, nil
}

func (zdr *ZoneDataRepo) Get(zone ZoneName) (*AgentRepo, bool) {
	return zdr.Repo.Get(zone)
}

func (zdr *ZoneDataRepo) Set(zone ZoneName, agentRepo *AgentRepo) {
	zdr.Repo.Set(zone, agentRepo)
}

// CombinerUpdater is a component that updates the combiner with new information
// received from the agents that are sharing zones with us.
func (conf *Config) CombinerUpdater(updateQ chan *CombUpdate, stopch chan struct{}) {
	var combu *CombUpdate

	if !viper.GetBool("combinerupdater.active") {
		log.Printf("CombinerUpdater is NOT active. No updates will be sent to the combiner.")
		for range updateQ {
			combu = <-updateQ
			log.Printf("CombinerUpdater: NOT active, but received an update: %+v", combu)
			continue
		}
	}

	// XXX: Set up communication with the combiner

	zdr, err := NewZoneDataRepo()
	if err != nil {
		log.Printf("CombinerUpdater: Failed to create zone data repo: %v", err)
		return
	}

	log.Printf("*** CombinerUpdater starting ***")

	for {
		select {
		case combu = <-updateQ:
			log.Printf("CombinerUpdater: Received update: %+v", combu)

			// 1. Evaluate the update for applicability (valid zone, etc)
			// 2. Evaluate the update according to policy.

			// Prepare a response in case there is a response channel.
			resp := CombResponse{
				Zone:    combu.Zone,
				AgentId: combu.AgentId,
			}

			ok, msg, err := zdr.EvaluateUpdate(combu)
			if err != nil {
				log.Printf("CombinerUpdater: Failed to evaluate update: %v", err)
				continue
			}

			if !ok {
				log.Printf("CombinerUpdater: Update not applicable, skipping")
				resp.Error = true
				resp.ErrorMsg = msg
			} else {
				resp.Msg = msg
				// 3. Add the update to the agent data repo.
				err = zdr.ProcessUpdate(combu)
				if err != nil {
					log.Printf("CombinerUpdater: Failed to add update to agent data repo: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				}
			}
			if combu.Response != nil {
				select {
				case combu.Response <- &resp:
				default:
					log.Printf("CombinerUpdater: Response channel blocked, skipping response")
				}
			}

			// 4. Send the update to the combiner if it is applicable.
		}
	}
}

var validRRtype = map[uint16]bool{
	dns.TypeDNSKEY: true,
	dns.TypeCDS:    true,
	dns.TypeCSYNC:  true,
	dns.TypeNS:     true,
	// dns.TypeKEY: true,
}

func (zdr *ZoneDataRepo) EvaluateUpdate(combu *CombUpdate) (bool, string, error) {
	// 1. Evaluate the update for applicability (valid zone, etc)
	// 2. Evaluate the update according to policy.
	for _, rrset := range combu.Update.Data {
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
	var nar *AgentRepo
	var err error
	if nar, ok := zdr.Get(combu.Zone); !ok {
		nar, err = NewAgentRepo()
		if err != nil {
			return err
		}
		zdr.Set(combu.Zone, nar)
	}
	// Initialize agent data if it doesn't exist
	var nod *OwnerData
	var ok bool
	if nod, ok = nar.Get(combu.AgentId); !ok {
		nod = NewOwnerData(string(combu.Zone))
		nar.Set(combu.AgentId, nod)
	}

	// Iterate through RRsets in the update and only replace those with data
	for rrtype, rrset := range combu.Update.Data {
		if len(rrset.RRs) > 0 {
			log.Printf("CombinerUpdater: Adding %s %s RRset to agent %s", combu.Zone, dns.TypeToString[rrtype], combu.AgentId)
			// XXX: If there are new RRs, then we just replace the existing RRset.
			// nar.Get(update.AgentId).RRtypes.Set(rrtype, rrset)
			nod.RRtypes.Set(rrtype, rrset)
		}
	}
	nar.Set(combu.AgentId, nod)
	zdr.Set(combu.Zone, nar)
	return nil
}

func (zdr *ZoneDataRepo) SendUpdate(update *CombUpdate) error {
	// 1. Send the update to the combiner.
	return nil
}
