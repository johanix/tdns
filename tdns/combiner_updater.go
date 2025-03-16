/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"log"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

type CombinerUpdate struct {
	Zone    ZoneName
	AgentId AgentId
	Update  ZoneUpdate
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

type AgentDataRepo struct {
	Repo map[ZoneName]ZoneRepo // map[zonename]ZoneRepo
}

type ZoneRepo struct {
	Data map[AgentId]OwnerData // map[agentid]data
}

func (conf *Config) NewAgentDataRepo() (*AgentDataRepo, error) {
	return &AgentDataRepo{
		Repo: make(map[ZoneName]ZoneRepo),
	}, nil
}

// CombinerUpdater is a component that updates the combiner with new information
// received from the agents that are sharing zones with us.
func (conf *Config) CombinerUpdater(updateQ chan *CombinerUpdate, stopch chan struct{}) {
	var update *CombinerUpdate

	if !viper.GetBool("combinerupdater.active") {
		log.Printf("CombinerUpdater is NOT active. No updates will be sent to the combiner.")
		for range updateQ {
			update = <-updateQ
			log.Printf("CombinerUpdater: NOT active, but received an update: %+v", update)
			continue
		}
	}

	// XXX: Set up communication with the combiner

	adr, err := conf.NewAgentDataRepo()
	if err != nil {
		log.Printf("CombinerUpdater: Failed to create agent data repo: %v", err)
		return
	}

	log.Printf("*** CombinerUpdater starting ***")

	for {
		select {
		case update = <-updateQ:
			log.Printf("CombinerUpdater: Received update: %+v", update)

			// 1. Evaluate the update for applicability (valid zone, etc)
			// 2. Evaluate the update according to policy.
			ok, err := adr.EvaluateUpdate(update)
			if err != nil {
				log.Printf("CombinerUpdater: Failed to evaluate update: %v", err)
				continue
			}
			if !ok {
				log.Printf("CombinerUpdater: Update not applicable, skipping")
				continue
			}
			// 3. Add the update to the agent data repo.
			err = adr.AddUpdate(update)
			if err != nil {
				log.Printf("CombinerUpdater: Failed to add update to agent data repo: %v", err)
				continue
			}
			// 4. Send the update to the combiner if it is applicable.
		}
	}
}

func (adr *AgentDataRepo) EvaluateUpdate(update *CombinerUpdate) (bool, error) {
	// 1. Evaluate the update for applicability (valid zone, etc)
	// 2. Evaluate the update according to policy.
	return true, nil
}

func (adr *AgentDataRepo) AddUpdate(update *CombinerUpdate) error {
	if _, ok := adr.Repo[update.Zone]; !ok {
		adr.Repo[update.Zone] = ZoneRepo{
			Data: make(map[AgentId]OwnerData),
		}
	}
	// Initialize agent data if it doesn't exist
	if _, ok := adr.Repo[update.Zone].Data[update.AgentId]; !ok {
		adr.Repo[update.Zone].Data[update.AgentId] = OwnerData{
			Name:    string(update.Zone),
			RRtypes: NewRRTypeStore(),
		}
	}

	// Iterate through RRsets in the update and only replace those with data
	for rrtype, rrset := range update.Update.Data {
		if len(rrset.RRs) > 0 {
			log.Printf("CombinerUpdater: Adding %s %s RRset to agent %s", update.Zone, dns.TypeToString[rrtype], update.AgentId)
			adr.Repo[update.Zone].Data[update.AgentId].RRtypes.Set(rrtype, rrset)
		}
	}
	return nil
}

func (adr *AgentDataRepo) SendUpdate(update *CombinerUpdate) error {
	// 1. Send the update to the combiner.
	return nil
}
