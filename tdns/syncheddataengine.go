/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"log"
	"time"

	"github.com/gookit/goutil/dump"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/spf13/viper"
)

type SynchedDataUpdate struct {
	Zone     ZoneName
	AgentId  AgentId
	Update   *ZoneUpdate
	Response chan *SynchedDataResponse
}

type SynchedDataResponse struct {
	Zone     ZoneName
	AgentId  AgentId
	Time     time.Time
	Msg      string
	Error    bool
	ErrorMsg string
}

type ZoneUpdate struct {
	Zone    ZoneName
	AgentId AgentId
	RRsets  map[uint16]RRset
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
	dump.P(ar.Data)
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

// SynchedDataEngine is a component that updates the combiner with new information
// received from the agents that are sharing zones with us.
func (conf *Config) SynchedDataEngine(updateQ chan *SynchedDataUpdate, stopch chan struct{}) {
	var synchedDataUpdate *SynchedDataUpdate

	if !viper.GetBool("syncheddataengine.active") {
		log.Printf("SynchedDataEngine is NOT active. No updates will be sent to the combiner.")
		for range updateQ {
			synchedDataUpdate = <-updateQ
			log.Printf("SynchedDataEngine: NOT active, but received an update: %+v", synchedDataUpdate)
			continue
		}
	}

	// XXX: Set up communication with the combiner

	zdr, err := NewZoneDataRepo()
	if err != nil {
		log.Printf("SynchedDataEngine: Failed to create zone data repo: %v", err)
		return
	}

	log.Printf("*** SynchedDataEngine starting ***")

	for {
		select {
		case synchedDataUpdate = <-updateQ:
			log.Printf("SynchedDataEngine: Received update: %+v", synchedDataUpdate)

			// 1. Evaluate the update for applicability (valid zone, etc)
			// 2. Evaluate the update according to policy.

			// Prepare a response in case there is a response channel.
			resp := SynchedDataResponse{
				Zone:    synchedDataUpdate.Zone,
				AgentId: synchedDataUpdate.AgentId,
			}

			// agent_policy.go: EvaluateUpdate()
			ok, msg, err := zdr.EvaluateUpdate(synchedDataUpdate)
			if err != nil {
				log.Printf("SynchedDataEngine: Failed to evaluate update: %v", err)
				continue
			}

			if !ok {
				log.Printf("SynchedDataEngine: Update not applicable, skipping")
				resp.Error = true
				resp.ErrorMsg = msg
			} else {
				resp.Msg = msg

				// 3. Add the update to the agent data repo.
				// agent_policy.go: ProcessUpdate()
				err = zdr.ProcessUpdate(synchedDataUpdate)
				if err != nil {
					log.Printf("SynchedDataEngine: Failed to add update to agent data repo: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				}
			}
			if synchedDataUpdate.Response != nil {
				select {
				case synchedDataUpdate.Response <- &resp:
				default:
					log.Printf("SynchedDataEngine: Response channel blocked, skipping response")
				}
			}

			// 4. Send the update to the combiner if it is applicable.
		}
	}
}

func (zdr *ZoneDataRepo) SendUpdate(update *SynchedDataUpdate) error {
	// 1. Send the update to the combiner.
	return nil
}
