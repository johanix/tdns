/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	core "github.com/johanix/tdns/v0.x/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

type SynchedDataUpdate struct {
	Zone       ZoneName
	AgentId    AgentId
	UpdateType string // "local" or "remote"
	Update     *ZoneUpdate
	// Response chan *SynchedDataResponse
	Response chan *AgentMsgResponse
}

type SynchedDataResponse struct {
	Zone    ZoneName
	AgentId AgentId
	Time    time.Time
	Msg     string
	// RfiType     string
	RfiResponse RfiData
	Error       bool
	ErrorMsg    string
}

type SynchedDataCmd struct {
	Cmd      string
	Zone     ZoneName
	Response chan *SynchedDataCmdResponse
}

type SynchedDataCmdResponse struct {
	Cmd      string
	Msg      string
	Error    bool
	ErrorMsg string
	Zone     ZoneName
	// ZDR      map[ZoneName]map[AgentId]*OwnerData
	ZDR map[ZoneName]map[AgentId]map[uint16][]string
}

type ZoneUpdate struct {
	Zone    ZoneName
	AgentId AgentId
	RRsets  map[uint16]core.RRset // remote updates are only per RRset (i.e. full replace)
	RRs     []dns.RR              // local updates can be per RR
}

type AgentId string

func (id AgentId) String() string {
	return string(id)
}

type ZoneName string

func (name ZoneName) String() string {
	return string(name)
}

type ZoneDataRepo struct {
	// Repo map[ZoneName]ZoneRepo // map[zonename]ZoneRepo
	Repo core.ConcurrentMap[ZoneName, *AgentRepo] // map[zonename]ZoneRepo
}
type AgentRepo struct {
	// Data map[AgentId]OwnerData // map[agentid]data
	Data core.ConcurrentMap[AgentId, *OwnerData] // map[agentid]data
}

func (ar *AgentRepo) Get(agentId AgentId) (*OwnerData, bool) {
	// dump.P(ar.Data)
	return ar.Data.Get(agentId)
}

func (ar *AgentRepo) Set(agentId AgentId, ownerData *OwnerData) {
	ar.Data.Set(agentId, ownerData)
}

func NewAgentRepo() (*AgentRepo, error) {
	return &AgentRepo{
		Data: core.NewStringer[AgentId, *OwnerData](),
	}, nil
}

func NewZoneDataRepo() (*ZoneDataRepo, error) {
	return &ZoneDataRepo{
		Repo: core.NewStringer[ZoneName, *AgentRepo](),
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
func (conf *Config) SynchedDataEngine(ctx context.Context, agentQs *AgentQs) {
	SDupdateQ := agentQs.SynchedDataUpdate
	SDcmdQ := agentQs.SynchedDataCmd

	var synchedDataUpdate *SynchedDataUpdate
	var ok bool

	if !viper.GetBool("syncheddataengine.active") {
		log.Printf("SynchedDataEngine is NOT active. No updates will be sent to the combiner.")
		for {
			select {
			case <-ctx.Done():
				log.Printf("SynchedDataEngine: context cancelled")
				return
			case synchedDataUpdate, ok = <-SDupdateQ:
				if !ok {
					log.Printf("SynchedDataEngine: synchedDataUpdate channel closed")
					return
				}
			}
			log.Printf("SynchedDataEngine: NOT active, but received an update: %+v", synchedDataUpdate)
			continue
		}
	} else {
		log.Printf("SynchedDataEngine: Starting")
	}

	// XXX: Set up communication with the combiner

	zdr, err := NewZoneDataRepo()
	if err != nil {
		log.Printf("SynchedDataEngine: Failed to create zone data repo: %v", err)
		return
	}

	conf.Internal.ZoneDataRepo = zdr

	log.Printf("*** SynchedDataEngine starting ***")

	for {
		select {
		case <-ctx.Done():
			log.Printf("SynchedDataEngine: context cancelled")
			return
			// stopch removed; ctx.Done() handles shutdown

		case synchedDataUpdate = <-SDupdateQ:
			var change bool
			switch synchedDataUpdate.UpdateType {
			case "local":
				log.Printf("SynchedDataEngine: Received local update: %+v", synchedDataUpdate)

				// 1. Evaluate the update for applicability (valid zone, etc)
				// 2. Evaluate the update according to policy.

				// Prepare a response in case there is a response channel.
				// resp := SynchedDataResponse{
				resp := AgentMsgResponse{
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
					change, msg, err = zdr.ProcessUpdate(synchedDataUpdate)
					if err != nil {
						log.Printf("SynchedDataEngine: Failed to add update to agent data repo: %v", err)
						resp.Error = true
						resp.ErrorMsg = err.Error()
						resp.Msg = msg
					}
					if change {
						var errstrs []string
						ar := conf.Internal.AgentRegistry
						log.Printf("SynchedDataEngine: Update applied, local data has changed, need to send update both to combiner and remote agents")

						// TODO: Send update to combiner
						// TODO: Send update to remote agents
						// Find remote agents for this zone
						zad, notOperationalAgents, err := ar.RemoteOperationalAgents(synchedDataUpdate.Zone)
						if err != nil {
							resp.Error = true
							resp.ErrorMsg = fmt.Sprintf("Error getting zone agent data for zone %s: %v", synchedDataUpdate.Zone, err)
						}

						log.Printf("SynchedDataEngine: Sending NOTIFY message to %d agents", len(zad.Agents))

						// If any remote agent is not operational, we can't send the message
						if len(notOperationalAgents) > 0 {
							resp.Error = true
							resp.ErrorMsg = fmt.Sprintf("Agents %v are not operational, ignoring command for now", notOperationalAgents)
							log.Printf("SynchedDataEngine: %s", resp.ErrorMsg)
							// XXX: Mark this zone as "dirty", i.e. not yet sent to the remote agents
							continue
						} else {
							// Send message to each agent
							for _, agent := range zad.Agents {
								amr, err := agent.SendApiMsg(&AgentMsgPost{
									MessageType:  AgentMsgNotify,
									MyIdentity:   AgentId(ar.LocalAgent.Identity),
									YourIdentity: agent.Identity,
									Zone:         synchedDataUpdate.Zone,
									// RRs:          // XXX: here we need to send complete RRsets
									Time: time.Now(),
								})

								if err != nil {
									log.Printf("SynchedDataEngine: Error sending message to agent %s: %v", agent.Identity, err)
									errstrs = append(errstrs, fmt.Sprintf("Error sending message to agent %s: %v", agent.Identity, err))
									continue
								}

								resp.Msg = amr.Msg
								resp.Error = amr.Error
								resp.ErrorMsg = amr.ErrorMsg
							}
							if len(errstrs) > 0 {
								resp.Error = true
								resp.ErrorMsg = strings.Join(errstrs, "\n")
							}
						}
					}
				}

				if synchedDataUpdate.Response != nil {
					select {
					case synchedDataUpdate.Response <- &resp:
					default:
						log.Printf("SynchedDataEngine: Response channel blocked, skipping response")
					}
				}
			case "remote":
				log.Printf("SynchedDataEngine: Received remote update: %+v", synchedDataUpdate)

				// 1. Evaluate the update for applicability (valid zone, etc)
				// 2. Evaluate the update according to policy.

				// Prepare a response in case there is a response channel.
				// resp := SynchedDataResponse{
				resp := AgentMsgResponse{
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
					change, msg, err = zdr.ProcessUpdate(synchedDataUpdate)
					if err != nil {
						log.Printf("SynchedDataEngine: Failed to add update to agent data repo: %v", err)
						resp.Error = true
						resp.ErrorMsg = err.Error()
					}
					resp.Msg = msg
					if change {
						log.Printf("SynchedDataEngine: Update applied, remote data has changed, need to send update to combiner")
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
				// XXX: NYI
			}

		case sdcmd := <-SDcmdQ:
			log.Printf("SynchedDataEngine: Received command: %+v", sdcmd)
			switch sdcmd.Cmd {
			case "dump-zonedatarepo":

				if sdcmd.Response == nil {
					log.Printf("SynchedDataEngine: Command has no response channel, skipping")
					continue
				}
				log.Printf("SynchedDataEngine: Dumping zone data repo")

				// (1) Create a map[ZoneName]map[AgentId]map[uint16][]string
				dumpData := make(map[ZoneName]map[AgentId]map[uint16][]string)

				// (2) Traverse the ZoneDataRepo and copy all data from the concurrent maps to the (normal) map
				if sdcmd.Zone != "" {
					if agentRepo, ok := zdr.Repo.Get(sdcmd.Zone); ok {
						agentData := make(map[AgentId]map[uint16][]string)
						for agentId, ownerData := range agentRepo.Data.Items() {
							rrsetData := make(map[uint16][]string)
							for rrtype, rrset := range ownerData.RRtypes.data.Items() {
								var rrs []string
								for _, rr := range rrset.RRs {
									rrs = append(rrs, rr.String())
								}
								rrsetData[rrtype] = rrs
							}
							agentData[agentId] = rrsetData
						}
						dumpData[sdcmd.Zone] = agentData
					}
				} else {
					for zone, agentRepo := range zdr.Repo.Items() {
						agentData := make(map[AgentId]map[uint16][]string)
						for agentId, ownerData := range agentRepo.Data.Items() {
							rrsetData := make(map[uint16][]string)
							for rrtype, rrset := range ownerData.RRtypes.data.Items() {
								var rrs []string
								for _, rr := range rrset.RRs {
									rrs = append(rrs, rr.String())
								}
								rrsetData[rrtype] = rrs
							}
							agentData[agentId] = rrsetData
						}
						dumpData[zone] = agentData
					}
				}

				sdcmd.Response <- &SynchedDataCmdResponse{
					Zone:     "",
					ZDR:      dumpData,
					Msg:      "Zone data repo dumped",
					Error:    false,
					ErrorMsg: "",
				}

				// Use dump.P to print the JSON serializable structure
				// dump.P(dumpData)
			}
		}
	}
}

func (zdr *ZoneDataRepo) SendUpdate(update *SynchedDataUpdate) error {
	// 1. Send the update to the combiner.
	log.Printf("SynchedDataEngine: Sending update to combiner (NYI)")
	return nil
}
