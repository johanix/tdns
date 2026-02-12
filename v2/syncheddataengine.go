/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"log"
	"time"

	core "github.com/johanix/tdns/v2/core"
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
	ZDR      map[ZoneName]map[AgentId]map[uint16][]TrackedRRInfo
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

	// Tracking stores per-RR lifecycle state parallel to Repo.
	// Accessed only from the SynchedDataEngine goroutine.
	// Structure: zone → agentId → rrtype → TrackedRRset
	Tracking map[ZoneName]map[AgentId]map[uint16]*TrackedRRset
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
		Repo:     core.NewStringer[ZoneName, *AgentRepo](),
		Tracking: make(map[ZoneName]map[AgentId]map[uint16]*TrackedRRset),
	}, nil
}

func (zdr *ZoneDataRepo) Get(zone ZoneName) (*AgentRepo, bool) {
	return zdr.Repo.Get(zone)
}

func (zdr *ZoneDataRepo) Set(zone ZoneName, agentRepo *AgentRepo) {
	zdr.Repo.Set(zone, agentRepo)
}

// RRState represents the lifecycle state of a tracked RR.
type RRState uint8

const (
	RRStatePending  RRState = iota // Sent to combiner, awaiting confirmation
	RRStateAccepted                // Combiner accepted
	RRStateRejected                // Combiner rejected (see Reason)
)

func (s RRState) String() string {
	switch s {
	case RRStatePending:
		return "pending"
	case RRStateAccepted:
		return "accepted"
	case RRStateRejected:
		return "rejected"
	default:
		return "unknown"
	}
}

// TrackedRR wraps a dns.RR with lifecycle state for combiner confirmation tracking.
type TrackedRR struct {
	RR             dns.RR
	State          RRState
	Reason         string // Rejection reason (empty unless rejected)
	DistributionID string // Last distribution this RR was part of
	UpdatedAt      time.Time
}

// TrackedRRset holds a set of tracked RRs for a single RRtype.
type TrackedRRset struct {
	Tracked []TrackedRR
}

// ConfirmationDetail carries per-RR confirmation feedback from the combiner
// through to the SynchedDataEngine.
type ConfirmationDetail struct {
	DistributionID string
	Zone           ZoneName
	Status         string // "ok", "partial", "error"
	Message        string
	AppliedRecords []string
	RejectedItems  []RejectedItemInfo
	Truncated      bool
	Timestamp      time.Time
}

// RejectedItemInfo describes an RR rejected by the combiner.
type RejectedItemInfo struct {
	Record string
	Reason string
}

// TrackedRRInfo is the JSON-serializable form for dump output.
type TrackedRRInfo struct {
	RR             string `json:"rr"`
	State          string `json:"state"`
	Reason         string `json:"reason,omitempty"`
	DistributionID string `json:"distribution_id"`
	UpdatedAt      string `json:"updated_at"`
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
				log.Printf("SynchedDataEngine: NOT active, but received an update: %+v", synchedDataUpdate)
				// Send error response back to avoid timeout
				if synchedDataUpdate.Response != nil {
					synchedDataUpdate.Response <- &AgentMsgResponse{
						Error:    true,
						ErrorMsg: "SynchedDataEngine is not active",
						Msg:      "syncheddataengine.active is set to false in configuration",
					}
				}
			}
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
						log.Printf("SynchedDataEngine: Update applied, local data has changed, enqueuing for combiner and remote agents")

						tm := conf.Internal.TransportManager
						if tm != nil && synchedDataUpdate.Update != nil {
							// Enqueue for combiner (reliable delivery with retry)
							distID, err := tm.EnqueueForCombiner(synchedDataUpdate.Zone, synchedDataUpdate.Update)
							if err != nil {
								log.Printf("SynchedDataEngine: Failed to enqueue for combiner: %v", err)
								resp.Error = true
								resp.ErrorMsg = fmt.Sprintf("Combiner enqueue error: %v", err)
							} else {
								// Mark all RRs in this update as pending with the distribution ID
								zdr.MarkRRsPending(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, synchedDataUpdate.Update, distID)
							}

							// Enqueue for all remote agents in this zone (reliable delivery with retry)
							if err := tm.EnqueueForZoneAgents(synchedDataUpdate.Zone, synchedDataUpdate.Update); err != nil {
								log.Printf("SynchedDataEngine: Failed to enqueue for zone agents: %v", err)
								if resp.ErrorMsg != "" {
									resp.ErrorMsg += "; " + fmt.Sprintf("Agent enqueue error: %v", err)
								} else {
									resp.Error = true
									resp.ErrorMsg = fmt.Sprintf("Agent enqueue error: %v", err)
								}
							}

							if !resp.Error {
								resp.Msg = "Local update applied, sync enqueued for combiner and zone agents"
							}
						} else if tm == nil {
							log.Printf("SynchedDataEngine: TransportManager not available, cannot enqueue sync messages")
							resp.Error = true
							resp.ErrorMsg = "TransportManager not available"
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
						log.Printf("SynchedDataEngine: Update applied, remote data has changed, enqueuing for combiner")

						tm := conf.Internal.TransportManager
						if tm != nil && synchedDataUpdate.Update != nil {
							// Remote update: only enqueue for combiner (not back to agents)
							distID, err := tm.EnqueueForCombiner(synchedDataUpdate.Zone, synchedDataUpdate.Update)
							if err != nil {
								log.Printf("SynchedDataEngine: Failed to enqueue for combiner: %v", err)
								resp.Error = true
								resp.ErrorMsg = fmt.Sprintf("Combiner enqueue error: %v", err)
							} else {
								zdr.MarkRRsPending(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, synchedDataUpdate.Update, distID)
								resp.Msg = "Remote update applied, sync enqueued for combiner"
							}
						} else if tm == nil {
							log.Printf("SynchedDataEngine: TransportManager not available, cannot enqueue sync messages")
							resp.Error = true
							resp.ErrorMsg = "TransportManager not available"
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

				dumpData := make(map[ZoneName]map[AgentId]map[uint16][]TrackedRRInfo)

				// dumpZoneAgent extracts RRs and their tracking state for a zone/agent
				dumpZoneAgent := func(zone ZoneName, agentId AgentId, ownerData *OwnerData) map[uint16][]TrackedRRInfo {
					rrsetData := make(map[uint16][]TrackedRRInfo)
					for rrtype, rrset := range ownerData.RRtypes.data.Items() {
						var infos []TrackedRRInfo
						for _, rr := range rrset.RRs {
							info := TrackedRRInfo{
								RR:    rr.String(),
								State: "unknown",
							}
							// Look up tracking state
							if zdr.Tracking[zone] != nil &&
								zdr.Tracking[zone][agentId] != nil &&
								zdr.Tracking[zone][agentId][rrtype] != nil {
								for _, tr := range zdr.Tracking[zone][agentId][rrtype].Tracked {
									if tr.RR.String() == info.RR {
										info.State = tr.State.String()
										info.Reason = tr.Reason
										info.DistributionID = tr.DistributionID
										info.UpdatedAt = tr.UpdatedAt.Format(time.RFC3339)
										break
									}
								}
							}
							infos = append(infos, info)
						}
						rrsetData[rrtype] = infos
					}
					return rrsetData
				}

				if sdcmd.Zone != "" {
					if agentRepo, ok := zdr.Repo.Get(sdcmd.Zone); ok {
						agentData := make(map[AgentId]map[uint16][]TrackedRRInfo)
						for agentId, ownerData := range agentRepo.Data.Items() {
							agentData[agentId] = dumpZoneAgent(sdcmd.Zone, agentId, ownerData)
						}
						dumpData[sdcmd.Zone] = agentData
					}
				} else {
					for zone, agentRepo := range zdr.Repo.Items() {
						agentData := make(map[AgentId]map[uint16][]TrackedRRInfo)
						for agentId, ownerData := range agentRepo.Data.Items() {
							agentData[agentId] = dumpZoneAgent(zone, agentId, ownerData)
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
			}

		case detail := <-agentQs.Confirmation:
			log.Printf("SynchedDataEngine: Received confirmation for distribution %s zone %s status=%s applied=%d rejected=%d truncated=%v",
				detail.DistributionID, detail.Zone, detail.Status, len(detail.AppliedRecords), len(detail.RejectedItems), detail.Truncated)
			zdr.ProcessConfirmation(detail)
		}
	}
}

func (zdr *ZoneDataRepo) SendUpdate(update *SynchedDataUpdate) error {
	// 1. Send the update to the combiner.
	log.Printf("SynchedDataEngine: Sending update to combiner (NYI)")
	return nil
}

// getOrCreateTracking returns (or creates) the TrackedRRset for the given zone/agent/rrtype.
func (zdr *ZoneDataRepo) getOrCreateTracking(zone ZoneName, agent AgentId, rrtype uint16) *TrackedRRset {
	if zdr.Tracking[zone] == nil {
		zdr.Tracking[zone] = make(map[AgentId]map[uint16]*TrackedRRset)
	}
	if zdr.Tracking[zone][agent] == nil {
		zdr.Tracking[zone][agent] = make(map[uint16]*TrackedRRset)
	}
	if zdr.Tracking[zone][agent][rrtype] == nil {
		zdr.Tracking[zone][agent][rrtype] = &TrackedRRset{}
	}
	return zdr.Tracking[zone][agent][rrtype]
}

// removeTracking removes all tracking for a zone/agent/rrtype (used on ClassANY deletion).
func (zdr *ZoneDataRepo) removeTracking(zone ZoneName, agent AgentId, rrtype uint16) {
	if zdr.Tracking[zone] != nil && zdr.Tracking[zone][agent] != nil {
		delete(zdr.Tracking[zone][agent], rrtype)
	}
}

// removeTrackedRR removes a specific tracked RR by its string representation (used on ClassNONE deletion).
func (zdr *ZoneDataRepo) removeTrackedRR(zone ZoneName, agent AgentId, rrtype uint16, rrStr string) {
	if zdr.Tracking[zone] == nil || zdr.Tracking[zone][agent] == nil {
		return
	}
	tracked := zdr.Tracking[zone][agent][rrtype]
	if tracked == nil {
		return
	}
	for i := range tracked.Tracked {
		if tracked.Tracked[i].RR.String() == rrStr {
			tracked.Tracked = append(tracked.Tracked[:i], tracked.Tracked[i+1:]...)
			return
		}
	}
}

// MarkRRsPending marks all RRs in a ZoneUpdate as pending with the given distribution ID.
// Called after successful enqueue for combiner delivery.
func (zdr *ZoneDataRepo) MarkRRsPending(zone ZoneName, agent AgentId, update *ZoneUpdate, distID string) {
	now := time.Now()

	// Handle RRsets (remote updates)
	for rrtype, rrset := range update.RRsets {
		tracked := zdr.getOrCreateTracking(zone, agent, rrtype)
		for _, rr := range rrset.RRs {
			if rr.Header().Class != dns.ClassINET {
				continue // Only track additions
			}
			rrStr := rr.String()
			// Check if this RR is already tracked; if so, update it
			found := false
			for i := range tracked.Tracked {
				if tracked.Tracked[i].RR.String() == rrStr {
					tracked.Tracked[i].State = RRStatePending
					tracked.Tracked[i].Reason = ""
					tracked.Tracked[i].DistributionID = distID
					tracked.Tracked[i].UpdatedAt = now
					found = true
					break
				}
			}
			if !found {
				tracked.Tracked = append(tracked.Tracked, TrackedRR{
					RR:             rr,
					State:          RRStatePending,
					DistributionID: distID,
					UpdatedAt:      now,
				})
			}
		}
	}

	// Handle individual RRs (local updates)
	for _, rr := range update.RRs {
		if rr.Header().Class != dns.ClassINET {
			continue // Only track additions
		}
		rrtype := rr.Header().Rrtype
		tracked := zdr.getOrCreateTracking(zone, agent, rrtype)
		rrStr := rr.String()
		found := false
		for i := range tracked.Tracked {
			if tracked.Tracked[i].RR.String() == rrStr {
				tracked.Tracked[i].State = RRStatePending
				tracked.Tracked[i].Reason = ""
				tracked.Tracked[i].DistributionID = distID
				tracked.Tracked[i].UpdatedAt = now
				found = true
				break
			}
		}
		if !found {
			tracked.Tracked = append(tracked.Tracked, TrackedRR{
				RR:             rr,
				State:          RRStatePending,
				DistributionID: distID,
				UpdatedAt:      now,
			})
		}
	}
}

// ProcessConfirmation updates tracked RR states based on combiner confirmation feedback.
func (zdr *ZoneDataRepo) ProcessConfirmation(detail *ConfirmationDetail) {
	now := time.Now()

	// Build a set of applied RR strings for fast lookup
	appliedSet := make(map[string]bool, len(detail.AppliedRecords))
	for _, rr := range detail.AppliedRecords {
		appliedSet[rr] = true
	}

	// Build a map of rejected RR strings → reason
	rejectedMap := make(map[string]string, len(detail.RejectedItems))
	for _, ri := range detail.RejectedItems {
		rejectedMap[ri.Record] = ri.Reason
	}

	// Walk all tracked RRs for this zone and match by distribution ID + RR string
	zoneTracking := zdr.Tracking[detail.Zone]
	if zoneTracking == nil {
		log.Printf("SynchedDataEngine: ProcessConfirmation: no tracking data for zone %s", detail.Zone)
		return
	}

	matched := 0
	for _, agentTracking := range zoneTracking {
		for _, trackedRRset := range agentTracking {
			for i := range trackedRRset.Tracked {
				tr := &trackedRRset.Tracked[i]
				if tr.State != RRStatePending {
					continue // Only update pending RRs
				}
				if tr.DistributionID != detail.DistributionID {
					continue // Wrong distribution
				}
				rrStr := tr.RR.String()
				if appliedSet[rrStr] {
					tr.State = RRStateAccepted
					tr.Reason = ""
					tr.UpdatedAt = now
					matched++
				} else if reason, rejected := rejectedMap[rrStr]; rejected {
					tr.State = RRStateRejected
					tr.Reason = reason
					tr.UpdatedAt = now
					matched++
				}
				// If truncated and RR not in either list, leave as pending
			}
		}
	}

	log.Printf("SynchedDataEngine: ProcessConfirmation: distribution %s zone %s: matched %d RRs (applied=%d rejected=%d truncated=%v)",
		detail.DistributionID, detail.Zone, matched, len(detail.AppliedRecords), len(detail.RejectedItems), detail.Truncated)
}
