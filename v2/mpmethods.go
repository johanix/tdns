/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 *
 * MP methods: methods on types defined in mptypes.go.
 * Relocated from legacy_* files to enable incremental
 * removal of MP functions from tdns.
 */
package tdns

import (
	"time"

	core "github.com/johanix/tdns/v2/core"
)

// --- ZoneData MP accessors (moved from structs.go) ---

func (zd *ZoneData) GetLastKeyInventory() *KeyInventorySnapshot {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.MP == nil {
		return nil
	}
	return zd.MP.LastKeyInventory
}

func (zd *ZoneData) SetLastKeyInventory(inv *KeyInventorySnapshot) {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.EnsureMP()
	zd.MP.LastKeyInventory = inv
}

func (zd *ZoneData) GetKeystateOK() bool {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.MP == nil {
		return false
	}
	return zd.MP.KeystateOK
}

func (zd *ZoneData) SetKeystateOK(ok bool) {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.EnsureMP()
	zd.MP.KeystateOK = ok
}

func (zd *ZoneData) GetKeystateError() string {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.MP == nil {
		return ""
	}
	return zd.MP.KeystateError
}

func (zd *ZoneData) SetKeystateError(err string) {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.EnsureMP()
	zd.MP.KeystateError = err
}

func (zd *ZoneData) GetKeystateTime() time.Time {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.MP == nil {
		return time.Time{}
	}
	return zd.MP.KeystateTime
}

func (zd *ZoneData) SetKeystateTime(t time.Time) {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.EnsureMP()
	zd.MP.KeystateTime = t
}

// EnsureMP initializes the MP extension if nil. Must be called
// with zd.mu held or before concurrent access begins.
func (zd *ZoneData) EnsureMP() {
	if zd.MP == nil {
		zd.MP = &ZoneMPExtension{}
	}
}

// --- Agent methods ---

// IsAnyTransportOperational returns true if at least one transport layer
// (DNS or API) is in the OPERATIONAL state. DNS is checked first as it is
// the primary (and currently only fully implemented) transport.
func (a *Agent) IsAnyTransportOperational() bool {
	a.Mu.RLock()
	defer a.Mu.RUnlock()
	if a.DnsDetails != nil && a.DnsDetails.State == AgentStateOperational {
		return true
	}
	if a.ApiDetails != nil && a.ApiDetails.State == AgentStateOperational {
		return true
	}
	return false
}

// EffectiveState returns the most relevant transport-layer state.
// DNS is checked first as it is the primary transport.
// Falls back to the top-level aggregate state if no transport is operational.
func (a *Agent) EffectiveState() AgentState {
	a.Mu.RLock()
	defer a.Mu.RUnlock()
	if a.DnsDetails != nil && a.DnsDetails.State == AgentStateOperational {
		return AgentStateOperational
	}
	if a.ApiDetails != nil && a.ApiDetails.State == AgentStateOperational {
		return AgentStateOperational
	}
	return a.State
}

// --- AgentId / ZoneName methods ---

func (id AgentId) String() string {
	return string(id)
}

func (name ZoneName) String() string {
	return string(name)
}

// --- AgentRepo methods ---

func (ar *AgentRepo) Get(agentId AgentId) (*OwnerData, bool) {
	return ar.Data.Get(agentId)
}

func (ar *AgentRepo) Set(agentId AgentId, ownerData *OwnerData) {
	ar.Data.Set(agentId, ownerData)
}

// --- ZoneDataRepo methods (moved to tdns-mp) ---

// --- RRState methods ---

func (s RRState) String() string {
	switch s {
	case RRStatePending:
		return "pending"
	case RRStateAccepted:
		return "accepted"
	case RRStateRejected:
		return "rejected"
	case RRStatePendingRemoval:
		return "pending-removal"
	case RRStateRemoved:
		return "removed"
	default:
		return "unknown"
	}
}

func NewAgentRepo() (*AgentRepo, error) {
	return &AgentRepo{
		Data: core.NewStringer[AgentId, *OwnerData](),
	}, nil
}

func NewZoneDataRepo() (*ZoneDataRepo, error) {
	return &ZoneDataRepo{
		Repo:                  core.NewStringer[ZoneName, *AgentRepo](),
		Tracking:              make(map[ZoneName]map[AgentId]map[uint16]*TrackedRRset),
		PendingRemoteConfirms: make(map[string]*PendingRemoteConfirmation),
	}, nil
}

// allRecipientsConfirmed returns true if every expected recipient has sent a
// non-pending confirmation. If ExpectedRecipients is empty, returns true.
func allRecipientsConfirmed(tr *TrackedRR) bool {
	if len(tr.ExpectedRecipients) == 0 {
		return true
	}
	for _, r := range tr.ExpectedRecipients {
		c, ok := tr.Confirmations[r]
		if !ok || c.Status == "pending" {
			return false
		}
	}
	return true
}
