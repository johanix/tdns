package tdns

import (
	"log/slog"
	"sync"
	"time"
)

var lgGossip *slog.Logger = Logger("gossip")

// GossipMessage carries gossip state for one provider group.
// Included in beats between agents that share group membership.
type GossipMessage struct {
	GroupHash string                  `json:"group_hash"`
	GroupName GroupNameProposal       `json:"group_name"`
	Members   map[string]*MemberState `json:"members"` // key: provider identity
	Election  GroupElectionState      `json:"election"`
}

// MemberState is one member's view of all other members in the group.
// Only the member itself updates its own MemberState (sets Timestamp).
// Other agents propagate it via gossip without modification.
type MemberState struct {
	Identity   string            `json:"identity"`
	PeerStates map[string]string `json:"peer_states"` // key: peer identity, value: state string
	Zones      []string          `json:"zones"`       // zones this member serves in this group
	Timestamp  time.Time         `json:"timestamp"`   // set by the member itself
}

// GroupElectionState carries election state for a provider group.
type GroupElectionState struct {
	Leader       string    `json:"leader,omitempty"` // identity of current leader
	Term         uint32    `json:"term,omitempty"`
	LeaderExpiry time.Time `json:"leader_expiry,omitempty"`
}

// GossipStateTable manages the NxN state matrix for all provider groups.
// Each entry is a MemberState keyed by (groupHash, memberIdentity).
type GossipStateTable struct {
	mu sync.RWMutex
	// key: group hash → member identity → MemberState
	States map[string]map[string]*MemberState
	// key: group hash → GroupElectionState
	Elections map[string]*GroupElectionState
	// key: group hash → GroupNameProposal (best proposal seen)
	Names map[string]*GroupNameProposal
	// Our identity
	LocalID string
	// Callbacks
	onGroupOperational func(groupHash string)
	onGroupDegraded    func(groupHash string)
	onElectionUpdate   func(groupHash string, state GroupElectionState)
	// Track which groups have fired operational callback
	operationalGroups map[string]bool
}

// NewGossipStateTable creates a new gossip state table.
func NewGossipStateTable(localID string) *GossipStateTable {
	return &GossipStateTable{
		States:            make(map[string]map[string]*MemberState),
		Elections:         make(map[string]*GroupElectionState),
		Names:             make(map[string]*GroupNameProposal),
		LocalID:           localID,
		operationalGroups: make(map[string]bool),
	}
}

// UpdateLocalState updates our own state entry for a group.
// This sets the Timestamp to now — only we update our own state.
func (gst *GossipStateTable) UpdateLocalState(groupHash string, peerStates map[string]string, zones []string) {
	gst.mu.Lock()
	defer gst.mu.Unlock()

	if gst.States[groupHash] == nil {
		gst.States[groupHash] = make(map[string]*MemberState)
	}

	gst.States[groupHash][gst.LocalID] = &MemberState{
		Identity:   gst.LocalID,
		PeerStates: peerStates,
		Zones:      zones,
		Timestamp:  time.Now(),
	}
}

// MergeGossip merges received gossip into the local state table.
// For each member's state entry, keep the one with the latest timestamp.
// The member's PeerStates map is replaced atomically (never cherry-pick
// individual peer entries from different timestamps).
func (gst *GossipStateTable) MergeGossip(msg *GossipMessage) {
	// Capture callback and election data under lock, invoke callback outside.
	var electionCallback func(string, GroupElectionState)
	var electionHash string
	var electionState GroupElectionState

	gst.mu.Lock()

	groupHash := msg.GroupHash

	// Merge member states
	if gst.States[groupHash] == nil {
		gst.States[groupHash] = make(map[string]*MemberState)
	}
	for id, remote := range msg.Members {
		local, exists := gst.States[groupHash][id]
		if !exists || remote.Timestamp.After(local.Timestamp) {
			gst.States[groupHash][id] = remote
		}
	}

	// Merge election state (higher term wins)
	if msg.Election.Term > 0 {
		existing := gst.Elections[groupHash]
		if existing == nil || msg.Election.Term > existing.Term {
			elCopy := msg.Election
			gst.Elections[groupHash] = &elCopy
			if gst.onElectionUpdate != nil {
				electionCallback = gst.onElectionUpdate
				electionHash = groupHash
				electionState = elCopy
			}
		}
	}

	// Merge group name proposal (earliest ProposedAt wins)
	if msg.GroupName.Name != "" {
		existing := gst.Names[groupHash]
		if existing == nil || msg.GroupName.ProposedAt.Before(existing.ProposedAt) {
			nameCopy := msg.GroupName
			gst.Names[groupHash] = &nameCopy
		}
	}

	gst.mu.Unlock()

	// Invoke callback outside the lock to avoid deadlocks
	if electionCallback != nil {
		electionCallback(electionHash, electionState)
	}
}

// BuildGossipForPeer builds gossip messages for all groups shared with a peer.
// If a LeaderElectionManager is provided, group election state is included.
func (gst *GossipStateTable) BuildGossipForPeer(peerID string, pgm *ProviderGroupManager, lem ...*LeaderElectionManager) []GossipMessage {
	gst.mu.RLock()
	defer gst.mu.RUnlock()

	if pgm == nil {
		return nil
	}

	var messages []GossipMessage

	pgm.mu.RLock()
	defer pgm.mu.RUnlock()

	for hash, pg := range pgm.Groups {
		// Check if both we and the peer are members of this group
		localInGroup := false
		peerInGroup := false
		for _, member := range pg.Members {
			if member == gst.LocalID {
				localInGroup = true
			}
			if member == peerID {
				peerInGroup = true
			}
		}
		if !localInGroup || !peerInGroup {
			lgGossip.Debug("BuildGossipForPeer: skipping group",
				"group", hash[:8], "peerID", peerID,
				"localID", gst.LocalID, "members", pg.Members,
				"localInGroup", localInGroup, "peerInGroup", peerInGroup)
			continue
		}

		msg := GossipMessage{
			GroupHash: hash,
			Members:   make(map[string]*MemberState),
		}

		// Include all member states we know about for this group
		if groupStates, ok := gst.States[hash]; ok {
			for id, state := range groupStates {
				msg.Members[id] = state
			}
		}

		// Include election state — prefer live state from LeaderElectionManager
		electionIncluded := false
		if len(lem) > 0 && lem[0] != nil {
			es := lem[0].GetGroupElectionState(hash)
			if es.Term > 0 {
				msg.Election = es
				electionIncluded = true
			}
		}
		if !electionIncluded {
			if el, ok := gst.Elections[hash]; ok {
				msg.Election = *el
			}
		}

		// Include best group name proposal
		if name, ok := gst.Names[hash]; ok {
			msg.GroupName = *name
		} else if pg.NameProposal != nil {
			msg.GroupName = *pg.NameProposal
		}

		lgGossip.Debug("BuildGossipForPeer: including group",
			"group", hash[:8], "peerID", peerID, "memberStates", len(msg.Members))
		messages = append(messages, msg)
	}

	return messages
}

// GetGroupState returns a deep copy of the state matrix for a group.
func (gst *GossipStateTable) GetGroupState(groupHash string) (map[string]*MemberState, *GroupElectionState, *GroupNameProposal) {
	gst.mu.RLock()
	defer gst.mu.RUnlock()

	// Deep copy member states
	var statesCopy map[string]*MemberState
	if src := gst.States[groupHash]; src != nil {
		statesCopy = make(map[string]*MemberState, len(src))
		for k, ms := range src {
			cp := *ms
			cp.PeerStates = make(map[string]string, len(ms.PeerStates))
			for pk, pv := range ms.PeerStates {
				cp.PeerStates[pk] = pv
			}
			cp.Zones = append([]string(nil), ms.Zones...)
			statesCopy[k] = &cp
		}
	}

	// Shallow copy election and name (scalar + time fields)
	var electionCopy *GroupElectionState
	if e := gst.Elections[groupHash]; e != nil {
		ec := *e
		electionCopy = &ec
	}
	var nameCopy *GroupNameProposal
	if n := gst.Names[groupHash]; n != nil {
		nc := *n
		nameCopy = &nc
	}

	return statesCopy, electionCopy, nameCopy
}

func (gst *GossipStateTable) SetOnGroupOperational(fn func(groupHash string)) {
	gst.mu.Lock()
	defer gst.mu.Unlock()
	gst.onGroupOperational = fn
}

func (gst *GossipStateTable) SetOnGroupDegraded(fn func(groupHash string)) {
	gst.mu.Lock()
	defer gst.mu.Unlock()
	gst.onGroupDegraded = fn
}

func (gst *GossipStateTable) SetOnElectionUpdate(fn func(groupHash string, state GroupElectionState)) {
	gst.mu.Lock()
	defer gst.mu.Unlock()
	gst.onElectionUpdate = fn
}

// CheckGroupState checks if all cells in the NxN matrix for a group are OPERATIONAL.
// Fires OnGroupOperational when the group first reaches full agreement.
// Fires OnGroupDegraded when a previously operational group loses agreement.
func (gst *GossipStateTable) CheckGroupState(groupHash string, expectedMembers []string) {
	gst.mu.Lock()

	groupStates := gst.States[groupHash]
	allOperational := true

	if len(groupStates) < len(expectedMembers) {
		// Not all members have reported yet
		allOperational = false
	} else {
		for _, member := range expectedMembers {
			ms, ok := groupStates[member]
			if !ok {
				allOperational = false
				break
			}
			for _, peer := range expectedMembers {
				if peer == member {
					continue
				}
				state, ok := ms.PeerStates[peer]
				if !ok || state != AgentStateToString[AgentStateOperational] {
					allOperational = false
					break
				}
			}
			if !allOperational {
				break
			}
		}
	}

	wasOperational := gst.operationalGroups[groupHash]
	gst.operationalGroups[groupHash] = allOperational

	// Capture callbacks before releasing lock
	onOp := gst.onGroupOperational
	onDeg := gst.onGroupDegraded
	gst.mu.Unlock()

	if allOperational && !wasOperational {
		lgGossip.Info("group reached mutual OPERATIONAL", "group", groupHash[:8])
		if onOp != nil {
			onOp(groupHash)
		}
	} else if !allOperational && wasOperational {
		lgGossip.Info("group lost mutual OPERATIONAL", "group", groupHash[:8])
		if onDeg != nil {
			onDeg(groupHash)
		}
	}
}

// RefreshLocalStates updates our local state entries for all groups
// based on current agent registry state.
func (gst *GossipStateTable) RefreshLocalStates(ar *AgentRegistry, pgm *ProviderGroupManager) {
	if ar == nil || pgm == nil {
		return
	}

	pgm.mu.RLock()
	defer pgm.mu.RUnlock()

	for hash, pg := range pgm.Groups {
		// Build our peer states for this group
		peerStates := make(map[string]string)
		var zones []string

		for _, member := range pg.Members {
			if member == gst.LocalID {
				continue
			}
			// Look up agent state
			agent, exists := ar.S.Get(AgentId(member))
			if !exists {
				peerStates[member] = AgentStateToString[AgentStateNeeded]
				continue
			}
			agent.Mu.RLock()
			state := agent.EffectiveState()
			agent.Mu.RUnlock()
			peerStates[member] = AgentStateToString[state]
		}

		// Zones this member serves
		for _, z := range pg.Zones {
			zones = append(zones, string(z))
		}

		lgGossip.Debug("RefreshLocalStates", "group", hash[:8],
			"localID", gst.LocalID, "peerStates", peerStates, "zones", zones)
		gst.UpdateLocalState(hash, peerStates, zones)
	}
}
