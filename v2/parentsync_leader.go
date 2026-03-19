/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

var lgElect = Logger("elect")

// LeaderElection tracks the per-zone election state.
type LeaderElection struct {
	mu            sync.Mutex
	Zone          ZoneName
	Leader        AgentId
	LeaderExpiry  time.Time
	Active        bool
	Term          uint64
	MyVote        uint32
	Votes         map[AgentId]uint32
	Confirms      map[AgentId]AgentId
	ExpectedPeers int
	VoteTimer     *time.Timer
	ConfirmTimer  *time.Timer
	ReelectTimer  *time.Timer
}

// LeaderElectionManager coordinates leader election across all zones.
// Phase 6: supports both per-zone elections (legacy) and per-group elections.
// When a ProviderGroupManager is set, elections are per-group and the leader
// covers all zones in the group. IsLeader checks group membership first.
type LeaderElectionManager struct {
	mu                    sync.RWMutex
	elections             map[ZoneName]*LeaderElection
	pendingElections      map[ZoneName]bool          // zones where election was deferred (peers not yet operational)
	groupElections        map[string]*LeaderElection // key: group hash
	pendingGroupElections map[string]bool            // group hashes waiting for OnGroupOperational
	localID               AgentId
	leaderTTL             time.Duration
	broadcastFunc         func(zone ZoneName, rfiType string, records map[string][]string) error
	operationalPeersFunc  func(zone ZoneName) int   // returns count of operational peers for a zone
	configuredPeersFunc   func(zone ZoneName) int   // returns count of configured peers for a zone
	onLeaderElected       func(zone ZoneName) error // called when local agent wins election
	providerGroupMgr      *ProviderGroupManager
}

func NewLeaderElectionManager(localID AgentId, leaderTTL time.Duration, broadcastFunc func(ZoneName, string, map[string][]string) error) *LeaderElectionManager {
	return &LeaderElectionManager{
		elections:             make(map[ZoneName]*LeaderElection),
		pendingElections:      make(map[ZoneName]bool),
		groupElections:        make(map[string]*LeaderElection),
		pendingGroupElections: make(map[string]bool),
		localID:               localID,
		leaderTTL:             leaderTTL,
		broadcastFunc:         broadcastFunc,
	}
}

// SetProviderGroupManager sets the provider group manager for group-based elections.
func (lem *LeaderElectionManager) SetProviderGroupManager(pgm *ProviderGroupManager) {
	lem.providerGroupMgr = pgm
}

// SetOperationalPeersFunc sets the callback used to count operational peers for re-election.
func (lem *LeaderElectionManager) SetOperationalPeersFunc(f func(zone ZoneName) int) {
	lem.operationalPeersFunc = f
}

// SetConfiguredPeersFunc sets the callback that returns the number of configured
// peers for a zone (from HSYNC3 records, minus self). Elections require ALL
// configured peers to participate — partial elections are aborted.
func (lem *LeaderElectionManager) SetConfiguredPeersFunc(f func(zone ZoneName) int) {
	lem.configuredPeersFunc = f
}

// configuredPeers returns the number of configured peers for a zone.
// Falls back to operationalPeersFunc if configuredPeersFunc is not set.
func (lem *LeaderElectionManager) configuredPeers(zone ZoneName) int {
	if lem.configuredPeersFunc != nil {
		return lem.configuredPeersFunc(zone)
	}
	if lem.operationalPeersFunc != nil {
		return lem.operationalPeersFunc(zone)
	}
	return 0
}

// SetOnLeaderElected sets the callback invoked when the local agent wins an election.
// Used to trigger delegation sync setup (SIG(0) key generation + bootstrap with parent).
func (lem *LeaderElectionManager) SetOnLeaderElected(f func(zone ZoneName) error) {
	lem.onLeaderElected = f
}

// StartGroupElection initiates a leader election for a provider group.
// The election is broadcast using one of the group's zones as the RFI channel.
// The winner becomes leader for ALL zones in the group.
func (lem *LeaderElectionManager) StartGroupElection(groupHash string, members []string, zones []ZoneName) {
	expectedPeers := len(members) - 1 // minus self

	lem.mu.Lock()
	le, ok := lem.groupElections[groupHash]
	if !ok {
		le = &LeaderElection{
			Zone:     ZoneName(groupHash), // use group hash as key
			Votes:    make(map[AgentId]uint32),
			Confirms: make(map[AgentId]AgentId),
		}
		lem.groupElections[groupHash] = le
	}
	delete(lem.pendingGroupElections, groupHash)
	lem.mu.Unlock()

	le.mu.Lock()

	// Single agent: self-elect immediately
	if expectedPeers == 0 {
		le.Leader = lem.localID
		le.LeaderExpiry = time.Now().Add(lem.leaderTTL)
		le.Active = false
		lgElect.Info("single agent in group, self-elected as leader", "group", groupHash[:8])
		lem.scheduleGroupReelection(le, groupHash, members, zones)
		le.mu.Unlock()

		if lem.onLeaderElected != nil {
			for _, zone := range zones {
				go func(z ZoneName) {
					if err := lem.onLeaderElected(z); err != nil {
						lgElect.Error("onLeaderElected callback failed", "zone", z, "group", groupHash[:8], "error", err)
					}
				}(zone)
			}
		}
		return
	}

	// Reset election state
	le.Active = true
	le.Term++
	le.MyVote = rand.Uint32()
	le.Votes = map[AgentId]uint32{lem.localID: le.MyVote}
	le.Confirms = make(map[AgentId]AgentId)
	le.ExpectedPeers = expectedPeers
	term := le.Term
	vote := le.MyVote

	if le.VoteTimer != nil {
		le.VoteTimer.Stop()
	}
	if le.ConfirmTimer != nil {
		le.ConfirmTimer.Stop()
	}

	le.VoteTimer = time.AfterFunc(5*time.Second, func() {
		lem.onGroupVoteTimeout(groupHash, term, members, zones)
	})

	le.mu.Unlock()

	lgElect.Info("starting group election", "group", groupHash[:8], "term", term, "peers", expectedPeers, "zones", len(zones))

	// Broadcast ELECT-CALL using first zone as the RFI channel.
	// Group hash is included in records so receivers can match to their group.
	if len(zones) > 0 {
		records := map[string][]string{
			"_term":  {strconv.FormatUint(term, 10)},
			"_group": {groupHash},
		}
		if err := lem.broadcastFunc(zones[0], "ELECT-CALL", records); err != nil {
			lgElect.Error("failed to broadcast group ELECT-CALL", "group", groupHash[:8], "err", err)
		}

		voteRecords := map[string][]string{
			"_vote":  {strconv.FormatUint(uint64(vote), 10)},
			"_term":  {strconv.FormatUint(term, 10)},
			"_group": {groupHash},
		}
		if err := lem.broadcastFunc(zones[0], "ELECT-VOTE", voteRecords); err != nil {
			lgElect.Error("failed to broadcast group ELECT-VOTE", "group", groupHash[:8], "err", err)
		}
	}
}

// DeferGroupElection records a group as needing an election when OnGroupOperational fires.
func (lem *LeaderElectionManager) DeferGroupElection(groupHash string) {
	lem.mu.Lock()
	lem.pendingGroupElections[groupHash] = true
	lem.mu.Unlock()
	lgElect.Info("deferring group election until group is operational", "group", groupHash[:8])
}

// HandleGroupMessage dispatches an election message that carries a _group record.
func (lem *LeaderElectionManager) HandleGroupMessage(groupHash string, senderID AgentId, rfiType string, records map[string][]string) {
	lem.mu.Lock()
	le, ok := lem.groupElections[groupHash]
	if !ok {
		le = &LeaderElection{
			Zone:     ZoneName(groupHash),
			Votes:    make(map[AgentId]uint32),
			Confirms: make(map[AgentId]AgentId),
		}
		lem.groupElections[groupHash] = le
	}
	lem.mu.Unlock()

	// Find group metadata for callbacks
	var members []string
	var zones []ZoneName
	if lem.providerGroupMgr != nil {
		pg := lem.providerGroupMgr.GetGroup(groupHash)
		if pg != nil {
			members = pg.Members
			zones = pg.Zones
		}
	}

	switch rfiType {
	case "ELECT-CALL":
		lem.handleGroupCall(le, groupHash, senderID, records, members, zones)
	case "ELECT-VOTE":
		lem.handleGroupVote(le, groupHash, senderID, records, members, zones)
	case "ELECT-CONFIRM":
		lem.handleGroupConfirm(le, groupHash, senderID, records, members, zones)
	}
}

func (lem *LeaderElectionManager) handleGroupCall(le *LeaderElection, groupHash string, senderID AgentId, records map[string][]string, members []string, zones []ZoneName) {
	term := parseUint64(records, "_term")
	le.mu.Lock()

	if le.Active && le.Term >= term {
		le.mu.Unlock()
		return
	}

	le.Active = true
	le.Term = term
	le.MyVote = rand.Uint32()
	le.Votes = map[AgentId]uint32{lem.localID: le.MyVote}
	le.Confirms = make(map[AgentId]AgentId)
	le.ExpectedPeers = len(members) - 1
	vote := le.MyVote

	if le.VoteTimer != nil {
		le.VoteTimer.Stop()
	}
	le.VoteTimer = time.AfterFunc(5*time.Second, func() {
		lem.onGroupVoteTimeout(groupHash, term, members, zones)
	})
	le.mu.Unlock()

	lgElect.Info("joining group election", "group", groupHash[:8], "term", term, "from", senderID)

	if len(zones) > 0 {
		voteRecords := map[string][]string{
			"_vote":  {strconv.FormatUint(uint64(vote), 10)},
			"_term":  {strconv.FormatUint(term, 10)},
			"_group": {groupHash},
		}
		if err := lem.broadcastFunc(zones[0], "ELECT-VOTE", voteRecords); err != nil {
			lgElect.Error("failed to broadcast group ELECT-VOTE", "group", groupHash[:8], "err", err)
		}
	}
}

func (lem *LeaderElectionManager) handleGroupVote(le *LeaderElection, groupHash string, senderID AgentId, records map[string][]string, members []string, zones []ZoneName) {
	term := parseUint64(records, "_term")
	vote := uint32(parseUint64(records, "_vote"))

	le.mu.Lock()
	defer le.mu.Unlock()

	if !le.Active || le.Term != term {
		return
	}

	le.Votes[senderID] = vote
	lgElect.Info("received group vote", "group", groupHash[:8], "from", senderID, "votes", len(le.Votes), "expected", le.ExpectedPeers+1)

	if len(le.Votes) >= le.ExpectedPeers+1 {
		if le.VoteTimer != nil {
			le.VoteTimer.Stop()
		}
		go lem.determineAndConfirmGroup(groupHash, term, members, zones)
	}
}

func (lem *LeaderElectionManager) handleGroupConfirm(le *LeaderElection, groupHash string, senderID AgentId, records map[string][]string, members []string, zones []ZoneName) {
	term := parseUint64(records, "_term")
	winner := AgentId(parseString(records, "_winner"))

	le.mu.Lock()
	if !le.Active || le.Term != term {
		le.mu.Unlock()
		return
	}

	le.Confirms[senderID] = winner

	if len(le.Confirms) >= le.ExpectedPeers+1 {
		if le.ConfirmTimer != nil {
			le.ConfirmTimer.Stop()
		}
		le.mu.Unlock()
		lem.finalizeGroupElection(groupHash, term, members, zones)
		return
	}
	le.mu.Unlock()
}

func (lem *LeaderElectionManager) onGroupVoteTimeout(groupHash string, term uint64, members []string, zones []ZoneName) {
	lem.mu.RLock()
	le := lem.groupElections[groupHash]
	lem.mu.RUnlock()
	if le == nil {
		return
	}

	le.mu.Lock()
	if !le.Active || le.Term != term {
		le.mu.Unlock()
		return
	}
	collected := len(le.Votes)
	expected := le.ExpectedPeers + 1
	if collected < expected {
		le.Active = false
		le.mu.Unlock()
		lgElect.Warn("group election aborted: not all members voted",
			"group", groupHash[:8], "term", term, "votes", collected, "expected", expected)
		return
	}
	le.mu.Unlock()
	lem.determineAndConfirmGroup(groupHash, term, members, zones)
}

func (lem *LeaderElectionManager) determineAndConfirmGroup(groupHash string, term uint64, members []string, zones []ZoneName) {
	lem.mu.RLock()
	le := lem.groupElections[groupHash]
	lem.mu.RUnlock()
	if le == nil {
		return
	}

	le.mu.Lock()
	if !le.Active || le.Term != term {
		le.mu.Unlock()
		return
	}

	winner := determineWinner(le.Votes)
	le.Confirms[lem.localID] = winner

	if le.ConfirmTimer != nil {
		le.ConfirmTimer.Stop()
	}
	le.ConfirmTimer = time.AfterFunc(5*time.Second, func() {
		lem.onGroupConfirmTimeout(groupHash, term, members, zones)
	})
	le.mu.Unlock()

	lgElect.Info("group election: determined winner, broadcasting confirm", "group", groupHash[:8], "winner", winner, "term", term)

	if len(zones) > 0 {
		confirmRecords := map[string][]string{
			"_winner": {string(winner)},
			"_term":   {strconv.FormatUint(term, 10)},
			"_group":  {groupHash},
		}
		if err := lem.broadcastFunc(zones[0], "ELECT-CONFIRM", confirmRecords); err != nil {
			lgElect.Error("failed to broadcast group ELECT-CONFIRM", "group", groupHash[:8], "err", err)
		}
	}
}

func (lem *LeaderElectionManager) onGroupConfirmTimeout(groupHash string, term uint64, members []string, zones []ZoneName) {
	lem.mu.RLock()
	le := lem.groupElections[groupHash]
	lem.mu.RUnlock()
	if le == nil {
		return
	}

	le.mu.Lock()
	if !le.Active || le.Term != term {
		le.mu.Unlock()
		return
	}
	collected := len(le.Confirms)
	expected := le.ExpectedPeers + 1
	if collected < expected {
		le.Active = false
		le.mu.Unlock()
		lgElect.Warn("group election aborted: not all members confirmed",
			"group", groupHash[:8], "term", term, "confirms", collected, "expected", expected)
		return
	}
	le.mu.Unlock()
	lem.finalizeGroupElection(groupHash, term, members, zones)
}

func (lem *LeaderElectionManager) finalizeGroupElection(groupHash string, term uint64, members []string, zones []ZoneName) {
	lem.mu.RLock()
	le := lem.groupElections[groupHash]
	lem.mu.RUnlock()
	if le == nil {
		return
	}

	le.mu.Lock()
	if le.Term != term {
		le.mu.Unlock()
		return
	}

	var agreedWinner AgentId
	consensus := true
	for _, winner := range le.Confirms {
		if agreedWinner == "" {
			agreedWinner = winner
		} else if winner != agreedWinner {
			consensus = false
			break
		}
	}

	if !consensus || agreedWinner == "" {
		le.Active = false
		expectedPeers := le.ExpectedPeers
		le.mu.Unlock()
		lgElect.Warn("group election: no consensus, re-electing", "group", groupHash[:8], "term", term)
		time.AfterFunc(time.Duration(500+rand.Intn(1000))*time.Millisecond, func() {
			_ = expectedPeers // avoid unused warning
			lem.StartGroupElection(groupHash, members, zones)
		})
		return
	}

	le.Leader = agreedWinner
	le.LeaderExpiry = time.Now().Add(lem.leaderTTL)
	le.Active = false

	isUs := agreedWinner == lem.localID
	lgElect.Info("group leader elected", "group", groupHash[:8], "leader", agreedWinner, "is_us", isUs, "term", term, "zones", len(zones))

	lem.scheduleGroupReelection(le, groupHash, members, zones)
	le.mu.Unlock()

	if isUs && lem.onLeaderElected != nil {
		for _, zone := range zones {
			go func(z ZoneName) {
				if err := lem.onLeaderElected(z); err != nil {
					lgElect.Error("onLeaderElected callback failed", "zone", z, "group", groupHash[:8], "error", err)
				}
			}(zone)
		}
	}
}

// scheduleGroupReelection sets up a timer to re-elect at 90% of leader TTL.
// Must be called with le.mu held.
func (lem *LeaderElectionManager) scheduleGroupReelection(le *LeaderElection, groupHash string, members []string, zones []ZoneName) {
	if le.ReelectTimer != nil {
		le.ReelectTimer.Stop()
	}
	le.ReelectTimer = time.AfterFunc(lem.leaderTTL*9/10, func() {
		lgElect.Info("group leader TTL expiring, triggering re-election", "group", groupHash[:8])
		lem.StartGroupElection(groupHash, members, zones)
	})
}

// GetGroupLeader returns the current leader for a provider group.
func (lem *LeaderElectionManager) GetGroupLeader(groupHash string) (AgentId, bool) {
	lem.mu.RLock()
	le, ok := lem.groupElections[groupHash]
	lem.mu.RUnlock()
	if !ok {
		return "", false
	}
	le.mu.Lock()
	defer le.mu.Unlock()
	if le.Leader == "" || time.Now().After(le.LeaderExpiry) {
		return "", false
	}
	return le.Leader, true
}

// GetGroupElectionState returns the election state for a group (for gossip).
func (lem *LeaderElectionManager) GetGroupElectionState(groupHash string) GroupElectionState {
	lem.mu.RLock()
	le, ok := lem.groupElections[groupHash]
	lem.mu.RUnlock()
	if !ok {
		return GroupElectionState{}
	}
	le.mu.Lock()
	defer le.mu.Unlock()
	return GroupElectionState{
		Leader:       string(le.Leader),
		Term:         uint32(le.Term),
		LeaderExpiry: le.LeaderExpiry,
	}
}

// DeferElection records a zone as needing an election once peers become operational.
// Called from OnFirstLoad when peers aren't ready yet at zone load time.
func (lem *LeaderElectionManager) DeferElection(zone ZoneName) {
	lem.mu.Lock()
	lem.pendingElections[zone] = true
	lem.mu.Unlock()
	lgElect.Info("deferring leader election until peers are operational", "zone", zone)
}

// NotifyPeerOperational is called when a peer becomes operational.
// Checks if deferred elections or leaderless zones can now hold elections.
// Elections require ALL configured peers to be operational.
func (lem *LeaderElectionManager) NotifyPeerOperational(peerZones map[ZoneName]bool) {
	// Collect zones that need an election: either deferred or leaderless
	var candidates []ZoneName

	lem.mu.RLock()
	for zone := range peerZones {
		if lem.pendingElections[zone] {
			candidates = append(candidates, zone)
			continue
		}
		// Also check if this zone has no active leader (expired or never elected)
		if le, ok := lem.elections[zone]; ok {
			le.mu.Lock()
			needsElection := le.Leader == "" || time.Now().After(le.LeaderExpiry)
			le.mu.Unlock()
			if needsElection {
				candidates = append(candidates, zone)
			}
		}
	}
	lem.mu.RUnlock()

	if len(candidates) == 0 {
		return
	}

	for _, zone := range candidates {
		operational := 0
		if lem.operationalPeersFunc != nil {
			operational = lem.operationalPeersFunc(zone)
		}
		configured := lem.configuredPeers(zone)
		if configured > 0 && operational >= configured {
			lgElect.Info("all configured peers operational, starting election",
				"zone", zone, "operational", operational, "configured", configured)
			lem.mu.Lock()
			delete(lem.pendingElections, zone)
			lem.mu.Unlock()
			lem.StartElection(zone, configured)
		} else if operational > 0 {
			lgElect.Debug("waiting for all configured peers before election",
				"zone", zone, "operational", operational, "configured", configured)
		}
	}
}

// GetPendingElections returns zones with deferred elections (waiting for peers).
func (lem *LeaderElectionManager) GetPendingElections() []ZoneName {
	lem.mu.RLock()
	defer lem.mu.RUnlock()
	result := make([]ZoneName, 0, len(lem.pendingElections))
	for zone := range lem.pendingElections {
		result = append(result, zone)
	}
	return result
}

// getOrCreate returns the election state for a zone, creating if needed.
func (lem *LeaderElectionManager) getOrCreate(zone ZoneName) *LeaderElection {
	lem.mu.Lock()
	defer lem.mu.Unlock()
	le, ok := lem.elections[zone]
	if !ok {
		le = &LeaderElection{
			Zone:     zone,
			Votes:    make(map[AgentId]uint32),
			Confirms: make(map[AgentId]AgentId),
		}
		lem.elections[zone] = le
	}
	return le
}

// GetLeader returns the current leader for a zone, if known and not expired.
func (lem *LeaderElectionManager) GetLeader(zone ZoneName) (AgentId, bool) {
	lem.mu.RLock()
	le, ok := lem.elections[zone]
	lem.mu.RUnlock()
	if !ok {
		return "", false
	}
	le.mu.Lock()
	defer le.mu.Unlock()
	if le.Leader == "" || time.Now().After(le.LeaderExpiry) {
		return "", false
	}
	return le.Leader, true
}

// IsLeader returns true if the local agent is the current leader for a zone.
// Checks group-based election first (if provider groups are configured),
// then falls back to per-zone election.
func (lem *LeaderElectionManager) IsLeader(zone ZoneName) bool {
	// Check group-based leader first
	if lem.providerGroupMgr != nil {
		pg := lem.providerGroupMgr.GetGroupForZone(zone)
		if pg != nil {
			leader, ok := lem.GetGroupLeader(pg.GroupHash)
			if ok {
				return leader == lem.localID
			}
			// Group exists but no leader yet — fall through to per-zone check
		}
	}
	// Fall back to per-zone election
	leader, ok := lem.GetLeader(zone)
	if !ok {
		return false
	}
	return leader == lem.localID
}

// LeaderStatus describes the current leader for a single zone.
type LeaderStatus struct {
	Zone   ZoneName
	Leader AgentId
	IsSelf bool
	Term   uint64
	Expiry time.Time
}

// GetAllLeaders returns the current leader status for all zones with an active leader.
func (lem *LeaderElectionManager) GetAllLeaders() []LeaderStatus {
	lem.mu.RLock()
	defer lem.mu.RUnlock()

	// Track zones covered by group elections to avoid duplicates
	groupCoveredZones := make(map[ZoneName]bool)

	var result []LeaderStatus

	// Group-based leaders first
	for groupHash, le := range lem.groupElections {
		le.mu.Lock()
		if le.Leader != "" && time.Now().Before(le.LeaderExpiry) {
			// Find all zones in this group
			var zones []ZoneName
			if lem.providerGroupMgr != nil {
				pg := lem.providerGroupMgr.GetGroup(groupHash)
				if pg != nil {
					zones = pg.Zones
				}
			}
			for _, zone := range zones {
				groupCoveredZones[zone] = true
				result = append(result, LeaderStatus{
					Zone:   zone,
					Leader: le.Leader,
					IsSelf: le.Leader == lem.localID,
					Term:   le.Term,
					Expiry: le.LeaderExpiry,
				})
			}
		}
		le.mu.Unlock()
	}

	// Per-zone leaders (only for zones not covered by group elections)
	for zone, le := range lem.elections {
		if groupCoveredZones[zone] {
			continue
		}
		le.mu.Lock()
		if le.Leader != "" && time.Now().Before(le.LeaderExpiry) {
			result = append(result, LeaderStatus{
				Zone:   zone,
				Leader: le.Leader,
				IsSelf: le.Leader == lem.localID,
				Term:   le.Term,
				Expiry: le.LeaderExpiry,
			})
		}
		le.mu.Unlock()
	}
	return result
}

// StartElection initiates a new election for a zone. If expectedPeers is 0,
// the local agent immediately becomes leader without sending any messages.
func (lem *LeaderElectionManager) StartElection(zone ZoneName, expectedPeers int) {
	le := lem.getOrCreate(zone)
	le.mu.Lock()

	// Single agent: become leader immediately
	if expectedPeers == 0 {
		le.Leader = lem.localID
		le.LeaderExpiry = time.Now().Add(lem.leaderTTL)
		le.Active = false
		lgElect.Info("single agent, self-elected as leader", "zone", zone)
		lem.scheduleReelection(le)
		le.mu.Unlock()

		// Trigger delegation sync setup (SIG(0) key generation + bootstrap)
		if lem.onLeaderElected != nil {
			go func() {
				if err := lem.onLeaderElected(zone); err != nil {
					lgElect.Error("onLeaderElected callback failed", "zone", zone, "error", err)
				}
			}()
		}
		return
	}

	// Reset election state
	le.Active = true
	le.Term++
	le.MyVote = rand.Uint32()
	le.Votes = map[AgentId]uint32{lem.localID: le.MyVote}
	le.Confirms = make(map[AgentId]AgentId)
	le.ExpectedPeers = expectedPeers
	term := le.Term
	vote := le.MyVote

	// Cancel any existing timers
	if le.VoteTimer != nil {
		le.VoteTimer.Stop()
	}
	if le.ConfirmTimer != nil {
		le.ConfirmTimer.Stop()
	}

	// Start vote collection timer
	le.VoteTimer = time.AfterFunc(5*time.Second, func() {
		lem.onVoteTimeout(zone, term)
	})

	le.mu.Unlock()

	lgElect.Info("starting election", "zone", zone, "term", term, "peers", expectedPeers)

	// Broadcast ELECT-CALL
	records := map[string][]string{
		"_term": {strconv.FormatUint(term, 10)},
	}
	if err := lem.broadcastFunc(zone, "ELECT-CALL", records); err != nil {
		lgElect.Error("failed to broadcast ELECT-CALL", "zone", zone, "err", err)
	}

	// Broadcast our own vote
	voteRecords := map[string][]string{
		"_vote": {strconv.FormatUint(uint64(vote), 10)},
		"_term": {strconv.FormatUint(term, 10)},
	}
	if err := lem.broadcastFunc(zone, "ELECT-VOTE", voteRecords); err != nil {
		lgElect.Error("failed to broadcast ELECT-VOTE", "zone", zone, "err", err)
	}
}

// HandleMessage dispatches an incoming election message to the appropriate handler.
func (lem *LeaderElectionManager) HandleMessage(zone ZoneName, senderID AgentId, rfiType string, records map[string][]string) {
	switch rfiType {
	case "ELECT-CALL":
		lem.handleCall(zone, senderID, records)
	case "ELECT-VOTE":
		lem.handleVote(zone, senderID, records)
	case "ELECT-CONFIRM":
		lem.handleConfirm(zone, senderID, records)
	}
}

func (lem *LeaderElectionManager) handleCall(zone ZoneName, senderID AgentId, records map[string][]string) {
	term := parseUint64(records, "_term")
	le := lem.getOrCreate(zone)
	le.mu.Lock()

	// If we already have an active election with equal or higher term, ignore
	if le.Active && le.Term >= term {
		le.mu.Unlock()
		lgElect.Debug("ignoring ELECT-CALL with stale term", "zone", zone, "our_term", le.Term, "their_term", term)
		return
	}

	// Join the election
	le.Active = true
	le.Term = term
	le.MyVote = rand.Uint32()
	le.Votes = map[AgentId]uint32{lem.localID: le.MyVote}
	le.Confirms = make(map[AgentId]AgentId)
	vote := le.MyVote

	if le.VoteTimer != nil {
		le.VoteTimer.Stop()
	}
	le.VoteTimer = time.AfterFunc(5*time.Second, func() {
		lem.onVoteTimeout(zone, term)
	})

	le.mu.Unlock()

	lgElect.Info("joining election", "zone", zone, "term", term, "from", senderID)

	// Broadcast our vote
	voteRecords := map[string][]string{
		"_vote": {strconv.FormatUint(uint64(vote), 10)},
		"_term": {strconv.FormatUint(term, 10)},
	}
	if err := lem.broadcastFunc(zone, "ELECT-VOTE", voteRecords); err != nil {
		lgElect.Error("failed to broadcast ELECT-VOTE", "zone", zone, "err", err)
	}
}

func (lem *LeaderElectionManager) handleVote(zone ZoneName, senderID AgentId, records map[string][]string) {
	term := parseUint64(records, "_term")
	vote := uint32(parseUint64(records, "_vote"))

	le := lem.getOrCreate(zone)
	le.mu.Lock()
	defer le.mu.Unlock()

	if !le.Active || le.Term != term {
		lgElect.Debug("ignoring vote for wrong term", "zone", zone, "expected", le.Term, "got", term)
		return
	}

	le.Votes[senderID] = vote
	lgElect.Info("received vote", "zone", zone, "from", senderID, "vote", vote, "votes_collected", len(le.Votes), "expected", le.ExpectedPeers+1)

	// Check if all votes are in (our vote + peers)
	if len(le.Votes) >= le.ExpectedPeers+1 {
		if le.VoteTimer != nil {
			le.VoteTimer.Stop()
		}
		go lem.determineAndConfirm(zone, term)
	}
}

func (lem *LeaderElectionManager) handleConfirm(zone ZoneName, senderID AgentId, records map[string][]string) {
	term := parseUint64(records, "_term")
	winner := AgentId(parseString(records, "_winner"))

	le := lem.getOrCreate(zone)
	le.mu.Lock()

	if !le.Active || le.Term != term {
		le.mu.Unlock()
		lgElect.Debug("ignoring confirm for inactive/wrong term", "zone", zone, "active", le.Active, "expected", le.Term, "got", term)
		return
	}

	le.Confirms[senderID] = winner
	lgElect.Info("received confirm", "zone", zone, "from", senderID, "winner", winner, "confirms_collected", len(le.Confirms), "expected", le.ExpectedPeers+1)

	// Check if all confirms are in
	if len(le.Confirms) >= le.ExpectedPeers+1 {
		if le.ConfirmTimer != nil {
			le.ConfirmTimer.Stop()
		}
		le.mu.Unlock()
		lem.finalizeElection(zone, term)
		return
	}

	le.mu.Unlock()
}

// onVoteTimeout is called when the vote collection timer expires.
// If not all expected peers voted, the election is aborted — no partial elections.
func (lem *LeaderElectionManager) onVoteTimeout(zone ZoneName, term uint64) {
	le := lem.getOrCreate(zone)
	le.mu.Lock()
	if !le.Active || le.Term != term {
		le.mu.Unlock()
		return
	}

	collected := len(le.Votes)
	expected := le.ExpectedPeers + 1 // peers + self
	if collected < expected {
		le.Active = false
		le.mu.Unlock()
		lgElect.Warn("election aborted: not all peers voted, cannot elect without full participation",
			"zone", zone, "term", term, "votes", collected, "expected", expected)
		return
	}
	le.mu.Unlock()

	lem.determineAndConfirm(zone, term)
}

// determineAndConfirm picks the winner from collected votes, adds our own confirm,
// and broadcasts ELECT-CONFIRM.
func (lem *LeaderElectionManager) determineAndConfirm(zone ZoneName, term uint64) {
	le := lem.getOrCreate(zone)
	le.mu.Lock()

	if !le.Active || le.Term != term {
		le.mu.Unlock()
		return
	}

	winner := determineWinner(le.Votes)
	le.Confirms[lem.localID] = winner

	// Start confirm collection timer
	if le.ConfirmTimer != nil {
		le.ConfirmTimer.Stop()
	}
	le.ConfirmTimer = time.AfterFunc(5*time.Second, func() {
		lem.onConfirmTimeout(zone, term)
	})

	le.mu.Unlock()

	lgElect.Info("determined winner, broadcasting confirm", "zone", zone, "winner", winner, "term", term)

	confirmRecords := map[string][]string{
		"_winner": {string(winner)},
		"_term":   {strconv.FormatUint(term, 10)},
	}
	if err := lem.broadcastFunc(zone, "ELECT-CONFIRM", confirmRecords); err != nil {
		lgElect.Error("failed to broadcast ELECT-CONFIRM", "zone", zone, "err", err)
	}
}

// onConfirmTimeout is called when the confirm collection timer expires.
// If not all expected peers confirmed, the election is aborted — no partial elections.
func (lem *LeaderElectionManager) onConfirmTimeout(zone ZoneName, term uint64) {
	le := lem.getOrCreate(zone)
	le.mu.Lock()
	if !le.Active || le.Term != term {
		le.mu.Unlock()
		return
	}

	collected := len(le.Confirms)
	expected := le.ExpectedPeers + 1
	if collected < expected {
		le.Active = false
		le.mu.Unlock()
		lgElect.Warn("election aborted: not all peers confirmed, cannot elect without full participation",
			"zone", zone, "term", term, "confirms", collected, "expected", expected)
		return
	}
	le.mu.Unlock()

	lem.finalizeElection(zone, term)
}

// finalizeElection checks consensus and caches the leader.
func (lem *LeaderElectionManager) finalizeElection(zone ZoneName, term uint64) {
	le := lem.getOrCreate(zone)
	le.mu.Lock()

	if le.Term != term {
		le.mu.Unlock()
		return
	}

	// Check consensus: all confirms must agree
	var agreedWinner AgentId
	consensus := true
	for _, winner := range le.Confirms {
		if agreedWinner == "" {
			agreedWinner = winner
		} else if winner != agreedWinner {
			consensus = false
			break
		}
	}

	if !consensus || agreedWinner == "" {
		le.Active = false
		le.mu.Unlock()
		lgElect.Warn("no consensus, re-electing", "zone", zone, "term", term)
		// Re-elect after a short random delay to avoid thundering herd
		time.AfterFunc(time.Duration(500+rand.Intn(1000))*time.Millisecond, func() {
			lem.StartElection(zone, le.ExpectedPeers)
		})
		return
	}

	le.Leader = agreedWinner
	le.LeaderExpiry = time.Now().Add(lem.leaderTTL)
	le.Active = false

	isUs := agreedWinner == lem.localID
	lgElect.Info("leader elected", "zone", zone, "leader", agreedWinner, "is_us", isUs, "term", term, "ttl", lem.leaderTTL)

	lem.scheduleReelection(le)
	le.mu.Unlock()

	// If we won, trigger delegation sync setup (SIG(0) key generation + bootstrap)
	if isUs && lem.onLeaderElected != nil {
		go func() {
			if err := lem.onLeaderElected(zone); err != nil {
				lgElect.Error("onLeaderElected callback failed", "zone", zone, "error", err)
			}
		}()
	}
}

// scheduleReelection sets up a timer to re-elect at 90% of the leader TTL.
// Must be called with le.mu held.
func (lem *LeaderElectionManager) scheduleReelection(le *LeaderElection) {
	if le.ReelectTimer != nil {
		le.ReelectTimer.Stop()
	}
	zone := le.Zone
	le.ReelectTimer = time.AfterFunc(lem.leaderTTL*9/10, func() {
		configured := lem.configuredPeers(zone)
		operational := 0
		if lem.operationalPeersFunc != nil {
			operational = lem.operationalPeersFunc(zone)
		}

		if configured == 0 {
			// Truly single agent — self-elect
			lgElect.Info("leader TTL expiring, single agent, re-self-electing", "zone", zone)
			lem.StartElection(zone, 0)
		} else if operational >= configured {
			// All configured peers are operational — hold election
			lgElect.Info("leader TTL expiring, all peers operational, triggering re-election",
				"zone", zone, "operational", operational, "configured", configured)
			lem.StartElection(zone, configured)
		} else {
			// Not all configured peers are reachable — cannot elect.
			// Leader TTL will expire, causing a change freeze until peers reconnect.
			lgElect.Warn("leader TTL expiring, not all configured peers operational — no election, change freeze",
				"zone", zone, "operational", operational, "configured", configured)
			lem.DeferElection(zone)
		}
	})
}

// determineWinner picks the agent with the highest vote. Ties broken by lexicographic label.
func determineWinner(votes map[AgentId]uint32) AgentId {
	var winner AgentId
	var highVote uint32
	for id, vote := range votes {
		if vote > highVote || (vote == highVote && string(id) < string(winner)) {
			winner = id
			highVote = vote
		}
	}
	return winner
}

// importSig0KeyFromPeer imports a SIG(0) key received from a peer via RFI CONFIG.
// configData must contain "algorithm", "privatekey" (PEM), and "keyrr" (KEY RR string).
func importSig0KeyFromPeer(kdb *KeyDB, keyName string, configData map[string]string) error {
	algorithm := configData["algorithm"]
	privatekey := configData["privatekey"]
	keyrr := configData["keyrr"]

	if algorithm == "" || privatekey == "" || keyrr == "" {
		return fmt.Errorf("incomplete key data: algorithm=%q privatekey=%d bytes keyrr=%q",
			algorithm, len(privatekey), keyrr)
	}

	// Parse the PEM private key + KEY RR into a PrivateKeyCache
	pkc, err := PrepareKeyCache(privatekey, keyrr)
	if err != nil {
		return fmt.Errorf("PrepareKeyCache failed: %v", err)
	}

	// Import via Sig0KeyMgmt "add" (also adds to TrustStore)
	kp := KeystorePost{
		Command:         "sig0-mgmt",
		SubCommand:      "add",
		Keyname:         keyName,
		State:           Sig0StateActive,
		PrivateKeyCache: pkc,
	}
	resp, err := kdb.Sig0KeyMgmt(nil, kp)
	if err != nil {
		return fmt.Errorf("Sig0KeyMgmt add failed: %v", err)
	}
	if resp.Error {
		return fmt.Errorf("Sig0KeyMgmt add error: %s", resp.ErrorMsg)
	}
	lgElect.Info("imported SIG(0) key from peer", "name", keyName, "algorithm", algorithm, "keyid", pkc.KeyId)
	return nil
}

// broadcastElectToZone sends an election RFI message to all agents in a zone.
func (ar *AgentRegistry) broadcastElectToZone(zone ZoneName, rfiType string, records map[string][]string) error {
	zad, err := ar.GetZoneAgentData(zone)
	if err != nil {
		return fmt.Errorf("broadcastElectToZone: %w", err)
	}

	for _, agent := range zad.Agents {
		if AgentId(agent.Identity) == AgentId(ar.LocalAgent.Identity) {
			continue // don't send to ourselves
		}
		if !agent.IsAnyTransportOperational() {
			lgElect.Debug("skipping non-operational agent", "agent", agent.Identity)
			continue
		}
		msg := &AgentMsgPost{
			MessageType:  AgentMsgRfi,
			OriginatorID: AgentId(ar.LocalAgent.Identity),
			Zone:         zone,
			RfiType:      rfiType,
			Records:      records,
			Time:         time.Now(),
		}
		go func(a *Agent) {
			if _, err := ar.sendRfiToAgent(a, msg); err != nil {
				lgElect.Warn("failed to send election message", "agent", a.Identity, "rfiType", rfiType, "err", err)
			}
		}(agent)
	}
	return nil
}

// Helper functions for parsing records

func parseUint64(records map[string][]string, key string) uint64 {
	vals, ok := records[key]
	if !ok || len(vals) == 0 {
		return 0
	}
	v, _ := strconv.ParseUint(vals[0], 10, 64)
	return v
}

func parseString(records map[string][]string, key string) string {
	vals, ok := records[key]
	if !ok || len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// PeerSyncInfo describes a peer agent's status for a zone.
type PeerSyncInfo struct {
	Identity    AgentId `json:"identity"`
	State       string  `json:"state"`
	Transport   string  `json:"transport"`
	Operational bool    `json:"operational"`
}

// DsyncSchemeInfo describes a parent DSYNC sync scheme.
type DsyncSchemeInfo struct {
	Scheme string `json:"scheme"` // "UPDATE", "NOTIFY", etc.
	Type   string `json:"type"`   // "CDS", "CSYNC", "ANY", etc.
	Target string `json:"target"` // target host
	Port   uint16 `json:"port"`
}

// ParentSyncStatus holds on-demand status information about parent delegation sync for a zone.
type ParentSyncStatus struct {
	Zone            ZoneName        `json:"zone"`
	Leader          AgentId         `json:"leader"`
	LeaderExpiry    time.Time       `json:"leader_expiry"`
	ElectionTerm    uint64          `json:"election_term"`
	IsLeader        bool            `json:"is_leader"`
	KeyAlgorithm    string          `json:"key_algorithm,omitempty"`
	KeyID           uint16          `json:"key_id,omitempty"`
	KeyRR           string          `json:"key_rr,omitempty"`
	ApexPublished   bool            `json:"apex_published"`
	ParentState     uint8           `json:"parent_state"`
	ParentStateName string          `json:"parent_state_name,omitempty"`
	ChildNS         []string        `json:"child_ns,omitempty"`
	KeyPublication  map[string]bool `json:"key_publication,omitempty"`
	LastChecked     time.Time       `json:"last_checked"`

	// Sync scheme info from parent DSYNC discovery
	ParentZone   string            `json:"parent_zone,omitempty"`
	SyncSchemes  []DsyncSchemeInfo `json:"sync_schemes,omitempty"`
	ActiveScheme string            `json:"active_scheme,omitempty"` // best scheme: "UPDATE", "NOTIFY", etc.

	// CDS/CSYNC publication status
	CdsPublished   bool `json:"cds_published"`
	CsyncPublished bool `json:"csync_published"`
	ZoneSigned     bool `json:"zone_signed"`

	// Peer agents for this zone
	Peers []PeerSyncInfo `json:"peers,omitempty"`
}

// Sig0KeyOwnerName computes the RFC 9615-style owner name for a child SIG(0) KEY RR.
// Format: _sig0key.<zone>._signal.<nameserver>
func Sig0KeyOwnerName(zone, nameserver string) string {
	return "_sig0key." + dns.Fqdn(zone) + "_signal." + dns.Fqdn(nameserver)
}

// GetParentSyncStatus computes the current parent sync status for a zone on demand.
func (lem *LeaderElectionManager) GetParentSyncStatus(zone ZoneName, zd *ZoneData, kdb *KeyDB, imr *Imr, ar *AgentRegistry) ParentSyncStatus {
	status := ParentSyncStatus{
		Zone:        zone,
		LastChecked: time.Now(),
	}

	// 1. Leader election state
	le := lem.getOrCreate(zone)
	le.mu.Lock()
	status.Leader = le.Leader
	status.LeaderExpiry = le.LeaderExpiry
	status.ElectionTerm = le.Term
	le.mu.Unlock()
	status.IsLeader = status.Leader == lem.localID && time.Now().Before(status.LeaderExpiry)

	if zd == nil || kdb == nil {
		return status
	}

	// 2. SIG(0) key info
	targetName := DsyncUpdateTargetName(string(zone))
	if targetName == "" {
		targetName = string(zone)
	}
	sak, err := kdb.GetSig0Keys(targetName, Sig0StateActive)
	if err == nil && len(sak.Keys) > 0 {
		key := sak.Keys[0]
		status.KeyAlgorithm = dns.AlgorithmToString[key.Algorithm]
		status.KeyID = key.KeyId
		status.KeyRR = key.KeyRR.String()

		// Read parent_state from keystore
		var parentState int
		row := kdb.DB.QueryRow("SELECT COALESCE(parent_state, 0) FROM Sig0KeyStore WHERE zonename=? AND keyid=?",
			targetName, key.KeyId)
		if err := row.Scan(&parentState); err == nil {
			status.ParentState = uint8(parentState)
			status.ParentStateName = edns0.KeyStateToString(uint8(parentState))
		}
	}

	// 3. Check apex records
	owner, err := zd.GetOwner(zd.ZoneName)
	if err == nil && owner != nil {
		// KEY publication
		if _, keyExists := owner.RRtypes.Get(dns.TypeKEY); keyExists {
			status.ApexPublished = true
		}
		// CDS publication
		if cdsRRset, exists := owner.RRtypes.Get(dns.TypeCDS); exists && len(cdsRRset.RRs) > 0 {
			status.CdsPublished = true
		}
		// CSYNC publication
		if csyncRRset, exists := owner.RRtypes.Get(dns.TypeCSYNC); exists && len(csyncRRset.RRs) > 0 {
			status.CsyncPublished = true
		}
		// Zone signing status
		status.ZoneSigned = zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning]
	}

	// 4. Get child NS names
	if owner != nil {
		nsRRset := owner.RRtypes.GetOnlyRRSet(dns.TypeNS)
		for _, rr := range nsRRset.RRs {
			if nsRR, ok := rr.(*dns.NS); ok {
				status.ChildNS = append(status.ChildNS, nsRR.Ns)
			}
		}
	}

	// 5. Check _signal KEY publication for each child NS via IMR.
	// Only check if we actually have a SIG(0) key — if no key exists locally,
	// any KEY records found at _signal names belong to someone else.
	if imr != nil && len(status.ChildNS) > 0 && status.KeyAlgorithm != "" {
		status.KeyPublication = make(map[string]bool)
		for _, ns := range status.ChildNS {
			ownerName := Sig0KeyOwnerName(string(zone), ns)
			resp, err := imr.ImrQuery(context.Background(), ownerName, dns.TypeKEY, dns.ClassINET, nil)
			published := err == nil && resp != nil && resp.RRset != nil && len(resp.RRset.RRs) > 0
			status.KeyPublication[ownerName] = published
		}
	}

	// 6. DSYNC discovery — find what sync schemes the parent supports
	if imr != nil {
		dsyncRes, err := imr.DsyncDiscovery(context.Background(), string(zone), false)
		if err == nil {
			status.ParentZone = dsyncRes.Parent
			for _, drr := range dsyncRes.Rdata {
				scheme := "UNKNOWN"
				switch drr.Scheme {
				case core.SchemeNotify:
					scheme = "NOTIFY"
				case core.SchemeUpdate:
					scheme = "UPDATE"
				case core.SchemeScanner:
					scheme = "SCANNER"
				case core.SchemeAPI:
					scheme = "API"
				}
				rrtype := dns.TypeToString[drr.Type]
				if rrtype == "" {
					rrtype = fmt.Sprintf("TYPE%d", drr.Type)
				}
				status.SyncSchemes = append(status.SyncSchemes, DsyncSchemeInfo{
					Scheme: scheme,
					Type:   rrtype,
					Target: drr.Target,
					Port:   drr.Port,
				})
			}
			// Determine best active scheme
			activeScheme, _, err := zd.BestSyncScheme(context.Background(), imr)
			if err == nil {
				status.ActiveScheme = activeScheme
			}
		}
	}

	// 7. Peer agents for this zone
	if ar != nil {
		zad, err := ar.GetZoneAgentData(zone)
		if err == nil {
			for _, agent := range zad.Agents {
				if agent.Identity == lem.localID {
					continue // skip self
				}
				transport := "-"
				if agent.DnsDetails != nil && agent.DnsDetails.State == AgentStateOperational {
					transport = "DNS"
				} else if agent.ApiDetails != nil && agent.ApiDetails.State == AgentStateOperational {
					transport = "API"
				}
				status.Peers = append(status.Peers, PeerSyncInfo{
					Identity:    agent.Identity,
					State:       string(agent.EffectiveState()),
					Transport:   transport,
					Operational: agent.IsAnyTransportOperational(),
				})
			}
		}
	}

	return status
}

// PublishKeyToCombiner sends a KEY RR to the combiner as a REPLACE operation.
// Used by MP zones where the combiner manages the zone apex.
func PublishKeyToCombiner(zone ZoneName, keyRR dns.RR, tm *TransportManager) (string, error) {
	update := &ZoneUpdate{
		Zone: zone,
		Operations: []core.RROperation{{
			Operation: "replace",
			RRtype:    "KEY",
			Records:   []string{keyRR.String()},
		}},
	}
	return tm.EnqueueForCombiner(zone, update, "")
}
