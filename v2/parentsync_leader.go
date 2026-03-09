/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"time"
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
type LeaderElectionManager struct {
	mu            sync.RWMutex
	elections     map[ZoneName]*LeaderElection
	localID       AgentId
	leaderTTL     time.Duration
	broadcastFunc func(zone ZoneName, rfiType string, records map[string][]string) error
}

func NewLeaderElectionManager(localID AgentId, leaderTTL time.Duration, broadcastFunc func(ZoneName, string, map[string][]string) error) *LeaderElectionManager {
	return &LeaderElectionManager{
		elections:     make(map[ZoneName]*LeaderElection),
		localID:       localID,
		leaderTTL:     leaderTTL,
		broadcastFunc: broadcastFunc,
	}
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
func (lem *LeaderElectionManager) IsLeader(zone ZoneName) bool {
	leader, ok := lem.GetLeader(zone)
	if !ok {
		return false
	}
	return leader == lem.localID
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
	le.VoteTimer = time.AfterFunc(3*time.Second, func() {
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
	le.VoteTimer = time.AfterFunc(3*time.Second, func() {
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
	lgElect.Debug("received vote", "zone", zone, "from", senderID, "vote", vote, "total", len(le.Votes))

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

	if le.Term != term {
		le.mu.Unlock()
		lgElect.Debug("ignoring confirm for wrong term", "zone", zone, "expected", le.Term, "got", term)
		return
	}

	le.Confirms[senderID] = winner
	lgElect.Debug("received confirm", "zone", zone, "from", senderID, "winner", winner, "total", len(le.Confirms))

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
func (lem *LeaderElectionManager) onVoteTimeout(zone ZoneName, term uint64) {
	le := lem.getOrCreate(zone)
	le.mu.Lock()
	if !le.Active || le.Term != term {
		le.mu.Unlock()
		return
	}
	le.mu.Unlock()

	lgElect.Info("vote timeout, determining winner with available votes", "zone", zone, "term", term)
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
	le.ConfirmTimer = time.AfterFunc(3*time.Second, func() {
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
func (lem *LeaderElectionManager) onConfirmTimeout(zone ZoneName, term uint64) {
	lgElect.Info("confirm timeout, finalizing with available confirms", "zone", zone, "term", term)
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
}

// scheduleReelection sets up a timer to re-elect at 90% of the leader TTL.
// Must be called with le.mu held.
func (lem *LeaderElectionManager) scheduleReelection(le *LeaderElection) {
	if le.ReelectTimer != nil {
		le.ReelectTimer.Stop()
	}
	zone := le.Zone
	peers := le.ExpectedPeers
	le.ReelectTimer = time.AfterFunc(lem.leaderTTL*9/10, func() {
		lgElect.Info("leader TTL expiring, triggering re-election", "zone", zone)
		lem.StartElection(zone, peers)
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
