/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Reliable message queue for TDNS agent synchronization.
 *
 * Ensures that sync messages to combiners and remote agents are delivered
 * with retry-until-confirmed semantics. Messages are queued immediately
 * regardless of recipient state and delivered when the recipient becomes
 * operational. Failed deliveries are retried with exponential backoff.
 *
 * Architecture:
 *   SynchedDataEngine → TransportManager.EnqueueFor*() → ReliableMessageQueue
 *   ReliableMessageQueue → TransportManager.SendSyncWithFallback() → Transport
 *
 * See tdns/docs/reliable-message-delivery-architecture.md for full design.
 */
package tdns

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"
)

// MessageState tracks the delivery state of a queued message.
type MessageState uint8

const (
	MessageQueued          MessageState = iota // Waiting to be sent
	MessageSending                            // Send in progress
	MessageAwaitingConfirm                    // Sent, waiting for confirmation
	MessageConfirmed                          // Delivery confirmed
	MessageFailed                             // Permanently failed (expired or max retries)
)

var messageStateToString = map[MessageState]string{
	MessageQueued:          "QUEUED",
	MessageSending:         "SENDING",
	MessageAwaitingConfirm: "AWAITING_CONFIRM",
	MessageConfirmed:       "CONFIRMED",
	MessageFailed:          "FAILED",
}

func (s MessageState) String() string {
	if str, ok := messageStateToString[s]; ok {
		return str
	}
	return "UNKNOWN"
}

// MessagePriority determines delivery order when multiple messages are pending.
type MessagePriority uint8

const (
	PriorityHigh   MessagePriority = iota // Combiner updates (zone consistency)
	PriorityNormal                        // Agent-to-agent updates
)

// OutgoingMessage represents a message to be delivered reliably.
type OutgoingMessage struct {
	DistributionID string          // Unique ID for tracking this delivery
	RecipientID    AgentId         // Who should receive this
	RecipientType  string          // "combiner" or "agent"
	Zone           ZoneName        // Zone context
	Update         *ZoneUpdate     // The zone update data to send
	Priority       MessagePriority // Delivery priority
	CreatedAt      time.Time       // When enqueued
	ExpiresAt      time.Time       // When to give up
}

// PendingMessage wraps an OutgoingMessage with delivery state tracking.
type PendingMessage struct {
	Message      *OutgoingMessage
	State        MessageState
	AttemptCount int
	LastAttempt  time.Time
	NextAttempt  time.Time // Scheduled time for next delivery attempt
	LastError    string
}

// QueueStats provides visibility into the queue's current state.
type QueueStats struct {
	TotalPending   int            `json:"total_pending"`
	ByState        map[string]int `json:"by_state"`
	ByPriority     map[string]int `json:"by_priority"`
	TotalDelivered int            `json:"total_delivered"`
	TotalFailed    int            `json:"total_failed"`
	TotalExpired   int            `json:"total_expired"`
	OldestAge      time.Duration  `json:"oldest_age_seconds"`
}

// PendingMessageInfo is a JSON-serializable snapshot of a pending message for CLI display.
type PendingMessageInfo struct {
	DistributionID string `json:"distribution_id"`
	RecipientID    string `json:"recipient_id"`
	RecipientType  string `json:"recipient_type"`
	Zone           string `json:"zone"`
	Priority       string `json:"priority"`
	State          string `json:"state"`
	AttemptCount   int    `json:"attempt_count"`
	CreatedAt      string `json:"created_at"`
	ExpiresAt      string `json:"expires_at"`
	NextAttempt    string `json:"next_attempt"`
	LastAttempt    string `json:"last_attempt,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	Age            string `json:"age"`
}

// ReliableMessageQueue ensures messages are delivered with retry-until-confirmed semantics.
//
// Messages are accepted immediately via Enqueue() regardless of recipient state.
// A background worker periodically processes the queue:
//   - Checks if recipient is operational before attempting delivery
//   - Sends via TransportManager (which handles transport selection)
//   - Retries with exponential backoff on failure
//   - Tracks confirmations via distribution ID
//   - Expires messages after a configurable timeout
type ReliableMessageQueue struct {
	mu sync.RWMutex

	// Pending messages indexed by distribution ID
	pending map[string]*PendingMessage

	// References to other components (set after creation, before Start)
	agentRegistry *AgentRegistry

	// sendFunc is called to actually deliver a message. Set by TransportManager
	// after queue creation to avoid circular dependency.
	// Returns nil on successful send (message is now awaiting confirmation).
	sendFunc func(ctx context.Context, msg *OutgoingMessage) error

	// Statistics
	totalDelivered int
	totalFailed    int
	totalExpired   int

	// Configuration
	baseBackoff        time.Duration // Initial retry interval (default: 2s)
	maxBackoff         time.Duration // Maximum retry interval (default: 60s)
	confirmTimeout     time.Duration // How long to wait for confirmation after send (default: 30s)
	expirationTimeout  time.Duration // How long to keep retrying (default: 24h)
	processInterval    time.Duration // How often to process the queue (default: 1s)
	maxQueueSize       int           // Maximum number of pending messages (default: 10000)
}

// ReliableMessageQueueConfig holds configuration for creating a queue.
type ReliableMessageQueueConfig struct {
	AgentRegistry     *AgentRegistry
	BaseBackoff       time.Duration // Default: 2s
	MaxBackoff        time.Duration // Default: 60s
	ConfirmTimeout    time.Duration // Default: 30s
	ExpirationTimeout time.Duration // Default: 24h
	ProcessInterval   time.Duration // Default: 1s
	MaxQueueSize      int           // Default: 10000
}

// NewReliableMessageQueue creates a new queue with the given configuration.
func NewReliableMessageQueue(cfg *ReliableMessageQueueConfig) *ReliableMessageQueue {
	q := &ReliableMessageQueue{
		pending:       make(map[string]*PendingMessage),
		agentRegistry: cfg.AgentRegistry,

		baseBackoff:       withDefault(cfg.BaseBackoff, 2*time.Second),
		maxBackoff:        withDefault(cfg.MaxBackoff, 60*time.Second),
		confirmTimeout:    withDefault(cfg.ConfirmTimeout, 30*time.Second),
		expirationTimeout: withDefault(cfg.ExpirationTimeout, 24*time.Hour),
		processInterval:   withDefault(cfg.ProcessInterval, 1*time.Second),
		maxQueueSize:      withDefaultInt(cfg.MaxQueueSize, 10000),
	}

	return q
}

// SetSendFunc sets the function used to deliver messages. Must be called before Start().
// This is set by TransportManager to avoid circular dependency at construction time.
func (q *ReliableMessageQueue) SetSendFunc(f func(ctx context.Context, msg *OutgoingMessage) error) {
	q.sendFunc = f
}

// Start begins processing the queue. Runs until the context is cancelled.
func (q *ReliableMessageQueue) Start(ctx context.Context) {
	if q.sendFunc == nil {
		log.Printf("ReliableMessageQueue: WARNING - started without sendFunc, messages will not be delivered")
	}

	log.Printf("ReliableMessageQueue: Starting (backoff: %s-%s, expiration: %s, interval: %s)",
		q.baseBackoff, q.maxBackoff, q.expirationTimeout, q.processInterval)

	ticker := time.NewTicker(q.processInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			q.mu.RLock()
			remaining := len(q.pending)
			q.mu.RUnlock()
			log.Printf("ReliableMessageQueue: Shutting down with %d pending messages", remaining)
			return

		case <-ticker.C:
			q.processQueue(ctx)
		}
	}
}

// Enqueue adds a message to the queue for reliable delivery.
// Returns immediately. The message will be delivered asynchronously.
func (q *ReliableMessageQueue) Enqueue(msg *OutgoingMessage) error {
	if msg == nil {
		return fmt.Errorf("cannot enqueue nil message")
	}
	if msg.DistributionID == "" {
		return fmt.Errorf("message must have a DistributionID")
	}
	if msg.RecipientID == "" {
		return fmt.Errorf("message must have a RecipientID")
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	// Check queue size
	if len(q.pending) >= q.maxQueueSize {
		return fmt.Errorf("queue full (%d messages), rejecting message %s for %s",
			len(q.pending), msg.DistributionID, msg.RecipientID)
	}

	// Check for duplicate distribution ID
	if _, exists := q.pending[msg.DistributionID]; exists {
		return fmt.Errorf("duplicate distribution ID: %s", msg.DistributionID)
	}

	pending := &PendingMessage{
		Message:     msg,
		State:       MessageQueued,
		NextAttempt: time.Now(), // Try immediately
	}

	q.pending[msg.DistributionID] = pending

	log.Printf("ReliableMessageQueue: Enqueued %s for %s (zone: %s, type: %s, expires: %s)",
		msg.DistributionID, msg.RecipientID, msg.Zone, msg.RecipientType,
		msg.ExpiresAt.Format(time.RFC3339))

	return nil
}

// MarkConfirmed marks a message as successfully delivered and removes it from the queue.
func (q *ReliableMessageQueue) MarkConfirmed(distributionID string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	pending, exists := q.pending[distributionID]
	if !exists {
		// Not in queue - may have already been confirmed or expired
		return false
	}

	log.Printf("ReliableMessageQueue: Confirmed %s for %s (after %d attempts, age: %s)",
		distributionID, pending.Message.RecipientID, pending.AttemptCount,
		time.Since(pending.Message.CreatedAt).Round(time.Second))

	pending.State = MessageConfirmed
	delete(q.pending, distributionID)
	q.totalDelivered++
	return true
}

// GetStats returns current queue statistics.
func (q *ReliableMessageQueue) GetStats() QueueStats {
	q.mu.RLock()
	defer q.mu.RUnlock()

	stats := QueueStats{
		TotalPending:   len(q.pending),
		ByState:        make(map[string]int),
		ByPriority:     make(map[string]int),
		TotalDelivered: q.totalDelivered,
		TotalFailed:    q.totalFailed,
		TotalExpired:   q.totalExpired,
	}

	var oldest time.Time
	for _, pm := range q.pending {
		stats.ByState[pm.State.String()]++
		if pm.Message.Priority == PriorityHigh {
			stats.ByPriority["high"]++
		} else {
			stats.ByPriority["normal"]++
		}
		if oldest.IsZero() || pm.Message.CreatedAt.Before(oldest) {
			oldest = pm.Message.CreatedAt
		}
	}

	if !oldest.IsZero() {
		stats.OldestAge = time.Since(oldest)
	}

	return stats
}

// GetPendingMessages returns a JSON-serializable snapshot of all pending messages.
func (q *ReliableMessageQueue) GetPendingMessages() []PendingMessageInfo {
	q.mu.RLock()
	defer q.mu.RUnlock()

	msgs := make([]PendingMessageInfo, 0, len(q.pending))
	now := time.Now()

	for _, pm := range q.pending {
		priority := "normal"
		if pm.Message.Priority == PriorityHigh {
			priority = "high"
		}

		info := PendingMessageInfo{
			DistributionID: pm.Message.DistributionID,
			RecipientID:    string(pm.Message.RecipientID),
			RecipientType:  pm.Message.RecipientType,
			Zone:           string(pm.Message.Zone),
			Priority:       priority,
			State:          pm.State.String(),
			AttemptCount:   pm.AttemptCount,
			CreatedAt:      pm.Message.CreatedAt.Format(time.RFC3339),
			ExpiresAt:      pm.Message.ExpiresAt.Format(time.RFC3339),
			NextAttempt:    pm.NextAttempt.Format(time.RFC3339),
			LastError:      pm.LastError,
			Age:            now.Sub(pm.Message.CreatedAt).Round(time.Second).String(),
		}
		if !pm.LastAttempt.IsZero() {
			info.LastAttempt = pm.LastAttempt.Format(time.RFC3339)
		}

		msgs = append(msgs, info)
	}

	return msgs
}

// processQueue is called periodically to attempt delivery of pending messages.
func (q *ReliableMessageQueue) processQueue(ctx context.Context) {
	q.mu.Lock()

	now := time.Now()
	var toSend []*PendingMessage
	var toRemove []string

	for distID, pending := range q.pending {
		// Check expiration
		if now.After(pending.Message.ExpiresAt) {
			log.Printf("ReliableMessageQueue: Expired %s for %s (after %d attempts, age: %s)",
				distID, pending.Message.RecipientID, pending.AttemptCount,
				time.Since(pending.Message.CreatedAt).Round(time.Second))
			toRemove = append(toRemove, distID)
			q.totalExpired++
			continue
		}

		// Skip if not ready for next attempt
		if now.Before(pending.NextAttempt) {
			continue
		}

		// Skip if already being sent
		if pending.State == MessageSending {
			continue
		}

		// Check if recipient is reachable via any transport
		if !q.isRecipientReady(pending.Message.RecipientID) {
			// Log on first deferral to aid debugging
			if pending.AttemptCount == 0 {
				agent, exists := q.agentRegistry.S.Get(pending.Message.RecipientID)
				stateStr := "not in registry"
				if exists {
					dnsState := "nil"
					apiState := "nil"
					if agent.DnsDetails != nil {
						dnsState = AgentStateToString[agent.DnsDetails.State]
					}
					if agent.ApiDetails != nil {
						apiState = AgentStateToString[agent.ApiDetails.State]
					}
					stateStr = fmt.Sprintf("top-level=%s dns=%s api=%s",
						AgentStateToString[agent.State], dnsState, apiState)
				}
				log.Printf("ReliableMessageQueue: Deferring %s for %s (recipient state: %s)",
					distID, pending.Message.RecipientID, stateStr)
			}
			// Not ready - schedule a retry but don't count it as a failed attempt
			q.scheduleRetryLocked(pending, false)
			continue
		}

		// Ready to send
		toSend = append(toSend, pending)
		pending.State = MessageSending
	}

	// Remove expired messages
	for _, distID := range toRemove {
		delete(q.pending, distID)
	}

	q.mu.Unlock()

	// Send messages outside the lock
	for _, pending := range toSend {
		q.attemptDelivery(ctx, pending)
	}
}

// isRecipientReady checks if the recipient agent is reachable via at least one transport.
// It checks per-transport states (DnsDetails.State, ApiDetails.State) rather than the
// top-level Agent.State, because transport states reflect actual communication readiness
// while the top-level state may lag behind (e.g. stuck at KNOWN after discovery).
func (q *ReliableMessageQueue) isRecipientReady(recipientID AgentId) bool {
	if q.agentRegistry == nil {
		return false
	}

	agent, exists := q.agentRegistry.S.Get(recipientID)
	if !exists {
		return false
	}

	// Check if either transport is in a reachable state
	return isTransportReady(agent.DnsDetails) || isTransportReady(agent.ApiDetails)
}

// isTransportReady returns true if the transport details indicate a reachable agent.
func isTransportReady(details *AgentDetails) bool {
	if details == nil {
		return false
	}
	switch details.State {
	case AgentStateOperational, AgentStateIntroduced, AgentStateLegacy,
		AgentStateDegraded, AgentStateInterrupted:
		return true
	default:
		return false
	}
}

// attemptDelivery tries to send a message and handles the result.
func (q *ReliableMessageQueue) attemptDelivery(ctx context.Context, pending *PendingMessage) {
	msg := pending.Message

	if q.sendFunc == nil {
		q.mu.Lock()
		pending.LastError = "no sendFunc configured"
		q.scheduleRetryLocked(pending, true)
		q.mu.Unlock()
		return
	}

	// Attempt delivery
	err := q.sendFunc(ctx, msg)

	q.mu.Lock()
	defer q.mu.Unlock()

	pending.AttemptCount++
	pending.LastAttempt = time.Now()

	if err != nil {
		log.Printf("ReliableMessageQueue: Send failed for %s to %s (attempt %d): %v",
			msg.DistributionID, msg.RecipientID, pending.AttemptCount, err)
		pending.LastError = err.Error()
		q.scheduleRetryLocked(pending, true)
		return
	}

	// Successfully sent and transport-level acknowledged.
	// SendSyncWithFallback returns nil only when the recipient ACKed the NOTIFY,
	// which is sufficient confirmation for reliable delivery purposes.
	// Mark as confirmed and remove from queue.
	log.Printf("ReliableMessageQueue: Confirmed %s for %s (attempt %d, age: %s)",
		msg.DistributionID, msg.RecipientID, pending.AttemptCount,
		time.Since(msg.CreatedAt).Round(time.Second))
	pending.State = MessageConfirmed
	delete(q.pending, msg.DistributionID)
	q.totalDelivered++
}

// scheduleRetryLocked calculates the next retry time using exponential backoff.
// Must be called with q.mu held.
// If countAsAttempt is false, uses a fixed short backoff (for "not ready" cases).
func (q *ReliableMessageQueue) scheduleRetryLocked(pending *PendingMessage, countAsAttempt bool) {
	if !countAsAttempt {
		// Recipient not ready - use a fixed backoff, don't count as attempt
		pending.NextAttempt = time.Now().Add(q.baseBackoff)
		pending.State = MessageQueued
		return
	}

	// Exponential backoff: base * 2^(attempts-1), capped at maxBackoff
	backoff := q.baseBackoff
	for i := 1; i < pending.AttemptCount && backoff < q.maxBackoff; i++ {
		backoff *= 2
	}
	if backoff > q.maxBackoff {
		backoff = q.maxBackoff
	}

	pending.NextAttempt = time.Now().Add(backoff)
	pending.State = MessageQueued

	log.Printf("ReliableMessageQueue: Retry scheduled for %s to %s in %s (attempt %d)",
		pending.Message.DistributionID, pending.Message.RecipientID,
		backoff.Round(time.Millisecond), pending.AttemptCount)
}

// GenerateQueueDistributionID creates a unique distribution ID for queue messages.
func GenerateQueueDistributionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("q-%s-%d", hex.EncodeToString(b), time.Now().UnixMilli())
}

// --- Helper functions ---

func withDefault(val, def time.Duration) time.Duration {
	if val == 0 {
		return def
	}
	return val
}

func withDefaultInt(val, def int) int {
	if val == 0 {
		return def
	}
	return val
}

