/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * In-memory error journal for the combiner/receiver. Records errors that occur
 * during HandleChunkNotify processing, indexed by distribution ID for targeted
 * diagnostic queries.
 */
package tdns

import (
	"sync"
	"time"
)

// ErrorJournalEntry records a single error that occurred during CHUNK NOTIFY processing.
type ErrorJournalEntry struct {
	DistributionID string    `json:"distribution_id"`
	Sender         string    `json:"sender"`       // Sender identity (extracted from QNAME control zone)
	MessageType    string    `json:"message_type"` // "ping", "beat", "sync", "update", or "unknown"
	ErrorMsg       string    `json:"error_msg"`
	QNAME          string    `json:"qname"` // Original NOTIFY qname
	Timestamp      time.Time `json:"timestamp"`
}

// ErrorJournal is a bounded, time-windowed in-memory ring buffer of errors.
// Thread-safe. No persistence — this is for operational debugging.
type ErrorJournal struct {
	mu       sync.RWMutex
	entries  []ErrorJournalEntry
	maxCount int           // Maximum number of entries to retain
	maxAge   time.Duration // Maximum age of entries to retain
}

// NewErrorJournal creates a new error journal with the given retention limits.
func NewErrorJournal(maxCount int, maxAge time.Duration) *ErrorJournal {
	if maxCount <= 0 {
		maxCount = 1000
	}
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	return &ErrorJournal{
		entries:  make([]ErrorJournalEntry, 0, maxCount),
		maxCount: maxCount,
		maxAge:   maxAge,
	}
}

// Record adds a new error entry to the journal, evicting old entries as needed.
func (ej *ErrorJournal) Record(entry ErrorJournalEntry) {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	ej.mu.Lock()
	defer ej.mu.Unlock()

	// Evict by age first
	ej.evictOldLocked()

	// Evict by count: make room before appending
	if len(ej.entries) >= ej.maxCount {
		excess := len(ej.entries) - ej.maxCount + 1
		ej.entries = ej.entries[excess:]
	}

	// Append
	ej.entries = append(ej.entries, entry)
}

// ListSince returns all errors within the given duration from now.
func (ej *ErrorJournal) ListSince(duration time.Duration) []ErrorJournalEntry {
	ej.mu.RLock()
	defer ej.mu.RUnlock()

	cutoff := time.Now().Add(-duration)
	var result []ErrorJournalEntry
	for _, e := range ej.entries {
		if e.Timestamp.After(cutoff) {
			result = append(result, e)
		}
	}
	return result
}

// LookupByDistID returns the error entry for a specific distribution ID, if any.
func (ej *ErrorJournal) LookupByDistID(distID string) (*ErrorJournalEntry, bool) {
	ej.mu.RLock()
	defer ej.mu.RUnlock()

	// Search from newest to oldest for most recent match
	for i := len(ej.entries) - 1; i >= 0; i-- {
		if ej.entries[i].DistributionID == distID {
			entry := ej.entries[i] // copy
			return &entry, true
		}
	}
	return nil, false
}

// evictOldLocked removes entries older than maxAge. Must be called with mu held.
func (ej *ErrorJournal) evictOldLocked() {
	cutoff := time.Now().Add(-ej.maxAge)
	// Entries are in chronological order; find first non-expired
	idx := 0
	for idx < len(ej.entries) && ej.entries[idx].Timestamp.Before(cutoff) {
		idx++
	}
	if idx > 0 {
		ej.entries = ej.entries[idx:]
	}
}
