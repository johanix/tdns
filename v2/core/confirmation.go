/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Generic confirmation accumulation framework
 * Extracted from tdns-nm/tnm for shared use by KDC, KRS, and agents
 */

package core

import (
	"fmt"
	"time"
)

// ConfirmationEntry is a generic interface for confirmation entries.
//
// This interface is implemented by specific types like:
//   - KeyStatusEntry (KDC/KRS key installation confirmation)
//   - ComponentStatusEntry (KDC/KRS component installation confirmation)
//   - SyncStatusEntry (Agent-to-agent sync confirmation)
//
// Each implementation provides its own fields and logic, but all must
// provide an ID, status, and details for generic accumulation.
type ConfirmationEntry interface {
	// GetId returns the unique identifier for this confirmation entry
	// (e.g., key ID, component ID, sync operation ID)
	GetId() string

	// GetStatus returns "success" or "failed"
	GetStatus() string

	// GetDetails returns additional details or error message
	// Returns empty string for successful operations
	GetDetails() string
}

// ConfirmationAccumulator accumulates confirmation entries and tracks timing.
//
// This is a generic accumulator used by KDC, KRS, and agents to collect
// success/failure status for operations before sending confirmation messages.
//
// Usage pattern:
//  1. Create accumulator: acc := NewConfirmationAccumulator()
//  2. Add entries as operations complete: acc.AddEntry(entry)
//  3. Get results: successes := acc.GetSuccesses(), failures := acc.GetFailures()
//  4. Mark complete: acc.MarkComplete()
type ConfirmationAccumulator struct {
	entries       map[string]ConfirmationEntry // Keyed by entry ID
	startTime     time.Time
	completedTime *time.Time
}

// NewConfirmationAccumulator creates a new confirmation accumulator.
func NewConfirmationAccumulator() *ConfirmationAccumulator {
	return &ConfirmationAccumulator{
		entries:   make(map[string]ConfirmationEntry),
		startTime: time.Now(),
	}
}

// AddEntry adds a confirmation entry to the accumulator.
//
// If an entry with the same ID already exists, it will be replaced.
// This allows updating the status of an operation.
func (ca *ConfirmationAccumulator) AddEntry(entry ConfirmationEntry) {
	ca.entries[entry.GetId()] = entry
}

// GetSuccesses returns all entries with status "success".
func (ca *ConfirmationAccumulator) GetSuccesses() []ConfirmationEntry {
	var successes []ConfirmationEntry
	for _, entry := range ca.entries {
		if entry.GetStatus() == "success" {
			successes = append(successes, entry)
		}
	}
	return successes
}

// GetFailures returns all entries with status "failed".
func (ca *ConfirmationAccumulator) GetFailures() []ConfirmationEntry {
	var failures []ConfirmationEntry
	for _, entry := range ca.entries {
		if entry.GetStatus() == "failed" {
			failures = append(failures, entry)
		}
	}
	return failures
}

// GetAllEntries returns all entries regardless of status.
func (ca *ConfirmationAccumulator) GetAllEntries() []ConfirmationEntry {
	var all []ConfirmationEntry
	for _, entry := range ca.entries {
		all = append(all, entry)
	}
	return all
}

// GetEntry retrieves a specific entry by ID, or nil if not found.
func (ca *ConfirmationAccumulator) GetEntry(id string) ConfirmationEntry {
	return ca.entries[id]
}

// HasEntry returns true if an entry with the given ID exists.
func (ca *ConfirmationAccumulator) HasEntry(id string) bool {
	_, exists := ca.entries[id]
	return exists
}

// MarkComplete marks the accumulator as complete and sets the completion time.
func (ca *ConfirmationAccumulator) MarkComplete() {
	now := time.Now()
	ca.completedTime = &now
}

// IsComplete returns true if the accumulator has been marked complete.
func (ca *ConfirmationAccumulator) IsComplete() bool {
	return ca.completedTime != nil
}

// GetStartTime returns the time when the accumulator was created.
func (ca *ConfirmationAccumulator) GetStartTime() time.Time {
	return ca.startTime
}

// GetCompletedTime returns the completion time, or error if not yet complete.
func (ca *ConfirmationAccumulator) GetCompletedTime() (time.Time, error) {
	if ca.completedTime == nil {
		return time.Time{}, fmt.Errorf("accumulator not yet complete")
	}
	return *ca.completedTime, nil
}

// GetDuration returns the duration from start to completion, or error if not yet complete.
func (ca *ConfirmationAccumulator) GetDuration() (time.Duration, error) {
	if ca.completedTime == nil {
		return 0, fmt.Errorf("accumulator not yet complete")
	}
	return ca.completedTime.Sub(ca.startTime), nil
}

// GetStats returns summary statistics about the accumulator.
func (ca *ConfirmationAccumulator) GetStats() (total int, successes int, failures int) {
	total = len(ca.entries)
	for _, entry := range ca.entries {
		if entry.GetStatus() == "success" {
			successes++
		} else if entry.GetStatus() == "failed" {
			failures++
		}
	}
	return total, successes, failures
}

// Clear removes all entries from the accumulator (useful for reuse).
func (ca *ConfirmationAccumulator) Clear() {
	ca.entries = make(map[string]ConfirmationEntry)
	ca.startTime = time.Now()
	ca.completedTime = nil
}
