/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Utility functions for HPKE key distribution
 */

package hpke

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// GenerateDistributionID generates a unique distribution ID (hex string)
func GenerateDistributionID() (string, error) {
	// Generate 16 random bytes = 32 hex characters
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate distribution ID: %v", err)
	}
	return hex.EncodeToString(buf), nil
}

// ValidateDistributionID validates that a string is a valid hex distribution ID
func ValidateDistributionID(id string) error {
	if len(id) != 32 {
		return fmt.Errorf("distribution ID must be 32 hex characters (got %d)", len(id))
	}
	if _, err := hex.DecodeString(id); err != nil {
		return fmt.Errorf("invalid distribution ID format: %v", err)
	}
	return nil
}

// TimestampToUnix converts a time.Time to Unix timestamp (uint64)
func TimestampToUnix(t time.Time) uint64 {
	return uint64(t.Unix())
}

// UnixToTimestamp converts a Unix timestamp (uint64) to time.Time
func UnixToTimestamp(ts uint64) time.Time {
	return time.Unix(int64(ts), 0)
}

// IsExpired checks if a timestamp has expired relative to now
func IsExpired(timestamp uint64, now time.Time) bool {
	ts := UnixToTimestamp(timestamp)
	return ts.Before(now)
}

// IsExpiredPtr checks if a timestamp pointer has expired (nil = never expires)
func IsExpiredPtr(timestamp *uint64, now time.Time) bool {
	if timestamp == nil {
		return false // Never expires
	}
	return IsExpired(*timestamp, now)
}

