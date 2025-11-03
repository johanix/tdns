/*
 * Copyright (c) 2025 Johan Stenstam
 */
package tdns

import (
	"fmt"
	"time"
)

// TtlPrint returns a human-friendly TTL remaining until expiration.
// If the expiration time has passed, it returns "expired".
func TtlPrint(expiration time.Time) string {
    d := time.Until(expiration)
    if d <= 0 {
        return "expired"
    }
    // Work with whole seconds
    d = d.Truncate(time.Second)
    total := int(d.Seconds())

    hours := total / 3600
    rem := total % 3600
    mins := rem / 60
    secs := rem % 60

    out := ""
    if hours > 0 {
        out += fmt.Sprintf("%dh", hours)
    }
    if mins > 0 {
        out += fmt.Sprintf("%dm", mins)
    }
    // Include seconds when non-zero, or when both hours and minutes are zero
    if secs > 0 || out == "" {
        out += fmt.Sprintf("%ds", secs)
    }
    return out
}

// ExpirationFromTtl converts an insertion time and TTL seconds to an expiration time.
// This is only used for formatting and display, not for cache logic.
func ExpirationFromTtl(addedAt time.Time, ttl uint32) time.Time {
    if addedAt.IsZero() || ttl == 0 {
        return addedAt
    }
    return addedAt.Add(time.Duration(ttl) * time.Second)
}


