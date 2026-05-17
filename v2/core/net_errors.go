/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import (
	"errors"
	"net"
	"syscall"
)

// IsTransientNetErr reports whether err is a transient network error worth
// retrying against the same server address: i/o timeout, connection refused,
// connection reset, or EAGAIN. Authoritative response codes (REFUSED, SERVFAIL,
// NOTAUTH) come back as successful Exchange calls with a non-zero Rcode — they
// are NOT errors here and are handled in the caller's per-zone backoff path.
func IsTransientNetErr(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EAGAIN) {
		return true
	}
	return false
}
