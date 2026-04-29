package tdns

import (
	"strings"
	"sync"
)

// Per-zone mutex registry that serializes the rollover tick against API
// mutating handlers. Both call sites — RolloverAutomatedTick at the top
// of its per-zone work, and HTTP handlers for /rollover/asap, cancel,
// reset, unstick before any DB write — acquire the same per-zone mutex
// here, so a CLI-driven write cannot interleave with a tick advance.
//
// Granularity is per-zone, not global: each zone's tick work is
// independent of every other zone's, so contention is naturally
// limited. Read endpoints (status, when) do NOT take the lock —
// sqlite WAL mode gives snapshot reads while writers are in flight,
// and the API contract for those endpoints is "best-effort current
// state at response time" which a lock-free snapshot satisfies.
//
// The current rollover tick is short-lived (a single phase advance
// per zone, no inline DNS UPDATE retries under the lock) so the
// mutex is held for milliseconds at a time. If the tick ever grows
// long-running operations under the lock, revisit and consider a
// request-channel pattern that takes the work out of the API handler
// goroutine entirely.

var (
	rolloverLocks   = make(map[string]*sync.Mutex)
	rolloverLocksMu sync.Mutex
)

// AcquireRolloverLock returns the per-zone mutex for zone, creating it on
// first call. Caller must Lock and Unlock; nothing here calls those for
// you. The returned pointer is stable across calls for the same zone.
func AcquireRolloverLock(zone string) *sync.Mutex {
	zone = strings.TrimSpace(zone)
	rolloverLocksMu.Lock()
	defer rolloverLocksMu.Unlock()
	m, ok := rolloverLocks[zone]
	if !ok {
		m = &sync.Mutex{}
		rolloverLocks[zone] = m
	}
	return m
}
