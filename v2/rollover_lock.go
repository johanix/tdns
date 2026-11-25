package tdns

import (
	"strings"
	"sync"

	core "github.com/johanix/tdns/v2/core"
)

// Per-zone mutex registry that serializes the rollover tick against API
// mutating handlers. The call sites — RolloverAutomatedTick at the top
// of its per-zone work, the HTTP handlers for /rollover/asap, cancel,
// reset, unstick before any DB write, and change-policy from its gates
// through the bind — acquire the same per-zone mutex here, so a
// CLI-driven write cannot interleave with a tick advance.
//
// Granularity is per-zone, not global: each zone's tick work is
// independent of every other zone's, so contention is naturally
// limited. Read endpoints (status, when) do NOT take the lock —
// NewKeyDB opens the keystore in WAL mode, so a read neither waits
// for nor holds up a writer and sees the last committed state, and
// the API contract for those endpoints is "best-effort current state
// at response time", which such reads satisfy.
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
//
// The lookup key is canonicalized (lowercased, trailing dot stripped)
// so "Example.COM.", "example.com.", and "example.com" all resolve to
// the same mutex. Today every caller passes dns.Fqdn(...) output and
// hits the same form, but defense in depth is cheap.
func AcquireRolloverLock(zone string) *sync.Mutex {
	// A lock key derived from a zone name. strings.ToLower folds by Unicode, so
	// two distinct zones differing only by U+212A would have shared one
	// rollover lock -- and a lock shared when it should not be is the direction
	// that lets two rollovers run as one.
	key := core.CanonicalizeName(strings.TrimSpace(zone))
	key = strings.TrimSuffix(key, ".")
	rolloverLocksMu.Lock()
	defer rolloverLocksMu.Unlock()
	m, ok := rolloverLocks[key]
	if !ok {
		m = &sync.Mutex{}
		rolloverLocks[key] = m
	}
	return m
}

// Per-zone mutex that serializes the paths that make a zone's DNSSEC keys
// outside the rollover machinery -- EnsureActiveDnssecKeys making a zone's
// first keys (makeMissingDnssecKeys), the key state worker's standby keys,
// a policy reset's regenerated ones -- against a zone delete taking the
// zone's keys (removeZoneKeys). Each checks zd.removed under it, so its keys
// are either made before the delete takes the lock, and go with the zone,
// or not made at all.
//
// Not the rollover lock, which a caller of those paths can hold: a policy
// change holds it across its re-sign, which makes a keyless zone's first
// keys, and takes zd.mu and policyApplyMu under it, while the publish path
// makes keys with zd.mu held and a policy apply with policyApplyMu held.
// Taking the rollover lock there would deadlock against the policy change,
// or against itself. This one is a leaf: held only around the zd.removed
// check and the KeyDB work that makes or counts keys, which takes no
// ZoneData lock, so a caller may hold zd.mu, policyApplyMu, templateApplyMu
// or the rollover lock when it takes it. It must not be taken with a KeyDB
// transaction open: the KeyDB work under it begins its own. removeZoneKeys
// takes it after the rollover lock.
var (
	zoneKeysLocks   = make(map[string]*sync.Mutex)
	zoneKeysLocksMu sync.Mutex
)

// acquireZoneKeysLock returns the per-zone zone keys mutex for zone, keyed
// as AcquireRolloverLock keys its own. The caller locks and unlocks it.
func acquireZoneKeysLock(zone string) *sync.Mutex {
	key := strings.TrimSuffix(core.CanonicalizeName(strings.TrimSpace(zone)), ".")
	zoneKeysLocksMu.Lock()
	defer zoneKeysLocksMu.Unlock()
	m, ok := zoneKeysLocks[key]
	if !ok {
		m = &sync.Mutex{}
		zoneKeysLocks[key] = m
	}
	return m
}
