package tdns

import (
	"log/slog"
	"time"
)

// RolloverEngineDeps bundles every dependency the rollover engine needs to
// run a single per-zone tick or push. The struct is the seam between the
// orchestrator (tdns/v2's KeyStateWorker, tdns-mp/v2's KeyStateWorker) and
// the rollover engine itself: each orchestrator iterates its own zones,
// builds a deps for each one, and calls RolloverAutomatedTick. The engine
// has no package-level globals or implicit conf.Internal lookups.
//
// Conf is a passthrough for helpers (AtomicRollover, triggerResign,
// completeRolloverWithdraw, scheduleFastObservePoll) that take *Config
// directly today and are not in scope for this phase. The "no globals"
// goal is bounded to the implicit dependencies of the push path itself
// (Imr, DnssecPolicies, lock acquirer, logger).
type RolloverEngineDeps struct {
	Conf             *Config
	KDB              *KeyDB
	Zone             *ZoneData
	Imr              *Imr
	NotifyQ          chan NotifyRequest
	InternalUpdateQ  chan UpdateRequest
	Policy           *DnssecPolicy
	AcquireLock      func(zoneName string) (release func(), err error)
	Logger           *slog.Logger
	PropagationDelay time.Duration
	Now              func() time.Time

	// TargetKeySnapshot is an optional precomputed snapshot of the
	// "keys belonging in the rollover-target DS RRset" query result.
	// PushDSRRsetForRollover sets this before fanning out to the
	// UPDATE and NOTIFY goroutines so both paths describe an identical
	// key set. When nil, push paths fall back to recomputing via
	// loadTargetKSKsForRollover. W5 tightens the auto-mode parallel
	// dispatch race by removing the "each goroutine reloads
	// independently" window.
	TargetKeySnapshot *RolloverTargetKeySnapshot
}

// RolloverTargetKeySnapshot is the keystore-load result used by both
// the UPDATE and NOTIFY DS-push paths. Captured once by the dispatcher,
// shared by both goroutines — read-only after construction.
type RolloverTargetKeySnapshot struct {
	Rows            []kskForDSRow
	IndexLow        int
	IndexHigh       int
	IndexRangeKnown bool
}

// defaultAcquireRolloverLock is the tdns/v2 lock acquirer wired into
// RolloverEngineDeps.AcquireLock by the in-tree orchestrator. It blocks
// on the per-zone mutex from rollover_lock.go and returns an unlock
// function. tdns/v2 never returns an error here; the error path exists
// for tdns-mp's leader-aware wrapper, which can refuse with ErrNotLeader
// when the local instance is not leader for the zone's provider group.
func defaultAcquireRolloverLock(zone string) (func(), error) {
	m := AcquireRolloverLock(zone)
	m.Lock()
	return m.Unlock, nil
}
