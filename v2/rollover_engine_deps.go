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
