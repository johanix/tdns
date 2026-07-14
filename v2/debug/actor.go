/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"context"
	"sync"
	"time"
)

// Actor is one independent-cadence worker in a test scenario (design doc §7):
// update-sender, bumper, resigner, query-hammer, AXFR-poller, txlog-poller.
// Actors whose Requires() capability is absent are skipped (reported, never
// failed). A Step error does not stop the run: it is counted, and repeated
// failure of an API actor degrades its capability.
type Actor interface {
	Name() string
	Requires() string // capability name (CapNone for pure DNS)
	Cadence() time.Duration
	Step(ctx context.Context) error
}

// RunActors drives every eligible actor on its own ticker until ctx is done.
// Ineligible actors (absent capability) are recorded as skipped in the
// report. Consecutive Step failures of an actor beyond degradeAfter mark its
// capability degraded — dependent checks become tainted, not failed.
func RunActors(ctx context.Context, actors []Actor, caps *CapabilityMatrix, rep *Report) {
	const degradeAfter = 5
	var wg sync.WaitGroup

	for _, a := range actors {
		if !caps.Available(a.Requires()) {
			rep.Skip("actor "+a.Name(), "capability "+a.Requires()+" is "+string(caps.Get(a.Requires())))
			continue
		}
		wg.Add(1)
		go func(a Actor) {
			defer wg.Done()
			ticker := time.NewTicker(a.Cadence())
			defer ticker.Stop()
			failures := 0
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := a.Step(ctx); err != nil {
						failures++
						// rep.Stat is mutex-guarded: actors run concurrently, so
						// never touch rep.Stats directly (fatal concurrent map write).
						rep.Stat("actor."+a.Name()+".errors", 1)
						if failures == degradeAfter && a.Requires() != CapNone {
							caps.Degrade(a.Requires(), err.Error())
							rep.Skip("actor "+a.Name(), "degraded mid-run: "+err.Error())
						}
					} else {
						failures = 0
						rep.Stat("actor."+a.Name()+".steps", 1)
					}
				}
			}
		}(a)
	}
	wg.Wait()
}
