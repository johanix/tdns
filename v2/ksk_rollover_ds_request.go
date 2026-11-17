/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The rollover engine's one way to the parent: a SYNC-DS to the delegation
 * syncher, answered on a channel the engine waits on.
 */
package tdns

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
)

// requestDSSyncForRollover is the rollover engine's DS push. It takes the
// snapshot of the keys whose DS the parent should hold, hands it to the
// delegation syncher as a SYNC-DS, and waits for the syncher's answer, which
// is what the engine's phases are decided from. The engine sends nothing to
// the parent itself.
//
// The wait is bounded by ctx, the engine's push deadline, and the request
// carries that deadline so the syncher does not work past it either. A
// syncher that is busy with other zones and cannot take or answer the
// request in time is reported as a transport failure: the engine retries on
// its own schedule, as it does for a parent that did not answer.
func requestDSSyncForRollover(ctx context.Context, deps RolloverEngineDeps) (KSKDSPushResult, error) {
	zd := deps.Zone
	if zd == nil || deps.KDB == nil {
		return KSKDSPushResult{Category: SoftfailChildConfigLocalError},
			fmt.Errorf("requestDSSyncForRollover: nil argument")
	}
	q := deps.delegationSyncQ()
	if q == nil {
		return KSKDSPushResult{Category: SoftfailChildConfigLocalError},
			fmt.Errorf("requestDSSyncForRollover: no delegation syncher to send the DS for %s", zd.ZoneName)
	}
	snap, err := loadRolloverTargetSnapshot(deps.KDB, dns.Fqdn(zd.ZoneName))
	if err != nil {
		return KSKDSPushResult{Category: SoftfailChildConfigLocalError},
			fmt.Errorf("requestDSSyncForRollover: %w", err)
	}

	req := DSSyncRequest{Snapshot: snap, Policy: deps.Policy}
	if d, ok := ctx.Deadline(); ok {
		req.Deadline = d
	}
	resp := make(chan DSSyncResponse, 1)
	select {
	case q <- DelegationSyncRequest{
		Command:    "SYNC-DS",
		ZoneName:   zd.ZoneName,
		ZoneData:   zd,
		DSSync:     &req,
		DSResponse: resp,
	}:
	case <-ctx.Done():
		return KSKDSPushResult{Category: SoftfailTransport},
			fmt.Errorf("requestDSSyncForRollover: the delegation syncher did not take the request for %s: %w",
				zd.ZoneName, ctx.Err())
	}
	select {
	case r := <-resp:
		return r.Result, r.Err
	case <-ctx.Done():
		return KSKDSPushResult{Category: SoftfailTransport},
			fmt.Errorf("requestDSSyncForRollover: no answer from the delegation syncher for %s: %w",
				zd.ZoneName, ctx.Err())
	}
}

// delegationSyncQ is the queue the engine's SYNC-DS goes to: the one given
// in the deps, else the zone's own, else the process-wide one.
func (deps RolloverEngineDeps) delegationSyncQ() chan DelegationSyncRequest {
	if deps.DelegationSyncQ != nil {
		return deps.DelegationSyncQ
	}
	if deps.Zone != nil && deps.Zone.DelegationSyncQ != nil {
		return deps.Zone.DelegationSyncQ
	}
	if deps.Conf != nil && deps.Conf.Internal.DelegationSyncQ != nil {
		return deps.Conf.Internal.DelegationSyncQ
	}
	return nil
}
