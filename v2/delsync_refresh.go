/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Delegation sync on refresh (docs/2026-09-23-delegation-sync-on-refresh.md).
 */
package tdns

import (
	"context"
	"time"
)

// refreshSyncSteps are the parts of the REFRESH-SYNC-DELEGATION arm that talk
// to the parent, passed in so a test can stand in for them.
type refreshSyncSteps struct {
	analyse func() (DelegationSyncStatus, error)
	sync    func(DelegationSyncStatus) (string, uint8, UpdateResult, error)
	requeue func(next DelegationSyncRequest, delay time.Duration)
}

// handleRefreshSyncDelegationWith is the REFRESH-SYNC-DELEGATION arm. Not
// implemented yet: stage 2 fills it in.
func handleRefreshSyncDelegationWith(ctx context.Context, ready *ImrReadiness, delsyncq chan DelegationSyncRequest,
	zd *ZoneData, ds DelegationSyncRequest, steps refreshSyncSteps) <-chan struct{} {
	return nil
}
