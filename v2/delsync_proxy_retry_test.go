/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"testing"
	"time"
)

// A failed proxy sync is re-run, a bounded number of times, with growing
// waits (#722). Nothing else re-sends the change: the next transfer is compared
// with a copy that already has it.
func TestNextProxySyncRetry(t *testing.T) {
	ds := DelegationSyncRequest{Command: "PROXY-SYNC", ZoneName: "child.test."}
	failedAt := time.Now()
	var last time.Duration
	for i := range proxySyncRetryDelays {
		next, delay, ok := nextProxySyncRetry(ds, failedAt)
		if !ok {
			t.Fatalf("attempt %d: retries ran out after %d of %d", i+1, i, len(proxySyncRetryDelays))
		}
		if next.Attempt != ds.Attempt+1 || !next.FailedAt.Equal(failedAt) {
			t.Errorf("attempt %d: next = {Attempt %d, FailedAt %v}", i+1, next.Attempt, next.FailedAt)
		}
		if next.Command != "PROXY-SYNC" || next.ZoneName != ds.ZoneName {
			t.Errorf("attempt %d: the retry lost the request: %+v", i+1, next)
		}
		if delay <= last {
			t.Errorf("attempt %d: wait %s does not grow from %s", i+1, delay, last)
		}
		last = delay
		ds = next
	}
	if _, _, ok := nextProxySyncRetry(ds, failedAt); ok {
		t.Error("retries never run out")
	}
}

// A retry is dropped once a later proxy sync has succeeded: that sync declared
// the whole delegation and took its withdrawals from the parent too, so it
// covered whatever the failed one was sending.
func TestProxyRetrySuperseded(t *testing.T) {
	zd := &ZoneData{ZoneName: "child.test."}
	failedAt := time.Now()

	first := DelegationSyncRequest{Command: "PROXY-SYNC", ZoneName: zd.ZoneName}
	retry, _, _ := nextProxySyncRetry(first, failedAt)

	if proxyRetrySuperseded(zd, first) {
		t.Error("a first attempt was treated as a superseded retry")
	}
	if proxyRetrySuperseded(zd, retry) {
		t.Error("a retry was dropped with no later success")
	}

	zd.proxyLastSyncOK = failedAt.Add(-time.Minute)
	if proxyRetrySuperseded(zd, retry) {
		t.Error("a retry was dropped because of a success from BEFORE the failure")
	}

	zd.proxyLastSyncOK = failedAt.Add(time.Minute)
	if !proxyRetrySuperseded(zd, retry) {
		t.Error("a retry survived a later successful sync")
	}
}

// A proxy sync that forwarded nothing is not a success for the retry rule
// (review of #724, C1). With no usable scheme -- here no IMR, so no DSYNC
// discovery -- SyncWithParent returns "nothing forwarded" with a nil error.
// Counting that as a success would let a later no-op cancel a queued retry
// although nothing had reached the parent.
func TestProxyNoopSyncDoesNotSupersedeARetry(t *testing.T) {
	zd := testZone(t, withdrawalChild, withdrawalAfter)

	msg, forwarded, err := zd.ProxyDelegationSync(context.Background(), nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("ProxyDelegationSync with no IMR: %v", err)
	}
	if forwarded {
		t.Errorf("a plan with no usable scheme reported forwarded=true (%q)", msg)
	}

	// Through proxySync itself: the no-op must not stamp proxyLastSyncOK.
	delsyncq := make(chan DelegationSyncRequest, 1)
	proxySync(context.Background(), zd, nil, nil, delsyncq, nil,
		DelegationSyncRequest{Command: "PROXY-SYNC", ZoneName: zd.ZoneName, ZoneData: zd})
	zd.mu.Lock()
	stamped := !zd.proxyLastSyncOK.IsZero()
	zd.mu.Unlock()
	if stamped {
		t.Error("a sync that forwarded nothing was recorded as a success")
	}

	// And so a retry of an earlier failure still runs.
	retry, _, _ := nextProxySyncRetry(DelegationSyncRequest{Command: "PROXY-SYNC", ZoneName: zd.ZoneName},
		time.Now().Add(-time.Minute))
	if proxyRetrySuperseded(zd, retry) {
		t.Error("a retry was dropped after a sync that forwarded nothing")
	}
}
