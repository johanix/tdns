/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
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
