/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A failed compare with the parent is re-run with growing waits, and the
// retries do not run out: past the schedule's end the last wait repeats.
// Nothing else re-sends what the parent lacks (#722): the next transfer is
// compared with a copy that already has it, and the next change is a
// difference against a zone that has it too.
func TestACompareRetryNeverRunsOut(t *testing.T) {
	ds := DelegationSyncRequest{Command: "PROXY-UPDATE-SETUP", ZoneName: "child.test."}
	failedAt := time.Now()
	var last time.Duration
	for i := range len(delegationSyncRetryDelays) + 3 {
		next, delay := nextDelegationSyncRetry(ds, failedAt)
		if next.Attempt != ds.Attempt+1 || !next.FailedAt.Equal(failedAt) {
			t.Errorf("attempt %d: next = {Attempt %d, FailedAt %v}", i+1, next.Attempt, next.FailedAt)
		}
		if next.Command != ds.Command || next.ZoneName != ds.ZoneName {
			t.Errorf("attempt %d: the retry lost the request: %+v", i+1, next)
		}
		switch {
		case i < len(delegationSyncRetryDelays) && delay <= last:
			t.Errorf("attempt %d: wait %s does not grow from %s", i+1, delay, last)
		case i >= len(delegationSyncRetryDelays) && delay != delegationSyncRetryDelays[len(delegationSyncRetryDelays)-1]:
			t.Errorf("attempt %d, past the schedule: wait %s, want the last, %s", i+1, delay,
				delegationSyncRetryDelays[len(delegationSyncRetryDelays)-1])
		}
		last = delay
		ds = next
	}
}

// A retry is dropped once a later proxy sync has succeeded: that sync declared
// the whole delegation and took its withdrawals from the parent too, so it
// covered whatever the failed one was sending.
func TestProxyRetrySuperseded(t *testing.T) {
	zd := &ZoneData{ZoneName: "child.test."}
	failedAt := time.Now()

	first := DelegationSyncRequest{Command: "PROXY-SYNC", ZoneName: zd.ZoneName}
	retry, _ := nextDelegationSyncRetry(first, failedAt)

	if delegationSyncRetrySuperseded(zd, first) {
		t.Error("a first attempt was treated as a superseded retry")
	}
	if delegationSyncRetrySuperseded(zd, retry) {
		t.Error("a retry was dropped with no later success")
	}

	zd.delegationLastSyncOK = failedAt.Add(-time.Minute)
	if delegationSyncRetrySuperseded(zd, retry) {
		t.Error("a retry was dropped because of a success from BEFORE the failure")
	}

	zd.delegationLastSyncOK = failedAt.Add(time.Minute)
	if !delegationSyncRetrySuperseded(zd, retry) {
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

	// Through proxySync itself: the no-op must not stamp delegationLastSyncOK.
	delsyncq := make(chan DelegationSyncRequest, 1)
	proxySync(context.Background(), zd, nil, nil, delsyncq, nil,
		DelegationSyncRequest{Command: "PROXY-SYNC", ZoneName: zd.ZoneName, ZoneData: zd})
	zd.mu.Lock()
	stamped := !zd.delegationLastSyncOK.IsZero()
	zd.mu.Unlock()
	if stamped {
		t.Error("a sync that forwarded nothing was recorded as a success")
	}
	if !zd.delegationOutOfStep.Load() {
		t.Error("a sync that forwarded nothing left the parent marked in step; the next change would assume it")
	}

	// And so a retry of an earlier failure still runs.
	retry, _ := nextDelegationSyncRetry(DelegationSyncRequest{Command: "PROXY-SYNC", ZoneName: zd.ZoneName},
		time.Now().Add(-time.Minute))
	if delegationSyncRetrySuperseded(zd, retry) {
		t.Error("a retry was dropped after a sync that forwarded nothing")
	}
}

// The proxy's compare clears the out-of-step mark only when it reached the
// parent: found it in step, or brought it there. One that sent nothing for want
// of a usable scheme returns no error and leaves the mark, and one that failed
// is retried (re-review 3, F4). Before, no proxy compare cleared it, so after
// one failed PROXY-SYNC every later change went as a compare.
func TestAProxyCompareClearsOutOfStepOnlyWhenItReachedTheParent(t *testing.T) {
	zd := &ZoneData{ZoneName: "child.test."}
	ds := DelegationSyncRequest{Command: "PROXY-UPDATE-SETUP", ZoneName: zd.ZoneName, ZoneData: zd}
	for _, c := range []struct {
		name     string
		inStep   bool
		err      error
		wantMark bool
		retries  int
	}{
		{"reached the parent", true, nil, false, 0},
		{"no usable scheme", false, nil, true, 0},
		{"failed", false, errors.New("the parent refused"), true, 1},
	} {
		zd.delegationOutOfStep.Store(true)
		var requeued []DelegationSyncRequest
		handleProxyCompareWith(zd, ds,
			func() (string, bool, error) { return "", c.inStep, c.err },
			func(next DelegationSyncRequest, _ time.Duration) { requeued = append(requeued, next) })
		if got := zd.delegationOutOfStep.Load(); got != c.wantMark {
			t.Errorf("%s: marked out of step %v, want %v", c.name, got, c.wantMark)
		}
		if len(requeued) != c.retries {
			t.Errorf("%s: %d retries, want %d", c.name, len(requeued), c.retries)
		}
	}
}
