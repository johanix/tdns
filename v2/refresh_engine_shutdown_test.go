package tdns

import (
	"context"
	"testing"
	"time"
)

// TestRefreshEngineExitsOnRootCancel checks that cancelling the root context
// brings the refresh engine down promptly.
//
// Be clear about what this does and does not prove. The engine's select already
// exited on ctx.Done() before this PR, so this is a REGRESSION GUARD on
// shutdown, not evidence for the cancellation work here. The tests that pin
// this PR's behaviour are the drain tests -- above all
// TestDrainReleasesReaderOnCancellation, which models the library's unbuffered
// reader and fails if the abort+drain is removed.
//
// An earlier version also asserted a goroutine-count delta. That was dropped:
// the count is shared with every other test in the binary and moves under
// -race, so it was a flake waiting to happen rather than a real leak check.
func TestRefreshEngineExitsOnRootCancel(t *testing.T) {
	conf := &Config{}
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 1)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		RefreshEngine(ctx, conf)
	}()

	// Let the engine reach its select loop, then pull the plug.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// exited
	case <-time.After(5 * time.Second):
		t.Fatal("RefreshEngine did not return within 5s of root-context cancellation")
	}

}
