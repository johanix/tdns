package tdns

import (
	"context"
	"runtime"
	"testing"
	"time"
)

// TestRefreshEngineExitsOnRootCancel is the engine-level half of the
// cancellation story: threading ctx into the refresh chain is only useful if
// cancelling the root context actually brings the engine down promptly and
// without retaining goroutines.
//
// Deliberately bounded and self-contained -- it drives the real RefreshEngine
// with a minimal Config rather than standing up a full server, so it stays a
// unit test. The goroutine check is a delta against a settled baseline, not an
// absolute count: the test binary has its own background goroutines and other
// tests may leave some running.
func TestRefreshEngineExitsOnRootCancel(t *testing.T) {
	conf := &Config{}
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 1)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)

	settle := func() int {
		// Let anything from a previous test wind down before counting.
		for i := 0; i < 20; i++ {
			runtime.Gosched()
			time.Sleep(5 * time.Millisecond)
		}
		return runtime.NumGoroutine()
	}

	before := settle()

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

	after := settle()
	// A small delta is tolerated (the runtime parks and reuses Ms; other tests
	// share this binary). What this catches is the engine leaving its own
	// goroutines behind on every shutdown.
	if after > before+2 {
		t.Errorf("goroutine count grew across engine shutdown: before=%d after=%d", before, after)
	}
}
