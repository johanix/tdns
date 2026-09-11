package tdns

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
)

// The rule the ticker's due-processing is shaped around, pinned as a fact
// rather than left as a comment.
//
// IterCb holds each shard's read lock while it runs the callback. Taking that
// shard's WRITE lock from inside -- Set or Remove -- deadlocks the goroutine
// permanently. In the refresh engine that goroutine is the one reading
// zonerefch and bumpch, so the whole engine stops: the same stall #364 and #502
// are about, reached from the inside.
//
// The engine hit this twice. Remove was handled when the orphan-dropping was
// added; Set was not, because initialLoadZone calls it for the very zone being
// iterated -- on the adopted-copy path and on success -- and the ticker reached
// initialLoadZone from inside the callback for any zone still in first load.
//
// If this test ever FAILS, IterCb has stopped holding the lock across the
// callback and the collect-then-process shape is no longer required. That is
// worth knowing deliberately rather than discovering by simplifying it away.
func TestMutatingTheCounterMapInsideIterCbDeadlocks(t *testing.T) {
	// The probe itself runs in a CHILD process, because a deadlocked goroutine
	// cannot be stopped: this used to run it in-process and leave it blocked
	// for the rest of the package run, which is a leak by construction and one
	// that would poison any later goroutine-leak check. The child is killed
	// once it has proved the point; nothing is left behind here.
	if os.Getenv(iterCbDeadlockProbeEnv) == "1" {
		m := core.NewCmap[*RefreshCounter]()
		m.Set("one.example.", &RefreshCounter{Name: "one.example."})
		m.IterCb(func(zone string, rc *RefreshCounter) {
			// Exactly what initialLoadZone does with the zone being iterated.
			m.Set(zone, rc)
		})
		// Reaching here means it did NOT deadlock.
		os.Exit(0)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^TestMutatingTheCounterMapInsideIterCbDeadlocks$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), iterCbDeadlockProbeEnv+"=1")
	out, err := cmd.CombinedOutput()

	switch {
	case ctx.Err() == context.DeadlineExceeded:
		// Still blocked when the deadline came, and killed: deadlocked, as the
		// engine's structure assumes.
	case err == nil:
		t.Fatal("mutating the map from inside IterCb completed. The engine's" +
			" collect-then-process shape exists only because this deadlocks;" +
			" if the map has changed, revisit that shape deliberately")
	case strings.Contains(string(out), "all goroutines are asleep - deadlock"):
		// The runtime noticed the deadlock itself and said so. Same verdict.
	default:
		t.Fatalf("the deadlock probe failed for some other reason: %v\n%s", err, out)
	}
}

// iterCbDeadlockProbeEnv tells the test binary it is the child of
// TestMutatingTheCounterMapInsideIterCbDeadlocks and should run the probe.
const iterCbDeadlockProbeEnv = "TDNS_ITERCB_DEADLOCK_PROBE"

// And the shape that avoids it: decide nothing inside the walk, mutate after.
func TestCollectingInsideThenMutatingAfterIsSafe(t *testing.T) {
	m := core.NewCmap[*RefreshCounter]()
	for _, z := range []string{"a.example.", "b.example.", "c.example."} {
		m.Set(z, &RefreshCounter{Name: z, CurRefresh: 1})
	}

	done := make(chan struct{})
	go func() {
		defer close(done)

		var due []*RefreshCounter
		m.IterCb(func(zone string, rc *RefreshCounter) {
			// Mutating the VALUE is fine; it is the map that is locked.
			rc.CurRefresh--
			if rc.CurRefresh <= 0 {
				due = append(due, rc)
			}
		})

		// Both kinds of mutation, after the walk has released every shard.
		for _, rc := range due {
			m.Set(rc.Name, rc)
		}
		m.Remove("a.example.")
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("collect-then-mutate deadlocked; the engine's tick would hang")
	}
}
