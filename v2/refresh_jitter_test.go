package tdns

import (
	"math/rand"
	"testing"
)

// withDeterministicJitter fixes the jitter source for one test, so a test about
// distribution is not a test about luck.
func withDeterministicJitter(t *testing.T, seed int64) {
	t.Helper()
	refreshJitterMu.Lock()
	prev := refreshJitter
	refreshJitter = rand.New(rand.NewSource(seed))
	refreshJitterMu.Unlock()
	t.Cleanup(func() {
		refreshJitterMu.Lock()
		refreshJitter = prev
		refreshJitterMu.Unlock()
	})
}

// Zones sharing a SOA REFRESH must not all come due on the same tick. Without
// jitter every template-provisioned zone in a deployment refreshes together,
// forever, and each cycle arrives as a herd.
func TestFirstRefreshIsSpreadAcrossTheInterval(t *testing.T) {
	withDeterministicJitter(t, 1)

	const refresh = 3600
	seen := map[uint32]int{}
	for i := 0; i < 200; i++ {
		v := jitteredFirstRefresh(refresh)
		if v < 1 || v > refresh {
			t.Fatalf("jittered counter %d is outside [1, %d]", v, refresh)
		}
		seen[v]++
	}
	// 200 draws over an hour: a handful of collisions is expected, everything
	// landing on one value is the bug.
	if len(seen) < 100 {
		t.Fatalf("200 zones landed on only %d distinct ticks; they are still a herd", len(seen))
	}
	if seen[refresh] == 200 {
		t.Fatal("every zone kept the unjittered interval")
	}
}

// A degenerate interval must not produce a zero or negative counter, which the
// ticker would treat as permanently due.
func TestJitterHandlesTinyIntervals(t *testing.T) {
	withDeterministicJitter(t, 2)

	for _, refresh := range []uint32{0, 1, 2} {
		got := jitteredFirstRefresh(refresh)
		if refresh <= 1 {
			if got != refresh {
				t.Errorf("refresh %d: got %d, want it returned unchanged", refresh, got)
			}
			continue
		}
		if got < 1 || got > refresh {
			t.Errorf("refresh %d: got %d, outside [1, %d]", refresh, got, refresh)
		}
	}
}
