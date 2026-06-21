package tdns

import (
	"testing"
	"time"
)

func TestZskRollDue(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	activeAt := now.Add(-48 * time.Hour)
	lifetime := uint32((24 * time.Hour).Seconds())

	// Lifetime-driven cases (no manual request). The manual-override cases
	// are covered by TestZskRollDueManualOverride.
	if due, manual := zskRollDue(now, &activeAt, lifetime, ""); !due || manual {
		t.Fatalf("expected scheduled roll due (true,false), got (%v,%v)", due, manual)
	}
	if due, _ := zskRollDue(now, &activeAt, 0, ""); due {
		t.Fatal("lifetime 0 must never roll")
	}
	if due, _ := zskRollDue(now, nil, lifetime, ""); due {
		t.Fatal("nil active_at must not roll")
	}
	if due, _ := zskRollDue(now, &now, lifetime, ""); due {
		t.Fatal("fresh active key must not roll")
	}
}

func TestZskRemovalMargin(t *testing.T) {
	prop := time.Hour
	maxTTL := uint32(7200)
	got := zskRemovalMargin(prop, maxTTL)
	want := prop + 2*time.Hour
	if got != want {
		t.Fatalf("margin = %v, want %v", got, want)
	}
	if zskRemovalMargin(prop, 0) != prop {
		t.Fatal("zero max TTL should leave propagation_delay only")
	}
}
