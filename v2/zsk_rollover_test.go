package tdns

import (
	"testing"
	"time"
)

func TestZskRollDue(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	activeAt := now.Add(-48 * time.Hour)
	lifetime := uint32((24 * time.Hour).Seconds())

	if !zskRollDue(now, &activeAt, lifetime) {
		t.Fatal("expected roll due when active age exceeds lifetime")
	}
	if zskRollDue(now, &activeAt, 0) {
		t.Fatal("lifetime 0 must never roll")
	}
	if zskRollDue(now, nil, lifetime) {
		t.Fatal("nil active_at must not roll")
	}
	if zskRollDue(now, &now, lifetime) {
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
