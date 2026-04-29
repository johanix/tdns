package tdns

import (
	"testing"
	"time"
)

func TestClampedDuration(t *testing.T) {
	margin := 15 * time.Minute
	if g, w := ClampedDuration(2*time.Hour, 24*time.Hour, margin), 2*time.Hour; g != w {
		t.Fatalf("steady state: got %v want %v", g, w)
	}
	if g, w := ClampedDuration(2*time.Hour, 10*time.Minute, margin), 25*time.Minute; g != w {
		t.Fatalf("near rollover: got %v want %v", g, w)
	}
	if g, w := ClampedDuration(2*time.Hour, 0, margin), margin; g != w {
		t.Fatalf("R=0: got %v want %v", g, w)
	}
	if g, w := ClampedDuration(0, time.Hour, margin), time.Duration(0); g != w {
		t.Fatalf("zero configured: got %v want %v", g, w)
	}
}
