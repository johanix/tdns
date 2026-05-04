package tdns

import (
	"testing"
)

// TestEarliestStatusToString covers the wire-form mapping used by
// RolloverWhenResponse.Status.
func TestEarliestStatusToString(t *testing.T) {
	tests := []struct {
		s    EarliestRolloverStatus
		want string
	}{
		{EarliestStatusReady, "ready"},
		{EarliestStatusWaitingForParent, "waiting-for-parent"},
		{EarliestStatusPolicyBlocked, "policy-blocked"},
		{EarliestRolloverStatus(99), "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := earliestStatusToString(tc.s); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
