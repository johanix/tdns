package cli

import (
	"strings"
	"testing"
	"time"
)

// In pending-parent-push the status kept printing "expected by:" and
// "attempt timeout:" from an earlier attempt long after both had passed, as if
// the engine were still waiting for them.
func TestRolloverDeadlineValue(t *testing.T) {
	now := time.Now().UTC()
	future := now.Add(10 * time.Minute).Format(time.RFC3339)
	past := now.Add(-10 * time.Minute).Format(time.RFC3339)

	for _, tc := range []struct {
		name     string
		deadline string
		phase    string
		wantShow bool
		passed   bool
	}{
		{"unset", "", "pending-parent-observe", false, false},
		{"ahead, push", future, "pending-parent-push", true, false},
		{"ahead, observe", future, "pending-parent-observe", true, false},
		{"passed, push: left out", past, "pending-parent-push", false, false},
		{"passed, observe: marked", past, "pending-parent-observe", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, ok := rolloverDeadlineValue(tc.deadline, tc.phase, now)
			if ok != tc.wantShow {
				t.Fatalf("shown = %v (%q), want %v", ok, v, tc.wantShow)
			}
			if !ok {
				return
			}
			if got := strings.Contains(v, "passed"); got != tc.passed {
				t.Errorf("%q: marked passed = %v, want %v", v, got, tc.passed)
			}
			if tc.passed && !strings.HasSuffix(v, " ago, passed)") {
				t.Errorf("%q: want the passed mark inside the parenthetical", v)
			}
		})
	}
}
