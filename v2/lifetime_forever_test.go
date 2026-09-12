package tdns

import (
	"testing"
	"time"
)

// "forever" is a large FINITE number, chosen so renderLifetime can print it back
// as "forever". The roll decisions tested only for zero, so a policy saying
// forever scheduled a roll after about 417 days -- and nothing the operator can
// read said so, because the config says forever and the API renders forever
// (#567).
func TestForeverNeverSchedulesARoll(t *testing.T) {
	for _, tc := range []struct {
		name string
		secs uint32
		want bool
	}{
		{"unset", 0, false},
		{"forever", foreverLifetimeSecs, false},
		{"a real lifetime", uint32(90 * 24 * 3600), true},
		{"one second short of forever", foreverLifetimeSecs - 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := lifetimeSchedulesRoll(tc.secs); got != tc.want {
				t.Errorf("lifetimeSchedulesRoll(%d) = %v, want %v", tc.secs, got, tc.want)
			}
		})
	}
}

// The ZSK decision, through the function the engine actually calls: a key active
// for far longer than the forever sentinel must still not be due.
func TestZskRollNeverDueOnAForeverLifetime(t *testing.T) {
	now := time.Now().UTC()
	// Comfortably past 10000h, which is what the sentinel is worth in seconds.
	activeAt := now.Add(-3 * 10000 * time.Hour)

	if due, _ := zskRollDue(now, &activeAt, foreverLifetimeSecs, ""); due {
		t.Error("a ZSK on a `forever` lifetime came due; BuiltinDefaultDnssecPolicy uses" +
			" forever for both KSK and ZSK and documents itself as making no automatic" +
			" rollovers, so this fired on every zone that took the built-in default")
	}
	if due, _ := zskRollDue(now, &activeAt, 0, ""); due {
		t.Error("an unset lifetime came due")
	}
	// And a real lifetime still rolls, or the fix would have disabled rollovers.
	if due, _ := zskRollDue(now, &activeAt, uint32(30*24*3600), ""); !due {
		t.Error("a 30-day lifetime did not come due for a key active far longer than that")
	}
}

// A manual request is an operator asking for a roll now, and it is answered
// before any lifetime is consulted -- forever must not veto it.
func TestForeverDoesNotBlockAManualRoll(t *testing.T) {
	now := time.Now().UTC()
	activeAt := now.Add(-time.Hour)
	earliest := now.Add(-time.Minute).Format(time.RFC3339)

	due, manual := zskRollDue(now, &activeAt, foreverLifetimeSecs, earliest)
	if !due || !manual {
		t.Errorf("manual roll on a forever lifetime: due=%v manual=%v, want true/true", due, manual)
	}
}

// The built-in default says it schedules no automatic rollovers. That is now
// true; it was not before.
func TestBuiltinDefaultPolicySchedulesNoRollovers(t *testing.T) {
	pol := BuiltinDefaultDnssecPolicy()
	for _, tc := range []struct {
		role string
		secs uint32
	}{
		{"KSK", pol.KSK.Lifetime},
		{"ZSK", pol.ZSK.Lifetime},
	} {
		if lifetimeSchedulesRoll(tc.secs) {
			t.Errorf("the built-in default policy schedules a %s roll after %s,"+
				" while documenting itself as making no automatic key rollovers",
				tc.role, renderLifetime(tc.secs))
		}
	}
}
