package tdns

import "testing"

// §9, the forced-transfer contract: a forced transfer MUST perform the
// transfer and apply whatever upstream has, including a serial LOWER than or
// EQUAL to our own.
//
// This matters because a forced retransfer is the only remedy for a downstream
// wedged behind a secondary whose serial stepped backwards (see the migration
// section of the design doc), and the only escape hatch from a zone holding
// corrupt data under a current serial. Both properties were previously either
// incidental or outright broken.

// TestForcedTransferReappliesEqualSerial covers the case that was broken: a
// forced retransfer of an already-current zone was discarded, silently, while
// reporting success — so `force` did not mean force.
func TestForcedTransferReappliesEqualSerial(t *testing.T) {
	tests := []struct {
		name              string
		incoming, current uint32
		force             bool
		wantDiscard       bool
	}{
		{"unforced, unchanged serial: no-op refresh", 42, 42, false, true},
		{"FORCED, unchanged serial: must re-apply", 42, 42, true, false},
		{"unforced, upstream advanced: apply", 43, 42, false, false},
		{"forced, upstream advanced: apply", 43, 42, true, false},
		// The migration case: upstream is BEHIND us because our serial was
		// inflated before the mirror fix. A forced retransfer is the operator's
		// only remedy, so it must never be discarded.
		{"unforced, upstream behind: apply", 42, 5000, false, false},
		{"FORCED, upstream behind: apply (the migration remedy)", 42, 5000, true, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldDiscardUnchangedTransfer(tc.incoming, tc.current, tc.force)
			if got != tc.wantDiscard {
				t.Errorf("shouldDiscardUnchangedTransfer(%d, %d, force=%v) = %v, want %v",
					tc.incoming, tc.current, tc.force, got, tc.wantDiscard)
			}
		})
	}
}

// TestForcedTransferNeverDiscarded is the invariant stated directly: whatever
// the serials, a forced transfer is never thrown away. Pins the contract
// against a future "tightening" of the comparison, which would otherwise break
// the migration remedy silently — silently, because the forced transfer would
// still report success while changing nothing.
func TestForcedTransferNeverDiscarded(t *testing.T) {
	for _, incoming := range []uint32{0, 1, 41, 42, 43, 5000} {
		for _, current := range []uint32{0, 42, 5000} {
			if shouldDiscardUnchangedTransfer(incoming, current, true) {
				t.Errorf("forced transfer discarded (incoming=%d current=%d): force must mean force",
					incoming, current)
			}
		}
	}
}
