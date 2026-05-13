package tdns

import (
	"testing"
	"time"
)

// TestWaitingForParentDelay covers the cap logic for the
// child-config:waiting-for-parent subcategory: the returned softfail
// delay must never exceed waitingForParentBackoffCap (1h), regardless
// of what the policy specifies.
func TestWaitingForParentDelay(t *testing.T) {
	tests := []struct {
		name string
		pol  *DnssecPolicy
		want time.Duration
	}{
		{
			name: "nil policy -> default minimum (1h)",
			pol:  nil,
			want: defaultSoftfailDelayMinimum,
		},
		{
			name: "explicit short delay -> uses it",
			pol: func() *DnssecPolicy {
				p := &DnssecPolicy{}
				p.Rollover.SoftfailDelay = 15 * time.Minute
				return p
			}(),
			want: 15 * time.Minute,
		},
		{
			name: "explicit at-cap delay -> uses it",
			pol: func() *DnssecPolicy {
				p := &DnssecPolicy{}
				p.Rollover.SoftfailDelay = time.Hour
				return p
			}(),
			want: time.Hour,
		},
		{
			name: "explicit above-cap delay -> capped at 1h",
			pol: func() *DnssecPolicy {
				p := &DnssecPolicy{}
				p.Rollover.SoftfailDelay = 6 * time.Hour
				return p
			}(),
			want: waitingForParentBackoffCap,
		},
		{
			name: "policy zero, derived from ds-publish-delay above cap -> capped",
			pol: func() *DnssecPolicy {
				p := &DnssecPolicy{}
				p.Rollover.DsPublishDelay = 4 * time.Hour
				return p
			}(),
			want: waitingForParentBackoffCap,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := waitingForParentDelay(tt.pol)
			if got != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
			if got > waitingForParentBackoffCap {
				t.Fatalf("returned delay %s exceeds cap %s", got, waitingForParentBackoffCap)
			}
		})
	}
}
