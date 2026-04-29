package tdns

import (
	"database/sql"
	"testing"
)

// TestKskIndexPushNeeded covers the gate function reformulated in
// rollover-overhaul phase 3: compare against confirmed (parent
// reality), not submitted (our local "I tried"). The case that
// previously caused stuck zones — submitted populated and matching
// target while confirmed is empty — must now return true.
func TestKskIndexPushNeeded(t *testing.T) {
	nullInt := func() sql.NullInt64 { return sql.NullInt64{} }
	validInt := func(v int64) sql.NullInt64 { return sql.NullInt64{Int64: v, Valid: true} }

	tests := []struct {
		name    string
		row     *RolloverZoneRow
		low     int
		high    int
		indexOK bool
		haveDS  bool
		want    bool
	}{
		{
			name: "no DS to publish",
			row:  &RolloverZoneRow{LastConfirmedLow: validInt(1), LastConfirmedHigh: validInt(3)},
			low:  1, high: 3, indexOK: true, haveDS: false,
			want: false,
		},
		{
			name: "indexOK false",
			row:  &RolloverZoneRow{LastConfirmedLow: validInt(1), LastConfirmedHigh: validInt(3)},
			low:  1, high: 3, indexOK: false, haveDS: true,
			want: false,
		},
		{
			name: "nil row — never confirmed, push",
			row:  nil,
			low:  1, high: 3, indexOK: true, haveDS: true,
			want: true,
		},
		{
			name: "confirmed NULL — never confirmed, push",
			row:  &RolloverZoneRow{LastConfirmedLow: nullInt(), LastConfirmedHigh: nullInt()},
			low:  1, high: 3, indexOK: true, haveDS: true,
			want: true,
		},
		{
			name: "confirmed matches target — no push",
			row:  &RolloverZoneRow{LastConfirmedLow: validInt(1), LastConfirmedHigh: validInt(3)},
			low:  1, high: 3, indexOK: true, haveDS: true,
			want: false,
		},
		{
			name: "confirmed differs (low) — push",
			row:  &RolloverZoneRow{LastConfirmedLow: validInt(0), LastConfirmedHigh: validInt(3)},
			low:  1, high: 3, indexOK: true, haveDS: true,
			want: true,
		},
		{
			name: "confirmed differs (high) — push",
			row:  &RolloverZoneRow{LastConfirmedLow: validInt(1), LastConfirmedHigh: validInt(2)},
			low:  1, high: 3, indexOK: true, haveDS: true,
			want: true,
		},
		{
			// The regression-fix case: submitted matches target but
			// confirmed is empty (stuck-zone scenario from 2026-04-28).
			// Old code returned false here and the zone never recovered.
			// New code must return true.
			name: "submitted matches target, confirmed empty — push (the regression case)",
			row: &RolloverZoneRow{
				LastSubmittedLow:  validInt(1),
				LastSubmittedHigh: validInt(3),
				LastConfirmedLow:  nullInt(),
				LastConfirmedHigh: nullInt(),
			},
			low: 1, high: 3, indexOK: true, haveDS: true,
			want: true,
		},
		{
			// Mid-rollover scenario: submitted ahead of confirmed.
			// Both populated but confirmed range narrower than target.
			// Push needed to bring parent up to current target.
			name: "submitted ahead of confirmed — push",
			row: &RolloverZoneRow{
				LastSubmittedLow:  validInt(1),
				LastSubmittedHigh: validInt(3),
				LastConfirmedLow:  validInt(0),
				LastConfirmedHigh: validInt(2),
			},
			low: 1, high: 3, indexOK: true, haveDS: true,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := kskIndexPushNeeded(tt.row, tt.low, tt.high, tt.indexOK, tt.haveDS)
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
