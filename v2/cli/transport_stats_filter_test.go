/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cli

import (
	"reflect"
	"testing"
)

// TestTransportStatsFilter_Matches guards the zone/suffix/all selection used by
// `stats transport-stats`, `... {zone}`, and `... suffix {suffix}`. ServerMap
// keys are fqdns, so the filter operands are fqdns too.
func TestTransportStatsFilter_Matches(t *testing.T) {
	tests := []struct {
		name   string
		filter transportStatsFilter
		zone   string
		want   bool
	}{
		{"all-matches-anything", transportStatsFilter{}, "dsync.se.", true},
		{"exact-hit", transportStatsFilter{zone: "dsync.se."}, "dsync.se.", true},
		{"exact-miss-child", transportStatsFilter{zone: "dsync.se."}, "johani.dsync.se.", false},
		{"exact-miss-other", transportStatsFilter{zone: "dsync.se."}, "iis.se.", false},
		{"suffix-hit-self", transportStatsFilter{suffix: "dsync.se."}, "dsync.se.", true},
		{"suffix-hit-child", transportStatsFilter{suffix: "dsync.se."}, "johani.dsync.se.", true},
		{"suffix-hit-tld", transportStatsFilter{suffix: "se."}, "iis.se.", true},
		{"suffix-miss", transportStatsFilter{suffix: "se."}, "example.com.", false},
		// zone takes precedence over suffix when both are set (they never are in
		// practice, but the precedence must be deterministic).
		{"zone-wins-over-suffix", transportStatsFilter{zone: "dsync.se.", suffix: "com."}, "dsync.se.", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.filter.matches(tt.zone); got != tt.want {
				t.Errorf("matches(%q) = %v, want %v", tt.zone, got, tt.want)
			}
		})
	}
}

// TestTransportStatsFilter_Data checks the API request payload the remote path
// (tdns-cli) sends, so the imr applies the same filter it would in-process.
func TestTransportStatsFilter_Data(t *testing.T) {
	tests := []struct {
		name   string
		filter transportStatsFilter
		want   map[string]interface{}
	}{
		{"all-empty", transportStatsFilter{}, map[string]interface{}{}},
		{"zone-only", transportStatsFilter{zone: "dsync.se."}, map[string]interface{}{"zone": "dsync.se."}},
		{"suffix-only", transportStatsFilter{suffix: "se."}, map[string]interface{}{"suffix": "se."}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.filter.data(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("data() = %v, want %v", got, tt.want)
			}
		})
	}
}
