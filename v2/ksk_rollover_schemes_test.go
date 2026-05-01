package tdns

import (
	"reflect"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
)

// TestDecideRolloverSchemes covers the 4 × 5 = 20 cells of
// (advertised UPDATE? × advertised NOTIFY?) × (auto, prefer-update,
// prefer-notify, force-update, force-notify), plus an empty-string
// default-preference cell and an unknown-preference error cell.
func TestDecideRolloverSchemes(t *testing.T) {
	tests := []struct {
		name       string
		update     bool
		notify     bool
		preference string
		want       []core.DsyncScheme
		wantErr    string // substring match; empty = no error expected
	}{
		// auto
		{"auto/none", false, false, DsyncSchemePreferenceAuto, nil, "no rollover-usable DSYNC"},
		{"auto/update-only", true, false, DsyncSchemePreferenceAuto, []core.DsyncScheme{core.SchemeUpdate}, ""},
		{"auto/notify-only", false, true, DsyncSchemePreferenceAuto, []core.DsyncScheme{core.SchemeNotify}, ""},
		{"auto/both-parallel", true, true, DsyncSchemePreferenceAuto, []core.DsyncScheme{core.SchemeUpdate, core.SchemeNotify}, ""},

		// prefer-update
		{"prefer-update/none", false, false, DsyncSchemePreferencePreferUpdate, nil, "no rollover-usable DSYNC"},
		{"prefer-update/update-only", true, false, DsyncSchemePreferencePreferUpdate, []core.DsyncScheme{core.SchemeUpdate}, ""},
		{"prefer-update/notify-only", false, true, DsyncSchemePreferencePreferUpdate, []core.DsyncScheme{core.SchemeNotify}, ""},
		{"prefer-update/both", true, true, DsyncSchemePreferencePreferUpdate, []core.DsyncScheme{core.SchemeUpdate}, ""},

		// prefer-notify
		{"prefer-notify/none", false, false, DsyncSchemePreferencePreferNotify, nil, "no rollover-usable DSYNC"},
		{"prefer-notify/update-only", true, false, DsyncSchemePreferencePreferNotify, []core.DsyncScheme{core.SchemeUpdate}, ""},
		{"prefer-notify/notify-only", false, true, DsyncSchemePreferencePreferNotify, []core.DsyncScheme{core.SchemeNotify}, ""},
		{"prefer-notify/both", true, true, DsyncSchemePreferencePreferNotify, []core.DsyncScheme{core.SchemeNotify}, ""},

		// force-update
		{"force-update/none", false, false, DsyncSchemePreferenceForceUpdate, nil, "force-update"},
		{"force-update/update-only", true, false, DsyncSchemePreferenceForceUpdate, []core.DsyncScheme{core.SchemeUpdate}, ""},
		{"force-update/notify-only", false, true, DsyncSchemePreferenceForceUpdate, nil, "force-update"},
		{"force-update/both", true, true, DsyncSchemePreferenceForceUpdate, []core.DsyncScheme{core.SchemeUpdate}, ""},

		// force-notify
		{"force-notify/none", false, false, DsyncSchemePreferenceForceNotify, nil, "force-notify"},
		{"force-notify/update-only", true, false, DsyncSchemePreferenceForceNotify, nil, "force-notify"},
		{"force-notify/notify-only", false, true, DsyncSchemePreferenceForceNotify, []core.DsyncScheme{core.SchemeNotify}, ""},
		{"force-notify/both", true, true, DsyncSchemePreferenceForceNotify, []core.DsyncScheme{core.SchemeNotify}, ""},

		// edge cases
		{"empty-pref-defaults-to-auto/both", true, true, "", []core.DsyncScheme{core.SchemeUpdate, core.SchemeNotify}, ""},
		{"unknown-pref", true, true, "weird", nil, "invalid dsync-scheme-preference"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decideRolloverSchemes(tt.update, tt.notify, tt.preference)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
