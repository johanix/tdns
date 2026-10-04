package cli

import (
	"reflect"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// A server-wide add-transport-signal is never among a zone's own options, so
// the listings add it, marked, or they would show it off on a zone that has it.
func TestZoneOptionStringsShowTheServerWideTransportSignal(t *testing.T) {
	for _, tc := range []struct {
		name string
		zc   tdns.ZoneConf
		want []string
	}{
		{"off", tdns.ZoneConf{Options: []tdns.ZoneOption{tdns.OptAllowUpdates}},
			[]string{"allow-updates"}},
		{"zone", tdns.ZoneConf{Options: []tdns.ZoneOption{tdns.OptAddTransportSignal}, AddTransportSignalSource: "zone"},
			[]string{"add-transport-signal"}},
		{"global", tdns.ZoneConf{Options: []tdns.ZoneOption{tdns.OptAllowUpdates}, AddTransportSignalSource: "global"},
			[]string{"add-transport-signal(global)", "allow-updates"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := zoneOptionStrings(tc.zc); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
