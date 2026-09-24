/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cli

import (
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// black-lies selects compact denial, which synthesizes and signs an NSEC for
// each negative answer. On a zone this server does not sign there is no key to
// sign with, so the option does nothing and config check says so.
func TestCheckZonesWarnsBlackLiesWithoutSigning(t *testing.T) {
	for _, tc := range []struct {
		name string
		zone tdns.ZoneConf
		want bool
	}{
		{"secondary with black-lies",
			tdns.ZoneConf{Name: "sec.example.", Type: "secondary", OptionsStrs: []string{"black-lies"}}, true},
		{"primary with black-lies, not signed",
			tdns.ZoneConf{Name: "pri.example.", Type: "primary", OptionsStrs: []string{"black-lies"}}, true},
		{"online-signing with black-lies",
			tdns.ZoneConf{Name: "signed.example.", Type: "primary", DnssecPolicy: "default",
				OptionsStrs: []string{"online-signing", "black-lies"}}, false},
		{"inline-signing with black-lies",
			tdns.ZoneConf{Name: "inline.example.", Type: "secondary", DnssecPolicy: "default",
				OptionsStrs: []string{"inline-signing", "black-lies"}}, false},
		{"secondary without black-lies",
			tdns.ZoneConf{Name: "plain.example.", Type: "secondary"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tdns.Config{}
			cfg.Zones = []tdns.ZoneConf{tc.zone}
			rep := newCCReport()
			checkZones(cfg, rep, false, "auth")

			var got bool
			for _, f := range rep.byGroup["Zones"] {
				if f.level == ccWARN && strings.Contains(f.msg, "black-lies has no effect") {
					got = true
				}
			}
			if got != tc.want {
				t.Errorf("black-lies warning = %v, want %v (options %v)", got, tc.want, tc.zone.OptionsStrs)
			}
		})
	}
}
