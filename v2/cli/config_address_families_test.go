/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// `config check` fails an unknown address family, says so when only one family
// is used, and says nothing when both are.
func TestConfigCheckImrAddressFamilies(t *testing.T) {
	for _, tc := range []struct {
		name     string
		families []string
		reported bool
		want     ccLevel
	}{
		{"unset", nil, false, 0},
		{"both", []string{"ipv4", "ipv6"}, false, 0},
		{"ipv4 only", []string{"ipv4"}, true, ccPASS},
		{"ipv6 only", []string{"IPv6"}, true, ccPASS},
		{"unknown", []string{"ipv4", "ipv5"}, true, ccFAIL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tdns.Config{}
			cfg.Listeners.Addresses = []string{"127.0.0.1:53"}
			cfg.Listeners.Transports = []string{"do53"}
			cfg.Imr.AddressFamilies = tc.families
			rep := newCCReport()
			checkImrEngine(cfg, rep)
			levels := levelsFor(rep, "IMR engine", "address-families")
			if !tc.reported {
				if len(levels) != 0 {
					t.Errorf("address-families %v: reported %v, want nothing", tc.families, levels)
				}
				return
			}
			if len(levels) != 1 || levels[0] != tc.want {
				t.Errorf("address-families %v: levels %v, want [%v]", tc.families, levels, tc.want)
			}
		})
	}
}
