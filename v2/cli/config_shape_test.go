/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cli

import (
	"testing"

	"github.com/spf13/viper"
)

// TestLooksLikeServerConfig: telling tdns-cli's own config from a server's,
// which is what lets the "wrong file" mistake be named instead of surfacing
// as a mapstructure complaint about 'Zones[0]' expected type 'string'.
func TestLooksLikeServerConfig(t *testing.T) {
	tests := []struct {
		name  string
		zones interface{}
		want  bool
	}{
		{"server config: zones are objects", []interface{}{
			map[string]interface{}{"name": "example.com", "type": "primary"},
		}, true},
		{"cli config: zones are names", []interface{}{"example.com", "example.net"}, false},
		{"no zones at all", nil, false},
		{"empty list", []interface{}{}, false},
		{"not a list", "example.com", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := viper.New()
			if tc.zones != nil {
				v.Set("zones", tc.zones)
			}
			if got := looksLikeServerConfig(v); got != tc.want {
				t.Errorf("looksLikeServerConfig() = %v, want %v", got, tc.want)
			}
		})
	}
}
