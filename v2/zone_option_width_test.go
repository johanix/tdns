/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// Each repo's range is 512 values wide and starts one past the previous one's
// end. tdns filled the 32 values a uint8 layout gave it.
func TestZoneOptionRanges(t *testing.T) {
	var prev ZoneOption
	for _, r := range []struct {
		name string
		max  ZoneOption
	}{
		{"tdns", TdnsZoneOptionMax},
		{"tdns-mp", TdnsMpZoneOptionMax},
		{"tdns-nm", TdnsNmZoneOptionMax},
		{"tdns-es", TdnsEsZoneOptionMax},
	} {
		if r.max-prev != 512 {
			t.Errorf("%s: range %d..%d is %d values, want 512", r.name, prev+1, r.max, r.max-prev)
		}
		prev = r.max
	}
	if optZoneOptionTdnsSentinel-1 > TdnsZoneOptionMax {
		t.Errorf("tdns's options end at %d, past its range", optZoneOptionTdnsSentinel-1)
	}
}

// The zone list carries each zone's options by number, and the CLI names
// them. Every value must come back as sent, a downstream repo's included,
// whose numbers no longer fit in a byte.
func TestZoneListCarriesOptionNumbers(t *testing.T) {
	want := []ZoneOption{OptChildSync, optZoneOptionTdnsSentinel - 1, TdnsZoneOptionMax + 1, TdnsEsZoneOptionMax}
	sent := CommandResponse{Zones: map[string]ZoneConf{"example.": {Name: "example.", Options: want}}}
	data, err := json.Marshal(sent)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), `"Options":[`) {
		t.Errorf("options are not a JSON array of numbers: %s", data)
	}
	var got CommandResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if opts := got.Zones["example."].Options; !slices.Equal(opts, want) {
		t.Errorf("options came back as %v, want %v", opts, want)
	}
}
