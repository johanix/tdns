/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package core

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseTransportString parses a transport string like "doq:30,dot:20" into a map.
// - Keys are lower-cased and trimmed
// - Values are clamped to [0,100] (values >100 become 100; never rejected)
// - Duplicate keys are rejected
// - Absence defaults (draft-johani-dnsop-svcb-oots): do53→100, others→0
func ParseTransportString(s string) (map[string]uint8, error) {
	transports := make(map[string]uint8)
	s = strings.TrimSpace(s)
	if s != "" {
		parts := strings.Split(s, ",")
		for _, p := range parts {
			kv := strings.SplitN(strings.TrimSpace(p), ":", 2)
			if len(kv) != 2 {
				return nil, fmt.Errorf("transport: bad token %q (want key:value)", p)
			}
			k := strings.ToLower(strings.TrimSpace(kv[0]))
			vstr := strings.TrimSpace(kv[1])
			if k == "" || vstr == "" {
				return nil, fmt.Errorf("transport: empty key or value in %q", p)
			}
			if _, exists := transports[k]; exists {
				return nil, fmt.Errorf("transport: duplicate key %q", k)
			}
			v64, err := strconv.ParseUint(vstr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("transport: bad value for %q: %v", k, err)
			}
			if v64 > 100 {
				v64 = 100
			}
			transports[k] = uint8(v64)
		}
	}
	ApplyTransportDefaults(transports)
	return transports, nil
}

// ApplyTransportDefaults fills absence defaults from draft-johani-dnsop-svcb-oots:
// missing do53 → 100; missing dot/doh/doq → 0. Explicit entries (including
// do53:0) are left unchanged.
func ApplyTransportDefaults(m map[string]uint8) {
	if m == nil {
		return
	}
	if _, ok := m["do53"]; !ok {
		m["do53"] = 100
	}
	for _, p := range []string{"dot", "doh", "doq"} {
		if _, ok := m[p]; !ok {
			m[p] = 0
		}
	}
}
