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
// - Values must be integers in [0,100]
// - Duplicate keys are rejected
func ParseTransportString(s string) (map[string]uint8, error) {
	transports := make(map[string]uint8)
	s = strings.TrimSpace(s)
	if s == "" {
		return transports, nil
	}
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
		v64, err := strconv.ParseUint(vstr, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("transport: bad value for %q: %v", k, err)
		}
		v := uint8(v64)
		if v > 100 {
			return nil, fmt.Errorf("transport: value for %q out of range: %d", k, v)
		}
		transports[k] = v
	}
	return transports, nil
}
