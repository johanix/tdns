/*
 * Copyright (c) 2024 Johan Stenstam
 */
package tdns

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	core "github.com/johanix/tdns/tdns/core"
	"github.com/miekg/dns"
)

// ParseTransportString parses a transport string like "doq:30,dot:20" into a map.
// - Keys are lower-cased and trimmed
// - Values must be integers in [0,100]
// - Duplicate keys are rejected
func xxxParseTransportString(s string) (map[string]uint8, error) {
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

// MarshalTransport converts a transport map back to a canonical string (sorted by key).
func MarshalTransport(transports map[string]uint8) string {
	if len(transports) == 0 {
		return ""
	}
	keys := make([]string, 0, len(transports))
	for k := range transports {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(int(transports[k])))
	}
	return b.String()
}

// GetAlpn extracts the ALPN protocols from an SVCB RR (from SVCBAlpn param).
func GetAlpn(svcb *dns.SVCB) []string {
	var alpn []string
	if svcb == nil {
		return alpn
	}
	for _, kv := range svcb.Value {
		if a, ok := kv.(*dns.SVCBAlpn); ok {
			for _, v := range a.Alpn {
				alpn = append(alpn, strings.ToLower(v))
			}
		}
	}
	return alpn
}

// ValidateTransportAgainstAlpn is deprecated; transport is the source of truth.
// Kept for compatibility; always returns nil.
// func ValidateTransportAgainstAlpn(transports map[string]uint8, alpn []string) error { return nil }

// ComputeDo53Remainder returns the implicit remainder for do53 (clip at 0).
func ComputeDo53Remainder(pct map[string]uint8) uint8 {
	var sum int
	for _, v := range pct {
		sum += int(v)
	}
	if sum >= 100 {
		return 0
	}
	return uint8(100 - sum)
}

// GetTransportParam fetches and parses the transport parameter from the SVCB RR, if present.
func GetTransportParam(svcb *dns.SVCB) (map[string]uint8, bool, error) {
	if svcb == nil {
		return nil, false, fmt.Errorf("GetTransportParam: nil svcb")
	}
	for _, kv := range svcb.Value {
		if local, ok := kv.(*dns.SVCBLocal); ok {
			if uint16(local.Key()) == SvcbTransportKey {
				m, err := core.ParseTransportString(string(local.Data))
				if err != nil {
					return nil, true, err
				}
				return m, true, nil
			}
		}
	}
	return nil, false, nil
}

// ValidateExplicitServerSVCB validates an explicit SVCB RR for server use.
// It checks transport weights against the ALPN list, if present. If transport is absent,
// the record is accepted as-is. If transport is present but alpn is missing, it's invalid.
func ValidateExplicitServerSVCB(svcb *dns.SVCB) error {
	if svcb == nil {
		return fmt.Errorf("ValidateExplicitServerSVCB: nil svcb")
	}
	_, _, err := GetTransportParam(svcb)
	if err != nil {
		return fmt.Errorf("invalid transport value: %w", err)
	}
	return nil
}
