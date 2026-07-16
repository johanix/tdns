/*
 * Copyright (c) 2024 Johan Stenstam
 */
package tdns

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

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

// GetTransportParam fetches and parses the oots SvcParam from the SVCB RR, if present.
func GetTransportParam(svcb *dns.SVCB) (map[string]uint8, bool, error) {
	if svcb == nil {
		return nil, false, fmt.Errorf("GetTransportParam: nil svcb")
	}
	for _, kv := range svcb.Value {
		if oots, ok := kv.(*dns.SVCBOots); ok {
			m := svcbOotsToTransportMap(oots)
			return m, true, nil
		}
	}
	return nil, false, nil
}

// svcbOotsToTransportMap converts a parsed SVCBOots value into a weight map
// with -03 absence defaults applied.
func svcbOotsToTransportMap(oots *dns.SVCBOots) map[string]uint8 {
	m := make(map[string]uint8)
	if oots == nil {
		core.ApplyTransportDefaults(m)
		return m
	}
	for _, e := range oots.Oots {
		w := e.Weight
		if w > 100 {
			w = 100
		}
		m[strings.ToLower(e.Proto)] = w
	}
	core.ApplyTransportDefaults(m)
	return m
}

// ValidateExplicitServerSVCB validates an explicit SVCB RR for server use.
// If oots is present it must parse cleanly; absence of oots is accepted.
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
