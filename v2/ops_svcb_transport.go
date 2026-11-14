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
	m, ok, err := GetTransportParamRaw(svcb)
	if ok && err == nil {
		core.ApplyTransportDefaults(m)
	}
	return m, ok, err
}

// GetTransportParamRaw is GetTransportParam without the absence defaults: the
// map holds only the transports the oots SvcParam names, as a record of what
// the server said. Selection wants the defaults; use GetTransportParam.
//
// Only signal tokens (core.IsSignalToken) are returned. An oots value that
// names none of them -- only `udp`, `tcp` or tokens not yet defined -- reports
// no oots at all (ok false), exactly as a record without the SvcParam: there is
// nothing in it to act on, and applying the absence defaults instead would
// replace whatever another record of the RRset said.
func GetTransportParamRaw(svcb *dns.SVCB) (map[string]uint8, bool, error) {
	if svcb == nil {
		return nil, false, fmt.Errorf("GetTransportParam: nil svcb")
	}
	for _, kv := range svcb.Value {
		if oots, ok := kv.(*dns.SVCBOots); ok {
			m := svcbOotsToRawMap(oots)
			if len(m) == 0 {
				return nil, false, nil
			}
			return m, true, nil
		}
	}
	return nil, false, nil
}

// svcbOotsToRawMap converts a parsed SVCBOots value into a weight map of the
// signal tokens it names, weights clamped to 100. It is the only reader of
// SVCBOots.Oots. The dns codec keeps every entry, known or not, and the weight
// octet as received, so that a record packs back to the bytes it was signed
// as; ignoring the other tokens and the clamp are done here.
func svcbOotsToRawMap(oots *dns.SVCBOots) map[string]uint8 {
	m := make(map[string]uint8)
	if oots == nil {
		return m
	}
	for _, e := range oots.Oots {
		k := strings.ToLower(e.Proto)
		if !core.IsSignalToken(k) {
			continue
		}
		w := e.Weight
		if w > 100 {
			w = 100
		}
		m[k] = w
	}
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
