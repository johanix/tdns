/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package core

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ParseTransportString parses a transport string like "doq:30,dot:20" into a map.
// - Keys are lower-cased and trimmed
// - Values are clamped to [0,100] (values >100 become 100; never rejected)
// - Duplicate keys are rejected
// - Absence defaults (draft-johani-dnsop-svcb-oots): do53→100, others→0
func ParseTransportString(s string) (map[string]uint8, error) {
	transports, err := ParseTransportStringRaw(s)
	if err != nil {
		return nil, err
	}
	ApplyTransportDefaults(transports)
	return transports, nil
}

// ParseTransportStringRaw is ParseTransportString without the absence
// defaults: the map holds only the transports the string names, as a record of
// what a signal said. Selection wants the defaults; use ParseTransportString.
func ParseTransportStringRaw(s string) (map[string]uint8, error) {
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

// signalTokens are the oots tokens that transport selection acts on when a
// signal is RECEIVED, whatever path it arrives by: the oots SvcParam of a
// _dns SVCB, or the transport= string of a TSYNC. They are the transports the
// resolver implements. A received signal may name others -- `udp` and `tcp`
// from the token split, or a token not yet defined -- and the dns codec keeps
// those on the wire, but they never reach selection. Until the token split is
// built these four are the whole set.
//
// This is deliberately not StringToTransport, which also accepts aliases for
// operator input: its `tcp` maps to TransportDo53TCP, so a received `tcp:30`
// would install a Do53TCP weight. Operator input (imr set, config stubs) keeps
// using StringToTransport.
var signalTokens = map[string]bool{
	"do53": true,
	"dot":  true,
	"doh":  true,
	"doq":  true,
}

// IsSignalToken reports whether tok, lower-cased, is an oots token that
// selection acts on in a received signal. See signalTokens.
func IsSignalToken(tok string) bool {
	return signalTokens[tok]
}

// FilterSignalTokens returns a new map holding only the entries of m whose key
// is a signal token (IsSignalToken). The result may be empty: a signal that
// names no token selection acts on says nothing to act on, and the caller
// treats it as no signal rather than as one that gets the absence defaults.
func FilterSignalTokens(m map[string]uint8) map[string]uint8 {
	out := make(map[string]uint8, len(m))
	for k, v := range m {
		if IsSignalToken(k) {
			out[k] = v
		}
	}
	return out
}

// ParseReceivedTransportString parses a transport string that was RECEIVED
// (the transport= value of a TSYNC) into the weights selection acts on: as
// ParseTransportStringRaw, then FilterSignalTokens. Malformed strings are still
// refused as a whole; a well-formed entry with another token is dropped.
func ParseReceivedTransportString(s string) (map[string]uint8, error) {
	raw, err := ParseTransportStringRaw(s)
	if err != nil {
		return nil, err
	}
	return FilterSignalTokens(raw), nil
}

// ValidatePublishedTransportSignal checks a transport signal this server is
// about to PUBLISH (service.transport.signal): it must parse, and name only
// signal tokens. A tdns publisher may not emit another token until every node
// that can re-pack the record keeps it and every resolver ignores, rather than
// misapplies, what it cannot honor (the alternative-endpoint design, tdns
// #1043, section 8).
func ValidatePublishedTransportSignal(s string) error {
	raw, err := ParseTransportStringRaw(s)
	if err != nil {
		return err
	}
	var bad []string
	for k := range raw {
		if !IsSignalToken(k) {
			bad = append(bad, k)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("transport: %s not publishable (only %s until the token split)",
			strings.Join(bad, ", "), signalTokenList())
	}
	return nil
}

// signalTokenList names the signal tokens, sorted, for messages: built from
// signalTokens so that a message cannot name another set than the filter uses.
func signalTokenList() string {
	toks := make([]string, 0, len(signalTokens))
	for k := range signalTokens {
		toks = append(toks, k)
	}
	sort.Strings(toks)
	return strings.Join(toks, ", ")
}
