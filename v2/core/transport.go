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
//   - Keys are lower-cased and trimmed
//   - Values are clamped to [0,100] (values >100 become 100; never rejected)
//   - Duplicate keys are rejected
//   - Absence defaults and the do53 shorthand (ApplyTransportDefaults): udp and
//     tcp 100, the others 0
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

// ApplyTransportDefaults reads a signal's weights the way selection does:
//   - the do53 shorthand is expanded (ExpandDo53Shorthand), so the map names
//     udp and tcp, never do53;
//   - missing udp or tcp → 100. TCP is mandatory for a DNS server (RFC 7766),
//     and a default of 0 would make every signal that predates the split claim
//     there is none;
//   - missing dot, doh or doq → 0.
//
// Explicit entries, udp:0 and tcp:0 included, are left unchanged. The
// alternative-endpoint design, section 2.
func ApplyTransportDefaults(m map[string]uint8) {
	if m == nil {
		return
	}
	ExpandDo53Shorthand(m)
	for _, p := range []string{"udp", "tcp"} {
		if _, ok := m[p]; !ok {
			m[p] = 100
		}
	}
	for _, p := range []string{"dot", "doh", "doq"} {
		if _, ok := m[p]; !ok {
			m[p] = 0
		}
	}
}

// ExpandDo53Shorthand rewrites m in place: a do53:N entry becomes udp:N and
// tcp:N, and an explicit udp or tcp entry wins over it. do53 is the token the
// split replaced. It is kept as a receive-only shorthand, so that an old
// signal's do53:0 still reads as "send me none" rather than as the default
// of 100. No absence defaults are applied.
func ExpandDo53Shorthand(m map[string]uint8) {
	w, ok := m["do53"]
	if !ok {
		return
	}
	delete(m, "do53")
	for _, p := range []string{"udp", "tcp"} {
		if _, explicit := m[p]; !explicit {
			m[p] = w
		}
	}
}

// signalTokens are the oots tokens that transport selection acts on when a
// signal is RECEIVED, whatever path it arrives by: the oots SvcParam of a
// _dns SVCB, or the transport= string of a TSYNC. They are the transports the
// resolver implements: udp and tcp (cleartext DNS, StringToTransport maps them
// to TransportDo53 and TransportDo53TCP), dot, doh and doq, and do53, the
// receive-only shorthand for udp and tcp (ExpandDo53Shorthand). A received
// signal may name others, tokens not yet defined, and the dns codec keeps
// those on the wire, but they never reach selection.
//
// This is deliberately not StringToTransport, which also accepts aliases for
// operator input (do53-tcp, DoT, ...). Operator input (imr set, config stubs)
// keeps using StringToTransport.
var signalTokens = map[string]bool{
	"do53": true,
	"udp":  true,
	"tcp":  true,
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
// signal tokens, which tdns-auth publishes with do53 emitted as udp and tcp.
// A tdns publisher may not emit another token until every node that can
// re-pack the record keeps it and every resolver ignores, rather than
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
		return fmt.Errorf("transport: %s not publishable (only %s)",
			strings.Join(bad, ", "), tokenList(signalTokens))
	}
	return nil
}

// tokenList names a token set, sorted, for messages: built from the set itself
// so that a message cannot name another set than the check uses.
func tokenList(set map[string]bool) string {
	toks := make([]string, 0, len(set))
	for k := range set {
		toks = append(toks, k)
	}
	sort.Strings(toks)
	return strings.Join(toks, ", ")
}

// TransportToSignalToken is the oots token for each transport, for showing a
// signal in the tokens it is written in: TransportDo53 is udp (UDP, retried
// over TCP after truncation) and TransportDo53TCP is tcp. The transports keep
// their names in TransportToString.
var TransportToSignalToken = map[Transport]string{
	TransportDo53:    "udp",
	TransportDo53TCP: "tcp",
	TransportDoT:     "dot",
	TransportDoH:     "doh",
	TransportDoQ:     "doq",
}

// SelectableTransport reports whether transport selection may choose t on its
// own, and so whether t is entered among a server's transports. TransportDo53TCP
// is not: a tcp weight caps only the TCP a resolver chooses on its own, and
// tdns chooses none. Its TCP goes out after truncation or when forced, which
// no weight gates, tcp:0 included. Its weight is kept for the stats.
func SelectableTransport(t Transport) bool {
	return t != TransportDo53TCP
}
