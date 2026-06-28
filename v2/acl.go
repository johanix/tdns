/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"fmt"
	"net"
	"strings"
)

// BLOCKED is the ACL key-field sentinel meaning "deny this address-spec". It
// supersedes any allow entry (NSD semantics). It is a reserved name — a
// keys.tsig entry may not be named BLOCKED (see LoadTsigKeys).
const BLOCKED = "BLOCKED"

// AclEntry is one entry in an allow-notify: / downstreams: address ACL (NSD
// allow-notify / provide-xfr). Prefix is an ip-spec — a bare IP, CIDR
// (1.2.3.4/24), mask (1.2.3.4&255.255.255.0), range (1.2.3.4-1.2.3.25), or
// 0.0.0.0/0 / ::/0 for "any". Key is a keys.tsig name (TSIG required), NOKEY
// (unsigned accepted), or BLOCKED (deny). The struct shape matches PeerConf
// ({addr, key}) so the config keeps one entry style.
type AclEntry struct {
	Prefix string `yaml:"prefix" mapstructure:"prefix"`
	Key    string `yaml:"key" mapstructure:"key"`
}

// matchACL applies an ordered ACL to a source IP, NSD-style: a matching BLOCKED
// entry denies (it supersedes any allow, regardless of order); otherwise the
// first entry whose prefix matches wins. Returns (allowed, requiredKeyName) —
// requiredKeyName is NOKEY when no TSIG is required. No match (incl. an empty
// ACL) -> (false, ""); callers layer their empty-ACL defaults on top (downstreams
// empty => deny; allow-notify empty => accept from primaries). A malformed
// prefix never matches; it is rejected at config time by ValidateACL.
func matchACL(acl []AclEntry, ip net.IP) (allowed bool, requiredKey string) {
	for _, e := range acl { // BLOCKED supersedes — scan all first
		if e.Key == BLOCKED && ipSpecMatch(e.Prefix, ip) {
			return false, ""
		}
	}
	for _, e := range acl { // first non-BLOCKED prefix match wins
		if e.Key == BLOCKED {
			continue
		}
		if ipSpecMatch(e.Prefix, ip) {
			return true, e.Key
		}
	}
	return false, ""
}

// ipSpecMatch reports whether ip falls within the ip-spec. A spec that fails to
// parse (or a nil ip) returns false.
func ipSpecMatch(spec string, ip net.IP) bool {
	ipnet, lo, hi, err := parseIPSpec(spec)
	if err != nil || ip == nil {
		return false
	}
	if ipnet != nil {
		return ipnet.Contains(ip)
	}
	ip16 := ip.To16()
	return ip16 != nil && bytes.Compare(ip16, lo) >= 0 && bytes.Compare(ip16, hi) <= 0
}

// ValidateIPSpec returns an error if spec is not a valid ip-spec.
func ValidateIPSpec(spec string) error {
	_, _, _, err := parseIPSpec(spec)
	return err
}

// ValidateACL checks an ACL at config time: every prefix must parse and every
// key must be BLOCKED or accepted by keyDefined (NOKEY or a defined keys.tsig
// name). Returns the first error, for per-zone quarantine.
func ValidateACL(acl []AclEntry, keyDefined func(string) bool) error {
	for _, e := range acl {
		if err := ValidateIPSpec(e.Prefix); err != nil {
			return fmt.Errorf("acl entry %q: %w", e.Prefix, err)
		}
		if e.Key != BLOCKED && !keyDefined(e.Key) {
			return fmt.Errorf("acl entry %q: unknown key %q (use a keys.tsig name, NOKEY, or BLOCKED)", e.Prefix, e.Key)
		}
	}
	return nil
}

// parseIPSpec parses an ip-spec into either an *net.IPNet (CIDR / mask / bare IP
// host-route) or a [lo, hi] range (lo/hi in 16-byte form). Exactly one of ipnet
// or (lo,hi) is non-nil on success.
func parseIPSpec(spec string) (ipnet *net.IPNet, lo, hi net.IP, err error) {
	spec = strings.TrimSpace(spec)
	switch {
	case strings.Contains(spec, "/"): // CIDR (incl. 0.0.0.0/0, ::/0)
		_, n, e := net.ParseCIDR(spec)
		if e != nil {
			return nil, nil, nil, fmt.Errorf("bad CIDR %q: %w", spec, e)
		}
		return n, nil, nil, nil
	case strings.Contains(spec, "&"): // mask: ip&netmask
		parts := strings.SplitN(spec, "&", 2)
		base := net.ParseIP(strings.TrimSpace(parts[0]))
		maskIP := net.ParseIP(strings.TrimSpace(parts[1]))
		if base == nil || maskIP == nil {
			return nil, nil, nil, fmt.Errorf("bad masked spec %q", spec)
		}
		var mask net.IPMask
		if v4 := maskIP.To4(); v4 != nil {
			mask = net.IPMask(v4)
		} else {
			mask = net.IPMask(maskIP.To16())
		}
		return &net.IPNet{IP: base.Mask(mask), Mask: mask}, nil, nil, nil
	case strings.Contains(spec, "-"): // range: lo-hi
		parts := strings.SplitN(spec, "-", 2)
		loIP := net.ParseIP(strings.TrimSpace(parts[0]))
		hiIP := net.ParseIP(strings.TrimSpace(parts[1]))
		if loIP == nil || hiIP == nil {
			return nil, nil, nil, fmt.Errorf("bad range %q", spec)
		}
		lo16, hi16 := loIP.To16(), hiIP.To16()
		if lo16 == nil || hi16 == nil || bytes.Compare(lo16, hi16) > 0 {
			return nil, nil, nil, fmt.Errorf("bad range bounds %q", spec)
		}
		return nil, lo16, hi16, nil
	default: // bare IP -> host route
		ip := net.ParseIP(spec)
		if ip == nil {
			return nil, nil, nil, fmt.Errorf("bad ip-spec %q", spec)
		}
		bits := 128
		base := ip.To16()
		if v4 := ip.To4(); v4 != nil {
			bits, base = 32, v4
		}
		return &net.IPNet{IP: base, Mask: net.CIDRMask(bits, len(base)*8)}, nil, nil, nil
	}
}
