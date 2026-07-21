/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"net"
	"net/netip"
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
	// PeersRef holds the ids of a `- peers: [ id, ... ]` reference entry.
	// Consumed (and cleared) by expandAclList at parse time; a post-expansion
	// list never contains reference entries.
	PeersRef []string `yaml:"peers" mapstructure:"peers"`
	// TLSIdentity and PeerName are populated only by peer expansion in a
	// downstreams: list — the per-zone downstream-auth mechanisms tls-pin/
	// tls-pkix/tls-dane are satisfiable only through entries that carry an
	// identity. Inline entries yield prefix/tsig mechanisms only.
	TLSIdentity *TLSIdentity `yaml:"-" mapstructure:"-"`
	PeerName    string       `yaml:"-" mapstructure:"-"`
	// Legacy is set by stringToAclEntryHook when a bare-string allow-notify: /
	// downstreams: value is found (the pre-{prefix,key} shape). Not config: it
	// exists so a legacy list quarantines just that zone (ValidateACL rejects a
	// non-empty Legacy) instead of failing the whole config decode.
	Legacy string `yaml:"-" mapstructure:"-"`
}

// matchACL applies an ordered ACL to a source IP, NSD-style: a matching BLOCKED
// entry denies (it supersedes any allow, regardless of order); otherwise the source
// is approved for the SET of keys named by EVERY matching non-BLOCKED entry (a key
// may be NOKEY = unsigned accepted). Returning the full set — not just the first
// match — is what lets two entries for one source name two different keys, so the
// server accepts EITHER during a dual-key rotation (add the new key alongside the
// old, migrate clients, then drop the old). Returns (allowed, approvedKeys); no
// match (incl. an empty ACL) -> (false, nil); callers layer their empty-ACL defaults
// on top (downstreams empty => deny; allow-notify empty => accept from primaries).
// A malformed prefix never matches; it is rejected at config time by ValidateACL.
func matchACL(acl []AclEntry, ip netip.Addr) (allowed bool, approvedKeys []string) {
	for _, e := range acl { // BLOCKED supersedes — scan all first
		if e.Key == BLOCKED && ipSpecMatch(e.Prefix, ip) {
			return false, nil
		}
	}
	for _, e := range acl { // collect EVERY non-BLOCKED prefix match
		if e.Key == BLOCKED {
			continue
		}
		if ipSpecMatch(e.Prefix, ip) {
			approvedKeys = append(approvedKeys, e.Key)
		}
	}
	if len(approvedKeys) == 0 {
		return false, nil
	}
	return true, approvedKeys
}

// ipSpecMatch reports whether ip falls within the ip-spec. A spec that fails to
// parse (or an invalid ip) returns false.
func ipSpecMatch(spec string, ip netip.Addr) bool {
	pfx, lo, hi, isRange, err := parseIPSpec(spec)
	if err != nil || !ip.IsValid() {
		return false
	}
	a := ip.Unmap()
	if isRange {
		// Same-family comparison only; a v4 addr never falls in a v6 range.
		if a.Is4() != lo.Is4() {
			return false
		}
		return a.Compare(lo) >= 0 && a.Compare(hi) <= 0
	}
	return pfx.Contains(a)
}

// ValidateIPSpec returns an error if spec is not a valid ip-spec.
func ValidateIPSpec(spec string) error {
	_, _, _, _, err := parseIPSpec(spec)
	return err
}

// ValidateACL checks an ACL at config time: every prefix must parse and every
// key must be BLOCKED or accepted by keyDefined (NOKEY or a defined keys.tsig
// name). Returns the first error, for per-zone quarantine.
func ValidateACL(acl []AclEntry, keyDefined func(string) bool) error {
	for _, e := range acl {
		if e.Legacy != "" {
			return fmt.Errorf("entry %q is a legacy bare-string address; migrate to { prefix: %s, key: NOKEY } — {prefix, key} is now required, and downstreams: is an AXFR ACL (not a notify list)", e.Legacy, e.Legacy)
		}
		if err := ValidateIPSpec(e.Prefix); err != nil {
			return fmt.Errorf("acl entry %q: %w", e.Prefix, err)
		}
		if e.Key != BLOCKED && !keyDefined(e.Key) {
			return fmt.Errorf("acl entry %q: unknown key %q (use a keys.tsig or keystore tsig name, NOKEY, or BLOCKED)", e.Prefix, e.Key)
		}
	}
	return nil
}

// parseIPSpec parses an ip-spec into either a netip.Prefix (CIDR / mask / bare-IP
// host route) or a [lo, hi] netip.Addr range (isRange). lo/hi are Unmap'd and of
// the same family. The string spellings a&m and a-b have no netip parser, so the
// splitting is by hand; the addresses and matching are netip.
func parseIPSpec(spec string) (pfx netip.Prefix, lo, hi netip.Addr, isRange bool, err error) {
	spec = strings.TrimSpace(spec)
	switch {
	case strings.Contains(spec, "/"): // CIDR (incl. 0.0.0.0/0, ::/0)
		p, e := netip.ParsePrefix(spec)
		if e != nil {
			return pfx, lo, hi, false, fmt.Errorf("bad CIDR %q: %w", spec, e)
		}
		return p.Masked(), lo, hi, false, nil

	case strings.Contains(spec, "&"): // mask: ip&netmask
		parts := strings.SplitN(spec, "&", 2)
		base, e1 := netip.ParseAddr(strings.TrimSpace(parts[0]))
		maskAddr, e2 := netip.ParseAddr(strings.TrimSpace(parts[1]))
		if e1 != nil || e2 != nil {
			return pfx, lo, hi, false, fmt.Errorf("bad masked spec %q", spec)
		}
		// Reject a family mismatch before building the prefix: a v6 base with a v4
		// mask (or vice versa) would otherwise silently produce a wrong-scope prefix
		// (e.g. 2001:db8::&255.255.255.0 -> a /24 of the v6 address).
		if base.Unmap().Is4() != maskAddr.Unmap().Is4() {
			return pfx, lo, hi, false, fmt.Errorf("masked spec %q mixes IPv4 and IPv6", spec)
		}
		// Size returns (0, 0) for a non-canonical (non-contiguous) mask.
		ones, bits := net.IPMask(maskAddr.AsSlice()).Size()
		if bits == 0 {
			return pfx, lo, hi, false, fmt.Errorf("non-contiguous netmask in %q", spec)
		}
		p, e := base.Prefix(ones)
		if e != nil {
			return pfx, lo, hi, false, fmt.Errorf("bad masked spec %q: %w", spec, e)
		}
		return p, lo, hi, false, nil

	case strings.Contains(spec, "-"): // range: lo-hi
		parts := strings.SplitN(spec, "-", 2)
		loA, e1 := netip.ParseAddr(strings.TrimSpace(parts[0]))
		hiA, e2 := netip.ParseAddr(strings.TrimSpace(parts[1]))
		if e1 != nil || e2 != nil {
			return pfx, lo, hi, false, fmt.Errorf("bad range %q", spec)
		}
		loA, hiA = loA.Unmap(), hiA.Unmap()
		if loA.Is4() != hiA.Is4() {
			return pfx, lo, hi, false, fmt.Errorf("range %q mixes IPv4 and IPv6", spec)
		}
		if loA.Compare(hiA) > 0 {
			return pfx, lo, hi, false, fmt.Errorf("range %q: low > high", spec)
		}
		return pfx, loA, hiA, true, nil

	default: // bare IP -> host route
		a, e := netip.ParseAddr(spec)
		if e != nil {
			return pfx, lo, hi, false, fmt.Errorf("bad ip-spec %q", spec)
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), lo, hi, false, nil
	}
}
