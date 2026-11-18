/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package imr

import (
	"errors"
	"fmt"
	"strings"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The resolver's trust anchor when the config names none.
//
// An IMR whose config sets none of trust-anchor-ds, trust-anchor-dnskey and
// trust-anchor-file used to load no anchor at all, and so validated nothing:
// every answer Indeterminate, the root's own included, and nothing said so.
// It now uses the IANA root anchor compiled into the binary
// (cache.CompiledInRootTrustAnchor), as dog already did -- but only where the
// root it reaches is the IANA root, as far as the config can tell.
//
// A private root (test labs run their own) is reached through a root-hints
// file, a forward for "." or a stub for ".". Against such a root the IANA
// anchor makes every signed answer Bogus instead of Indeterminate, so with any
// of the three and no anchor configured the resolver keeps the old behaviour,
// and says that nothing will validate.

// AnchorConfigured reports whether the config names a trust anchor of its own,
// in any of the three forms.
func (ic *ImrEngineConf) AnchorConfigured() bool {
	return strings.TrimSpace(ic.TrustAnchorDS) != "" ||
		strings.TrimSpace(ic.TrustAnchorDNSKEY) != "" ||
		strings.TrimSpace(ic.TrustAnchorFile) != ""
}

// NonDefaultRoot says why the root this resolver reaches may not be the IANA
// root: a root-hints file, a forward for "." or a stub for ".". It returns ""
// when the config leaves the IANA root: the compiled-in root hints, and the
// root neither forwarded nor stubbed.
//
// A forward for "." counts whatever its upstream is: the root behind a
// resolver is whichever root that resolver uses, and nothing in the config
// says which. Quarantined and dropped entries count too; a config that names
// a private root is not a config for the IANA one because the entry is broken.
func (ic *ImrEngineConf) NonDefaultRoot() string {
	if hints := strings.TrimSpace(ic.RootHints); hints != "" {
		return fmt.Sprintf("root-hints is set (%s)", hints)
	}
	isRoot := func(zone string) bool {
		zone = strings.TrimSpace(zone)
		return zone != "" && dns.Fqdn(core.CanonicalizeName(zone)) == "."
	}
	for _, fc := range ic.Forward {
		if isRoot(fc.Zone) {
			return `the root is forwarded (forward zone ".")`
		}
	}
	for _, sc := range ic.Stubs {
		if isRoot(sc.Zone) {
			return `the root is a stub zone (stub zone ".")`
		}
	}
	return ""
}

// RootAnchorFallback reports whether the resolver uses the compiled-in IANA
// root anchor: when the config names no anchor, and the root is the IANA root
// (NonDefaultRoot is ""). When the config names no anchor and the root may be
// a private one, why says how; the resolver then has no anchor at all.
func (ic *ImrEngineConf) RootAnchorFallback() (use bool, why string) {
	if ic.AnchorConfigured() {
		return false, ""
	}
	if why := ic.NonDefaultRoot(); why != "" {
		return false, why
	}
	return true, ""
}

// compiledInRootAnchors parses cache.CompiledInRootTrustAnchor.
func compiledInRootAnchors() ([]*dns.DS, []*dns.DNSKEY, error) {
	var problems []string
	dss, keys, err := cache.ParseTrustAnchors(cache.CompiledInRootTrustAnchor, func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	})
	switch {
	case err != nil:
		return nil, nil, err
	case len(problems) > 0:
		// A constant in this binary: a line that does not parse is a bug.
		return nil, nil, fmt.Errorf("compiled-in root trust anchor: %s", strings.Join(problems, "; "))
	case len(dss) == 0 && len(keys) == 0:
		return nil, nil, errors.New("compiled-in root trust anchor holds no DS or DNSKEY")
	}
	return dss, keys, nil
}

// parseInlineAnchors reads every RR in s, a trust-anchor-ds or
// trust-anchor-dnskey value, in zone-file syntax: one record or several,
// as a YAML block scalar with one per line. The origin is "." and the default
// TTL 3600, as dns.NewRR has them, so that a single record reads as it always
// did. $INCLUDE is refused: that is what trust-anchor-file is for.
//
// It is an error if anything fails to parse, or if s holds no RR. The caller
// checks the types.
func parseInlineAnchors(s string) ([]dns.RR, error) {
	if !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	zp := dns.NewZoneParser(strings.NewReader(s), ".", "")
	zp.SetDefaultTTL(3600)
	var rrs []dns.RR
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		rrs = append(rrs, rr)
	}
	if err := zp.Err(); err != nil {
		return nil, err
	}
	if len(rrs) == 0 {
		return nil, errors.New("no resource record found")
	}
	return rrs, nil
}

// parseInlineDSAnchors reads a trust-anchor-ds value: every RR in it must be
// a DS.
func parseInlineDSAnchors(s string) ([]*dns.DS, error) {
	rrs, err := parseInlineAnchors(s)
	if err != nil {
		return nil, err
	}
	dss := make([]*dns.DS, 0, len(rrs))
	for _, rr := range rrs {
		ds, ok := rr.(*dns.DS)
		if !ok {
			return nil, fmt.Errorf("not a DS RR: %T (%s)", rr, rr.String())
		}
		dss = append(dss, ds)
	}
	return dss, nil
}

// parseInlineDNSKEYAnchors reads a trust-anchor-dnskey value: every RR in it
// must be a DNSKEY.
func parseInlineDNSKEYAnchors(s string) ([]*dns.DNSKEY, error) {
	rrs, err := parseInlineAnchors(s)
	if err != nil {
		return nil, err
	}
	keys := make([]*dns.DNSKEY, 0, len(rrs))
	for _, rr := range rrs {
		dk, ok := rr.(*dns.DNSKEY)
		if !ok {
			return nil, fmt.Errorf("not a DNSKEY RR: %T (%s)", rr, rr.String())
		}
		keys = append(keys, dk)
	}
	return keys, nil
}

// anchorZone is the zone a trust anchor is grouped under: its owner as a
// canonical (lowercase) FQDN. The caches key names case-insensitively, so
// "Example." and "example." are one zone there. Grouped apart, both groups
// would seed the same cache entry and the last one written would replace the
// other, keeping only part of the zone's anchors.
func anchorZone(owner string) string {
	return core.CanonicalizeName(dns.Fqdn(owner))
}
