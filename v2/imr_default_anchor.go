/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"errors"
	"fmt"
	"sort"
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
// (cache.CompiledInRootTrustAnchor), as dog already did -- where the root it
// reaches is the IANA root.
//
// A private root (test labs run their own) is reached through a root-hints
// file, a forward for "." or a stub for ".". Against such a root the IANA
// anchor would make every signed answer Bogus instead of Indeterminate. But
// the three are also how the IANA root is reached by hand (a stub for "." that
// names b.root-servers.net), and the config cannot tell the two apart. So
// with any of the three and no anchor configured, the resolver asks the root:
// it fetches its DNSKEY RRset and uses the compiled-in anchor if the keys
// match it (imr_root_anchor_probe.go). A root that does not match gets no
// anchor, as before, and a warning that nothing will validate.

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
	for _, fc := range ic.Forward {
		if isRootZone(fc.Zone) {
			return `the root is forwarded (forward zone ".")`
		}
	}
	for _, sc := range ic.Stubs {
		if isRootZone(sc.Zone) {
			return `the root is a stub zone (stub zone ".")`
		}
	}
	return ""
}

// isRootZone reports whether a configured zone name is the root.
func isRootZone(zone string) bool {
	zone = strings.TrimSpace(zone)
	return zone != "" && dns.Fqdn(core.CanonicalizeName(zone)) == "."
}

// rootServers names the servers the config reaches "." through: the addresses
// of every stub for "." and the address and port of every upstream of a forward
// for ".", sorted, so that two configs that ask the same servers give the same
// string. It is what the root probe's choice of anchor was made about
// (RootAnchorProbe): the choice stands only while the root is asked of the same
// servers. A server's name, its transports and their weights are left out, as
// they do not change which root it is, and a reload applies them.
func (ic *ImrEngineConf) rootServers() string {
	var servers []string
	for _, fc := range ic.Forward {
		if !isRootZone(fc.Zone) {
			continue
		}
		for _, u := range fc.Upstreams {
			servers = append(servers, fmt.Sprintf("forward %s port %d", strings.TrimSpace(u.Addr), u.Port))
		}
	}
	for _, sc := range ic.Stubs {
		if !isRootZone(sc.Zone) {
			continue
		}
		for i := range sc.Servers {
			for _, addr := range sc.Servers[i].Addrs {
				servers = append(servers, "stub "+strings.TrimSpace(addr))
			}
		}
	}
	sort.Strings(servers)
	return strings.Join(servers, ", ")
}

// RootAnchorProbe reports whether the compiled-in IANA root anchor is up to the
// root's keys: the config names no anchor, and the root may not be the IANA
// root (NonDefaultRoot says how it is reached). The resolver then fetches the
// root's DNSKEY RRset and uses the anchor if the keys match
// (rootAnchorByProbe).
func (ic *ImrEngineConf) RootAnchorProbe() (probe bool, why string) {
	if ic.AnchorConfigured() {
		return false, ""
	}
	why = ic.NonDefaultRoot()
	return why != "", why
}

// RootAnchorFallback reports whether the resolver uses the compiled-in IANA
// root anchor without asking the root: when the config names no anchor, and
// the root is the IANA root as far as the config can tell (NonDefaultRoot is
// ""). When the config names no anchor and the root may be another one, why
// says how it is reached, and the choice is the root's (RootAnchorProbe).
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
