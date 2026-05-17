/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// CompiledInRootTrustAnchor contains the IANA-published DS records for
// the root zone DNSKEY KSKs currently in active use. Used when no
// trust-anchor-file is configured (mirrors the CompiledInRootHints
// fallback). Format: standard DNS zone-file syntax, parseable by
// dns.NewRR.
//
// Maintenance: root KSK rollovers have historically been ~8 years
// apart (KSK-2010 → KSK-2017 → KSK-2024) so a compiled-in default is
// reasonable. ICANN has announced an intent to move to ~3-year
// rollovers; the compiled-in approach is still viable at that cadence
// but requires more regular updates. When rollovers happen, both the
// outgoing and incoming KSKs should be listed here for the overlap
// window per RFC 5011 / IANA process.
//
// Current state (2026):
//   - KSK-2017 (keytag 20326) — still active in the root DNSKEY RRset
//   - KSK-2024 (keytag 38696) — now the primary signing key
// Both DS records published by IANA at
// https://data.iana.org/root-anchors/root-anchors.xml
const CompiledInRootTrustAnchor = `; Root trust anchors - IANA-published DS records for the root KSKs
; This is compiled into the binary and used when no trust-anchor-file
; config is provided. Mirrors the CompiledInRootHints fallback.
;
; KSK-2017 (keytag 20326) — still active per IANA root-anchors.xml
.  IN  DS  20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
; KSK-2024 (keytag 38696) — current primary KSK
.  IN  DS  38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
`

// LoadTrustAnchorsFromFile reads a zone-file-format trust anchor file
// and returns the parsed DS and DNSKEY records. Blank lines and lines
// starting with ; or # are skipped. Unparseable lines are logged via
// the supplied logf (use nil to silently skip).
//
// Centralised here so both the IMR boot path (imrengine.go) and the
// dog sigchase command use the same parser. Matches the inline parser
// that used to live at imrengine.go:1416-1443.
func LoadTrustAnchorsFromFile(path string, logf func(format string, args ...any)) ([]*dns.DS, []*dns.DNSKEY, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read trust-anchor file %q: %w", path, err)
	}
	return ParseTrustAnchors(string(data), logf)
}

// ParseTrustAnchors parses zone-file-format trust anchor data (e.g.
// the contents of /etc/tdns/root.key or CompiledInRootTrustAnchor).
// Returns the DS and DNSKEY records found; unparseable lines are
// logged via logf (use nil to silently skip).
func ParseTrustAnchors(data string, logf func(format string, args ...any)) ([]*dns.DS, []*dns.DNSKEY, error) {
	var dss []*dns.DS
	var keys []*dns.DNSKEY
	for _, ln := range strings.Split(data, "\n") {
		s := strings.TrimSpace(ln)
		if s == "" || strings.HasPrefix(s, ";") || strings.HasPrefix(s, "#") {
			continue
		}
		rr, err := dns.NewRR(s)
		if err != nil {
			if logf != nil {
				logf("skipping unparsable trust-anchor line %q: %v", s, err)
			}
			continue
		}
		switch t := rr.(type) {
		case *dns.DS:
			dss = append(dss, t)
		case *dns.DNSKEY:
			keys = append(keys, t)
		default:
			if logf != nil {
				logf("ignoring non-TA RR in trust anchors: %s", rr.String())
			}
		}
	}
	return dss, keys, nil
}
