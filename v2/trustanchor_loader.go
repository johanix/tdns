/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"os"
	"strings"

	cache "github.com/johanix/tdns/v2/cache"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// LoadDefaultTrustAnchors resolves which trust anchors to use for a
// standalone caller (typically dog +sigchase) following this priority
// chain:
//
//  1. explicitFile (e.g. from a --trust-anchor / -k flag). If set,
//     try to parse it. On error fall through with a warning so the
//     user gets validation even if their explicit file was bad — but
//     log noisily so they notice.
//  2. The default IMR config file (DefaultImrCfgFile). If it exists
//     and parses, look for an imrengine.trust-anchor-file entry. If
//     set and that file exists, use it.
//  3. cache.CompiledInRootTrustAnchor — the IANA root DS records
//     baked into the binary.
//
// Each step that yields TAs returns them along with a short
// description of where they came from (for logging). The function
// never returns (nil, nil) — the compiled-in fallback always at least
// gives the root KSK DS records.
//
// logf is optional; pass nil to silently follow the chain.
func LoadDefaultTrustAnchors(explicitFile string, logf func(format string, args ...any)) (ds []*dns.DS, keys []*dns.DNSKEY, source string) {
	if logf == nil {
		logf = func(string, ...any) {}
	}

	// 1. Explicit file via flag.
	if explicitFile != "" {
		d, k, err := cache.LoadTrustAnchorsFromFile(explicitFile, logf)
		if err == nil && (len(d) > 0 || len(k) > 0) {
			return d, k, fmt.Sprintf("file %s", explicitFile)
		}
		if err != nil {
			logf("LoadDefaultTrustAnchors: --trust-anchor %s failed (%v); falling through", explicitFile, err)
		} else {
			logf("LoadDefaultTrustAnchors: --trust-anchor %s yielded no DS or DNSKEY; falling through", explicitFile)
		}
	}

	// 2. Discover via the IMR config file. All three of its anchor settings
	// count, not just the file one -- see imrConfigAnchors.
	if d, k, src := imrConfigAnchors(DefaultImrCfgFile, logf); len(d) > 0 || len(k) > 0 {
		return d, k, src
	}

	// 3. Compiled-in fallback. ParseTrustAnchors on a hard-coded
	// constant should not produce errors; if it somehow does, log and
	// return whatever it managed to parse.
	d, k, err := cache.ParseTrustAnchors(cache.CompiledInRootTrustAnchor, logf)
	if err != nil {
		logf("LoadDefaultTrustAnchors: compiled-in TA parse failed (%v); validation will be limited", err)
	}
	return d, k, "compiled-in"
}

// imrConfigAnchors reads the IMR config at cfgPath and returns every trust
// anchor it declares: the inline trust-anchor-ds and trust-anchor-dnskey RRs
// and the contents of trust-anchor-file.
//
// All three are additive and all three count, which is what the IMR's own
// parseTrustAnchorsFromConfig does. They used to disagree: this function read
// only trust-anchor-file, so a config that set trust-anchor-ds anchored the
// resolver but not dog, which fell through to the compiled-in IANA root DS
// records and called any other root bogus. A config means one thing, whoever
// is reading it.
//
// Returns ("" source) when the file is absent, unparseable, or declares no
// usable anchor; callers treat that as "fall through".
func imrConfigAnchors(cfgPath string, logf func(format string, args ...any)) ([]*dns.DS, []*dns.DNSKEY, string) {
	if cfgPath == "" {
		return nil, nil, ""
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		// Most common: config file simply isn't here (dog run on a
		// machine that doesn't host an IMR). Not worth logging.
		return nil, nil, ""
	}
	// Minimal YAML shape: only the trust anchor fields matter here. Using a
	// narrow struct avoids dragging the full Config schema into this code
	// path. These are yaml tags rather than mapstructure because this reads
	// the file directly; the daemons go through viper.
	var sub struct {
		Imrengine struct {
			TrustAnchorDS     string `yaml:"trust-anchor-ds"`
			TrustAnchorDNSKEY string `yaml:"trust-anchor-dnskey"`
			TrustAnchorFile   string `yaml:"trust-anchor-file"`
		} `yaml:"imrengine"`
	}
	if err := yaml.Unmarshal(data, &sub); err != nil {
		logf("imrConfigAnchors: %s parse failed (%v); ignoring", cfgPath, err)
		return nil, nil, ""
	}

	var dss []*dns.DS
	var keys []*dns.DNSKEY
	var srcs []string

	if v := strings.TrimSpace(sub.Imrengine.TrustAnchorDNSKEY); v != "" {
		switch rr, err := dns.NewRR(v); {
		case err != nil:
			logf("imrConfigAnchors: trust-anchor-dnskey in %s failed to parse (%v); ignoring", cfgPath, err)
		default:
			if dk, ok := rr.(*dns.DNSKEY); ok {
				keys = append(keys, dk)
				srcs = append(srcs, "trust-anchor-dnskey")
			} else {
				logf("imrConfigAnchors: trust-anchor-dnskey in %s is a %T, not a DNSKEY; ignoring", cfgPath, rr)
			}
		}
	}

	if v := strings.TrimSpace(sub.Imrengine.TrustAnchorDS); v != "" {
		switch rr, err := dns.NewRR(v); {
		case err != nil:
			logf("imrConfigAnchors: trust-anchor-ds in %s failed to parse (%v); ignoring", cfgPath, err)
		default:
			if ds, ok := rr.(*dns.DS); ok {
				dss = append(dss, ds)
				srcs = append(srcs, "trust-anchor-ds")
			} else {
				logf("imrConfigAnchors: trust-anchor-ds in %s is a %T, not a DS; ignoring", cfgPath, rr)
			}
		}
	}

	if v := strings.TrimSpace(sub.Imrengine.TrustAnchorFile); v != "" {
		if _, err := os.Stat(v); err != nil {
			logf("imrConfigAnchors: trust-anchor-file %q (from %s) is not accessible (%v); ignoring", v, cfgPath, err)
		} else if d, k, err := cache.LoadTrustAnchorsFromFile(v, logf); err != nil {
			logf("imrConfigAnchors: trust-anchor-file %q (from %s) failed (%v); ignoring", v, cfgPath, err)
		} else {
			dss = append(dss, d...)
			keys = append(keys, k...)
			srcs = append(srcs, fmt.Sprintf("file %s", v))
		}
	}

	if len(dss) == 0 && len(keys) == 0 {
		return nil, nil, ""
	}
	return dss, keys, fmt.Sprintf("%s (via %s)", strings.Join(srcs, " + "), cfgPath)
}
