/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"os"

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

	// 2. Discover via the IMR config file.
	if taPath := trustAnchorFromImrConfig(DefaultImrCfgFile, logf); taPath != "" {
		d, k, err := cache.LoadTrustAnchorsFromFile(taPath, logf)
		if err == nil && (len(d) > 0 || len(k) > 0) {
			return d, k, fmt.Sprintf("file %s (via %s)", taPath, DefaultImrCfgFile)
		}
		if err != nil {
			logf("LoadDefaultTrustAnchors: trust-anchor-file %s (from IMR config) failed (%v); falling through", taPath, err)
		}
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

// trustAnchorFromImrConfig reads the IMR config file at cfgPath and
// returns the imrengine.trust-anchor-file value if (a) the file
// exists, (b) it parses as YAML, (c) the value is set, and (d) that
// referenced file also exists. Returns "" in any failure case;
// callers should treat empty as "fall through".
func trustAnchorFromImrConfig(cfgPath string, logf func(format string, args ...any)) string {
	if cfgPath == "" {
		return ""
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		// Most common: config file simply isn't here (dog run on a
		// machine that doesn't host an IMR). Not worth logging.
		return ""
	}
	// Minimal YAML shape: only the imrengine.trust-anchor-file field
	// matters here. Using a narrow struct avoids dragging the full
	// Config schema into this code path.
	var sub struct {
		Imrengine struct {
			TrustAnchorFile string `yaml:"trust-anchor-file"`
		} `yaml:"imrengine"`
	}
	if err := yaml.Unmarshal(data, &sub); err != nil {
		logf("trustAnchorFromImrConfig: %s parse failed (%v); ignoring", cfgPath, err)
		return ""
	}
	ta := sub.Imrengine.TrustAnchorFile
	if ta == "" {
		return ""
	}
	if _, err := os.Stat(ta); err != nil {
		logf("trustAnchorFromImrConfig: imrengine.trust-anchor-file %q (from %s) is not accessible (%v); ignoring", ta, cfgPath, err)
		return ""
	}
	return ta
}
