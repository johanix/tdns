package tdns

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

var childBootstrapPreference = []string{"at-apex", "at-ns", "unsigned", "manual"}

func childBootstrapMethods(proxy bool) []string {
	methods := DelegationSyncConfig().CompiledChildMethods
	if methods == nil {
		methods = []string{"at-apex"}
	}
	if !proxy {
		return methods
	}
	out := make([]string, 0, len(methods))
	for _, m := range methods {
		if m != "at-ns" {
			out = append(out, m)
		}
	}
	return out
}

func (zd *ZoneData) zoneChildBootstrapMethods() []string {
	return childBootstrapMethods(zd != nil && zd.Options[OptDelSyncProxy])
}

func intersectBootstrapMethods(advertised, willing []string) []string {
	want := make(map[string]bool, len(willing))
	for _, m := range willing {
		want[m] = true
	}
	var out []string
	seen := make(map[string]bool, len(advertised))
	for _, m := range advertised {
		if want[m] && !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

func strongestBootstrapMethod(methods []string) string {
	have := make(map[string]bool, len(methods))
	for _, m := range methods {
		have[m] = true
	}
	for _, m := range childBootstrapPreference {
		if have[m] {
			return m
		}
	}
	return ""
}

func splitBootstrapMethods(data string) []string {
	if data == "" {
		return []string{}
	}
	var out []string
	for _, p := range strings.Split(data, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// selectChildBootstrapMethod picks the strongest method the child can satisfy.
// When advertisedPresent is false (no SVCB), it falls back to the child's
// configured methods.
func selectChildBootstrapMethod(advertised []string, advertisedPresent bool, willing []string) (string, error) {
	pool := willing
	if advertisedPresent {
		pool = intersectBootstrapMethods(advertised, willing)
	}
	m := strongestBootstrapMethod(pool)
	if m == "" {
		if advertisedPresent {
			return "", fmt.Errorf("no overlapping SIG(0) bootstrap method (parent advertises %v, child allows %v)",
				advertised, willing)
		}
		return "", fmt.Errorf("no SIG(0) bootstrap method configured (child allows %v)", willing)
	}
	return m, nil
}

func advertisedBootstrapMethods(ctx context.Context, imr *Imr, target string) ([]string, bool) {
	if imr == nil || target == "" {
		return nil, false
	}
	resp, err := imr.ImrQuery(ctx, dns.Fqdn(target), dns.TypeSVCB, dns.ClassINET, nil)
	if err != nil || resp == nil || resp.Error || resp.RRset == nil {
		return nil, false
	}
	data, count := publishedBootstrapSVCBData(resp.RRset.RRs)
	if count == 0 {
		return nil, false
	}
	return splitBootstrapMethods(data), true
}
