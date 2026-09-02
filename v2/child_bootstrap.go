package tdns

import (
	"context"
	"fmt"
	"strings"

	"github.com/johanix/tdns/v2/cache"
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

// advertisedBootstrapMethods returns the parent's SVCB bootstrap advertisement
// at the DSYNC UPDATE target. present=false means there is no advertisement
// the child may act on: none is published, the lookup failed, or the
// advertisement is unauthenticated -- the DSYNC lookup that named the target
// or the SVCB lookup itself did not DNSSEC-validate -- and allow-insecure is
// off. An unauthenticated advertisement is ignored, not honoured, so a forged
// SVCB can neither talk the child out of bootstrapping (an empty or
// manual-only set refuses) nor into a method it did not choose; the caller
// then falls back to the child's own configured list, exactly as for a parent
// that publishes no advertisement.
func advertisedBootstrapMethods(ctx context.Context, imr *Imr, target *DsyncTarget, allowInsecure bool) ([]string, bool) {
	if imr == nil || target == nil || target.Name == "" {
		return nil, false
	}
	resp, err := imr.ImrQuery(ctx, dns.Fqdn(target.Name), dns.TypeSVCB, dns.ClassINET, nil)
	if err != nil || (resp != nil && resp.Error) {
		// Treated as "no advertisement" for now; logged so a resolver
		// failure is not mistaken for a parent that publishes none.
		msg := ""
		if resp != nil {
			msg = resp.ErrorMsg
		}
		lgHandler.Warn("SVCB bootstrap advertisement lookup failed; proceeding as if none were published",
			"target", target.Name, "err", err, "imr", msg)
		return nil, false
	}
	if resp == nil || resp.RRset == nil {
		return nil, false
	}
	data, count := publishedBootstrapSVCBData(resp.RRset.RRs)
	if count == 0 {
		return nil, false
	}
	// A bogus verdict, on the SVCB or on the DSYNC that named the target, is
	// a failed chain of trust: ignored whatever allow-insecure says.
	if target.Bogus || resp.ValidationState == cache.ValidationStateBogus {
		lgHandler.Warn("ignoring SVCB bootstrap advertisement: DNSSEC validation FAILED (bogus), which no setting waives; falling back to the configured bootstrap methods",
			"target", target.Name, "advertised", data, "dsyncBogus", target.Bogus, "svcbBogus", resp.ValidationState == cache.ValidationStateBogus)
		return nil, false
	}
	if !bootstrapAdvertisementUsable(target.Validated, resp.Validated, allowInsecure) {
		lgHandler.Warn("ignoring unauthenticated SVCB bootstrap advertisement; falling back to the configured bootstrap methods (set "+allowInsecureKnob+" to act on it)",
			"target", target.Name, "advertised", data, "dsyncValidated", target.Validated, "svcbValidated", resp.Validated)
		return nil, false
	}
	return splitBootstrapMethods(data), true
}

// bootstrapAdvertisementUsable is the authentication gate on the SVCB bootstrap
// advertisement: both the DSYNC that named the target and the SVCB itself must
// have DNSSEC-validated, unless the operator has opted into insecure input.
func bootstrapAdvertisementUsable(dsyncValidated, svcbValidated, allowInsecure bool) bool {
	return allowInsecure || (dsyncValidated && svcbValidated)
}
