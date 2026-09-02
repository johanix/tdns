package tdns

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

var childBootstrapPreference = []string{"at-apex", "at-ns", "unsigned", "manual"}

// childBootstrapMethods is the child's willing list, filtered to what this
// zone can actually satisfy. at-ns needs the child's KEY published at
// _sig0key.<child>._signal.<ns> (draft §"When Child Nameserver Is In A
// DNSSEC-signed Zone"), which is possible only when canSignal: this server is
// primary for a zone one of the child's NS signal names falls in. A proxy
// never can -- _signal lives in the nameserver's zone, which a secondary
// proxying for a clueless primary does not control -- so proxy implies
// !canSignal on every path, BADKEY recovery included.
func childBootstrapMethods(proxy, canSignal bool) []string {
	methods := configuredChildBootstrapMethods()
	if !proxy && canSignal {
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

// configuredChildBootstrapMethods is the operator's list, or the omit-default
// (compileChildBootstrapMethods) when no delegationsync block has been
// installed at all.
func configuredChildBootstrapMethods() []string {
	if methods := DelegationSyncConfig().CompiledChildMethods; methods != nil {
		return methods
	}
	return []string{"at-apex", "at-ns"}
}

func (zd *ZoneData) zoneChildBootstrapMethods() []string {
	proxy := zd != nil && zd.Options[OptDelSyncProxy]
	canSignal := !proxy && zd != nil && zd.canPublishSig0KeyAtSignal()
	methods := childBootstrapMethods(proxy, canSignal)
	if zd != nil && !proxy && !canSignal {
		for _, m := range configuredChildBootstrapMethods() {
			if m == "at-ns" {
				lgHandler.Info("at-ns dropped from the SIG(0) bootstrap willing list: no NS of the zone has its _sig0key._signal name in a zone this server is primary for",
					"zone", zd.ZoneName, "willing", methods)
				break
			}
		}
	}
	return methods
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
// the child may act on: none is published, or the advertisement is
// unauthenticated -- the DSYNC lookup that named the target or the SVCB
// lookup itself did not DNSSEC-validate -- and allow-insecure is off. An
// unauthenticated advertisement is ignored, not honoured, so a forged
// SVCB can neither talk the child out of bootstrapping (an empty or
// manual-only set refuses) nor into a method it did not choose; the caller
// then falls back to the child's own configured list, exactly as for a parent
// that publishes no advertisement.
//
// The third result separates "the parent publishes no advertisement" from
// "the lookup failed": the former falls back to the child's list, the latter
// is errBootstrapAdvertisementLookup, which the bootstrap callers treat as
// retryable rather than proceeding as if the parent had said nothing. A
// transient resolver failure must not turn a manual-only parent's refusal
// into an automatic KEY UPDATE attempt.
func advertisedBootstrapMethods(ctx context.Context, imr *Imr, target *DsyncTarget, allowInsecure bool) ([]string, bool, error) {
	if imr == nil || target == nil || target.Name == "" {
		return nil, false, nil
	}
	resp, err := imr.ImrQuery(ctx, dns.Fqdn(target.Name), dns.TypeSVCB, dns.ClassINET, nil)
	rrs, lerr := classifyAdvertisementLookup(target.Name, resp, err)
	if lerr != nil {
		return nil, false, lerr
	}
	data, count := publishedBootstrapSVCBData(rrs)
	if count == 0 {
		return nil, false, nil
	}
	if !bootstrapAdvertisementUsable(target.Validated, resp.Validated, allowInsecure) {
		lgHandler.Warn("ignoring unauthenticated SVCB bootstrap advertisement; falling back to the configured bootstrap methods (set "+allowInsecureKnob+" to act on it)",
			"target", target.Name, "advertised", data, "dsyncValidated", target.Validated, "svcbValidated", resp.Validated)
		return nil, false, nil
	}
	return splitBootstrapMethods(data), true, nil
}

// errBootstrapAdvertisementLookup marks a failed (not merely empty) SVCB
// bootstrap advertisement lookup. Callers with a retry loop retry on it.
var errBootstrapAdvertisementLookup = errors.New("SVCB bootstrap advertisement lookup failed")

// classifyAdvertisementLookup sorts an IMR answer into "here is what is
// published" (rrs, possibly empty: the IMR reports NXDOMAIN and NODATA as a
// non-error response with no RRset) and "the lookup failed" (a transport or
// resolver error, or resp.Error, which the IMR sets only for those).
func classifyAdvertisementLookup(target string, resp *ImrResponse, err error) ([]dns.RR, error) {
	switch {
	case err != nil:
		return nil, fmt.Errorf("%w for %s: %v", errBootstrapAdvertisementLookup, target, err)
	case resp == nil:
		return nil, fmt.Errorf("%w for %s: no response", errBootstrapAdvertisementLookup, target)
	case resp.Error:
		return nil, fmt.Errorf("%w for %s: %s", errBootstrapAdvertisementLookup, target, resp.ErrorMsg)
	case resp.RRset == nil:
		return nil, nil
	}
	return resp.RRset.RRs, nil
}

// bootstrapAdvertisementUsable is the authentication gate on the SVCB bootstrap
// advertisement: both the DSYNC that named the target and the SVCB itself must
// have DNSSEC-validated, unless the operator has opted into insecure input.
func bootstrapAdvertisementUsable(dsyncValidated, svcbValidated, allowInsecure bool) bool {
	return allowInsecure || (dsyncValidated && svcbValidated)
}
