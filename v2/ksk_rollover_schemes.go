package tdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// errNoUsableScheme is the sentinel returned by pickRolloverSchemes
// when the parent advertises no DSYNC scheme this rollover policy can
// use. The dispatcher checks for this with errors.Is and translates
// it into child-config:waiting-for-parent (1h-capped softfail, never
// hardfails). Other errors from pickRolloverSchemes — DSYNC
// discovery transport failure, nil argument, etc. — are NOT
// "waiting for parent" and stay in their own categories.
var errNoUsableScheme = errors.New("parent advertises no rollover-usable DSYNC scheme")

// schemeChoice is one (scheme, target) pair the rollover engine
// intends to dispatch a push to. pickRolloverSchemes returns a slice
// of these — one element under any single-scheme policy outcome, two
// elements under "auto" when the parent advertises both UPDATE and
// NOTIFY.
type schemeChoice struct {
	Scheme core.DsyncScheme
	Target *DsyncTarget
}

// pickRolloverSchemes consults the parent's DSYNC RRset and the policy's
// dsync-scheme-preference and returns the list of scheme/target pairs
// the rollover engine should attempt for this push. The returned slice
// is non-empty on success and may contain one or two entries: one for
// any single-scheme outcome, two when "auto" is chosen against a
// parent advertising both UPDATE and NOTIFY (parallel dispatch).
//
// On "no usable scheme" — parent advertises nothing the policy will
// accept — pickRolloverSchemes returns a non-nil error. The dispatcher
// translates that error into a child-config:waiting-for-parent softfail
// that never hardfails (Phase 6); recovery happens automatically when
// the parent starts advertising a scheme matching the policy.
//
// Filter rule for NOTIFY: matches DSYNC RRs with RRtype == TypeCDS or
// RRtype == TypeANY. The rollover engine pushes DS by publishing CDS;
// CSYNC-only NOTIFY advertisements do not satisfy the rollover's
// requirements. (The delegation-sync plan uses a different filter — CSYNC or
// ANY — because it serves the general delegation-sync path, which is
// CSYNC-driven. Don't unify.)
//
// Filter rule for UPDATE: any UPDATE-scheme DSYNC RR (UPDATE
// advertisements are RRtype-agnostic by spec).
//
// Filter rule for API: same as UPDATE, RRtype-agnostic. The endpoint
// manages DS directly (dsyncApiManagedTypes), so what the DSYNC RR
// nominally covers does not constrain what can be pushed over it. API
// is only ever chosen as a last resort — see decideRolloverSchemes.
//
// The boolean returns (updateAdvertised, notifyAdvertised) reflect
// what the parent's DSYNC RRset itself contains, independent of the
// policy's scheme preference. Dispatcher persists these so status
// output can distinguish "parent doesn't advertise this scheme" from
// "engine hasn't pushed via this scheme yet".
//
// API advertisement is deliberately NOT returned or persisted here:
// that would mean a third tri-state column in RolloverZoneState and a
// schema change, for an observability nicety. The gap is that status
// output cannot yet say "the parent advertises API" — worth adding
// with the next schema change, not on its own.

// selectRolloverDsyncRRs picks the first usable DSYNC RR per scheme from a
// discovery result.
//
// Split out of pickRolloverSchemes so the gates below can be tested without a
// live IMR: the surrounding function's first act is a network discovery, which
// would otherwise make the API DNSSEC gate untestable.
func selectRolloverDsyncRRs(dsync DsyncResult, zoneName string) (updateRR, notifyRR, apiRR *core.DSYNC) {
	for _, rr := range dsync.Rdata {
		if rr == nil {
			continue
		}
		switch rr.Scheme {
		case core.SchemeUpdate:
			if updateRR == nil {
				updateRR = rr
			}
		case core.SchemeNotify:
			if rr.Type != dns.TypeCDS && rr.Type != dns.TypeANY {
				continue
			}
			if notifyRR == nil {
				notifyRR = rr
			}
		case core.SchemeAPI:
			// RRtype-agnostic like UPDATE: the endpoint manages DS
			// directly (dsyncApiManagedTypes), so what the DSYNC RR
			// nominally covers does not constrain what can be pushed.
			//
			// But it is gated on the DSYNC lookup having DNSSEC-validated,
			// which UPDATE and NOTIFY are not. This RR names the target
			// whose URI carries the endpoint the push then sends a bearer
			// credential to, so an unvalidated lookup lets whoever can
			// answer the query choose where that credential goes.
			// Discovering URI/TXT at the (possibly attacker-chosen) target
			// does not close it: a spoofed DSYNC names a zone whose own
			// records validate perfectly well.
			//
			// Same gate, same switch, as the delegation-sync planner.
			if !dsync.Validated && !DelegationSyncConfig().Child.Api.AllowInsecure {
				lgRollover.Warn("pickRolloverSchemes: ignoring the API scheme:"+
					" the DSYNC lookup did not DNSSEC-validate and"+
					" delegationsync.child.api.allow-insecure is not set",
					"zone", zoneName)
				continue
			}
			if apiRR == nil {
				apiRR = rr
			}
		}
	}
	return updateRR, notifyRR, apiRR
}

func pickRolloverSchemes(ctx context.Context, zd *ZoneData, imr *Imr, pol *DnssecPolicy) ([]schemeChoice, bool, bool, error) {
	if zd == nil || imr == nil || pol == nil {
		return nil, false, false, fmt.Errorf("pickRolloverSchemes: nil argument")
	}

	dsync, err := imr.DsyncDiscovery(ctx, zd.ZoneName, Globals.Verbose)
	if err != nil {
		return nil, false, false, fmt.Errorf("DsyncDiscovery: %w", err)
	}

	updateRR, notifyRR, apiRR := selectRolloverDsyncRRs(dsync, zd.ZoneName)
	updateAdvertised := updateRR != nil
	notifyAdvertised := notifyRR != nil
	apiAdvertised := apiRR != nil

	want, derr := decideRolloverSchemes(updateAdvertised, notifyAdvertised, apiAdvertised,
		pol.Rollover.DsyncSchemePreference)
	if derr != nil {
		return nil, updateAdvertised, notifyAdvertised, fmt.Errorf("zone %s: %w", zd.ZoneName, derr)
	}

	out := make([]schemeChoice, 0, len(want))
	for _, scheme := range want {
		var rr *core.DSYNC
		switch scheme {
		case core.SchemeUpdate:
			rr = updateRR
		case core.SchemeNotify:
			rr = notifyRR
		case core.SchemeAPI:
			rr = apiRR
		}
		if rr == nil {
			// Should not happen — categorization above guarantees the
			// chosen scheme has an advertised RR. Defensive only.
			continue
		}
		if scheme == core.SchemeAPI {
			// No address resolution for API. Its DSYNC target is a
			// service description point: the URI published there names
			// the host that actually resolves, and address records at
			// the target itself are optional. Requiring A/AAAA would
			// fail on a CORRECTLY configured parent.
			out = append(out, schemeChoice{Scheme: scheme, Target: &DsyncTarget{
				Name: rr.Target, Scheme: rr.Scheme, Port: rr.Port, RR: rr,
			}})
			continue
		}
		target, terr := resolveDsyncTarget(ctx, imr, rr)
		if terr != nil {
			// Per-scheme address-resolution failure: skip this
			// scheme and let the survivors carry the rollover. With
			// "auto" against a both-advertising parent, this means
			// one broken DSYNC target doesn't block the other from
			// firing. Logged at WARN so an operator can see it; if
			// every scheme fails resolution the len(out) == 0 check
			// below returns the aggregated "no usable scheme" error.
			lgSigner.Warn("rollover: DSYNC target resolution failed, skipping scheme",
				"zone", zd.ZoneName, "scheme", schemeName(scheme), "err", terr)
			continue
		}
		out = append(out, schemeChoice{Scheme: scheme, Target: target})
	}
	if len(out) == 0 {
		// Every advertised scheme's target failed address resolution.
		// Treated as waiting-for-parent: parent's DSYNC target
		// hostnames don't resolve (DNS misconfig at the parent), and
		// the recovery model is the same — wait for the parent to fix
		// it. Wrap the sentinel so the dispatcher takes that path.
		return nil, updateAdvertised, notifyAdvertised, fmt.Errorf("pickRolloverSchemes: no DSYNC targets resolvable for zone %s: %w", zd.ZoneName, errNoUsableScheme)
	}
	return out, updateAdvertised, notifyAdvertised, nil
}

// decideRolloverSchemes is the pure decision function: given which
// schemes the parent advertises (categorized by pickRolloverSchemes
// from the DSYNC RRset) and the policy's preference, returns the
// list of schemes the engine should attempt this push.
//
// API IS THE LAST RESORT, never a co-equal choice. It is reached only
// when neither UPDATE nor NOTIFY is available, so every deployment
// where one of those is advertised behaves exactly as before. Two
// reasons, and they agree:
//
//   - the design says so. "Preference order is the operator's and
//     defaults to putting api last: it is the fallback, not the
//     choice" (dsync-api-scheme §11), because the credential is a
//     bearer token and the scheme inherits a hard dependency on the
//     parent zone being signed that UPDATE does not have (§8).
//   - it costs something the others do not. Under "auto" against a
//     both-advertising parent the engine dispatches UPDATE and NOTIFY
//     in PARALLEL; adding API to that would put a credential on the
//     wire on every push for no gain when a DNS transport already
//     works.
//
// What this closes: before, a parent advertising ONLY the API scheme
// left both booleans false, which is errNoUsableScheme, which is
// child-config:waiting-for-parent -- a softfail that never hardfails.
// The rollover waited forever on a parent that could have accepted
// the DS immediately (dsyncApiManagedTypes includes DS).
//
// force-update / force-notify do NOT fall back to API. Force is force.
//
// Pulled out of pickRolloverSchemes so it can be exhaustively
// table-tested without standing up an Imr or a parent zone.
//
// Errors:
//   - "no usable scheme advertised" cases (auto/prefer-* with neither
//     advertised; force-X with X not advertised) wrap errNoUsableScheme.
//     The dispatcher translates these to child-config:waiting-for-parent
//     (1h cap, never hardfails). Force-X-not-advertised is included per
//     design doc Risks #5: "force is force; recover automatically when
//     parent starts advertising the forced scheme."
//   - "invalid preference value" is a config error (operator typo),
//     not a parent issue; returned with no sentinel and dispatched as
//     child-config:local-error.
func decideRolloverSchemes(updateAdvertised, notifyAdvertised, apiAdvertised bool, preference string) ([]core.DsyncScheme, error) {
	pref := preference
	if pref == "" {
		pref = defaultDsyncSchemePreference
	}
	switch pref {
	case DsyncSchemePreferenceAuto:
		switch {
		case updateAdvertised && notifyAdvertised:
			return []core.DsyncScheme{core.SchemeUpdate, core.SchemeNotify}, nil
		case updateAdvertised:
			return []core.DsyncScheme{core.SchemeUpdate}, nil
		case notifyAdvertised:
			return []core.DsyncScheme{core.SchemeNotify}, nil
		case apiAdvertised:
			return []core.DsyncScheme{core.SchemeAPI}, nil
		default:
			return nil, errNoUsableScheme
		}
	case DsyncSchemePreferencePreferUpdate:
		switch {
		case updateAdvertised:
			return []core.DsyncScheme{core.SchemeUpdate}, nil
		case notifyAdvertised:
			return []core.DsyncScheme{core.SchemeNotify}, nil
		case apiAdvertised:
			return []core.DsyncScheme{core.SchemeAPI}, nil
		default:
			return nil, errNoUsableScheme
		}
	case DsyncSchemePreferencePreferNotify:
		switch {
		case notifyAdvertised:
			return []core.DsyncScheme{core.SchemeNotify}, nil
		case updateAdvertised:
			return []core.DsyncScheme{core.SchemeUpdate}, nil
		case apiAdvertised:
			return []core.DsyncScheme{core.SchemeAPI}, nil
		default:
			return nil, errNoUsableScheme
		}
	case DsyncSchemePreferenceForceUpdate:
		if !updateAdvertised {
			return nil, fmt.Errorf("policy pins force-update but parent does not advertise UPDATE: %w", errNoUsableScheme)
		}
		return []core.DsyncScheme{core.SchemeUpdate}, nil
	case DsyncSchemePreferenceForceNotify:
		if !notifyAdvertised {
			return nil, fmt.Errorf("policy pins force-notify but parent does not advertise NOTIFY for CDS/ANY: %w", errNoUsableScheme)
		}
		return []core.DsyncScheme{core.SchemeNotify}, nil
	default:
		// Invalid preference is a config error, NOT a parent issue.
		// No sentinel wrap → dispatcher categorizes as
		// child-config:local-error (operator must fix the YAML).
		return nil, fmt.Errorf("invalid dsync-scheme-preference %q", preference)
	}
}

// resolveDsyncTarget resolves a DSYNC RR's Target FQDN to A/AAAA
// addresses via the IMR. Same shape as the address-resolution loop in
// LookupDSYNCTarget, factored out so pickRolloverSchemes can avoid a
// second DSYNC discovery query for each scheme.
func resolveDsyncTarget(ctx context.Context, imr *Imr, rr *core.DSYNC) (*DsyncTarget, error) {
	target := dns.Fqdn(rr.Target)
	var addrs []string
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		resp, qerr := imr.ImrQuery(ctx, target, qtype, dns.ClassINET, nil)
		if qerr != nil {
			continue
		}
		if resp.Error || resp.RRset == nil {
			continue
		}
		for _, r := range resp.RRset.RRs {
			switch v := r.(type) {
			case *dns.A:
				addrs = append(addrs, v.A.String())
			case *dns.AAAA:
				addrs = append(addrs, v.AAAA.String())
			}
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no A or AAAA for %s via IMR", target)
	}
	dt := &DsyncTarget{
		Name:   target,
		Scheme: rr.Scheme,
		Port:   rr.Port,
		RR:     rr,
	}
	for _, a := range addrs {
		dt.Addresses = append(dt.Addresses, net.JoinHostPort(a, strconv.Itoa(int(rr.Port))))
	}
	return dt, nil
}

// schemeName renders a DsyncScheme as the diagnostic string used in
// LastAttemptScheme + status output ("UPDATE" / "NOTIFY"). Other
// scheme values fall back to a numeric form; the rollover engine only
// emits UPDATE/NOTIFY in normal operation.
func schemeName(s core.DsyncScheme) string {
	switch s {
	case core.SchemeUpdate:
		return "UPDATE"
	case core.SchemeNotify:
		return "NOTIFY"
	case core.SchemeAPI:
		return "API"
	default:
		return fmt.Sprintf("scheme%d", s)
	}
}
