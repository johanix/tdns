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
// requirements. (BestSyncScheme uses a different filter — CSYNC or
// ANY — because it serves the general delegation-sync path, which is
// CSYNC-driven. Don't unify.)
//
// Filter rule for UPDATE: any UPDATE-scheme DSYNC RR (UPDATE
// advertisements are RRtype-agnostic by spec).
func pickRolloverSchemes(ctx context.Context, zd *ZoneData, imr *Imr, pol *DnssecPolicy) ([]schemeChoice, error) {
	if zd == nil || imr == nil || pol == nil {
		return nil, fmt.Errorf("pickRolloverSchemes: nil argument")
	}

	dsync, err := imr.DsyncDiscovery(ctx, zd.ZoneName, Globals.Verbose)
	if err != nil {
		return nil, fmt.Errorf("DsyncDiscovery: %w", err)
	}

	var updateRR, notifyRR *core.DSYNC
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
		}
	}

	want, derr := decideRolloverSchemes(updateRR != nil, notifyRR != nil, pol.Rollover.DsyncSchemePreference)
	if derr != nil {
		return nil, fmt.Errorf("zone %s: %w", zd.ZoneName, derr)
	}

	out := make([]schemeChoice, 0, len(want))
	for _, scheme := range want {
		var rr *core.DSYNC
		switch scheme {
		case core.SchemeUpdate:
			rr = updateRR
		case core.SchemeNotify:
			rr = notifyRR
		}
		if rr == nil {
			// Should not happen — categorization above guarantees the
			// chosen scheme has an advertised RR. Defensive only.
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
		return nil, fmt.Errorf("pickRolloverSchemes: no DSYNC targets resolvable for zone %s: %w", zd.ZoneName, errNoUsableScheme)
	}
	return out, nil
}

// decideRolloverSchemes is the pure decision function: given which
// schemes the parent advertises (categorized by pickRolloverSchemes
// from the DSYNC RRset) and the policy's preference, returns the
// list of schemes the engine should attempt this push.
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
func decideRolloverSchemes(updateAdvertised, notifyAdvertised bool, preference string) ([]core.DsyncScheme, error) {
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
		default:
			return nil, errNoUsableScheme
		}
	case DsyncSchemePreferencePreferUpdate:
		switch {
		case updateAdvertised:
			return []core.DsyncScheme{core.SchemeUpdate}, nil
		case notifyAdvertised:
			return []core.DsyncScheme{core.SchemeNotify}, nil
		default:
			return nil, errNoUsableScheme
		}
	case DsyncSchemePreferencePreferNotify:
		switch {
		case notifyAdvertised:
			return []core.DsyncScheme{core.SchemeNotify}, nil
		case updateAdvertised:
			return []core.DsyncScheme{core.SchemeUpdate}, nil
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
	default:
		return fmt.Sprintf("scheme%d", s)
	}
}
