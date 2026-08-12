/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * delegation-sync-proxy: ONE task, not three schemes.
 *
 * Synchronising a delegation with the parent is a single job. NOTIFY, UPDATE
 * and API are three transports for it, each with a gate deciding whether it is
 * usable here and now. Treating them as three separate features -- which is how
 * they arrived, one PR at a time -- produced two concrete problems this file
 * exists to remove:
 *
 *   1. REPEATED DISCOVERY. Every entry point re-derived the parent's DSYNC
 *      RRset for itself. A single startup reconcile ran DsyncDiscovery three
 *      times (precondition check, then ProxyUpdateParent redoing the
 *      precondition AND re-looking-up the target); a steady-state sync that
 *      fell back ran it four. The DSYNC RRset does not change between those
 *      calls, and each one is a full IMR resolution.
 *
 *   2. A FALLBACK THAT NEVER FIRED. ProxyNotifyParent called BestSyncScheme
 *      itself, which returns the operator's PREFERRED scheme -- so when the
 *      UPDATE path fell back to it, it was handed "UPDATE" again, failed its
 *      own scheme != "NOTIFY" check, and reported "parent advertises no NOTIFY
 *      DSYNC target; nothing forwarded" while the parent was advertising one.
 *      That fired whenever update was preferred over notify, which is the
 *      documented default, so the fallback had never once forwarded anything.
 *      Deriving the scheme twice is what made it possible; the plan below is
 *      derived once and then only consumed.
 *
 * So: discover once, build the list of transports that are actually usable,
 * and walk it. A gate that fails is recorded with its reason rather than
 * silently dropping the scheme, because "nothing was forwarded" is not a
 * diagnosis and every one of these has a different fix.
 */
package tdns

import (
	"context"
	"fmt"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// SyncCandidate is one transport that is advertised by the parent, configured
// here, and past its gate -- i.e. one that can actually be attempted.
type SyncCandidate struct {
	Scheme string // "UPDATE", "API" or "NOTIFY"
	Target *DsyncTarget
}

// SkippedScheme is a transport that was NOT usable, and why.
//
// Kept rather than discarded because the reasons are operationally distinct
// and each has its own fix: the parent does not offer it, the operator has not
// configured it, the KEY is not published yet, no credential was provisioned,
// the zone is unsigned. Collapsing those into "nothing forwarded" is what
// makes a proxy that silently does nothing hard to debug.
type SkippedScheme struct {
	Scheme string
	Reason string
}

// ParentSyncPlan is the result of ONE DSYNC discovery: everything the caller
// needs to get a delegation change to the parent, or to explain why it cannot.
type ParentSyncPlan struct {
	Parent     string
	Validated  bool // the DSYNC RRset itself DNSSEC-validated
	Candidates []SyncCandidate
	Skipped    []SkippedScheme
}

// Usable reports whether any transport survived its gate.
func (p *ParentSyncPlan) Usable() bool { return p != nil && len(p.Candidates) > 0 }

// Summary is the one line worth logging: what will be tried, and what was not.
func (p *ParentSyncPlan) Summary() string {
	if p == nil {
		return "no plan"
	}
	var b strings.Builder
	if len(p.Candidates) == 0 {
		b.WriteString("no usable scheme")
	} else {
		names := make([]string, 0, len(p.Candidates))
		for _, c := range p.Candidates {
			names = append(names, c.Scheme)
		}
		b.WriteString("will try " + strings.Join(names, ", "))
	}
	for _, s := range p.Skipped {
		fmt.Fprintf(&b, "; %s skipped (%s)", s.Scheme, s.Reason)
	}
	return b.String()
}

// BuildParentSyncPlan performs the single DSYNC discovery and evaluates every
// configured scheme against it.
//
// It does not fail when nothing is usable. A delegation-sync-proxy zone whose
// parent offers nothing this host can use is operationally degraded, not
// broken: the zone is still served, and the resilient-config quarantine model
// says that is a per-zone warning rather than a hard error. Only a genuine
// discovery failure is returned as an error.
func (zd *ZoneData) BuildParentSyncPlan(ctx context.Context, kdb *KeyDB, imr *Imr) (*ParentSyncPlan, error) {
	plan := &ParentSyncPlan{}

	// No IMR means no discovery is possible at all. Not an error: it is how a
	// zone behaves before the resolver is up, and the caller reports it as the
	// degraded state it is.
	if imr == nil {
		plan.Skipped = append(plan.Skipped, SkippedScheme{
			Scheme: "all", Reason: "no IMR available to discover the parent's DSYNC records"})
		return plan, nil
	}

	if zd.Parent == "" || zd.Parent == "." {
		p, err := imr.ParentZone(zd.ZoneName)
		if err != nil {
			return nil, fmt.Errorf("BuildParentSyncPlan: ParentZone(%s): %w", zd.ZoneName, err)
		}
		zd.Parent = p
	}
	plan.Parent = zd.Parent

	// THE single discovery. Everything below reads this result.
	dsyncRes, err := imr.DsyncDiscovery(ctx, zd.ZoneName, Globals.Verbose)
	if err != nil {
		return nil, fmt.Errorf("BuildParentSyncPlan: DsyncDiscovery(%s): %w", zd.ZoneName, err)
	}
	plan.Validated = dsyncRes.Validated
	if plan.Parent == "" {
		plan.Parent = dsyncRes.Parent
	}
	if len(dsyncRes.Rdata) == 0 {
		plan.Skipped = append(plan.Skipped, SkippedScheme{
			Scheme: "all", Reason: fmt.Sprintf("parent %s publishes no DSYNC records", plan.Parent)})
		return plan, nil
	}

	schemes := viper.GetStringSlice("delegationsync.child.schemes")
	if len(schemes) == 0 {
		plan.Skipped = append(plan.Skipped, SkippedScheme{
			Scheme: "all", Reason: "no schemes configured in delegationsync.child.schemes"})
		return plan, nil
	}

	// Order is the OPERATOR's preference, preserved as configured. The one
	// correctness rule that overrides configuration is the unsigned-zone gate
	// on NOTIFY below -- and it removes the scheme rather than reordering it,
	// so preference never has to be second-guessed.
	for _, scheme := range schemes {
		switch strings.ToLower(strings.TrimSpace(scheme)) {
		case "update":
			zd.planConsiderUpdate(ctx, kdb, imr, dsyncRes, plan)
		case "api":
			zd.planConsiderApi(dsyncRes, plan)
		case "notify":
			zd.planConsiderNotify(ctx, imr, dsyncRes, plan)
		default:
			plan.Skipped = append(plan.Skipped, SkippedScheme{
				Scheme: scheme, Reason: "unknown scheme name in delegationsync.child.schemes"})
		}
	}
	return plan, nil
}

// findDsync returns the first advertised DSYNC RR for a scheme, or nil.
func findDsync(res DsyncResult, scheme core.DsyncScheme, wantNotifyType bool) *core.DSYNC {
	for _, drr := range res.Rdata {
		if drr.Scheme != scheme {
			continue
		}
		// NOTIFY is only actionable for the types the proxy can signal about;
		// this mirrors BestSyncScheme's long-standing filter.
		if wantNotifyType && drr.Type != dns.TypeCSYNC && drr.Type != dns.TypeANY {
			continue
		}
		return drr
	}
	return nil
}

func (zd *ZoneData) planConsiderUpdate(ctx context.Context, kdb *KeyDB, imr *Imr,
	res DsyncResult, plan *ParentSyncPlan) {

	drr := findDsync(res, core.SchemeUpdate, false)
	if drr == nil {
		plan.Skipped = append(plan.Skipped, SkippedScheme{"UPDATE", "parent does not advertise it"})
		return
	}
	// The KEY-bootstrap state machine (§10.8). The gate that used to live at
	// the top of it -- "does the parent advertise UPDATE?" -- is the findDsync
	// above, so this no longer re-discovers anything.
	state, err := zd.proxyUpdateKeyState(kdb)
	if err != nil {
		plan.Skipped = append(plan.Skipped, SkippedScheme{"UPDATE", fmt.Sprintf("key state: %v", err)})
		return
	}
	if state != ProxyUpdateReady {
		plan.Skipped = append(plan.Skipped, SkippedScheme{"UPDATE", string(state)})
		return
	}
	target, terr := resolveDsyncTarget(ctx, imr, drr)
	if terr != nil {
		plan.Skipped = append(plan.Skipped, SkippedScheme{"UPDATE", terr.Error()})
		return
	}
	plan.Candidates = append(plan.Candidates, SyncCandidate{Scheme: "UPDATE", Target: target})
}

func (zd *ZoneData) planConsiderApi(res DsyncResult, plan *ParentSyncPlan) {
	drr := findDsync(res, core.SchemeAPI, false)
	if drr == nil {
		plan.Skipped = append(plan.Skipped, SkippedScheme{"API", "parent does not advertise it"})
		return
	}
	// The credential arrives out of band by definition (§10), so its absence
	// is settled here rather than after a round trip: there is nothing to wait
	// for and nothing to retry.
	cred, ok := DelegationSyncConfig().Child.Api.CredentialForChild(zd.Parent, zd.ZoneName)
	if !ok || cred.Username == "" || cred.Key == "" {
		plan.Skipped = append(plan.Skipped, SkippedScheme{"API",
			fmt.Sprintf("no usable credential for parent %s (delegationsync.child.api.credentials)", zd.Parent)})
		return
	}
	// No address resolution for API (§16.7): the DSYNC target is a service
	// description point, and the URI published there names the host that
	// actually resolves. Requiring A/AAAA here would fail on a CORRECTLY
	// configured parent.
	plan.Candidates = append(plan.Candidates, SyncCandidate{
		Scheme: "API",
		Target: &DsyncTarget{Name: drr.Target, Port: drr.Port, RR: drr, Scheme: drr.Scheme},
	})
}

func (zd *ZoneData) planConsiderNotify(ctx context.Context, imr *Imr, res DsyncResult, plan *ParentSyncPlan) {
	drr := findDsync(res, core.SchemeNotify, true)
	if drr == nil {
		plan.Skipped = append(plan.Skipped, SkippedScheme{"NOTIFY", "parent does not advertise it"})
		return
	}
	// THE gate that makes NOTIFY different from the other two. NOTIFY carries
	// no data -- it says "come re-scan me" -- and what the parent then reads is
	// CDS/CSYNC, which it can only act on if it validates. For an unsigned zone
	// there is nothing for the parent to validate, so a NOTIFY is a no-op that
	// nonetheless looks like a success.
	//
	// That matters here specifically because this is a LADDER: a vacuous
	// success stops it, and an unsigned zone would sit behind a NOTIFY that
	// achieved nothing while UPDATE -- which works fine unsigned -- was never
	// tried. So it is removed from the list, not merely ranked below the
	// others.
	if !zoneLooksSigned(zd) {
		plan.Skipped = append(plan.Skipped, SkippedScheme{"NOTIFY",
			"zone is unsigned; a NOTIFY would leave the parent nothing it can validate"})
		return
	}
	target, terr := resolveDsyncTarget(ctx, imr, drr)
	if terr != nil {
		plan.Skipped = append(plan.Skipped, SkippedScheme{"NOTIFY", terr.Error()})
		return
	}
	plan.Candidates = append(plan.Candidates, SyncCandidate{Scheme: "NOTIFY", Target: target})
}

// Address resolution for the DNS-carrying schemes reuses resolveDsyncTarget
// (ksk_rollover_schemes.go), which was factored out of LookupDSYNCTarget for
// exactly this reason: to let a caller that already holds the DSYNC RR resolve
// its target without a second discovery query. It goes through the IMR rather
// than net.LookupHost -- the stdlib resolver consults /etc/resolv.conf, which
// in a DNS training lab is not the view of the namespace the rest of this code
// is working in. (BestSyncScheme still uses net.LookupHost on the tdns-auth
// child path; a separate inconsistency, untouched here.)

// SyncWithParent walks the plan, trying each usable transport until one gets
// the change to the parent.
//
// Every candidate has already passed its gate, so a failure here is a runtime
// one -- the parent refused, the network broke, discovery of the API endpoint
// did not validate. The walk continues past it, because the intersection of
// "what the parent offers" and "what this host is configured for" is usually
// one or two entries and there is nothing to be gained by giving up on the
// first. The accumulated reasons are returned together if none worked; a
// caller that sees only the last one cannot tell which transport was even
// expected to work.
func (zd *ZoneData) SyncWithParent(ctx context.Context, kdb *KeyDB, notifyq chan NotifyRequest,
	imr *Imr, plan *ParentSyncPlan, analysis *ProxyDelegationAnalysis) (string, error) {

	if !plan.Usable() {
		lgDns.Info("delegation-sync-proxy: nothing forwarded", "zone", zd.ZoneName,
			"parent", plan.Parent, "plan", plan.Summary())
		return "no usable sync scheme; nothing forwarded (" + plan.Summary() + ")", nil
	}

	var failures []string
	for _, cand := range plan.Candidates {
		var msg string
		var err error

		switch cand.Scheme {
		case "UPDATE":
			msg, err = zd.ProxyUpdateParent(ctx, kdb, imr, cand.Target)
		case "API":
			msg, err = zd.ProxyApiParent(ctx, imr, cand.Target, analysis)
		case "NOTIFY":
			msg, err = zd.ProxyNotifyParent(ctx, notifyq, analysis, cand.Target)
		default:
			err = fmt.Errorf("unknown scheme %q in plan", cand.Scheme)
		}

		if err == nil {
			if len(failures) > 0 {
				return fmt.Sprintf("%s (after %s)", msg, strings.Join(failures, "; ")), nil
			}
			return msg, nil
		}
		lgDns.Warn("delegation-sync-proxy: scheme failed, trying the next one",
			"zone", zd.ZoneName, "scheme", cand.Scheme, "err", err)
		failures = append(failures, fmt.Sprintf("%s failed: %v", cand.Scheme, err))
	}

	return "", fmt.Errorf("zone %s: every available sync scheme failed: %s [%s]",
		zd.ZoneName, strings.Join(failures, "; "), plan.Summary())
}

// proxyAnalysisFromSyncStatus synthesises the change analysis that the NOTIFY
// path needs, from a parent-vs-child comparison rather than from a transfer
// diff.
//
// The steady-state path gets its analysis from PreRefresh, which sees the zone
// before and after a transfer. The startup reconcile has no such diff -- it has
// AnalyseZoneDelegation, which compares this zone against what the PARENT
// currently holds. That answers the same question the act-mapping (D4) needs:
// a DS or DNSKEY disagreement is what NOTIFY(CDS) is for, and an NS or glue
// disagreement is what NOTIFY(CSYNC) is for.
func proxyAnalysisFromSyncStatus(dss DelegationSyncStatus) *ProxyDelegationAnalysis {
	return &ProxyDelegationAnalysis{
		DelegationStatus: dss,
		NsOrGlueChanged: len(dss.NsAdds) > 0 || len(dss.NsRemoves) > 0 ||
			len(dss.AAdds) > 0 || len(dss.ARemoves) > 0 ||
			len(dss.AAAAAdds) > 0 || len(dss.AAAARemoves) > 0,
		DnskeyChanged: len(dss.DSAdds) > 0 || len(dss.DSRemoves) > 0 ||
			len(dss.DNSKEYAdds) > 0 || len(dss.DNSKEYRemoves) > 0,
	}
}
