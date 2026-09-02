/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Delegation synchronisation with the parent: ONE task, not three schemes.
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
 *
 * BOTH ROLES USE THIS. A tdns-auth zone syncing its own delegation and a
 * tdns-agent proxying for a DSYNC-unaware primary are the same task; they
 * differ in exactly two places, and both are parameterised rather than
 * duplicated:
 *
 *   - the UPDATE gate. A child publishes its own KEY at its apex, so there is
 *     nothing to wait for. A proxy is a SECONDARY and cannot author the zone,
 *     so it needs the §10.8 bootstrap -- the operator must publish the agent's
 *     KEY at the primary -- and until that happens UPDATE is not usable.
 *   - who sends. The child calls SyncZoneDelegationVia*, the proxy calls
 *     Proxy*Parent. Same walk, different senders; walkSyncPlan holds the walk.
 *
 * Before this, the child path had its own scheme selection in BestSyncScheme,
 * which picked ONE scheme by operator preference and lived with it: if that
 * scheme failed, nothing else was tried even when the parent advertised a
 * transport that would have worked. It also resolved target addresses with
 * net.LookupHost -- the stdlib resolver, via /etc/resolv.conf -- while the rest
 * of this code deliberately uses the IMR. In a DNS training lab those are very
 * different answers. BestSyncScheme is gone; this is what replaced it.
 */
package tdns

import (
	"context"
	"fmt"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// SyncRole is which of the two callers is building the plan. It selects the
// UPDATE gate, and nothing else.
type SyncRole int

const (
	// SyncRoleChild is a tdns-auth zone syncing its OWN delegation. It
	// publishes its own KEY at its apex, so UPDATE needs no bootstrap: the
	// only question is whether the parent advertises it.
	SyncRoleChild SyncRole = iota
	// SyncRoleProxy is a tdns-agent secondary forwarding on behalf of a
	// DSYNC-unaware primary. It cannot author the zone, so the agent's KEY has
	// to be published at the PRIMARY by the operator before the parent will
	// trust an UPDATE -- the §10.8 state machine, which is the UPDATE gate.
	SyncRoleProxy
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
func (zd *ZoneData) BuildParentSyncPlan(ctx context.Context, kdb *KeyDB, imr *Imr,
	role SyncRole) (*ParentSyncPlan, error) {

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

	// The typed config, not viper. config_delegationsync.go states the rule:
	// this block is modelled in full and that struct is its only reader, with
	// one named exception that is not this one. The reason it was unwound is
	// that viper splits keys on "." and returns the zero value with no sign
	// anything went wrong -- and tdns-auth and tdns-agent never call
	// viper.ReadInConfig() at all, so a viper read here returns empty in
	// exactly the daemons that run this plan.
	//
	// The failure was total and silent: no schemes meant SkippedScheme{"all"},
	// an unusable plan, and every configured transport ignored. zone_utils.go
	// reads the same setting through DelegationSyncConfig(); now so does this.
	schemes := DelegationSyncConfig().Child.Schemes
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
			zd.planConsiderUpdate(ctx, kdb, imr, dsyncRes, plan, role)
		case "api":
			zd.planConsiderApi(dsyncRes, plan)
		case "notify":
			zd.planConsiderNotify(ctx, imr, dsyncRes, plan, role)
		default:
			plan.Skipped = append(plan.Skipped, SkippedScheme{
				Scheme: scheme, Reason: "unknown scheme name in delegationsync.child.schemes"})
		}
	}
	return plan, nil
}

// updateGateBlocked is the one role-dependent gate: whether this host can sign
// an UPDATE the parent will trust.
//
// A PROXY must clear the §10.8 KEY bootstrap first. It is a SECONDARY and
// cannot author the zone, so the operator has to publish the agent's KEY at the
// primary; until then an UPDATE would be REFUSED and there is no point sending
// one.
//
// A CHILD publishes its own KEY and has nothing to clear, so it is never
// blocked here. Adding a gate would invent a restriction that never existed on
// that path -- and a child whose signing key is genuinely missing fails at send
// time, which is the right shape for a runtime problem: the walk records it and
// moves on to the next transport.
//
// The gate that used to sit at the top of the state machine -- "does the parent
// advertise UPDATE?" -- is the caller's findDsync, so nothing here rediscovers.
func (zd *ZoneData) updateGateBlocked(kdb *KeyDB, role SyncRole) (string, bool) {
	if role != SyncRoleProxy {
		return "", false
	}
	state, err := zd.proxySig0PublicationState(kdb)
	if err != nil {
		return fmt.Sprintf("key state: %v", err), true
	}
	if state != ProxyUpdateReady {
		return string(state), true
	}
	return "", false
}

// zoneIsSigned reports whether the parent will have anything to validate.
//
// Published DNSKEYs are the direct evidence and are what a PROXY sees: it
// serves a transferred copy, so if the primary signs the zone the DNSKEYs are
// in the data. A tdns-auth CHILD may sign the zone itself, where the keys are
// not necessarily sitting in the parsed zone at the moment this is asked --
// hence the options. Either is sufficient; asking only about the RRset would
// wrongly call an online-signing child unsigned and silently drop NOTIFY from
// its plan.
func zoneIsSigned(zd *ZoneData) bool {
	return zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning] || zoneLooksSigned(zd)
}

// findDsync returns the first advertised DSYNC RR for a scheme, or nil.
func findDsync(res DsyncResult, scheme core.DsyncScheme, wantNotifyType bool) *core.DSYNC {
	for _, drr := range res.Rdata {
		if drr.Scheme != scheme {
			continue
		}
		// NOTIFY is only actionable for the types that can be signalled about.
		//
		// CDS belongs in that set and was missing: the filter inherited from
		// BestSyncScheme accepted CSYNC and ANY only, so a parent advertising
		// exactly "DSYNC NOTIFY CDS" was reported as not offering NOTIFY at
		// all. That was survivable while CDS notifies were rare; this code
		// sends them on any DNSKEY change and from the startup synthesis, so
		// the mismatch is now load-bearing.
		//
		// No preference between the accepted types is expressed, deliberately:
		// emitProxyNotifies sends CDS and CSYNC to the SAME target list, so one
		// advertised NOTIFY target serves both signals and choosing between
		// them would decide nothing.
		if wantNotifyType &&
			drr.Type != dns.TypeCDS && drr.Type != dns.TypeCSYNC && drr.Type != dns.TypeANY {
			continue
		}
		return drr
	}
	return nil
}

func (zd *ZoneData) planConsiderUpdate(ctx context.Context, kdb *KeyDB, imr *Imr,
	res DsyncResult, plan *ParentSyncPlan, role SyncRole) {

	drr := findDsync(res, core.SchemeUpdate, false)
	if drr == nil {
		plan.Skipped = append(plan.Skipped, SkippedScheme{"UPDATE", "parent does not advertise it"})
		return
	}
	if reason, blocked := zd.updateGateBlocked(kdb, role); blocked {
		plan.Skipped = append(plan.Skipped, SkippedScheme{"UPDATE", reason})
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
	// THE gate that makes API different from the other two, and the one thing
	// BestSyncScheme did that this planner must not lose.
	//
	// The DSYNC RR names the target whose URI carries the endpoint this client
	// then posts a bearer credential to. If the DSYNC lookup did not
	// DNSSEC-validate, whoever can answer that query chooses where the
	// credential goes. Validating the URI and TXT records AT the discovered
	// target does not help: a spoofed DSYNC names an attacker-controlled zone
	// whose own URI/TXT then validate perfectly well, and the credential is
	// posted there.
	//
	// NOTIFY and UPDATE carry no secret and are deliberately not gated this
	// way. allow-insecure is the same switch DiscoverDsyncApiEndpoint uses for
	// its own requireDnssec, so one setting governs the whole path rather than
	// half of it.
	if !res.Validated && !DelegationSyncConfig().Child.Api.AllowInsecure {
		plan.Skipped = append(plan.Skipped, SkippedScheme{"API",
			"the DSYNC lookup did not DNSSEC-validate and" +
				" delegationsync.child.api.allow-insecure is not set"})
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

// zoneHasCdsOrCsync reports whether the served zone publishes either of the
// records a parent re-scans after a NOTIFY.
//
// An apex that cannot be read is treated as HAVING them: an unreadable zone is
// not evidence that the child publishes nothing, and guessing "no" would remove
// a transport the operator configured on the strength of a failed lookup.
func zoneHasCdsOrCsync(zd *ZoneData) bool {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil || apex.RRtypes == nil {
		return true
	}
	return len(apex.RRtypes.GetOnlyRRSet(dns.TypeCDS).RRs) > 0 ||
		len(apex.RRtypes.GetOnlyRRSet(dns.TypeCSYNC).RRs) > 0
}

func (zd *ZoneData) planConsiderNotify(ctx context.Context, imr *Imr, res DsyncResult, plan *ParentSyncPlan, role SyncRole) {
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
	if !zoneIsSigned(zd) {
		plan.Skipped = append(plan.Skipped, SkippedScheme{"NOTIFY",
			"zone is unsigned; a NOTIFY would leave the parent nothing it can validate"})
		return
	}
	// The other half of the same gate, and the one the proxy actually meets.
	//
	// Being signed is not enough for a NOTIFY to mean anything. What the parent
	// re-scans is CDS and CSYNC, so a zone that publishes neither leaves it with
	// nothing to act on however well it validates -- and that is the ordinary
	// state of a DSYNC-unaware primary, which is exactly the zone a proxy
	// serves. It signs; it has never heard of CDS.
	//
	// It matters because the walk stops at the first success and a vacuous
	// NOTIFY looks like one. The shipped sample configs put notify first, so
	// without this the UPDATE and API transports this whole plan exists to
	// offer would never be reached for such a zone.
	//
	// Scoped to the proxy role. A tdns-auth child publishes its own CDS as part
	// of signing, so the same test there would race its first publication for
	// no benefit.
	if role == SyncRoleProxy && !zoneHasCdsOrCsync(zd) {
		plan.Skipped = append(plan.Skipped, SkippedScheme{"NOTIFY",
			"proxied zone publishes neither CDS nor CSYNC; a NOTIFY would leave the parent nothing to read"})
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
// is working in. BestSyncScheme, which resolved with net.LookupHost, was the
// last caller doing that and is gone.

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
	imr *Imr, plan *ParentSyncPlan, analysis *ProxyDelegationAnalysis, updateSync *DelegationSyncStatus) (string, error) {

	if !plan.Usable() {
		lgDns.Info("delegation-sync-proxy: nothing forwarded", "zone", zd.ZoneName,
			"parent", plan.Parent, "plan", plan.Summary())
		return "no usable sync scheme; nothing forwarded (" + plan.Summary() + ")", nil
	}

	return zd.walkSyncPlan(ctx, plan, func(cand SyncCandidate) (string, error) {
		switch cand.Scheme {
		case "UPDATE":
			return zd.ProxyUpdateParent(ctx, kdb, imr, cand.Target, updateSync)
		case "API":
			return zd.ProxyApiParent(ctx, imr, cand.Target, analysis)
		case "NOTIFY":
			return zd.ProxyNotifyParent(ctx, notifyq, analysis, cand.Target)
		}
		return "", fmt.Errorf("unknown scheme %q in plan", cand.Scheme)
	})
}

// walkSyncPlan tries each candidate via send, returning the first success.
//
// Shared by both roles: the candidates and the reasons are the same question,
// only the sender differs. Keeping the walk in one place is also what keeps the
// two honest about the thing that matters -- a failure does NOT end the walk.
// The intersection of "what the parent offers" and "what this host is
// configured for" is usually one or two entries, so there is nothing to be
// gained by giving up on the first, and the old child path did exactly that:
// BestSyncScheme picked one scheme and a failure was the end of it, even when
// the parent advertised another transport that would have worked.
//
// All failures are returned together. A caller shown only the last one cannot
// tell which transport was even expected to work.
func (zd *ZoneData) walkSyncPlan(ctx context.Context, plan *ParentSyncPlan,
	send func(SyncCandidate) (string, error)) (string, error) {

	var failures []string
	for _, cand := range plan.Candidates {
		// Each candidate is a network round trip over a different transport, and
		// the senders observe cancellation unevenly -- ProxyUpdateParent reaches
		// SendUpdate, which takes no context at all. Without a check here the
		// walk works its way through the rest of the plan after everything else
		// has shut down.
		if cerr := ctx.Err(); cerr != nil {
			if len(failures) > 0 {
				return "", fmt.Errorf("zone %s: sync abandoned (%w) after %s",
					zd.ZoneName, cerr, strings.Join(failures, "; "))
			}
			return "", fmt.Errorf("zone %s: sync abandoned before any attempt: %w",
				zd.ZoneName, cerr)
		}
		msg, err := send(cand)
		if err == nil {
			if len(failures) > 0 {
				return fmt.Sprintf("%s (after %s)", msg, strings.Join(failures, "; ")), nil
			}
			return msg, nil
		}
		lgDns.Warn("delegation sync: scheme failed, trying the next one",
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
