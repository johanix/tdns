/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * SYNC-DS: the KSK rollover engine's DS delivery, done by the delegation
 * syncher.
 *
 * The rollover engine used to send to the parent itself: its own DSYNC scheme
 * selection and its own UPDATE, NOTIFY(CDS) and API senders, beside the
 * delegation syncher's. The DS engine design (step 2) and the key lifecycle
 * ownership design (section 4.2) make the syncher the one component that talks
 * to the parent. The engine now hands the syncher the keys whose DS the parent
 * should hold and waits for the answer; the syncher discovers the parent's
 * schemes once, through the same plan it builds for NS and glue, and sends.
 *
 * What the parent sees is unchanged: the same DS RRset over a rollover, the
 * same CDS for a NOTIFY, the same ordering under the multi-DS scheme. Only the
 * sender moved.
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// DSSyncRequest is what a SYNC-DS carries: the keys whose DS the parent
// should hold, and the policy that chooses the scheme and the timings.
type DSSyncRequest struct {
	// Snapshot is the rollover target, taken by the engine when it decided to
	// push, so that every transport describes the same key set. nil loads it
	// from the keystore.
	Snapshot *RolloverTargetKeySnapshot
	// Policy is the zone's DNSSEC policy: dsync-scheme-preference, the DS TTL
	// and the NOTIFY timeout. nil sends over UPDATE alone, which is what the
	// CLI's offline ds-push asks for.
	Policy *DnssecPolicy
	// Deadline bounds the delivery. The engine waits for the answer until
	// then and no longer, so the syncher must not work past it either. Zero
	// means the syncher's own context is the only bound.
	Deadline time.Time
}

// DSSyncResponse is the syncher's answer to a SYNC-DS: the push result the
// rollover engine's states are decided from, and the error that goes with a
// failed attempt.
type DSSyncResponse struct {
	Result KSKDSPushResult
	Err    error
}

// KSKDSPushResult is the outcome of a DS delivery (rcode and wire
// diagnostics). Category is empty on success (rcode NOERROR, submitted range
// recorded); otherwise it is one of the SoftfailXxx constants from
// ksk_rollover_categories.go and the rollover engine records a softfail from
// it.
//
// Scheme reflects which scheme(s) completed at the wire level for this
// attempt. Comma-joined when a parallel send had at least one path return
// NOERROR ("UPDATE", "NOTIFY", or "UPDATE,NOTIFY"). Persisted to
// RolloverZoneState.last_attempt_scheme for status display.
//
// Detail concatenates per-path diagnostics from failures (rcode, EDE,
// transport error). Read by status output to render the cause of a
// parent-rejected or transport softfail.
type KSKDSPushResult struct {
	Rcode        int
	UpdateResult UpdateResult
	Category     string
	Scheme       string
	Detail       string
}

// handleDSSync is the SYNC-DS arm of the syncher: deliver the DS set the
// rollover engine asks for, and answer. The engine waits with a deadline, so
// the request runs at once and is never deferred; a parent that cannot be
// reached yet is reported, and the engine retries on its own schedule.
func handleDSSync(ctx context.Context, kdb *KeyDB, notifyq chan NotifyRequest, imr *Imr, ds DelegationSyncRequest) {
	var resp DSSyncResponse
	switch {
	case ds.ZoneData == nil || ds.DSSync == nil:
		resp = DSSyncResponse{
			Result: KSKDSPushResult{Category: SoftfailChildConfigLocalError},
			Err:    fmt.Errorf("SYNC-DS for %s: no zone or no request", ds.ZoneName),
		}
	default:
		if !ds.DSSync.Deadline.IsZero() {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, ds.DSSync.Deadline)
			defer cancel()
		}
		resp.Result, resp.Err = ds.ZoneData.SyncDSWithParent(ctx, kdb, notifyq, imr, *ds.DSSync)
	}
	if ds.DSResponse == nil {
		return
	}
	// The requester gives a channel with room for the one answer. Never block
	// the syncher on it.
	select {
	case ds.DSResponse <- resp:
	default:
		lgDns.Warn("DelegationSyncher: SYNC-DS answered but nobody took the answer", "zone", ds.ZoneName)
	}
}

// SyncDSWithParent delivers the rollover target's DS set to the parent: the
// body of SYNC-DS, and what the CLI's offline ds-push calls directly.
//
// With a policy and a resolver it builds the parent sync plan (one DSYNC
// discovery, every configured scheme through its gate), picks the schemes
// the policy's dsync-scheme-preference wants from it, and sends over each of
// them, in parallel when "auto" meets a parent that offers both UPDATE and
// NOTIFY. Per-path results are aggregated: any path that reached NOERROR
// makes the attempt a success.
//
// Without a policy or a resolver it sends over UPDATE alone, with the
// parent's UPDATE target looked up the way the pre-plan code did.
func (zd *ZoneData) SyncDSWithParent(ctx context.Context, kdb *KeyDB, notifyq chan NotifyRequest, imr *Imr,
	req DSSyncRequest) (KSKDSPushResult, error) {

	if zd == nil || kdb == nil {
		return KSKDSPushResult{Category: SoftfailChildConfigLocalError}, fmt.Errorf("SyncDSWithParent: nil argument")
	}
	child := dns.Fqdn(zd.ZoneName)
	snap := req.Snapshot
	if snap == nil {
		s, err := loadRolloverTargetSnapshot(kdb, child)
		if err != nil {
			return KSKDSPushResult{Category: SoftfailChildConfigLocalError}, fmt.Errorf("SyncDSWithParent: %w", err)
		}
		snap = s
	}
	pol := req.Policy

	// No scheme plan is possible without a policy or a resolver. The UPDATE
	// target is then found the way the pre-plan push did, with the same error
	// category, so the CLI's offline mode behaves as it always has.
	if pol == nil || imr == nil {
		if imr == nil {
			return KSKDSPushResult{Category: SoftfailChildConfigLocalError},
				fmt.Errorf("SyncDSWithParent: no IMR to find the parent's UPDATE target for %s", child)
		}
		target, terr := legacyUpdateTarget(ctx, imr, child)
		if terr != nil {
			return KSKDSPushResult{Category: SoftfailTransport, Scheme: "UPDATE"},
				fmt.Errorf("SyncDSWithParent: DSYNC target: %w", terr)
		}
		return zd.sendDSViaUpdate(ctx, kdb, imr, snap, pol, target)
	}

	plan, err := zd.BuildParentSyncPlan(ctx, kdb, imr, SyncRoleChild)
	if err != nil {
		// A CDS the rollover still owns cannot be consumed by a parent that
		// cannot be discovered; take it down rather than leave it orphaned
		// for the duration of the outage.
		cleanupCdsAfterConfirm(ctx, zd, kdb)
		return KSKDSPushResult{Category: SoftfailChildConfigLocalError, Detail: "parent sync plan: " + err.Error()},
			fmt.Errorf("SyncDSWithParent: %w", err)
	}

	choices, updateAdv, notifyAdv, err := rolloverSchemeChoices(plan, pol)
	// Persist what the parent's DSYNC RRset offered, so status output can
	// tell "the parent does not advertise this scheme" from "nothing has
	// been sent over it yet". Best-effort.
	_ = setParentDsyncAdvertised(kdb, zd.ZoneName, updateAdv, notifyAdv)
	if err != nil {
		cleanupCdsAfterConfirm(ctx, zd, kdb)
		// Two error shapes: errNoUsableScheme (the parent offers nothing the
		// policy accepts, or a force-X the parent does not offer) is
		// waiting-for-parent, a softfail with a 1h cap that never hardfails
		// and clears itself when the parent's DSYNC changes. Anything else
		// (an invalid preference, a credential missing for the one scheme on
		// offer) is a local error for the operator.
		cat := SoftfailChildConfigLocalError
		if errors.Is(err, errNoUsableScheme) {
			cat = SoftfailChildConfigWaitingForParent
			pref := pol.Rollover.DsyncSchemePreference
			if pref == "" {
				pref = defaultDsyncSchemePreference
			}
			zd.SetError(RolloverParentBlocker, "%s", rolloverBlockerText(plan, pref))
		}
		return KSKDSPushResult{
			Category: cat,
			Detail:   "scheme choice: " + err.Error() + " [" + plan.Summary() + "]",
		}, fmt.Errorf("SyncDSWithParent: %w", err)
	}

	// A usable choice means the waiting-for-parent blocker, if any, is stale.
	// Only that category: RolloverPolicyViolation is independent and stays.
	zd.ClearError(RolloverParentBlocker)

	// A CDS the rollover owns is republished only by a NOTIFY path. When none
	// is chosen this attempt, take the CDS down before sending so it does not
	// sit stale through the rollover.
	if !schemesContainNotify(choices) {
		cleanupCdsAfterConfirm(ctx, zd, kdb)
	}

	send := func(ch schemeChoice) pathResultLite {
		switch ch.Scheme {
		case core.SchemeUpdate:
			res, perr := zd.sendDSViaUpdate(ctx, kdb, imr, snap, pol, ch.Target)
			return pathResultLite{scheme: "UPDATE", res: res, err: perr}
		case core.SchemeNotify:
			res, perr := zd.sendDSViaNotify(ctx, kdb, notifyq, snap, pol, ch.Target)
			return pathResultLite{scheme: "NOTIFY", res: res, err: perr}
		case core.SchemeAPI:
			res, perr := zd.sendDSViaApi(ctx, kdb, imr, snap, ch.Target)
			return pathResultLite{scheme: "API", res: res, err: perr}
		}
		return pathResultLite{
			scheme: schemeName(ch.Scheme),
			res:    KSKDSPushResult{Category: SoftfailChildConfigLocalError, Detail: fmt.Sprintf("unknown scheme %d", ch.Scheme)},
			err:    fmt.Errorf("unknown scheme %d", ch.Scheme),
		}
	}

	results := make([]pathResultLite, len(choices))
	if len(choices) == 1 {
		results[0] = send(choices[0])
	} else {
		// One goroutine per scheme, each writing its own slot. The snapshot
		// is read-only, so both paths describe the same set.
		var wg sync.WaitGroup
		for i, ch := range choices {
			wg.Add(1)
			go func(i int, ch schemeChoice) {
				defer wg.Done()
				results[i] = send(ch)
			}(i, ch)
		}
		wg.Wait()
	}

	agg := aggregateRolloverPushResults(results)
	if agg.Scheme == "" {
		// Every path failed. Surface it as an error so the engine's failure
		// branch runs: a pure transport failure leaves agg.Rcode at 0, which
		// is NOERROR, and would otherwise read as a success.
		msg := agg.Detail
		if msg == "" {
			msg = agg.Category
		}
		if msg == "" {
			msg = "all push paths failed"
		}
		return agg, fmt.Errorf("SyncDSWithParent: %s", msg)
	}
	return agg, nil
}

// errNoUsableScheme is returned when the parent advertises no DSYNC scheme
// the zone's rollover policy can use. The caller translates it into
// child-config:waiting-for-parent (1h-capped softfail, never hardfails).
// Other errors from the scheme choice (an invalid preference, a missing
// credential) are not "waiting for parent" and stay in their own categories.
var errNoUsableScheme = errors.New("parent advertises no rollover-usable DSYNC scheme")

// schemeChoice is one (scheme, target) pair the DS delivery sends over.
// rolloverSchemeChoices returns one of these under any single-scheme policy
// outcome, two under "auto" when the parent offers both UPDATE and NOTIFY.
type schemeChoice struct {
	Scheme core.DsyncScheme
	Target *DsyncTarget
}

// rolloverSchemeChoices picks the schemes the policy's dsync-scheme-preference
// wants from the parent sync plan's candidates.
//
// The plan has done the discovery and the gates: the parent's DSYNC records,
// the operator's parentsync.schemes, the API scheme's DNSSEC and credential
// gates, the unsigned-zone gate on NOTIFY, address resolution. What is decided
// here is only the preference among the transports that survived. One rule
// is the rollover's own: a NOTIFY target advertised for CSYNC alone cannot
// carry a DS, so it is not a NOTIFY the rollover can use; the plan accepts it
// because NS and glue changes can.
//
// The two booleans are what the parent's DSYNC RRset advertised for UPDATE
// and for NOTIFY, whatever happened after that, for the status snapshot.
//
// Errors: a parent offering nothing the preference accepts, or a force-X the
// parent does not offer, wraps errNoUsableScheme. A parent whose only offer
// is the API scheme and whose API candidate this host cannot use (no
// credential, say) is a local configuration gap, not a parent to wait for,
// and is returned without the sentinel. An invalid preference is a config
// error, also without the sentinel.
func rolloverSchemeChoices(plan *ParentSyncPlan, pol *DnssecPolicy) ([]schemeChoice, bool, bool, error) {
	if plan == nil || pol == nil {
		return nil, false, false, fmt.Errorf("rolloverSchemeChoices: nil argument")
	}
	var updateAdv, notifyAdv, apiAdv bool
	var apiReason string
	for _, o := range plan.Outcomes {
		switch o.Scheme {
		case "UPDATE":
			updateAdv = updateAdv || o.Advertised
		case "NOTIFY":
			notifyAdv = notifyAdv || o.Advertised
		case "API":
			apiAdv = apiAdv || o.Advertised
			if o.Advertised && !o.Usable {
				apiReason = o.Reason
			}
		}
	}

	var updateTarget, notifyTarget, apiTarget *DsyncTarget
	for _, c := range plan.Candidates {
		switch c.Scheme {
		case "UPDATE":
			if updateTarget == nil {
				updateTarget = c.Target
			}
		case "NOTIFY":
			if c.Target != nil && c.Target.RR != nil &&
				c.Target.RR.Type != dns.TypeCDS && c.Target.RR.Type != dns.TypeANY {
				continue
			}
			if notifyTarget == nil {
				notifyTarget = c.Target
			}
		case "API":
			if apiTarget == nil {
				apiTarget = c.Target
			}
		}
	}

	want, err := decideRolloverSchemes(updateTarget != nil, notifyTarget != nil, apiTarget != nil,
		pol.Rollover.DsyncSchemePreference)
	if err != nil {
		// An API scheme the plan passed over although the DSYNC lookup
		// validated (or the operator accepted an unvalidated one) was
		// stopped by this host's own configuration, a missing credential:
		// the parent would take the DS, and waiting on it would leave the
		// rollover retrying invisibly forever. An unvalidated lookup is the
		// parent's to fix, and stays waiting-for-parent.
		apiLocalGap := apiAdv && apiReason != "" && (plan.Validated || ParentSyncConfig().Api.AllowInsecure)
		if errors.Is(err, errNoUsableScheme) && !updateAdv && !notifyAdv && apiLocalGap {
			return nil, updateAdv, notifyAdv, fmt.Errorf("the parent offers only the DSYNC API scheme, which this host cannot use: %s", apiReason)
		}
		return nil, updateAdv, notifyAdv, err
	}
	out := make([]schemeChoice, 0, len(want))
	for _, scheme := range want {
		switch scheme {
		case core.SchemeUpdate:
			out = append(out, schemeChoice{Scheme: scheme, Target: updateTarget})
		case core.SchemeNotify:
			out = append(out, schemeChoice{Scheme: scheme, Target: notifyTarget})
		case core.SchemeAPI:
			out = append(out, schemeChoice{Scheme: scheme, Target: apiTarget})
		}
	}
	return out, updateAdv, notifyAdv, nil
}

// decideRolloverSchemes is the pure decision function: given which schemes
// are usable against the parent and the policy's preference, it returns the
// list of schemes to send over this attempt.
//
// API IS THE LAST RESORT, never a co-equal choice. It is reached only when
// neither UPDATE nor NOTIFY is available, so every deployment where one of
// those is advertised behaves exactly as before. Two reasons, and they agree:
//
//   - the design says so. "Preference order is the operator's and defaults
//     to putting api last: it is the fallback, not the choice" (dsync-api-scheme
//     section 11), because the credential is a bearer token and the scheme
//     inherits a hard dependency on the parent zone being signed that UPDATE
//     does not have (section 8).
//   - it costs something the others do not. Under "auto" against a
//     both-advertising parent the DS is sent over UPDATE and NOTIFY in
//     PARALLEL; adding API to that would put a credential on the wire on
//     every push for no gain when a DNS transport already works.
//
// force-update / force-notify do NOT fall back to API. Force is force.
//
// Errors:
//   - "no usable scheme advertised" cases (auto/prefer-* with neither
//     advertised; force-X with X not advertised) wrap errNoUsableScheme, which
//     the caller turns into child-config:waiting-for-parent (1h cap, never
//     hardfails). Force-X-not-advertised is included on purpose: force is
//     force; recover automatically when the parent starts advertising the
//     forced scheme.
//   - "invalid preference value" is a config error (operator typo), not a
//     parent issue; returned with no sentinel and reported as
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
		return nil, fmt.Errorf("invalid dsync-scheme-preference %q", preference)
	}
}

// schemesContainNotify reports whether any chosen scheme is NOTIFY. When
// NOTIFY is not among the schemes sent over, a CDS the rollover published
// earlier will not be republished this attempt and is cleaned up first.
func schemesContainNotify(choices []schemeChoice) bool {
	for _, c := range choices {
		if c.Scheme == core.SchemeNotify {
			return true
		}
	}
	return false
}

// schemeName renders a DsyncScheme as the diagnostic string used in
// LastAttemptScheme and status output ("UPDATE", "NOTIFY", "API").
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

// legacyUpdateTarget resolves the parent's UPDATE target without a scheme
// plan, for the delivery that has no policy or no resolver to build one. It
// keeps the DS-then-ANY lookup the pre-plan push did.
//
// The planned path is deliberately NOT this: the plan accepts any
// UPDATE-scheme DSYNC RR, since UPDATE advertisements are RRtype-agnostic by
// spec, and this narrower form could fail to find a target the plan accepts.
func legacyUpdateTarget(ctx context.Context, imr *Imr, child string) (*DsyncTarget, error) {
	t, err := imr.LookupDSYNCTarget(ctx, child, dns.TypeDS, core.SchemeUpdate)
	if err == nil {
		return t, nil
	}
	return imr.LookupDSYNCTarget(ctx, child, dns.TypeANY, core.SchemeUpdate)
}

// pathResultLite is one transport's outcome, as aggregateRolloverPushResults
// consumes it.
type pathResultLite struct {
	scheme string
	res    KSKDSPushResult
	err    error
}

// aggregateRolloverPushResults applies the any-success-wins rule to the
// per-path results and returns the aggregate the rollover engine acts on.
func aggregateRolloverPushResults(results []pathResultLite) KSKDSPushResult {
	var ok []string
	var failParts []string
	failedCat := ""
	failedRcode := 0
	for _, r := range results {
		if r.err == nil && r.res.Rcode == dns.RcodeSuccess {
			ok = append(ok, r.scheme)
			continue
		}
		detail := r.scheme + ":"
		if r.res.Detail != "" {
			detail += " " + r.res.Detail
		} else if r.err != nil {
			detail += " " + r.err.Error()
		} else if r.res.Rcode != 0 {
			detail += " rcode=" + dns.RcodeToString[r.res.Rcode]
		}
		failParts = append(failParts, detail)
		failedCat = mergeFailureCategory(failedCat, r.res.Category)
		if r.res.Rcode != 0 && failedRcode == 0 {
			failedRcode = r.res.Rcode
		}
	}
	if len(ok) > 0 {
		return KSKDSPushResult{
			Rcode:  dns.RcodeSuccess,
			Scheme: strings.Join(ok, ","),
			Detail: strings.Join(failParts, " | "),
		}
	}
	return KSKDSPushResult{
		Rcode:    failedRcode,
		Category: failedCat,
		Detail:   strings.Join(failParts, " | "),
	}
}

// mergeFailureCategory picks the more actionable of two failure categories:
// parent-rejected > transport > child-config:*. Empty strings rank lowest.
// The child-config subcategories rank equally; the engine decides the
// backoff from the subcategory it is handed.
func mergeFailureCategory(a, b string) string {
	rank := func(s string) int {
		switch s {
		case SoftfailParentRejected:
			return 3
		case SoftfailTransport:
			return 2
		case SoftfailChildConfig,
			SoftfailChildConfigLocalError,
			SoftfailChildConfigWaitingForParent:
			return 1
		default:
			return 0
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// sendDSViaUpdate replaces the child's whole DS RRset at the parent with the
// target set: a DEL ANY DS followed by the set, signed with the child's active
// SIG(0) key, sent once. The parent's rcode comes back as the result's rcode;
// the rollover engine, not a retry loop, decides what a refusal means.
//
// On NOERROR the submitted index range is recorded for status output.
func (zd *ZoneData) sendDSViaUpdate(ctx context.Context, kdb *KeyDB, imr *Imr, snap *RolloverTargetKeySnapshot,
	pol *DnssecPolicy, target *DsyncTarget) (KSKDSPushResult, error) {

	var out KSKDSPushResult
	if zd == nil || kdb == nil || snap == nil {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("sendDSViaUpdate: nil argument")
	}
	if target == nil || len(target.Addresses) == 0 {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("sendDSViaUpdate: no usable UPDATE target for zone %s", zd.ZoneName)
	}
	child := dns.Fqdn(zd.ZoneName)
	parent, err := zd.ResolveParentVia(imr)
	if err != nil {
		out.Category = SoftfailTransport
		return out, fmt.Errorf("sendDSViaUpdate: parent zone: %w", err)
	}
	parent = dns.Fqdn(parent)

	dsSet, err := dsSetFromSnapshot(snap, child, uint8(dns.SHA256), pol)
	if err != nil {
		out.Category = SoftfailChildConfigLocalError
		return out, err
	}
	if len(dsSet) == 0 {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("sendDSViaUpdate: no DS records to publish for zone %s", child)
	}

	msg, err := BuildChildWholeDSUpdate(parent, child, dsSet)
	if err != nil {
		out.Category = SoftfailChildConfigLocalError
		return out, err
	}
	smsg, err := zd.signDelegationUpdate(kdb, msg)
	if err != nil {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("sendDSViaUpdate: %w", err)
	}

	rcode, ur, err := SendUpdate(ctx, smsg, parent, target.Addresses)
	out.Rcode = rcode
	out.UpdateResult = ur
	if err != nil {
		// A network-layer failure: timeout, no route, connection refused.
		// The parent's own refusals come back as an rcode without an error.
		out.Category = SoftfailTransport
		return out, err
	}
	if rcode != dns.RcodeSuccess {
		out.Category = SoftfailParentRejected
		return out, nil
	}
	if err := recordDSSubmitted(kdb, child, snap); err != nil {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("sendDSViaUpdate: %w", err)
	}
	out.Scheme = "UPDATE"
	return out, nil
}

// sendDSViaNotify asks the DS engine to publish the target's CDS at the child
// apex and, once the zone serves it, sends NOTIFY(CDS) to the parent's DSYNC
// NOTIFY target and waits for the response.
//
// The DS engine records the published index range (the rollover's claim on
// the CDS, which its cleanup triggers compare against) before the NOTIFY goes
// out. The CDS stays published until cleanupCdsAfterConfirm runs.
//
// On a NOTIFY failure the CDS is left published: the next attempt derives the
// same set, the publish is a no-op, and the NOTIFY is sent again. No churn.
func (zd *ZoneData) sendDSViaNotify(ctx context.Context, kdb *KeyDB, notifyq chan NotifyRequest,
	snap *RolloverTargetKeySnapshot, pol *DnssecPolicy, target *DsyncTarget) (KSKDSPushResult, error) {

	var out KSKDSPushResult
	if zd == nil || kdb == nil {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("sendDSViaNotify: nil argument")
	}
	if target == nil || len(target.Addresses) == 0 {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("sendDSViaNotify: no NOTIFY target addresses")
	}
	if notifyq == nil {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("sendDSViaNotify: NotifyQ not configured")
	}
	child := dns.Fqdn(zd.ZoneName)

	pub := kdb.askDSEngine(ctx, DSEngineRequest{
		cmd:      dsCmdPublishRolloverCDS,
		zd:       zd,
		snapshot: snap,
	})
	if pub.err != nil {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("sendDSViaNotify: %w", pub.err)
	}
	cdsSet := pub.cds
	lgDns.Debug("sendDSViaNotify: CDS published",
		"zone", child, "cds_count", len(cdsSet),
		"index_low", pub.low, "index_high", pub.high, "index_known", pub.rangeKnown)

	// Bound the NOTIFY round trip: a 30s floor for healthy parents, scaled
	// up for parents that batch their CDS polls (notifyTimeoutFromPolicy).
	notifyCtx, cancel := context.WithTimeout(ctx, notifyTimeoutFromPolicy(pol))
	defer cancel()
	respCh := make(chan NotifyResponse, 1)
	if !sendNotifyRequest(notifyCtx, notifyq, NotifyRequest{
		ZoneName: child,
		ZoneData: zd,
		RRtype:   dns.TypeCDS,
		Targets:  target.Addresses,
		Response: respCh,
	}) {
		out.Category = SoftfailTransport
		return out, fmt.Errorf("sendDSViaNotify: enqueue NOTIFY: %w", notifyCtx.Err())
	}
	var resp NotifyResponse
	select {
	case resp = <-respCh:
	case <-notifyCtx.Done():
		out.Category = SoftfailTransport
		return out, fmt.Errorf("sendDSViaNotify: await NOTIFY response: %w", notifyCtx.Err())
	}

	out.Rcode = resp.Rcode
	if resp.Error {
		// Set only on a transport failure (no target produced a usable
		// response). The parent's own rcodes come back below.
		out.Category = SoftfailTransport
		out.Detail = formatNotifyDetail(resp)
		return out, fmt.Errorf("sendDSViaNotify: %s", resp.ErrorMsg)
	}
	if resp.Rcode != dns.RcodeSuccess {
		out.Category = SoftfailParentRejected
		out.Detail = formatNotifyDetail(resp)
		return out, nil
	}
	// Acknowledged at the wire. Record the publication (keyids and time) so
	// the operator's "CDS published" status line survives the cleanup that
	// follows a confirmed rollover. Best-effort.
	keyids := cdsKeyids(cdsSet)
	if err := setCdsPublication(kdb, child, keyids, time.Now().UTC()); err != nil {
		lgDns.Warn("sendDSViaNotify: setCdsPublication failed", "zone", child, "err", err)
	} else {
		lgDns.Debug("sendDSViaNotify: CDS publication recorded", "zone", child, "keyids", keyids)
	}
	out.Scheme = "NOTIFY"
	return out, nil
}

// cdsKeyids extracts the keyid from each CDS RR in the slice.
func cdsKeyids(cdsSet []dns.RR) []uint16 {
	out := make([]uint16, 0, len(cdsSet))
	for _, rr := range cdsSet {
		if c, ok := rr.(*dns.CDS); ok {
			out = append(out, c.DS.KeyTag)
		}
	}
	return out
}

// formatNotifyDetail renders a NotifyResponse's diagnostics as one string for
// KSKDSPushResult.Detail: the rcode and any EDE codes and text.
func formatNotifyDetail(resp NotifyResponse) string {
	var parts []string
	if resp.Rcode != 0 {
		parts = append(parts, "rcode="+dns.RcodeToString[resp.Rcode])
	}
	for _, ede := range resp.EDE {
		s := fmt.Sprintf("EDE=%d", ede.InfoCode)
		if ede.ExtraText != "" {
			s += " '" + ede.ExtraText + "'"
		}
		parts = append(parts, s)
	}
	if resp.ErrorMsg != "" {
		parts = append(parts, resp.ErrorMsg)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ")
}

// notifyTimeoutFromPolicy returns the NOTIFY round-trip timeout for a DS
// delivery. Floor 30s (covers healthy parents that fetch CDS within seconds),
// scaling up to 2 x parent-cds-poll-estimate for parents that batch their
// CDS polls. Returns 30s when pol is nil.
func notifyTimeoutFromPolicy(pol *DnssecPolicy) time.Duration {
	const floor = 30 * time.Second
	if pol == nil {
		return floor
	}
	if est := pol.Rollover.ParentCdsPollEstimate; est > 0 {
		if scaled := est * 2; scaled > floor {
			return scaled
		}
	}
	return floor
}

// sendDSViaApi declares the target's DS RRset to the parent over the DSYNC
// API scheme, through the syncher's API sender with a status that carries DS
// and nothing else. "An RRset absent from the request is left alone by the
// parent" (dsync-api-scheme section 7.2) is what makes that safe: the
// rollover has an opinion about DS and none about NS or glue, and must not
// express one by omission.
//
// The target is the one the plan resolved; nothing is rediscovered. An API
// target carries no addresses by design: the URI published at it names the
// host that resolves.
func (zd *ZoneData) sendDSViaApi(ctx context.Context, kdb *KeyDB, imr *Imr, snap *RolloverTargetKeySnapshot,
	target *DsyncTarget) (KSKDSPushResult, error) {

	var out KSKDSPushResult
	out.Scheme = "API"
	if zd == nil || kdb == nil || imr == nil || snap == nil {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("sendDSViaApi: nil argument")
	}
	if target == nil || target.Name == "" {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("sendDSViaApi: no DSYNC API target")
	}
	child := dns.Fqdn(zd.ZoneName)
	if _, err := zd.ResolveParentVia(imr); err != nil {
		out.Category = SoftfailTransport
		return out, fmt.Errorf("sendDSViaApi: parent zone: %w", err)
	}

	// The same set the UPDATE path sends, from the same snapshot, so the
	// transports never disagree about what is being published. The DS TTL
	// is the parent's to choose over this scheme, as it is for NS and glue.
	dsSet, err := dsSetFromSnapshot(snap, child, uint8(dns.SHA256), nil)
	if err != nil {
		out.Category = SoftfailChildConfigLocalError
		return out, err
	}
	if len(dsSet) == 0 {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("sendDSViaApi: no DS records to publish for zone %s", child)
	}

	_, rcode, err := zd.SyncZoneDelegationViaApi(ctx, imr, DelegationSyncStatus{
		ZoneName:   child,
		Parent:     zd.GetParent(),
		NewDS:      dsSet,
		NewDSKnown: true,
	}, target)
	if err != nil {
		out.Category = classifyDsyncApiPushFailure(err)
		return out, fmt.Errorf("sendDSViaApi: %w", err)
	}
	// 200 from a tdns parent means applied, persisted and being served, the
	// same promise a NOERROR carries on the UPDATE path.
	out.Rcode = int(rcode)
	if out.Rcode != dns.RcodeSuccess {
		out.Category = SoftfailParentRejected
		return out, nil
	}
	if err := recordDSSubmitted(kdb, child, snap); err != nil {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("sendDSViaApi: %w", err)
	}
	return out, nil
}

// classifyDsyncApiPushFailure maps an endpoint failure onto the rollover's
// softfail categories, which decide the backoff and whether an operator is
// told to go and fix something.
//
// The status code is the whole signal, and dsync-api-scheme section 7.3
// already assigns it a meaning:
//
//	400  we sent something the endpoint will not accept  -> local error
//	401  our credential is wrong                         -> local error
//	403  authenticated, the parent's policy says no      -> parent rejected
//	404  no hosted parent, or scheme not offered         -> parent rejected
//	409  zone frozen at the parent                       -> parent rejected
//	5xx  the parent is having a bad day                  -> transport
//
// Anything that is not an HTTP answer at all (TLS refused, a redirect, a
// connection failure) never reached the parent, so it is transport.
func classifyDsyncApiPushFailure(err error) string {
	var httpErr *DsyncApiHttpError
	if !errors.As(err, &httpErr) {
		return SoftfailTransport
	}
	switch httpErr.StatusCode {
	case 400, 401:
		return SoftfailChildConfigLocalError
	case 403, 404, 409:
		return SoftfailParentRejected
	}
	if httpErr.StatusCode >= 500 {
		return SoftfailTransport
	}
	// Any other 4xx: the parent answered and declined. Not ours to retry away.
	return SoftfailParentRejected
}

// recordDSSubmitted records which rollover index range the parent accepted,
// when the snapshot's keys all have one; otherwise it clears a stale range
// from an earlier submission rather than leave columns describing an older
// one.
func recordDSSubmitted(kdb *KeyDB, zone string, snap *RolloverTargetKeySnapshot) error {
	if snap.IndexRangeKnown {
		if err := saveLastDSSubmittedRange(kdb, zone, snap.IndexLow, snap.IndexHigh); err != nil {
			return fmt.Errorf("persist submitted range: %w", err)
		}
		return nil
	}
	if err := clearLastDSSubmittedRange(kdb, zone); err != nil {
		return fmt.Errorf("clear stale submitted range: %w", err)
	}
	return nil
}

// rolloverBlockerText is the RolloverParentBlocker line of a DS delivery that
// found no usable scheme. The parent is the reason unless the plan stopped
// because parentsync.schemes names no scheme: then the config is, and the
// line says so, since the parent was never asked.
func rolloverBlockerText(plan *ParentSyncPlan, pref string) string {
	if plan != nil {
		for _, s := range plan.Skipped {
			if s.Scheme == "all" && s.Reason == reasonNoSchemesConfigured {
				return fmt.Sprintf("no scheme is configured in parentsync.schemes, so no DS can reach the parent (policy preference %q); rollover blocked", pref)
			}
		}
	}
	return fmt.Sprintf("parent advertises no DSYNC scheme matching policy preference %q; rollover blocked", pref)
}
