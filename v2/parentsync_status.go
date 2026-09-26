/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * parentsync status: can a delegation change reach the parent right now, by
 * which scheme, and if not, why not (#790).
 *
 * The answer is the sync plan -- the BuildParentSyncPlan that the sync code
 * walks -- so the command reports what a sync would do, the same way for every
 * scheme and for both roles. Before this the command checked one thing (is
 * there any KEY at the apex) and printed three hard-coded lines. It had no
 * notion of scheme: a NOTIFY-only setup was told about SIG(0) key publication,
 * and every zone was told its parent was in sync.
 *
 * It changes nothing on the zone. The one exception comes with the proxy UPDATE
 * bootstrap: in waiting-for-key the agent's keypair is generated if there is
 * none, which is what the agent's next sync does anyway, and it is what gives
 * the report records to print.
 */
package tdns

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// parentSyncStatusTimeout bounds the whole report. It makes up to four kinds
// of network query -- the DSYNC discovery, a target address lookup per scheme,
// the parent-vs-zone comparison and (child role) a KeyState inquiry -- and an
// operator command must not hang on a parent that does not answer.
const parentSyncStatusTimeout = 15 * time.Second

// ParentSyncStatus builds the status report, and the operator TODOs, for a
// zone with parentsync or parentsync-proxy. The caller has checked that it has
// exactly one of them.
func (zd *ZoneData) ParentSyncStatus(ctx context.Context, kdb *KeyDB, imr *Imr,
	delsyncq chan DelegationSyncRequest) (*ParentSyncReport, []string) {

	// Read first. Nothing below writes it, but the daemon's own sync may, and
	// the report should show what was there when it was asked for.
	warning := zd.delegationSyncWarningMsg()

	ctx, cancel := context.WithTimeout(ctx, parentSyncStatusTimeout)
	defer cancel()

	role := SyncRoleChild
	rep := &ParentSyncReport{
		Role:    ZoneOptionToString[OptParentSync],
		Parent:  zd.GetParent(),
		Warning: warning,
	}
	if zd.Options[OptParentSyncProxy] {
		role = SyncRoleProxy
		rep.Role = ZoneOptionToString[OptParentSyncProxy]
	}

	// Asked for now and collected last: the comparison runs on the delegation
	// syncher while the plan is built here.
	delegation := zd.requestDelegationStatus(ctx, delsyncq)

	plan, err := zd.buildParentSyncPlan(ctx, kdb, imr, role, true)
	if err != nil {
		rep.PlanError = err.Error()
		plan = nil
	} else {
		if plan.Parent != "" {
			rep.Parent = plan.Parent
		}
		rep.Validated = plan.Validated
		rep.Schemes = schemeReports(plan)
		if len(plan.Outcomes) == 0 {
			rep.PlanNote = planNote(plan)
		}
	}

	var todo []string
	configured := configuredSchemes(ParentSyncConfig().Schemes)
	if configured["update"] {
		rep.Update, todo = zd.updateReport(ctx, kdb, imr, role, plan)
	}
	if configured["notify"] {
		rep.Notify = zd.notifyReport()
	}
	if configured["api"] {
		rep.Api = apiReport(zd)
	}

	rep.Delegation, rep.DelegationError = delegation()
	return rep, todo
}

// delegationSyncWarningMsg returns the zone's delegation-sync-warning, the one
// "zone list" shows, or "".
func (zd *ZoneData) delegationSyncWarningMsg() string {
	for _, e := range zd.ErrorList() {
		if e.Type == DelegationSyncWarning {
			return e.Msg
		}
	}
	return ""
}

// requestDelegationStatus asks the delegation syncher for the parent-vs-zone
// comparison, and returns a function that waits for the answer.
//
// It is the DELEGATION-STATUS request that "parentsync delta" makes through
// /delegation, so the two commands cannot disagree about whether the parent is
// in sync.
func (zd *ZoneData) requestDelegationStatus(ctx context.Context,
	delsyncq chan DelegationSyncRequest) func() (*DelegationSyncStatus, string) {

	fail := func(msg string) func() (*DelegationSyncStatus, string) {
		return func() (*DelegationSyncStatus, string) { return nil, msg }
	}
	if delsyncq == nil {
		return fail("delegation sync not available")
	}
	respch := make(chan DelegationSyncStatus, 1)
	select {
	case delsyncq <- DelegationSyncRequest{
		Command:  "DELEGATION-STATUS",
		ZoneName: zd.ZoneName,
		ZoneData: zd,
		Response: respch,
	}:
	case <-ctx.Done():
		return fail(fmt.Sprintf("the delegation syncher did not take the request: %v", ctx.Err()))
	}
	return func() (*DelegationSyncStatus, string) {
		select {
		case dss := <-respch:
			if dss.Error {
				return nil, dss.ErrorMsg
			}
			dss.ToStrings()
			return &dss, ""
		case <-ctx.Done():
			return nil, fmt.Sprintf("no answer from the delegation syncher: %v", ctx.Err())
		}
	}
}

// schemeReports lists the plan's verdicts in the operator's order.
func schemeReports(plan *ParentSyncPlan) []ParentSyncSchemeReport {
	out := make([]ParentSyncSchemeReport, 0, len(plan.Outcomes))
	for _, o := range plan.Outcomes {
		r := ParentSyncSchemeReport{Scheme: o.Scheme, Usable: o.Usable}
		if o.Usable {
			if o.Target != nil {
				r.Target = fmt.Sprintf("%s port %d", o.Target.Name, o.Target.Port)
			}
		} else {
			r.Reason = describeSkipReason(o.Scheme, o.Reason)
		}
		out = append(out, r)
	}
	return out
}

// describeSkipReason turns the proxy UPDATE gate's reason, which is the bare
// §10.8 state name, into a sentence. The plan keeps the state name: it is what
// the log line has always said.
func describeSkipReason(scheme, reason string) string {
	if scheme != "UPDATE" {
		return reason
	}
	switch ProxyUpdateState(reason) {
	case ProxyUpdateWaiting:
		return "the agent's KEY is not published at the primary yet (" + reason + ")"
	case ProxyUpdateForeignKey:
		return "a KEY the agent does not hold is published at the apex (" + reason + ")"
	}
	return reason
}

// planNote is why a plan evaluated no scheme at all.
func planNote(plan *ParentSyncPlan) string {
	reasons := make([]string, 0, len(plan.Skipped))
	for _, s := range plan.Skipped {
		reasons = append(reasons, s.Reason)
	}
	return strings.Join(reasons, "; ")
}

func configuredSchemes(schemes []string) map[string]bool {
	m := make(map[string]bool, len(schemes))
	for _, s := range schemes {
		m[strings.ToLower(strings.TrimSpace(s))] = true
	}
	return m
}

// updateAdvertised reports whether the plan found a usable DSYNC UPDATE record
// at the parent.
func updateAdvertised(plan *ParentSyncPlan) bool {
	if plan == nil {
		return false
	}
	for _, o := range plan.Outcomes {
		if o.Scheme == "UPDATE" && o.Advertised {
			return true
		}
	}
	return false
}

// updateReport is the UPDATE detail.
//
// For a proxy it is the §10.8 report, word for word what "zone proxy-key"
// prints, and only when the parent advertises UPDATE. Otherwise the scheme line
// already says the parent does not offer it, and instructions to publish a KEY
// for a transport nobody will accept would mislead.
//
// For a child it is the zone's own SIG(0) key: whether one is active, whether
// its KEY is at the apex, and what the parent holds for it.
func (zd *ZoneData) updateReport(ctx context.Context, kdb *KeyDB, imr *Imr,
	role SyncRole, plan *ParentSyncPlan) (*ParentSyncUpdateReport, []string) {

	ur := &ParentSyncUpdateReport{}
	if role == SyncRoleProxy {
		if !updateAdvertised(plan) {
			return nil, nil
		}
		state, err := zd.proxySig0PublicationStateFor(kdb, true)
		if err != nil {
			ur.ProxyReport = fmt.Sprintf("zone %s: UPDATE proxy state could not be determined: %v\n", zd.ZoneName, err)
			return ur, nil
		}
		msg, err := zd.proxyKeyStatusMessage(state, kdb)
		if err != nil {
			ur.ProxyReport = fmt.Sprintf("zone %s: UPDATE proxy %s; the records could not be assembled: %v\n",
				zd.ZoneName, state, err)
			return ur, nil
		}
		ur.ProxyReport = msg
		return ur, nil
	}

	for _, rr := range zd.proxyApexKEYs() {
		if k, ok := rr.(*dns.KEY); ok {
			ur.ApexKeyIDs = append(ur.ApexKeyIDs, k.KeyTag())
		}
	}
	if sak, err := kdb.GetSig0Keys(zd.ZoneName, Sig0StateActive); err == nil && sak != nil && len(sak.Keys) > 0 {
		ur.HaveActiveKey = true
		ur.ActiveKeyID = sak.Keys[0].KeyId
	}

	var todo []string
	// A secondary cannot put the KEY into the zone itself.
	if len(ur.ApexKeyIDs) == 0 && zd.ZoneType == Secondary {
		todo = append(todo, fmt.Sprintf("Add the zone's SIG(0) KEY record to %s at the primary server", zd.ZoneName))
	}

	switch {
	case !ur.HaveActiveKey:
		ur.ParentKeyError = "not asked: there is no active SIG(0) key"
	case !updateAdvertised(plan):
		ur.ParentKeyError = "not asked: the parent does not advertise UPDATE"
	case imr == nil:
		ur.ParentKeyError = "not asked: no IMR available"
	default:
		ks, authenticated, err := QueryParentKeyState(ctx, kdb, imr, zd.ZoneName, ur.ActiveKeyID)
		if err != nil {
			ur.ParentKeyError = err.Error()
		} else {
			ur.ParentKeyState = edns0.KeyStateToString(ks.KeyState)
			ur.ParentKeyAuthenticated = authenticated
		}
	}
	return ur, todo
}

// notifyReport is the NOTIFY detail. What the parent re-scans after a NOTIFY is
// CDS and CSYNC, and it can act on them only if the zone is signed.
func (zd *ZoneData) notifyReport() *ParentSyncNotifyReport {
	nr := &ParentSyncNotifyReport{Signed: zoneIsSigned(zd)}
	apex, err := zd.GetOwner(zd.ZoneName)
	if err == nil && apex != nil && apex.RRtypes != nil {
		nr.PublishesCDS = len(apex.RRtypes.GetOnlyRRSet(dns.TypeCDS).RRs) > 0
		nr.PublishesCSYNC = len(apex.RRtypes.GetOnlyRRSet(dns.TypeCSYNC).RRs) > 0
	}
	return nr
}

// apiReport is the API detail: the credential arrives out of band, so whether
// one is configured is the question.
func apiReport(zd *ZoneData) *ParentSyncApiReport {
	cfg := ParentSyncConfig().Api
	cred, ok := cfg.CredentialForChild(zd.GetParent(), zd.ZoneName)
	return &ParentSyncApiReport{
		CredentialConfigured: ok && cred.Usable(),
		AllowInsecure:        cfg.AllowInsecure,
	}
}
