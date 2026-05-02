package tdns

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// pushDSRRsetViaNotify is the NOTIFY(CDS) counterpart to
// pushDSRRsetViaUpdate. It computes the engine's target CDS set,
// queues a publish-and-sign for it at the child apex via the
// internal-update queue, and dispatches NOTIFY(CDS) to the parent's
// DSYNC NOTIFY target. The publish path is best-effort
// (queue-and-forget): see "Implementation note" below.
//
// On NOTIFY NOERROR: persist last_published_cds_index_low/high to
// claim ownership of the on-wire CDS for cleanup-time comparison.
// CDS stays published until cleanupCdsAfterConfirm runs (Phase 5).
//
// On NOTIFY failure (transport or parent-rejected): leave CDS
// published. Next attempt re-derives the same CDS set; the publish
// step becomes a no-op (anti-CDS ClassANY delete + identical adds)
// and NOTIFY is re-sent. No churn.
//
// Implementation note (divergence from design doc):
// the design doc specifies "(publish CDS, sign CDS RRset, re-sign
// apex NSEC) as a single transaction" with a synchronous rollback
// path on sign failure. The codebase's existing CDS-publish path
// (PublishCdsRRs in ops_cds.go) is asynchronous fire-and-forget via
// kdb.UpdateQ — sign and NSEC re-sign happen in the resigner
// pipeline downstream, not synchronously with the publish. Adding
// the synchronous transaction would require widening the publish
// API across the codebase. This implementation uses a short
// queue-side timeout to detect immediate queue-full failures and
// otherwise relies on the asynchronous apply+sign racing forward
// before the parent fetches CDS. Acceptable in practice: a sign
// failure surfaces as a delay in CDS appearing on the wire, the
// parent's CDS-fetch retries, and the rollover engine's observe
// phase categorises it as parent-publish-failure on the next
// attempt window. The rollback path is unreachable in this design;
// document this when revisiting publish/sign sync.
func pushDSRRsetViaNotify(ctx context.Context, deps RolloverEngineDeps, target *DsyncTarget) (KSKDSPushResult, error) {
	var out KSKDSPushResult
	zd := deps.Zone
	kdb := deps.KDB
	notifyq := deps.NotifyQ
	updateq := deps.InternalUpdateQ
	if zd == nil || kdb == nil {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("pushDSRRsetViaNotify: nil argument")
	}
	if target == nil || len(target.Addresses) == 0 {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("pushDSRRsetViaNotify: no NOTIFY target addresses")
	}
	if notifyq == nil {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("pushDSRRsetViaNotify: NotifyQ not configured")
	}
	if updateq == nil {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("pushDSRRsetViaNotify: InternalUpdateQ not configured")
	}

	child := dns.Fqdn(zd.ZoneName)

	cdsSet, low, high, idxOK, err := ComputeTargetCDSSetForZone(kdb, child)
	if err != nil {
		out.Category = SoftfailChildConfigLocalError
		return out, err
	}
	if len(cdsSet) == 0 {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("pushDSRRsetViaNotify: no CDS records to publish for zone %s", child)
	}

	// Build the publish payload: anti-CDS ClassANY delete to clear
	// any prior CDS RRset, then ClassINET adds for the engine-computed
	// target. Same shape as ops_cds.go PublishCdsRRs but parameterized
	// on our explicit set.
	antiCds := &dns.CDS{}
	antiCds.Hdr = dns.RR_Header{
		Name:   child,
		Rrtype: dns.TypeCDS,
		Class:  dns.ClassANY,
		Ttl:    0,
	}
	actions := make([]dns.RR, 0, 1+len(cdsSet))
	actions = append(actions, antiCds)
	actions = append(actions, cdsSet...)

	lgRollover.Debug("pushDSRRsetViaNotify: queueing CDS publish",
		"zone", child, "cds_count", len(cdsSet), "actions", len(actions),
		"index_low", low, "index_high", high, "index_known", idxOK)
	select {
	case updateq <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       child,
		Actions:        actions,
		InternalUpdate: true,
	}:
		lgRollover.Debug("pushDSRRsetViaNotify: CDS publish enqueued on InternalUpdateQ",
			"zone", child)
	case <-time.After(5 * time.Second):
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("pushDSRRsetViaNotify: InternalUpdateQ full for 5s, skipping")
	case <-ctx.Done():
		out.Category = SoftfailChildConfigLocalError
		return out, ctx.Err()
	}

	// Persist the CDS-ownership marker before sending NOTIFY: if the
	// daemon crashes between publish and NOTIFY, the next attempt's
	// Trigger-2 cleanup logic still has a record of what we own, so
	// we don't orphan CDS.
	if idxOK {
		if err := setPublishedCdsRange(kdb, child, low, high); err != nil {
			out.Category = SoftfailChildConfigLocalError
			return out, fmt.Errorf("pushDSRRsetViaNotify: persist CDS range: %w", err)
		}
		lgRollover.Debug("pushDSRRsetViaNotify: CDS ownership marker stored",
			"zone", child, "index_low", low, "index_high", high)
	} else {
		// No authoritative range to record. Clear any stale range so a
		// subsequent cleanup pass doesn't compare against an old set.
		if err := clearPublishedCdsRange(kdb, child); err != nil {
			out.Category = SoftfailChildConfigLocalError
			return out, fmt.Errorf("pushDSRRsetViaNotify: clear CDS range: %w", err)
		}
		lgRollover.Debug("pushDSRRsetViaNotify: CDS ownership marker cleared (index range incomplete)",
			"zone", child)
	}

	// Send NOTIFY(CDS) and wait for the per-target aggregate response.
	respCh := make(chan NotifyResponse, 1)
	req := NotifyRequest{
		ZoneName: child,
		ZoneData: zd,
		RRtype:   dns.TypeCDS,
		Targets:  target.Addresses,
		Response: respCh,
	}
	notifyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	select {
	case notifyq <- req:
	case <-notifyCtx.Done():
		out.Category = SoftfailTransport
		return out, fmt.Errorf("pushDSRRsetViaNotify: enqueue NOTIFY: %w", notifyCtx.Err())
	}

	var resp NotifyResponse
	select {
	case resp = <-respCh:
	case <-notifyCtx.Done():
		out.Category = SoftfailTransport
		return out, fmt.Errorf("pushDSRRsetViaNotify: await NOTIFY response: %w", notifyCtx.Err())
	}

	out.Rcode = resp.Rcode
	if resp.Error {
		// resp.Error is set only on actual transport failure
		// (no target produced a usable response). Parent-rejected
		// rcodes come back via the resp.Rcode != NOERROR branch
		// below with resp.Error == false.
		out.Category = SoftfailTransport
		out.Detail = formatNotifyDetail(resp)
		return out, fmt.Errorf("pushDSRRsetViaNotify: %s", resp.ErrorMsg)
	}
	if resp.Rcode != dns.RcodeSuccess {
		out.Category = SoftfailParentRejected
		out.Detail = formatNotifyDetail(resp)
		return out, nil
	}
	// NOTIFY(CDS) acknowledged at the wire. Persist the publication
	// fact (keyids + timestamp) to the sparse RolloverCdsPublication
	// table. This survives Trigger-1 cleanup so the operator's
	// "CDS published [keyids] sent <time>" status line still
	// reflects the most recent publication after the rollover has
	// completed and the ownership marker is cleared.
	keyids := cdsKeyids(cdsSet)
	if err := setCdsPublication(kdb, child, keyids, time.Now().UTC()); err != nil {
		// Best-effort: a write failure here doesn't undo the on-wire
		// publication. Log and continue.
		lgRollover.Warn("pushDSRRsetViaNotify: setCdsPublication failed",
			"zone", child, "err", err)
	} else {
		lgRollover.Debug("pushDSRRsetViaNotify: CDS publication recorded",
			"zone", child, "keyids", keyids)
	}
	out.Scheme = "NOTIFY"
	return out, nil
}

// cdsKeyids extracts the SEP keyid from each CDS RR in the slice.
// Skips entries that aren't *dns.CDS (defensive; ComputeTargetCDSSetForZone
// only ever returns CDS RRs but the type assertion is cheap).
func cdsKeyids(cdsSet []dns.RR) []uint16 {
	out := make([]uint16, 0, len(cdsSet))
	for _, rr := range cdsSet {
		if c, ok := rr.(*dns.CDS); ok {
			out = append(out, c.DS.KeyTag)
		}
	}
	return out
}

// formatNotifyDetail renders a NotifyResponse's diagnostic info as
// a single string for KSKDSPushResult.Detail. Includes rcode and
// any EDE codes/text. Used by status output.
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
