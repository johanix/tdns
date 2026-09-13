package tdns

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// pushDSRRsetViaNotify is the NOTIFY(CDS) counterpart to
// pushDSRRsetViaUpdate. It asks the DS engine to publish the CDS for
// the rollover target at the child apex, and dispatches NOTIFY(CDS) to
// the parent's DSYNC NOTIFY target once the zone serves it.
//
// The DS engine also persists last_published_cds_index_low/high, the
// claim on the on-wire CDS that cleanup-time comparison reads, before
// this sends the NOTIFY. CDS stays published until
// cleanupCdsAfterConfirm runs (Phase 5).
//
// On NOTIFY failure (transport or parent-rejected): leave CDS
// published. Next attempt re-derives the same CDS set; the publish
// step becomes a no-op (anti-CDS ClassANY delete + identical adds)
// and NOTIFY is re-sent. No churn.
//
// The publish waits. It used to be queue-and-forget, relying on the
// asynchronous apply and sign racing ahead of the parent's fetch; a
// parent that fetched first found no CDS, or the previous one, and
// the attempt surfaced as a parent-side failure. The zone updater signs
// what it stages before the publish that carries it, so a CDS the zone
// serves is already signed.
func pushDSRRsetViaNotify(ctx context.Context, deps RolloverEngineDeps, target *DsyncTarget) (KSKDSPushResult, error) {
	var out KSKDSPushResult
	zd := deps.Zone
	kdb := deps.KDB
	notifyq := deps.NotifyQ
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

	child := dns.Fqdn(zd.ZoneName)

	pub := kdb.askDSEngine(ctx, DSEngineRequest{
		cmd:      dsCmdPublishRolloverCDS,
		zd:       zd,
		snapshot: deps.TargetKeySnapshot,
	})
	if pub.err != nil {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("pushDSRRsetViaNotify: %w", pub.err)
	}
	cdsSet := pub.cds
	lgRollover.Debug("pushDSRRsetViaNotify: CDS published",
		"zone", child, "cds_count", len(cdsSet),
		"index_low", pub.low, "index_high", pub.high, "index_known", pub.rangeKnown)

	// Send NOTIFY(CDS) and wait for the per-target aggregate response.
	respCh := make(chan NotifyResponse, 1)
	req := NotifyRequest{
		ZoneName: child,
		ZoneData: zd,
		RRtype:   dns.TypeCDS,
		Targets:  target.Addresses,
		Response: respCh,
	}
	// Bound the NOTIFY round-trip. Derive from the operator's
	// parent-cds-poll-estimate (W6) when set: max(30s, 2 ×
	// parentCdsPollEstimate) gives a 30s floor for healthy parents
	// and scales up for parents that batch CDS polls. Falls back to
	// 30s when policy is nil (legacy CLI offline call sites).
	notifyTimeout := notifyTimeoutFromPolicy(deps.Policy)
	notifyCtx, cancel := context.WithTimeout(ctx, notifyTimeout)
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

// notifyTimeoutFromPolicy returns the NOTIFY round-trip timeout for
// pushDSRRsetViaNotify. Floor 30s (covers healthy parents that fetch
// CDS within seconds), scales up to 2 × parent-cds-poll-estimate for
// parents that batch their CDS polls (registries with multi-minute
// poll cycles). Returns 30s when pol is nil (legacy CLI call sites).
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
