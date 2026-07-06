/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * delegation-sync-proxy: a tdns-agent acting as a SECONDARY for a zone whose
 * primary is DSYNC-unaware (BIND/Knot). On each incoming transfer the agent
 * diffs the apex CDS / CSYNC / NS+glue / DNSKEY RRsets old-vs-new and, when a
 * relevant RRset changed, forwards a NOTIFY(CDS/CSYNC) to the parent's DSYNC
 * receiver on the primary's behalf. The primary stays DSYNC-clueless.
 *
 * This file holds the change-detection trigger (P-2): a PreRefresh hook (which
 * sees both old and new zone data) records what changed into
 * zd.ProxyRefreshAnalysis, and a PostRefresh hook acts on it. The proxy NOTIFY
 * action itself is the PROXY-NOTIFY DelegationSyncher command (P-3).
 */
package tdns

import (
	"context"
	"fmt"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// ProxyDelegationAnalysis records, per incoming transfer, which
// delegation-relevant apex RRsets changed. Computed by the PreRefresh hook
// (old-vs-new), consumed by the PostRefresh hook. The wide set (NS/glue and
// DNSKEY in addition to CDS/CSYNC) is detected now so the future UPDATE path
// inherits the deltas; the NOTIFY act-mapping (D4) is:
//
//	NOTIFY(CDS)   when CdsChanged   OR DnskeyChanged
//	NOTIFY(CSYNC) when CsyncChanged OR NsOrGlueChanged
type ProxyDelegationAnalysis struct {
	CdsChanged      bool
	CsyncChanged    bool
	NsOrGlueChanged bool
	DnskeyChanged   bool
	// DelegationStatus carries the NS/glue/DS deltas from DelegationDataChangedNG,
	// kept for the future UPDATE-proxy path (it is not needed to decide a NOTIFY).
	DelegationStatus DelegationSyncStatus
}

// anyChange reports whether any dimension that drives a NOTIFY changed.
func (a *ProxyDelegationAnalysis) anyChange() bool {
	return a.CdsChanged || a.CsyncChanged || a.NsOrGlueChanged || a.DnskeyChanged
}

// wantCDSNotify / wantCSYNCNotify apply the D4 act-mapping.
func (a *ProxyDelegationAnalysis) wantCDSNotify() bool   { return a.CdsChanged || a.DnskeyChanged }
func (a *ProxyDelegationAnalysis) wantCSYNCNotify() bool { return a.CsyncChanged || a.NsOrGlueChanged }

// ProxyDelegationPreRefresh runs BEFORE the hard flip on a delegation-sync-proxy
// zone. It diffs the incoming zone (new_zd) against the currently-served zone
// (zd) for the four delegation-relevant dimensions and records the result in
// zd.ProxyRefreshAnalysis for the PostRefresh hook. It must NOT act here (the
// new data is not yet served).
func (zd *ZoneData) ProxyDelegationPreRefresh(new_zd *ZoneData) {
	analysis := &ProxyDelegationAnalysis{}

	// CDS / CSYNC: direct apex RRset diff. These are the primary's explicit
	// opt-in signal; a change in either is the core proxy trigger.
	analysis.CdsChanged = zd.apexRRsetChanged(new_zd, dns.TypeCDS)
	analysis.CsyncChanged = zd.apexRRsetChanged(new_zd, dns.TypeCSYNC)

	// NS + glue + DS: reuse the existing delegation diff (also yields the
	// deltas the future UPDATE path needs). NsOrGlueChanged is derived from the
	// NS/A/AAAA adds/removes; DS deltas are kept in DelegationStatus but do not
	// drive a NOTIFY on their own (a DS change at the child means a DNSKEY
	// change, which DnskeysChangedNG catches below).
	if changed, dss, err := zd.DelegationDataChangedNG(new_zd); err != nil {
		zd.Logger.Printf("ProxyDelegationPreRefresh: DelegationDataChangedNG failed for %s: %v", zd.ZoneName, err)
	} else if changed {
		analysis.DelegationStatus = dss
		analysis.NsOrGlueChanged = len(dss.NsAdds) > 0 || len(dss.NsRemoves) > 0 ||
			len(dss.AAdds) > 0 || len(dss.ARemoves) > 0 ||
			len(dss.AAAAAdds) > 0 || len(dss.AAAARemoves) > 0
	}

	// DNSKEY: reuse the existing DNSKEY diff. A DNSKEY change implies a possible
	// DS change at the parent, so it drives a NOTIFY(CDS) (D4).
	if changed, err := zd.DnskeysChangedNG(new_zd); err != nil {
		zd.Logger.Printf("ProxyDelegationPreRefresh: DnskeysChangedNG failed for %s: %v", zd.ZoneName, err)
	} else {
		analysis.DnskeyChanged = changed
	}

	zd.mu.Lock()
	zd.ProxyRefreshAnalysis = analysis
	zd.mu.Unlock()
}

// apexRRsetChanged reports whether the apex RRset of type rrtype differs between
// the served zone (zd) and the incoming zone (new_zd), using the canonical
// RRset comparison. A missing owner / RRset on either side is treated as an
// empty set, so an appearance or disappearance counts as a change.
func (zd *ZoneData) apexRRsetChanged(new_zd *ZoneData, rrtype uint16) bool {
	var oldRRs, newRRs []dns.RR
	if oldapex, err := zd.GetOwner(zd.ZoneName); err == nil && oldapex != nil {
		oldRRs = oldapex.RRtypes.GetOnlyRRSet(rrtype).RRs
	}
	if newapex, err := new_zd.GetOwner(zd.ZoneName); err == nil && newapex != nil {
		newRRs = newapex.RRtypes.GetOnlyRRSet(rrtype).RRs
	}
	differ, _, _ := core.RRsetDiffer(zd.ZoneName, newRRs, oldRRs, rrtype, zd.Logger, Globals.Verbose, Globals.Debug)
	return differ
}

// ProxyDelegationPostRefresh runs AFTER the hard flip on a
// delegation-sync-proxy zone. It consumes the analysis recorded by the
// PreRefresh hook and, when a NOTIFY-relevant dimension changed (D4), enqueues
// a PROXY-NOTIFY request to the DelegationSyncher (the action lives there,
// P-3). The analysis is cleared whether or not anything was enqueued, so a
// later unrelated refresh starts fresh.
func (zd *ZoneData) ProxyDelegationPostRefresh(delsyncq chan DelegationSyncRequest) {
	zd.mu.Lock()
	analysis := zd.ProxyRefreshAnalysis
	zd.ProxyRefreshAnalysis = nil
	zd.mu.Unlock()

	if analysis == nil || !analysis.anyChange() {
		return
	}
	if delsyncq == nil {
		zd.Logger.Printf("ProxyDelegationPostRefresh: DelegationSyncQ unavailable for %s; cannot proxy", zd.ZoneName)
		return
	}

	lgDns.Info("delegation-sync-proxy: change detected in transfer; queueing proxy sync",
		"zone", zd.ZoneName,
		"cds", analysis.CdsChanged, "csync", analysis.CsyncChanged,
		"ns_or_glue", analysis.NsOrGlueChanged, "dnskey", analysis.DnskeyChanged,
		"want_cds_notify", analysis.wantCDSNotify(), "want_csync_notify", analysis.wantCSYNCNotify())

	// Non-blocking enqueue: this runs on the refresh path, which has no ctx to
	// select on, so we must not block on a backed-up queue (e.g. during
	// shutdown). Dropping is safe — the proxy is idempotent: the next transfer
	// re-detects the still-unforwarded change and re-enqueues. The handler picks
	// UPDATE vs NOTIFY off the refresh path (scheme discovery is network).
	select {
	case delsyncq <- DelegationSyncRequest{
		Command:       "PROXY-SYNC",
		ZoneName:      zd.ZoneName,
		ZoneData:      zd,
		SyncStatus:    analysis.DelegationStatus,
		ProxyAnalysis: analysis,
	}:
	default:
		zd.Logger.Printf("ProxyDelegationPostRefresh: DelegationSyncQ full for %s; dropping proxy sync (will re-detect on next transfer)", zd.ZoneName)
	}
}

// ProxyNotifyParent forwards NOTIFY(CDS) and/or NOTIFY(CSYNC) to the parent's
// DSYNC NOTIFY receiver on behalf of a DSYNC-unaware primary, for the
// dimensions recorded in analysis (D4 act-mapping). It does NOT publish or sign
// anything: a NOTIFY is a contentless "come re-scan me" signal — the CDS/CSYNC
// the primary published are already in the served zone, and the parent reads
// them itself. NOTIFY is the only scheme used here (D3/D9); if the parent does
// not advertise a NOTIFY DSYNC target, this is a no-op (not an error — the
// parent may not offer the service, or may want UPDATE, which is later work).
func (zd *ZoneData) ProxyNotifyParent(ctx context.Context, notifyq chan NotifyRequest, imr *Imr, analysis *ProxyDelegationAnalysis) (string, error) {
	if analysis == nil || !analysis.anyChange() {
		return "no change to proxy", nil
	}
	if zd.Parent == "" || zd.Parent == "." {
		p, err := imr.ParentZone(zd.ZoneName)
		if err != nil {
			return "", fmt.Errorf("ProxyNotifyParent: ParentZone(%s): %w", zd.ZoneName, err)
		}
		zd.Parent = p
	}

	scheme, dsynctarget, err := zd.BestSyncScheme(ctx, imr)
	if err != nil {
		return "", fmt.Errorf("ProxyNotifyParent: BestSyncScheme(%s): %w", zd.ZoneName, err)
	}
	// NOTIFY-only for now (D3/D9). If the parent advertises only UPDATE we
	// cannot proxy yet; report and stop without error.
	if scheme != "NOTIFY" || dsynctarget == nil || len(dsynctarget.Addresses) == 0 {
		lgDns.Info("delegation-sync-proxy: parent does not advertise a usable NOTIFY DSYNC target; nothing forwarded",
			"zone", zd.ZoneName, "parent", zd.Parent, "scheme", scheme)
		return "parent advertises no NOTIFY DSYNC target; nothing forwarded", nil
	}

	sent := zd.emitProxyNotifies(ctx, notifyq, analysis, dsynctarget.Addresses)
	lgDns.Info("delegation-sync-proxy: forwarded NOTIFY(s) to parent",
		"zone", zd.ZoneName, "parent", zd.Parent, "sent", sent, "target", dsynctarget.Addresses)
	return fmt.Sprintf("forwarded NOTIFY(%v) to parent %s", sent, zd.Parent), nil
}

// emitProxyNotifies sends the NOTIFY(s) the act-mapping (D4) calls for to the
// given targets, and returns the list of RRtypes notified ("CSYNC"/"CDS").
// Separated from DSYNC discovery so the act-mapping → emission is testable
// without the network. CSYNC is sent before CDS for a stable, predictable order.
// The sends are ctx-aware so a backed-up notifyq cannot block shutdown; a
// cancelled context stops further sends and returns what was sent so far.
func (zd *ZoneData) emitProxyNotifies(ctx context.Context, notifyq chan NotifyRequest, analysis *ProxyDelegationAnalysis, targets []string) []string {
	var sent []string
	if analysis.wantCSYNCNotify() {
		select {
		case notifyq <- NotifyRequest{ZoneName: zd.ZoneName, ZoneData: zd, RRtype: dns.TypeCSYNC, Targets: targets}:
			sent = append(sent, "CSYNC")
		case <-ctx.Done():
			return sent
		}
	}
	if analysis.wantCDSNotify() {
		select {
		case notifyq <- NotifyRequest{ZoneName: zd.ZoneName, ZoneData: zd, RRtype: dns.TypeCDS, Targets: targets}:
			sent = append(sent, "CDS")
		case <-ctx.Done():
			return sent
		}
	}
	return sent
}
