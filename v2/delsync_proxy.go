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

	lgDns.Info("delegation-sync-proxy: change detected in transfer; queueing proxy NOTIFY",
		"zone", zd.ZoneName,
		"cds", analysis.CdsChanged, "csync", analysis.CsyncChanged,
		"ns_or_glue", analysis.NsOrGlueChanged, "dnskey", analysis.DnskeyChanged,
		"want_cds_notify", analysis.wantCDSNotify(), "want_csync_notify", analysis.wantCSYNCNotify())

	delsyncq <- DelegationSyncRequest{
		Command:    "PROXY-NOTIFY",
		ZoneName:   zd.ZoneName,
		ZoneData:   zd,
		SyncStatus: analysis.DelegationStatus,
	}
}
