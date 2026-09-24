/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * parentsync-proxy, API path: forwarding a child's delegation to a parent
 * that advertises the DSYNC API scheme (docs/2026-08-11-dsync-api-scheme.md),
 * on behalf of a DSYNC-unaware primary.
 *
 * This is the proxy counterpart of SyncZoneDelegationViaApi, and it is much
 * smaller than the UPDATE proxy for one reason: there is no key bootstrap. The
 * UPDATE proxy has to get a SIG(0) KEY published at the child apex before the
 * parent will trust it, which a SECONDARY cannot do itself -- hence the §10.8
 * state machine and the operator instruction. The API scheme's credential
 * arrives out of band by definition (§10), so it is either in the config or it
 * is not. Nothing to wait for, and no state machine.
 *
 * What does NOT relax here is §8. The credential is a bearer token, so a child
 * misdirected to the wrong endpoint hands an attacker something that works --
 * unlike a SIG(0)-signed UPDATE, which is useless to whoever receives it. Every
 * guard in the client path (DNSSEC-validated discovery, https, certificate
 * validation, no redirects) therefore applies unchanged to the proxy, and this
 * file adds no way around any of them.
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// ErrProxyApiNoCredential marks the one API failure that is a CONFIGURATION
// gap rather than a protocol or security failure: this agent holds no usable
// credential for the parent.
//
// In normal operation this is never returned: the sync plan evaluates the same
// condition as the API gate, so a candidate that reaches here already has a
// credential. It survives as a sentinel for two reasons -- a direct caller that
// did not build a plan, and the fact that "no credential" must stay
// distinguishable from a security refusal. A failed DNSSEC validation, a
// non-https endpoint or a redirect are the signals §8 exists to raise, and
// nothing may ever treat them as a routine configuration gap.
var ErrProxyApiNoCredential = errors.New("no usable DSYNC API credential for this parent")

// proxyApiDiscoveryTimeout bounds discovery plus the POST. Same 60s the
// tdns-auth child path uses; this runs in the DelegationSyncher, off the
// refresh path, so a slow parent delays nothing that serves DNS.
const proxyApiDiscoveryTimeout = 60 * time.Second

// ProxyApiParent forwards the current delegation to the parent over the DSYNC
// API scheme, on the primary's behalf.
//
// Declarative and idempotent, like the tdns-auth child path: it sends what the
// delegation SHOULD be rather than what changed, so a retry after an ambiguous
// failure is safe and a replayed send is a no-op at the parent.
//
// The payload is read from the SERVED zone (currentDelegationRRs), which
// is the same source the UPDATE proxy's replace form uses. It deliberately does
// NOT come from the ProxyDelegationAnalysis deltas: DelegationDataChangedNG
// fills only the Adds/Removes fields, never the New* ones that the declarative
// form is built from, so feeding it the analysis would produce an empty request
// and a silent no-op. The analysis is the trigger, not the payload -- with one
// exception: the nameservers it saw LEAVE the NS RRset. The served zone has no
// trace of those, and their glue has to be deleted in the same request
// (proxyRemovedNS, #665).
//
// It is not the un-signing witness: the DS question is decided by
// hasDnskeyRRset alone. Said explicitly because an earlier wording sent a
// reader looking for a witness check that does not exist.
func (zd *ZoneData) ProxyApiParent(ctx context.Context, imr *Imr, dsynctarget *DsyncTarget,
	analysis *ProxyDelegationAnalysis) (string, error) {

	if dsynctarget == nil || dsynctarget.Name == "" {
		return "", fmt.Errorf("zone %s: no DSYNC API target", zd.ZoneName)
	}
	if imr == nil {
		return "", fmt.Errorf("zone %s: no IMR available for DSYNC API discovery", zd.ZoneName)
	}

	// BuildParentSyncPlan resolves the parent before any gate is evaluated, so
	// on the normal path this is already set. Kept for a direct caller that did
	// not build a plan: the credential is keyed on the parent, so an unresolved
	// one would silently look up the wrong thing.
	parent, perr := zd.ResolveParentVia(imr)
	if perr != nil {
		return "", fmt.Errorf("ProxyApiParent: %w", perr)
	}

	childconf := ParentSyncConfig().Api
	// Keyed on (parent, child): one agent can be secondary for several child
	// zones under the same parent, each with its own credential there. An entry
	// with no child named matches any child under that parent, which is what a
	// single-child config already looks like.
	cred, ok := childconf.CredentialForChild(parent, zd.ZoneName)
	if !ok {
		return "", fmt.Errorf(
			"zone %s: parent %s advertises the DSYNC API scheme but this agent has no credential for it"+
				" (parentsync.api.credentials; set `child: %s` on the entry if this agent proxies"+
				" more than one zone under %s): %w",
			zd.ZoneName, parent, zd.ZoneName, parent, ErrProxyApiNoCredential)
	}
	if !cred.Usable() {
		return "", fmt.Errorf(
			"zone %s: the DSYNC API credential for parent %s is missing a username/key or a tls cert/key: %w",
			zd.ZoneName, parent, ErrProxyApiNoCredential)
	}

	// One switch for both, per §16.6: DNSSEC establishes which endpoint was
	// meant and TLS establishes that this is it, so they are not separable.
	requireDnssec := !childconf.AllowInsecure

	dctx, cancel := context.WithTimeout(ctx, proxyApiDiscoveryTimeout)
	defer cancel()

	endpoint, err := DiscoverDsyncApiEndpoint(dctx, imr, dsynctarget.Name, requireDnssec)
	if err != nil {
		return "", fmt.Errorf("zone %s: %v", zd.ZoneName, err)
	}
	lgDns.Info("parentsync-proxy: DSYNC API endpoint discovered", "zone", zd.ZoneName,
		"parent", parent, "target", endpoint.Target, "endpoint", endpoint.Url,
		"dialect", endpoint.Dialect, "addrs", endpoint.Addrs)

	rrsets := zd.proxyApiRRsets(analysis, zd.proxyParentOnlyNS(imr))
	if len(rrsets) == 0 {
		// An empty request is refused as malformed by the endpoint, and rightly
		// so: nothing to declare has to mean nothing, not "remove everything".
		return fmt.Sprintf("zone %s: nothing to declare to parent %s; nothing sent", zd.ZoneName, parent), nil
	}

	// The change is already public -- the agent learnt of it by transfer -- so
	// there is nothing to hold back on a refusal. What is left is to say
	// exactly what was sent and what the parent made of it, in the line that
	// reports the outcome.
	payload := dsyncApiRRsetsForLog(rrsets)
	del, err := DsyncApiPostDelegationRequest(dctx, endpoint, cred, zd.ZoneName, rrsets,
		childconf.AllowInsecure, childconf.CaFile)
	if err != nil {
		lgDns.Error("parentsync-proxy: the parent did not accept the delegation",
			"zone", zd.ZoneName, "parent", parent, "err", err, "rrsets", payload)
		return "", fmt.Errorf("zone %s: %v", zd.ZoneName, err)
	}

	// A 200 says applied; the read-back says whether the delegation is now
	// what was declared. Same check as the tdns-auth child path.
	diffs, comparable := dsyncApiUnconverged(rrsets, del)
	switch {
	case !comparable:
		lgDns.Warn("parentsync-proxy: the parent accepted the delegation; its read-back could not be compared",
			"zone", zd.ZoneName, "parent", parent, "rrsets", payload)
	case len(diffs) > 0:
		lgDns.Error("parentsync-proxy: the parent accepted the delegation but it differs from what was sent",
			"zone", zd.ZoneName, "parent", parent, "differences", strings.Join(diffs, "; "), "rrsets", payload)
		return "", fmt.Errorf("zone %s: parent %s applied the update but the delegation still differs from what was sent: %s",
			zd.ZoneName, parent, strings.Join(diffs, "; "))
	}

	msg := fmt.Sprintf("proxied delegation to parent %s via the DSYNC API scheme (%d RRset%s)",
		parent, len(rrsets), plural(len(rrsets)))
	lgDns.Info("parentsync-proxy: "+msg, "zone", zd.ZoneName, "parent", parent, "rrsets", payload)
	return msg, nil
}

// proxyRemovedNS returns the NS records a proxy sync takes out of the
// delegation: those the comparison that triggered it saw leave (the transfer
// diff, or at startup the parent-versus-child analysis), and parentOnly, the
// ones the parent still serves although the zone no longer has them
// (proxyParentOnlyNS).
//
// The served zone cannot answer this. A withdrawn nameserver is simply absent
// from it, so a payload built from it alone never deleted that nameserver's
// glue at the parent (#665). And the triggering comparison alone is not
// enough either: it describes one transfer, so a withdrawal whose sync failed
// was in no later comparison, and every later payload left its glue behind for
// the parent to refuse (#722). Duplicates, and names the zone has since taken
// back, are dropped where the glue deletes are derived (withdrawnGlueOwners).
func proxyRemovedNS(analysis *ProxyDelegationAnalysis, parentOnly []dns.RR) []dns.RR {
	var out []dns.RR
	if analysis != nil {
		out = append(out, analysis.DelegationStatus.NsRemoves...)
	}
	return append(out, parentOnly...)
}

// proxyParentOnlyNS returns the NS records the parent serves for the zone that
// the served zone no longer has: withdrawals the parent has not been told
// about, whatever happened to the sync that should have told it (#722). nil
// when the parent cannot be read; the triggering comparison is then all a sync
// has to go on, as before.
func (zd *ZoneData) proxyParentOnlyNS(imr *Imr) []dns.RR {
	if imr == nil {
		return nil
	}
	if err := zd.FetchParentData(imr); err != nil {
		lgDns.Warn("parentsync-proxy: cannot read the parent's NS RRset; withdrawals come from the triggering change only",
			"zone", zd.ZoneName, "err", err)
		return nil
	}
	pns, _, err := zd.parentNSRRset()
	if err != nil {
		lgDns.Warn("parentsync-proxy: cannot read the parent's NS RRset; withdrawals come from the triggering change only",
			"zone", zd.ZoneName, "err", err)
		return nil
	}
	childNS, _, _, _ := zd.currentDelegationRRs()
	return parentOnlyNS(zd.ZoneName, childNS, pns)
}

// parentOnlyNS returns the NS records in parentNS that childNS does not have.
//
// Nothing when childNS is empty. A delegation always has nameservers, so an
// empty set is a view of the zone that failed, not a zone that withdrew every
// nameserver -- and read as one, it would delete the glue of every nameserver
// the parent has.
func parentOnlyNS(zone string, childNS, parentNS []dns.RR) []dns.RR {
	if len(childNS) == 0 {
		return nil
	}
	_, _, removes := core.RRsetDiffer(zone, childNS, parentNS, dns.TypeNS, nil, false, false)
	return removes
}

// proxyApiRRsets renders the served zone's delegation in the declarative form
// the endpoint takes.
//
// The DS is the child's own statement about it, its CDS, when the child serves
// one (#752, design docs/2026-09-24-cds-publication-and-rfc-conformance.md
// §1.2 (e); B1 in docs/2026-08-23-proxy-delegation-sync-scope.md). A tdns
// signer now publishes one for every zone whose keys it manages. A CDS holding
// an algorithm-0 record is not delivered yet: which such set is the RFC 8078
// delete is Part 2's classifier to decide.
//
// With no CDS, DS is deliberately absent from the request, with one exception
// below. The proxy has no business deriving a DS set for a signed child. It
// sees only the zone as transferred, and the DS the parent should hold is not
// derivable from that: a multi-DS rollover puts the new DS at the parent BEFORE
// the matching DNSKEY appears, so anything derived from published keys is
// missing exactly the record the rollover just placed. Deriving it from
// SEP-flagged keys is wrong a second way, since SEP is advisory -- a zone
// signed with a flags-256 CSK yields an empty set, and declaring that empty set
// tells the parent to delete the DS of a perfectly good child. Omitting DS
// leaves the parent holding what it already has, which is right in every case
// except the one below.
//
// The exception: a child with NO DNSKEY RRset at all. There is no procedure
// that produces "unsigned child, DS at the parent" on purpose, the state makes
// every validating resolver declare the whole child bogus, and the child cannot
// signal its way out because RFC 8078 CDS-delete needs a validation it has no
// key to provide. The predicate is the absence of the RRset, NOT an empty
// derived set -- those are different questions and conflating them is what
// would delete a CSK-signed child's DS.
//
// analysis is the comparison that triggered the sync. Only the NS records it
// saw leave the delegation are read from it (proxyRemovedNS): that is the one
// thing the served zone cannot say, and it is what deletes a withdrawn
// nameserver's glue. nil means nothing was removed.
func (zd *ZoneData) proxyApiRRsets(analysis *ProxyDelegationAnalysis, parentOnly []dns.RR) []DsyncApiRRset {
	newNS, newA, newAAAA, _ := zd.currentDelegationRRs()

	status := DelegationSyncStatus{
		ZoneName:  zd.ZoneName,
		Parent:    zd.GetParent(),
		NewNS:     newNS,
		NewA:      newA,
		NewAAAA:   newAAAA,
		NsRemoves: proxyRemovedNS(analysis, parentOnly),
	}
	// The DS the served CDS asks for, when there is one: the signer's
	// statement of what the parent should hold (#752, design §1.2 (e)). With
	// no CDS the payload declares no DS, as before.
	signed := zd.hasDnskeyRRset()
	if cdsDS, served, usable := zd.proxyDSFromCDS(); signed && served && usable {
		status.NewDS, status.NewDSKnown = cdsDS, true
	}
	rrsets := DsyncApiRRsetsFromSyncStatus(zd.ZoneName, status)

	if !signed {
		lgDns.Info("parentsync-proxy: child publishes no DNSKEY RRset;"+
			" declaring an empty DS so the parent stops making it bogus", "zone", zd.ZoneName)
		rrsets = append(rrsets, DsyncApiRRset{
			Owner: dns.Fqdn(zd.ZoneName),
			Type:  dns.TypeToString[dns.TypeDS],
			RRs:   []string{},
		})
	}

	return rrsets
}

// hasDnskeyRRset reports whether the served zone publishes any DNSKEY at its
// apex, SEP-flagged or not.
//
// The SEP bit is deliberately not consulted. It is advisory, validators ignore
// it, and a zone signed with a flags-256 CSK is signed -- reading "no SEP key"
// as "not signed" is how a working child gets its DS deleted.
func (zd *ZoneData) hasDnskeyRRset() bool {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil || apex.RRtypes == nil {
		// Unknown, not empty. Saying "no DNSKEYs" on a failed lookup would turn
		// a transient read error into a DS withdrawal.
		return true
	}
	return len(apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs) > 0
}
