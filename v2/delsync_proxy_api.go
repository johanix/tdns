/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * delegation-sync-proxy, API path: forwarding a child's delegation to a parent
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
	"time"

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
// The payload is read from the SERVED zone (proxyCurrentDelegationRRs), which
// is the same source the UPDATE proxy's replace form uses. It deliberately does
// NOT come from the ProxyDelegationAnalysis deltas: DelegationDataChangedNG
// fills only the Adds/Removes fields, never the New* ones that the declarative
// form is built from, so feeding it the analysis would produce an empty request
// and a silent no-op. The analysis is the trigger and the un-signing witness
// (see the DS rule below), not the payload.
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
	if zd.Parent == "" || zd.Parent == "." {
		p, perr := imr.ParentZone(zd.ZoneName)
		if perr != nil {
			return "", fmt.Errorf("ProxyApiParent: ParentZone(%s): %w", zd.ZoneName, perr)
		}
		zd.Parent = p
	}
	parent := zd.Parent

	childconf := DelegationSyncConfig().Child.Api
	// Keyed on (parent, child): one agent can be secondary for several child
	// zones under the same parent, each with its own credential there. An entry
	// with no child named matches any child under that parent, which is what a
	// single-child config already looks like.
	cred, ok := childconf.CredentialForChild(parent, zd.ZoneName)
	if !ok {
		return "", fmt.Errorf(
			"zone %s: parent %s advertises the DSYNC API scheme but this agent has no credential for it"+
				" (delegationsync.child.api.credentials; set `child: %s` on the entry if this agent proxies"+
				" more than one zone under %s): %w",
			zd.ZoneName, parent, zd.ZoneName, parent, ErrProxyApiNoCredential)
	}
	if cred.Username == "" || cred.Key == "" {
		return "", fmt.Errorf(
			"zone %s: the DSYNC API credential for parent %s is missing a username or key: %w",
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
	lgDns.Info("delegation-sync-proxy: DSYNC API endpoint discovered", "zone", zd.ZoneName,
		"parent", parent, "target", endpoint.Target, "endpoint", endpoint.Url,
		"dialect", endpoint.Dialect)

	rrsets := zd.proxyApiRRsets()
	if len(rrsets) == 0 {
		// An empty request is refused as malformed by the endpoint, and rightly
		// so: nothing to declare has to mean nothing, not "remove everything".
		return fmt.Sprintf("zone %s: nothing to declare to parent %s; nothing sent", zd.ZoneName, parent), nil
	}

	if _, err := DsyncApiPostDelegationRequest(dctx, endpoint, cred, zd.ZoneName, rrsets,
		childconf.AllowInsecure, childconf.CaFile); err != nil {
		return "", fmt.Errorf("zone %s: %v", zd.ZoneName, err)
	}

	msg := fmt.Sprintf("proxied delegation to parent %s via the DSYNC API scheme (%d RRset%s)",
		parent, len(rrsets), plural(len(rrsets)))
	lgDns.Info("delegation-sync-proxy: "+msg, "zone", zd.ZoneName, "parent", parent)
	return msg, nil
}

// proxyApiRRsets renders the served zone's delegation in the declarative form
// the endpoint takes.
//
// DS is deliberately absent from the request, with one exception below.
//
// The proxy has no business asserting a DS set for a signed child. It sees only
// the zone as transferred, and the DS the parent should hold is not derivable
// from that: a multi-DS rollover puts the new DS at the parent BEFORE the
// matching DNSKEY appears, so anything derived from published keys is missing
// exactly the record the rollover just placed. Deriving it from SEP-flagged
// keys is wrong a second way, since SEP is advisory -- a zone signed with a
// flags-256 CSK yields an empty set, and declaring that empty set tells the
// parent to delete the DS of a perfectly good child.
//
// The child's own statement about DS is its CDS/CDNSKEY RRset, and forwarding
// that is B1 in docs/2026-08-23-proxy-delegation-sync-scope.md. Until it lands,
// omitting DS leaves the parent holding what it already has, which is right in
// every case except the one below.
//
// The exception: a child with NO DNSKEY RRset at all. There is no procedure
// that produces "unsigned child, DS at the parent" on purpose, the state makes
// every validating resolver declare the whole child bogus, and the child cannot
// signal its way out because RFC 8078 CDS-delete needs a validation it has no
// key to provide. The predicate is the absence of the RRset, NOT an empty
// derived set -- those are different questions and conflating them is what
// would delete a CSK-signed child's DS.
func (zd *ZoneData) proxyApiRRsets() []DsyncApiRRset {
	newNS, newA, newAAAA, _ := zd.proxyCurrentDelegationRRs()

	rrsets := DsyncApiRRsetsFromSyncStatus(zd.ZoneName, DelegationSyncStatus{
		ZoneName: zd.ZoneName,
		Parent:   zd.Parent,
		NewNS:    newNS,
		NewA:     newA,
		NewAAAA:  newAAAA,
	})

	if !zd.hasDnskeyRRset() {
		lgDns.Info("delegation-sync-proxy: child publishes no DNSKEY RRset;"+
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
