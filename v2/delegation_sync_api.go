/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// SyncZoneDelegationViaApi pushes the child's delegation to its parent over the
// DSYNC API scheme (docs/2026-08-11-dsync-api-scheme.md §11).
//
// Declarative and idempotent: it sends what the delegation SHOULD be, not what
// changed, which is why a retry after an ambiguous failure is safe.
//
// The rcode is a DNS rcode because that is what the two older schemes return
// and what the callers understand. NOERROR means the parent said 200 -- which,
// on a tdns parent, means applied, persisted and being served.
func (zd *ZoneData) SyncZoneDelegationViaApi(ctx context.Context, imr *Imr,
	syncstate DelegationSyncStatus, dsynctarget *DsyncTarget) (string, uint8, error) {

	if dsynctarget == nil || dsynctarget.Name == "" {
		return "", dns.RcodeServerFailure, fmt.Errorf("zone %s: no DSYNC API target", zd.ZoneName)
	}

	parent := zd.Parent
	if parent == "" {
		return "", dns.RcodeServerFailure, fmt.Errorf("zone %s: parent zone unknown", zd.ZoneName)
	}

	childconf := DelegationSyncConfig().Child.Api
	cred, ok := childconf.CredentialFor(parent)
	if !ok {
		// One clear line and no retry loop. There is nothing to wait for: a
		// credential arrives out of band, by definition (§10), so retrying
		// cannot make one appear.
		return "", dns.RcodeRefused, fmt.Errorf(
			"zone %s: parent %s offers only the DSYNC API scheme but no credential is configured for it"+
				" (delegationsync.child.api.credentials); obtain one from the parent operator",
			zd.ZoneName, parent)
	}
	if cred.Username == "" || cred.Key == "" {
		return "", dns.RcodeRefused, fmt.Errorf(
			"zone %s: the DSYNC API credential for parent %s is missing a username or key",
			zd.ZoneName, parent)
	}

	// requireDnssec is the inverse of allow-insecure, and deliberately the
	// same switch (§8): DNSSEC establishes which endpoint was meant and TLS
	// establishes that this is it, so an operator who disables one while
	// believing the other still protects them has no protection at all.
	requireDnssec := !childconf.AllowInsecure

	dctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	endpoint, err := DiscoverDsyncApiEndpoint(dctx, imr, dsynctarget.Name, requireDnssec)
	if err != nil {
		return "", dns.RcodeServerFailure, fmt.Errorf("zone %s: %v", zd.ZoneName, err)
	}
	lgDns.Info("DSYNC API endpoint discovered", "zone", zd.ZoneName, "parent", parent,
		"target", endpoint.Target, "endpoint", endpoint.Url, "dialect", endpoint.Dialect)

	rrsets := DsyncApiRRsetsFromSyncStatus(zd.ZoneName, syncstate)
	if len(rrsets) == 0 {
		// Sending nothing would be a request the parent refuses as malformed.
		// Nothing to declare means nothing to do.
		return fmt.Sprintf("Zone %s: nothing to send to parent %s", zd.ZoneName, parent),
			dns.RcodeSuccess, nil
	}

	if _, err := DsyncApiPostDelegationRequest(dctx, endpoint, cred, zd.ZoneName, rrsets,
		childconf.AllowInsecure, childconf.CaFile); err != nil {
		return "", dns.RcodeServerFailure, fmt.Errorf("zone %s: %v", zd.ZoneName, err)
	}

	lgDns.Info("delegation synced to parent over the DSYNC API scheme",
		"zone", zd.ZoneName, "parent", parent, "rrsets", len(rrsets))

	return fmt.Sprintf("Zone %s: delegation sent to parent %s via the DSYNC API scheme (%d RRset%s)",
		zd.ZoneName, parent, len(rrsets), plural(len(rrsets))), dns.RcodeSuccess, nil
}
