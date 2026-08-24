/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * KSK rollover: pushing the DS RRset to the parent over the DSYNC API scheme.
 *
 * The third transport, alongside UPDATE (ksk_rollover_ds_push.go) and NOTIFY
 * (ksk_rollover_ds_notify.go). It exists because without it a parent that
 * advertises ONLY the API scheme stalls a KSK rollover forever: the scheme
 * classifier saw nothing usable, which is errNoUsableScheme, which is
 * child-config:waiting-for-parent -- a softfail that by design never hardfails.
 * The rollover waited indefinitely on a parent that could have taken the DS
 * immediately, since the endpoint manages DS (dsyncApiManagedTypes).
 *
 * Declarative, and deliberately narrow: the request carries the DS RRset and
 * NOTHING else. "An RRset absent from the request is left alone by the parent"
 * (§7.2) is what makes that safe -- the rollover engine has an opinion about
 * DS and none whatsoever about NS or glue, and it must not express one by
 * omission or otherwise.
 *
 * Everything §8 requires of the API scheme applies here unchanged: the
 * endpoint comes only from DNSSEC-validated discovery, the credential only
 * goes over https to the host discovery named, certificates are validated and
 * redirects refused. Those live in the shared client; this file adds no way
 * around any of them.
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// rolloverApiTimeout bounds endpoint discovery plus the POST. The rollover
// engine runs on a tick, off any query path, so a slow parent delays nothing
// that serves DNS.
const rolloverApiTimeout = 60 * time.Second

// pushDSRRsetViaApi publishes the rollover's target DS RRset at the parent
// over the DSYNC API scheme.
//
// The target is the one pickRolloverSchemes already resolved; this does not
// rediscover. Note that an API target carries no addresses by design (§16.7) --
// only its name matters, because the URI published there names the host that
// actually resolves.
func pushDSRRsetViaApi(ctx context.Context, deps RolloverEngineDeps, target *DsyncTarget) (KSKDSPushResult, error) {
	var out KSKDSPushResult
	out.Scheme = "API"

	zd := deps.Zone
	kdb := deps.KDB
	imr := deps.Imr
	if zd == nil || kdb == nil || imr == nil {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("pushDSRRsetViaApi: nil argument")
	}
	if target == nil || target.Name == "" {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("pushDSRRsetViaApi: no DSYNC API target")
	}

	child := dns.Fqdn(zd.ZoneName)
	parent := dns.Fqdn(zd.Parent)
	if parent == "" || parent == "." {
		p, err := imr.ParentZone(child)
		if err != nil {
			out.Category = SoftfailTransport
			return out, fmt.Errorf("pushDSRRsetViaApi: parent zone: %w", err)
		}
		parent = dns.Fqdn(p)
	}

	// Same DS set the UPDATE path would send, from the same helpers, so the
	// three transports never disagree about what is being published.
	var (
		dsSet []dns.RR
		low   int
		high  int
		idxOK bool
		err   error
	)
	if deps.TargetKeySnapshot != nil {
		dsSet, low, high, idxOK, err = dsSetFromSnapshot(deps.TargetKeySnapshot, child, uint8(dns.SHA256), deps.Policy)
	} else {
		dsSet, low, high, idxOK, err = ComputeTargetDSSetForZone(kdb, child, uint8(dns.SHA256), deps.Policy)
	}
	if err != nil {
		out.Category = SoftfailChildConfigLocalError
		return out, err
	}
	if len(dsSet) == 0 {
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf("pushDSRRsetViaApi: no DS records to publish for zone %s", child)
	}

	childconf := DelegationSyncConfig().Child.Api
	cred, ok := childconf.CredentialFor(parent)
	if !ok || cred.Username == "" || cred.Key == "" {
		// A local configuration gap, NOT waiting-for-parent. The parent is
		// advertising the scheme correctly and would accept the push; what is
		// missing is a credential, which arrives out of band (§10) and which no
		// amount of waiting on the parent will produce. Categorising this as a
		// parent problem would leave it retrying invisibly forever.
		out.Category = SoftfailChildConfigLocalError
		return out, fmt.Errorf(
			"pushDSRRsetViaApi: no DSYNC API credential for parent %s"+
				" (delegationsync.child.api.credentials); obtain one from the parent operator", parent)
	}

	// One switch for plaintext and for unvalidated discovery (§16.6): they are
	// the same protection seen from two sides.
	requireDnssec := !childconf.AllowInsecure

	actx, cancel := context.WithTimeout(ctx, rolloverApiTimeout)
	defer cancel()

	endpoint, err := DiscoverDsyncApiEndpoint(actx, imr, target.Name, requireDnssec)
	if err != nil {
		// Discovery failed or did not validate. Retryable and the parent's to
		// fix, so transport rather than a local error -- but it is emphatically
		// not something to work around.
		out.Category = SoftfailTransport
		return out, fmt.Errorf("pushDSRRsetViaApi: %w", err)
	}

	rrs := make([]string, 0, len(dsSet))
	for _, rr := range dsSet {
		rrs = append(rrs, rr.String())
	}
	rrsets := []DsyncApiRRset{{
		Owner: child,
		Type:  dns.TypeToString[dns.TypeDS],
		RRs:   rrs,
	}}

	if _, err := DsyncApiPostDelegationRequest(actx, endpoint, cred, child, rrsets,
		childconf.AllowInsecure, childconf.CaFile); err != nil {
		out.Category = classifyDsyncApiPushFailure(err)
		return out, fmt.Errorf("pushDSRRsetViaApi: %w", err)
	}

	// 200 from a tdns parent means applied, persisted and being served (§7.3),
	// which is the same promise a NOERROR carries on the UPDATE path. Reported
	// as NOERROR so the aggregator treats the three transports alike.
	out.Rcode = dns.RcodeSuccess

	if idxOK {
		if err := saveLastDSSubmittedRange(kdb, child, low, high); err != nil {
			out.Category = SoftfailChildConfigLocalError
			return out, fmt.Errorf("pushDSRRsetViaApi: persist submitted range: %w", err)
		}
	} else {
		// No meaningful range to record; clear any stale one rather than leave
		// persisted columns describing an older submission.
		if err := clearLastDSSubmittedRange(kdb, child); err != nil {
			out.Category = SoftfailChildConfigLocalError
			return out, fmt.Errorf("pushDSRRsetViaApi: clear stale submitted range: %w", err)
		}
	}
	return out, nil
}

// classifyDsyncApiPushFailure maps an endpoint failure onto the rollover's
// softfail categories, which decide backoff and whether an operator is told to
// go and fix something.
//
// The status code is the whole signal, and §7.3 already assigns it a meaning:
//
//	400  we sent something the endpoint will not accept  -> local error
//	401  our credential is wrong                         -> local error
//	403  authenticated, the parent's policy says no      -> parent rejected
//	404  no hosted parent, or scheme not offered         -> parent rejected
//	409  zone frozen at the parent                       -> parent rejected
//	5xx  the parent is having a bad day                  -> transport
//
// Anything that is not an HTTP answer at all -- TLS refused, a redirect, a
// connection failure -- never reached the parent, so it is transport.
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
