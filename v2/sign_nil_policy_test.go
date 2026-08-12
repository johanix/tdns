/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Regression tests for the first-load SIGSEGV on a new online-signed zone
 * (docs/2026-07-19-new-signed-zone-firstload-segv.md). PR-2 defers DNSSEC policy
 * binding to the post-Ready sync, so a brand-new keyless zone reaches the
 * load-time re-sign path with zd.DnssecPolicy == nil; the key-generation branch
 * dereferenced it (SIGSEGV at sign.go GenerateKeypair). Both the resign site and
 * EnsureActiveDnssecKeys must now tolerate a not-yet-bound policy.
 */

package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// TestResignSOANilPolicyNoPanic: a first-load re-sign of a keyless online-signed
// zone whose policy is not yet bound must be a clean no-op, not a crash. Models
// the exact crash path (resignWorkingSetSOAIfSigned -> EnsureActiveDnssecKeys
// generate), differing from TestResignSOAUnderLockNoSelfDeadlock only in that
// DnssecPolicy is nil.
func TestResignSOANilPolicyNoPanic(t *testing.T) {
	kdb := newTestKeyDB(t)
	zone := `nilpol.example.	3600	IN	SOA	ns.nilpol.example. hostmaster.nilpol.example. 1 7200 1800 604800 7200
nilpol.example.	3600	IN	NS	ns.nilpol.example.
`
	zd := testZone(t, "nilpol.example.", zone)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptOnlineSigning: true}
	zd.DnssecPolicy = nil // policy binding deferred to the post-Ready sync (first-load)

	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.resignWorkingSetSOAIfSigned() // must NOT panic (was a SIGSEGV)
	apex := zd.workingSet[zd.ZoneName]
	zd.mu.Unlock()

	if apex == nil {
		t.Fatal("apex missing from working set after resign")
	}
	// Nothing to sign under yet — the zone is signed later by SetupZoneSigning
	// once the sync binds a policy. The point is it returned cleanly.
	if soa := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA); len(soa.RRSIGs) != 0 {
		t.Fatalf("expected no RRSIG on SOA with no policy bound, got %d", len(soa.RRSIGs))
	}
}

// TestEnsureActiveDnssecKeysNilPolicyReturnsError: the defense-in-depth guard —
// generating keys with no bound policy returns an error instead of dereferencing
// nil zd.DnssecPolicy.KSKAlgorithm.
func TestEnsureActiveDnssecKeysNilPolicyReturnsError(t *testing.T) {
	kdb := newTestKeyDB(t)
	zone := `nilpol2.example.	3600	IN	SOA	ns.nilpol2.example. hostmaster.nilpol2.example. 1 7200 1800 604800 7200
nilpol2.example.	3600	IN	NS	ns.nilpol2.example.
`
	zd := testZone(t, "nilpol2.example.", zone)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptOnlineSigning: true}
	zd.DnssecPolicy = nil

	if _, err := zd.EnsureActiveDnssecKeys(kdb, false); err == nil {
		t.Fatal("expected an error from EnsureActiveDnssecKeys with nil policy and no keys (was a SIGSEGV before the fix), got nil")
	}
}
