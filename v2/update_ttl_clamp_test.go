/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * An update signs what it writes under the TTL ceiling the re-signer uses.
 */
package tdns

import (
	"context"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// assertServedTTL checks that the zone serves <owner, rrtype> at ttl, and that
// its signatures were made for that TTL. want, if given, is a record the RRset
// must hold.
func assertServedTTL(t *testing.T, zd *ZoneData, how, owner string, rrtype uint16, ttl uint32, want ...dns.RR) {
	t.Helper()
	od := getOwnerFrom(zd.publishedSnapshot(), owner)
	if od == nil {
		t.Fatalf("%s: %s is not in the published zone", how, owner)
	}
	rrset := od.RRtypes.GetOnlyRRSet(rrtype)
	if len(rrset.RRs) == 0 {
		t.Fatalf("%s: the zone serves no %s at %s", how, dns.TypeToString[rrtype], owner)
	}
	if len(rrset.RRSIGs) == 0 {
		t.Fatalf("%s: the %s at %s is unsigned", how, dns.TypeToString[rrtype], owner)
	}
	for _, w := range want {
		held := false
		for _, rr := range rrset.RRs {
			held = held || core.IsDuplicate(rr, w)
		}
		if !held {
			t.Errorf("%s: the zone does not serve %q", how, w.String())
		}
	}
	for _, rr := range rrset.RRs {
		if rr.Header().Ttl != ttl {
			t.Errorf("%s: served %q; want TTL %d, the policy's max-served", how, rr.String(), ttl)
		}
	}
	for _, rr := range rrset.RRSIGs {
		if sig := rr.(*dns.RRSIG); sig.OrigTtl != ttl {
			t.Errorf("%s: the RRSIG over the %s at %s is for TTL %d; want %d",
				how, dns.TypeToString[rrtype], owner, sig.OrigTtl, ttl)
		}
	}
}

// An RRset an update writes is served, and signed, no longer than the policy's
// ttls.max-served, as the re-signer serves it. Updates used to sign at the TTL
// they carried, which was served until the next re-sign: a DS added with TTL
// 3600 under a five-minute ceiling was cached by validating resolvers for an
// hour, and so its withdrawal was too.
func TestUpdatesSignUnderTheMaxServedCeiling(t *testing.T) {
	const ds = "child.cut.example. 3600 IN DS 54321 15 2 " +
		"2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
	setup := func(t *testing.T) (*ZoneData, *KeyDB) {
		t.Helper()
		kdb := newTestKeyDB(t)
		zd := cutTestZone(t, kdb)
		zd.DnssecPolicy.TTLS.MaxServed = 300
		if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
			t.Fatalf("SignZone: %v", err)
		}
		assertServedTTL(t, zd, "after SignZone", "child.cut.example.", dns.TypeDS, 300)
		return zd, kdb
	}

	t.Run("zone update", func(t *testing.T) {
		zd, kdb := setup(t)
		applyRR(t, zd, kdb, VerbAddRR, ds)
		applyRR(t, zd, kdb, VerbAddRR, "alpha.cut.example. 3600 IN A 10.0.0.9")
		assertServedTTL(t, zd, "zone update", "child.cut.example.", dns.TypeDS, 300, fwdSecRR(t, ds))
		assertServedTTL(t, zd, "zone update", "alpha.cut.example.", dns.TypeA, 300)
	})

	// A child's DS replaced through the direct delegation backend, as a DSYNC
	// API or RFC 2136 child update arrives.
	t.Run("child update", func(t *testing.T) {
		withNotifyQ(t, 8)
		zd, kdb := dsdParentZone(t)
		zd.DnssecPolicy.TTLS.MaxServed = 300
		if _, err := zd.SignZone(context.Background(), kdb, true); err != nil {
			t.Fatalf("SignZone: %v", err)
		}
		if updated, err := dsdApply(t, zd, kdb, dsdReceived(t, []string{dsdNewDS}, nil)); err != nil || !updated {
			t.Fatalf("child update: updated=%v err=%v", updated, err)
		}
		assertServedTTL(t, zd, "child update", dsdChild, dns.TypeDS, 300, fwdSecRR(t, dsdNewDS))
	})
}
