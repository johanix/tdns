/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// policyAllowing builds an UpdatePolicy whose Zone detail permits exactly the
// listed rrtypes, which is what the applier's per-rrtype gate consults.
func policyAllowing(rrtypes ...uint16) UpdatePolicy {
	m := map[uint16]bool{}
	for _, t := range rrtypes {
		m[t] = true
	}
	return UpdatePolicy{
		Zone: UpdatePolicyDetail{Type: "selfsub", RRtypes: m, TTL: 3600},
	}
}

// verbOwnerTypes reports the rrtypes present at an owner in the PUBLISHED
// snapshot. The applier stages into a working set and swaps in a new snapshot
// in its deferred close; zd.Data is the pre-publish store and does not reflect
// an applied update, so reading it would pass regardless of what the applier
// did.
func verbOwnerTypes(t *testing.T, zd *ZoneData, owner string) map[uint16]bool {
	t.Helper()
	got := map[uint16]bool{}
	od, err := zd.GetOwner(owner)
	if err != nil || od == nil {
		return got
	}
	for _, rt := range od.RRtypes.Keys() {
		got[rt] = true
	}
	return got
}

const verbsZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
example.	3600	IN	TXT	"apex text"
www.example.	3600	IN	A	192.0.2.1
www.example.	3600	IN	A	192.0.2.2
www.example.	3600	IN	TXT	"hello"
www.example.	3600	IN	MX	10 mail.example.
`

// TestDelnameDeletesEveryRRsetAtOwner covers the RFC 2136 §2.5.3 statement that
// has been a silent no-op: CLASS=ANY + TYPE=ANY never matched a key in
// UpdatePolicy.Zone.RRtypes, so the per-rrtype gate skipped it entirely.
func TestDelnameDeletesEveryRRsetAtOwner(t *testing.T) {
	zd := testZone(t, "example.", verbsZone)
	registerZones(t, zd)
	zd.UpdatePolicy = policyAllowing(dns.TypeA, dns.TypeTXT, dns.TypeMX)

	before := verbOwnerTypes(t, zd, "www.example.")
	if !before[dns.TypeA] || !before[dns.TypeTXT] || !before[dns.TypeMX] {
		t.Fatalf("precondition: www should start with A, TXT and MX, got %v", before)
	}

	delname := &dns.ANY{Hdr: dns.RR_Header{
		Name: "www.example.", Rrtype: dns.TypeANY, Class: dns.ClassANY,
	}}

	updated, err := zd.ApplyZoneUpdateToZoneData(
		UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: []dns.RR{delname}},
		newTestKeyDB(t))
	if err != nil {
		t.Fatalf("ApplyZoneUpdateToZoneData: %v", err)
	}
	if !updated {
		t.Fatal("DELNAME reported no change -- this is the silent no-op the fix targets")
	}

	after := verbOwnerTypes(t, zd, "www.example.")
	for _, rt := range []uint16{dns.TypeA, dns.TypeTXT, dns.TypeMX} {
		if after[rt] {
			t.Errorf("%s survived DELNAME at www.example.", dns.TypeToString[rt])
		}
	}
}

// TestDelnameAtApexRetainsSoaAndNs: deleting the apex SOA and NS would dismantle
// the zone rather than a name within it (RFC 2136 §3.4.2.3).
func TestDelnameAtApexRetainsSoaAndNs(t *testing.T) {
	zd := testZone(t, "example.", verbsZone)
	registerZones(t, zd)
	zd.UpdatePolicy = policyAllowing(dns.TypeA, dns.TypeTXT, dns.TypeMX, dns.TypeSOA, dns.TypeNS)

	delname := &dns.ANY{Hdr: dns.RR_Header{
		Name: "example.", Rrtype: dns.TypeANY, Class: dns.ClassANY,
	}}

	if _, err := zd.ApplyZoneUpdateToZoneData(
		UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: []dns.RR{delname}},
		newTestKeyDB(t)); err != nil {
		t.Fatalf("ApplyZoneUpdateToZoneData: %v", err)
	}

	after := verbOwnerTypes(t, zd, "example.")
	if !after[dns.TypeSOA] {
		t.Error("apex SOA was deleted by DELNAME")
	}
	if !after[dns.TypeNS] {
		t.Error("apex NS was deleted by DELNAME")
	}
	if after[dns.TypeTXT] {
		t.Error("apex TXT survived DELNAME -- only SOA and NS are retained")
	}
}

// TestDelnameHonoursUpdatePolicy: DELNAME must not become a privilege
// escalation. A requestor permitted only TXT deletes only the TXT RRset, not
// every type at the name.
func TestDelnameHonoursUpdatePolicy(t *testing.T) {
	zd := testZone(t, "example.", verbsZone)
	registerZones(t, zd)
	zd.UpdatePolicy = policyAllowing(dns.TypeTXT)

	delname := &dns.ANY{Hdr: dns.RR_Header{
		Name: "www.example.", Rrtype: dns.TypeANY, Class: dns.ClassANY,
	}}

	if _, err := zd.ApplyZoneUpdateToZoneData(
		UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: []dns.RR{delname}},
		newTestKeyDB(t)); err != nil {
		t.Fatalf("ApplyZoneUpdateToZoneData: %v", err)
	}

	after := verbOwnerTypes(t, zd, "www.example.")
	if after[dns.TypeTXT] {
		t.Error("TXT was permitted by policy but survived DELNAME")
	}
	if !after[dns.TypeA] {
		t.Error("A was NOT permitted by policy but was deleted anyway -- DELNAME escalated privileges")
	}
	if !after[dns.TypeMX] {
		t.Error("MX was NOT permitted by policy but was deleted anyway -- DELNAME escalated privileges")
	}
}

// TestDelnamePreAuthorizedBypassesUpdatePolicy: update-policy governs the DDNS
// channel. An API request has already been authorized by the handler (F2), so
// the same restrictive policy that limits a wire client must not limit it.
func TestDelnamePreAuthorizedBypassesUpdatePolicy(t *testing.T) {
	zd := testZone(t, "example.", verbsZone)
	registerZones(t, zd)
	zd.UpdatePolicy = policyAllowing(dns.TypeTXT) // deliberately restrictive

	delname := &dns.ANY{Hdr: dns.RR_Header{
		Name: "www.example.", Rrtype: dns.TypeANY, Class: dns.ClassANY,
	}}

	if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: "example.",
		Actions:       []dns.RR{delname},
		PreAuthorized: true,
	}, newTestKeyDB(t)); err != nil {
		t.Fatalf("ApplyZoneUpdateToZoneData: %v", err)
	}

	after := verbOwnerTypes(t, zd, "www.example.")
	for _, rt := range []uint16{dns.TypeA, dns.TypeTXT, dns.TypeMX} {
		if after[rt] {
			t.Errorf("%s survived a PreAuthorized DELNAME; the API must not be bound by update-policy",
				dns.TypeToString[rt])
		}
	}
}

// TestDelnameAtApexRetainsZoneManagementRRsets: DELNAME is wholesale, and
// nobody issuing it at the apex means "and also dismantle DNSSEC". Deleting the
// apex DNSKEY on a zone whose DS is published at the parent does not make the
// zone insecure, it makes it BOGUS -- resolvers stop answering for the whole
// zone. Retaining more than RFC 2136 §3.4.2.3 requires is deliberate, and errs
// in the direction of deleting less.
func TestDelnameAtApexRetainsZoneManagementRRsets(t *testing.T) {
	const signedApex = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
example.	3600	IN	TXT	"apex text"
example.	3600	IN	DNSKEY	257 3 15 dem0H2M22a8CDAe0PDZoGBBCBB2fHJ1fe39FkhNToAA=
example.	3600	IN	CDS	1234 15 2 0000000000000000000000000000000000000000000000000000000000000000
example.	3600	IN	CDNSKEY	257 3 15 dem0H2M22a8CDAe0PDZoGBBCBB2fHJ1fe39FkhNToAA=
example.	3600	IN	CSYNC	66 3 A NS AAAA
`
	zd := testZone(t, "example.", signedApex)
	registerZones(t, zd)
	zd.UpdatePolicy = policyAllowing(dns.TypeTXT, dns.TypeDNSKEY, dns.TypeCDS,
		dns.TypeCDNSKEY, dns.TypeCSYNC, dns.TypeSOA, dns.TypeNS)

	delname := &dns.ANY{Hdr: dns.RR_Header{
		Name: "example.", Rrtype: dns.TypeANY, Class: dns.ClassANY,
	}}
	if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: []dns.RR{delname},
	}, newTestKeyDB(t)); err != nil {
		t.Fatalf("ApplyZoneUpdateToZoneData: %v", err)
	}

	after := verbOwnerTypes(t, zd, "example.")
	// CDNSKEY is in apexRetainedOnDelname alongside CDS and must be asserted
	// with it: a rollover signal half-deleted is worse than not deleted.
	for _, rt := range []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeDNSKEY, dns.TypeCDS,
		dns.TypeCDNSKEY, dns.TypeCSYNC} {
		if !after[rt] {
			t.Errorf("apex %s was deleted by DELNAME", dns.TypeToString[rt])
		}
	}
	// Ordinary apex data still goes.
	if after[dns.TypeTXT] {
		t.Error("apex TXT survived DELNAME; only the zone-management RRsets are retained")
	}
}

// TestApplierRefusesApexSoaNsRRsetDelete: the builder declines these, but
// actions can be constructed locally. A zone missing its apex SOA or NS cannot
// be served, and the apex guard in publishWorkingSetLocked would then refuse
// the whole publish -- discarding every other change in the same update.
func TestApplierRefusesApexSoaNsRRsetDelete(t *testing.T) {
	for _, rrtype := range []uint16{dns.TypeSOA, dns.TypeNS} {
		t.Run(dns.TypeToString[rrtype], func(t *testing.T) {
			zd := testZone(t, "example.", verbsZone)
			registerZones(t, zd)
			zd.UpdatePolicy = policyAllowing(dns.TypeSOA, dns.TypeNS)

			del := &dns.ANY{Hdr: dns.RR_Header{
				Name: "example.", Rrtype: rrtype, Class: dns.ClassANY,
			}}
			if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
				Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: []dns.RR{del},
			}, newTestKeyDB(t)); err != nil {
				t.Fatalf("ApplyZoneUpdateToZoneData: %v", err)
			}

			if !verbOwnerTypes(t, zd, "example.")[rrtype] {
				t.Errorf("apex %s RRset was deleted", dns.TypeToString[rrtype])
			}
		})
	}
}

// TestCallerTtlPreservedForApiAndInternal: update-policy dictates the TTL for
// records arriving over DDNS -- a wire client does not choose how long the zone
// caches what it just added. It has no business rewriting an operator's or an
// internal publisher's TTL: a rollover that wants a short TTL would silently
// get the policy's instead.
func TestCallerTtlPreservedForApiAndInternal(t *testing.T) {
	const callerTTL = 60

	for _, tc := range []struct {
		name string
		req  UpdateRequest
		want uint32
	}{
		{"PreAuthorized (API) keeps the caller's TTL",
			UpdateRequest{PreAuthorized: true}, callerTTL},
		{"InternalUpdate keeps the caller's TTL",
			UpdateRequest{InternalUpdate: true}, callerTTL},
		{"wire DDNS gets the policy TTL",
			UpdateRequest{}, 3600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zd := testZone(t, "example.", verbsZone)
			registerZones(t, zd)
			zd.UpdatePolicy = policyAllowing(dns.TypeA) // policy TTL is 3600

			add := &dns.A{
				Hdr: dns.RR_Header{Name: "new.example.", Rrtype: dns.TypeA,
					Class: dns.ClassINET, Ttl: callerTTL},
				A: []byte{10, 0, 0, 1},
			}
			req := tc.req
			req.Cmd = "ZONE-UPDATE"
			req.ZoneName = "example."
			req.Actions = []dns.RR{add}

			if _, err := zd.ApplyZoneUpdateToZoneData(req, newTestKeyDB(t)); err != nil {
				t.Fatalf("ApplyZoneUpdateToZoneData: %v", err)
			}

			od, err := zd.GetOwner("new.example.")
			if err != nil || od == nil {
				t.Fatalf("new.example. not published: %v", err)
			}
			rrset, ok := od.RRtypes.Get(dns.TypeA)
			if !ok || len(rrset.RRs) == 0 {
				t.Fatal("A RRset missing")
			}
			if got := rrset.RRs[0].Header().Ttl; got != tc.want {
				t.Errorf("published TTL = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestReplaceRRsetIsAtomicInOneApply checks the claim that REPLACE needs no new
// applier logic: a CLASS=ANY RRset delete followed by CLASS=INET adds, carried
// in a single Actions list, is applied in one pass under one zd.mu with a
// single publishLocked in the deferred close. Readers therefore never observe
// the intermediate empty RRset.
func TestReplaceRRsetIsAtomicInOneApply(t *testing.T) {
	zd := testZone(t, "example.", verbsZone)
	registerZones(t, zd)
	zd.UpdatePolicy = policyAllowing(dns.TypeA)

	serialBefore := zd.CurrentSerial

	del := &dns.ANY{Hdr: dns.RR_Header{
		Name: "www.example.", Rrtype: dns.TypeA, Class: dns.ClassANY,
	}}
	add1 := &dns.A{
		Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   []byte{10, 0, 0, 1},
	}
	add2 := &dns.A{
		Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   []byte{10, 0, 0, 2},
	}

	updated, err := zd.ApplyZoneUpdateToZoneData(
		UpdateRequest{
			Cmd: "ZONE-UPDATE", ZoneName: "example.",
			Actions: []dns.RR{del, add1, add2},
		}, newTestKeyDB(t))
	if err != nil {
		t.Fatalf("ApplyZoneUpdateToZoneData: %v", err)
	}
	if !updated {
		t.Fatal("REPLACE reported no change")
	}

	od, err := zd.GetOwner("www.example.")
	if err != nil || od == nil {
		t.Fatalf("www owner vanished from the published snapshot: %v", err)
	}
	rrset, ok := od.RRtypes.Get(dns.TypeA)
	if !ok {
		t.Fatal("A RRset missing after REPLACE")
	}
	if len(rrset.RRs) != 2 {
		t.Fatalf("A RRset has %d RRs after REPLACE, want exactly the 2 supplied: %v",
			len(rrset.RRs), rrset.RRs)
	}
	for _, rr := range rrset.RRs {
		a, ok := rr.(*dns.A)
		if !ok {
			t.Fatalf("non-A RR in the A RRset: %v", rr)
		}
		if got := a.A.String(); got != "10.0.0.1" && got != "10.0.0.2" {
			t.Errorf("pre-existing address %s survived REPLACE", got)
		}
	}

	// The serial is bumped once per publish. A REPLACE that leaked out as a
	// delete-then-add would publish twice and bump twice, and a secondary would
	// see an intermediate serial in which the RRset did not exist at all.
	if bumped := zd.CurrentSerial - serialBefore; bumped != 1 {
		t.Errorf("serial advanced by %d, want exactly 1 -- REPLACE must publish once", bumped)
	}
}

// replacerrset on the apex NS must REPLACE, not append.
//
// The regression it guards: replacerrset emits a ClassANY delete followed by
// the new records, and the applier refuses ClassANY deletes of the apex SOA
// and NS. The delete was dropped while the additions still ran, so an operator
// moving to a new set of nameservers got the union of old and new -- silently,
// and on the one RRset where a wrong answer breaks the delegation.
func TestReplaceApexNSReplacesRatherThanAppends(t *testing.T) {
	const apex = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns1.example.
example.	3600	IN	NS	ns2.example.
`
	zd := testZone(t, "example.", apex)
	registerZones(t, zd)
	zd.UpdatePolicy = policyAllowing(dns.TypeNS)

	actions, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{
		Verb: VerbReplaceRRset,
		RRs: []string{
			"example. 3600 IN NS ns3.example.",
			"example. 3600 IN NS ns4.example.",
		},
	})
	if err != nil {
		t.Fatalf("BuildZoneUpdateActions: %v", err)
	}
	if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: actions,
	}, newTestKeyDB(t)); err != nil {
		t.Fatalf("ApplyZoneUpdateToZoneData: %v", err)
	}

	owner, err := zd.GetOwner("example.")
	if err != nil || owner == nil {
		t.Fatalf("GetOwner: %v", err)
	}
	nsset, ok := owner.RRtypes.Get(dns.TypeNS)
	if !ok {
		t.Fatal("the apex NS RRset is gone; a replacement must leave one behind")
	}

	got := map[string]bool{}
	for _, rr := range nsset.RRs {
		if ns, ok := rr.(*dns.NS); ok {
			got[ns.Ns] = true
		}
	}
	for _, want := range []string{"ns3.example.", "ns4.example."} {
		if !got[want] {
			t.Errorf("%s missing from the replaced apex NS RRset", want)
		}
	}
	for _, gone := range []string{"ns1.example.", "ns2.example."} {
		if got[gone] {
			t.Errorf("%s survived the replacement: the RRset was appended to, not replaced", gone)
		}
	}
	if len(nsset.RRs) != 2 {
		t.Errorf("apex NS RRset has %d records, want exactly the 2 replacements", len(nsset.RRs))
	}
}

// A standalone delrrset of the apex NS is still refused -- the exception above
// is only for a delete that is one half of a replacement.
func TestDeleteApexNSStillRefused(t *testing.T) {
	const apex = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns1.example.
`
	zd := testZone(t, "example.", apex)
	registerZones(t, zd)
	zd.UpdatePolicy = policyAllowing(dns.TypeNS)

	// Straight to the applier: the builder refuses this too, and both layers
	// must hold.
	delrrset := &dns.ANY{Hdr: dns.RR_Header{
		Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassANY,
	}}
	if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: []dns.RR{delrrset},
	}, newTestKeyDB(t)); err != nil {
		t.Fatalf("ApplyZoneUpdateToZoneData: %v", err)
	}

	owner, err := zd.GetOwner("example.")
	if err != nil || owner == nil {
		t.Fatalf("GetOwner: %v", err)
	}
	if _, ok := owner.RRtypes.Get(dns.TypeNS); !ok {
		t.Error("the apex NS RRset was deleted by a standalone delrrset")
	}
}

// The apex SOA is refused at the builder, so it never reaches the applier as a
// half-applied replacement.
func TestReplaceApexSOARefused(t *testing.T) {
	_, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{
		Verb: VerbReplaceRRset,
		RRs:  []string{"example. 3600 IN SOA ns.example. hostmaster.example. 99 7200 1800 604800 7200"},
	})
	if err == nil {
		t.Fatal("replacerrset accepted the apex SOA")
	}
	if !strings.Contains(err.Error(), "serial is maintained by the server") {
		t.Errorf("error = %q; want it to say why", err)
	}
}

// An add BEFORE a delete is not a replacement -- RFC 2136 §3.4.2.6 processes
// the update section in order, so that list means "add ns9, then delete every
// NS", which would leave the apex with no NS RRset. The exception that lets a
// replacement delete the apex NS must not be reachable that way.
//
// BuildZoneUpdateActions always emits delete-first, but the Ns section of a
// DNS UPDATE arrives in whatever order the client sent.
func TestApexNSDeleteAfterAddIsNotAReplacement(t *testing.T) {
	const apex = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns1.example.
`
	zd := testZone(t, "example.", apex)
	registerZones(t, zd)
	zd.UpdatePolicy = policyAllowing(dns.TypeNS)

	add, err := dns.NewRR("example. 3600 IN NS ns9.example.")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	del := &dns.ANY{Hdr: dns.RR_Header{
		Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassANY,
	}}

	// Add first, delete second.
	if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: []dns.RR{add, del},
	}, newTestKeyDB(t)); err != nil {
		t.Fatalf("ApplyZoneUpdateToZoneData: %v", err)
	}

	owner, err := zd.GetOwner("example.")
	if err != nil || owner == nil {
		t.Fatalf("GetOwner: %v", err)
	}
	nsset, ok := owner.RRtypes.Get(dns.TypeNS)
	if !ok || len(nsset.RRs) == 0 {
		t.Fatal("the apex NS RRset was deleted: an add before the delete was treated as a replacement")
	}
}

// The delegation-sync delta must report an applied apex-NS replacement as
// removals too. Without this the local zone drops its old nameservers while the
// parent is only ever told about the new ones, and serves the union -- the same
// append-instead-of-replace bug, one hop further out.
func TestApexNSReplacementReportsRemovals(t *testing.T) {
	const apex = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns1.example.
example.	3600	IN	NS	ns2.example.
`
	zd := testZone(t, "example.", apex)
	registerZones(t, zd)
	zd.UpdatePolicy = policyAllowing(dns.TypeNS)

	// ns1 is kept, ns2 is dropped, ns3 is new.
	actions, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{
		Verb: VerbReplaceRRset,
		RRs: []string{
			"example. 3600 IN NS ns1.example.",
			"example. 3600 IN NS ns3.example.",
		},
	})
	if err != nil {
		t.Fatalf("BuildZoneUpdateActions: %v", err)
	}

	// Computed BEFORE the apply, as the updater does: it needs the pre-state.
	dss, err := zd.ZoneUpdateChangesDelegationDataNG(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: actions,
	})
	if err != nil {
		t.Fatalf("ZoneUpdateChangesDelegationDataNG: %v", err)
	}

	removed := map[string]bool{}
	for _, rr := range dss.NsRemoves {
		if ns, ok := rr.(*dns.NS); ok {
			removed[ns.Ns] = true
		}
	}
	if !removed["ns2.example."] {
		t.Error("ns2 was replaced away but not reported as removed; the parent would keep it")
	}
	// A nameserver the replacement re-adds must NOT be reported gone: on the
	// delta path an add reordered before its own remove would lose it.
	if removed["ns1.example."] {
		t.Error("ns1 survives the replacement but was reported as removed")
	}
	if dss.InSync {
		t.Error("a delegation change was reported as in sync")
	}
}

// A standalone apex-NS delete is still ignored by the delta computation, since
// the applier still refuses it. Reporting a removal that never happened would
// tell the parent to drop nameservers the child still serves.
func TestStandaloneApexNSDeleteReportsNoRemovals(t *testing.T) {
	const apex = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns1.example.
`
	zd := testZone(t, "example.", apex)
	registerZones(t, zd)
	zd.UpdatePolicy = policyAllowing(dns.TypeNS)

	del := &dns.ANY{Hdr: dns.RR_Header{
		Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassANY,
	}}
	dss, err := zd.ZoneUpdateChangesDelegationDataNG(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: []dns.RR{del},
	})
	if err != nil {
		t.Fatalf("ZoneUpdateChangesDelegationDataNG: %v", err)
	}
	if len(dss.NsRemoves) != 0 {
		t.Errorf("a refused standalone delete reported %d NS removals", len(dss.NsRemoves))
	}
}
