/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Classifying an UPDATE whose QNAME is the parent zone: child delegation
 * sync, or a change to the parent's own data?
 */
package tdns

import (
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// zoneWithChildren builds a parent holding one delegation per child, which is
// all IsChildDelegation needs: an owner below the apex carrying an NS RRset.
//
// GetOwner reads the PUBLISHED snapshot, not zd.Data, and refuses unless the
// zone is Ready and a MapZone -- so populating Data alone leaves every lookup
// returning nil and every case here failing for a reason that has nothing to do
// with classification.
func zoneWithChildren(t *testing.T, zone string, children ...string) *ZoneData {
	t.Helper()
	zd := &ZoneData{
		ZoneName:  zone,
		ZoneStore: MapZone,
		Data:      core.NewNameMap[OwnerData](),
	}

	apex := OwnerData{Name: zone, RRtypes: NewRRTypeStore()}
	soa := mustRR(t, zone+" 3600 IN SOA ns."+zone+" hostmaster."+zone+" 1 3600 600 86400 600")
	apex.RRtypes.Set(dns.TypeSOA, core.RRset{Name: zone, RRtype: dns.TypeSOA, Class: dns.ClassINET, RRs: []dns.RR{soa}})
	zd.Data.Set(zone, apex)

	for _, child := range children {
		del := OwnerData{Name: child, RRtypes: NewRRTypeStore()}
		ns := mustRR(t, child+" 3600 IN NS ns."+child)
		del.RRtypes.Set(dns.TypeNS, core.RRset{Name: child, RRtype: dns.TypeNS, Class: dns.ClassINET, RRs: []dns.RR{ns}})
		zd.Data.Set(child, del)
	}

	zd.Ready = true
	zd.InstallInitialSnapshot()
	return zd
}

// THE REGRESSION. A child bootstrapping SIG(0) sends its KEY at its own apex,
// with the RFC 2136 QNAME (the parent zone). That is a CHILD-UPDATE.
//
// It was classified as a ZONE-UPDATE, because the branch handling everything
// that is not NS or DS walked only STRICT ancestors of the owner: starting one
// label above "child.example." lands on "example.", the apex, and the walk
// stops having matched nothing. The parent then judged it against
// updatepolicy.zone -- conventionally "none" -- and answered REFUSED with
// EDE 519, which reads as "this zone takes no updates" and sends you looking
// at the wrong end.
//
// NS and DS never hit this: their branch tests the owner itself.
func TestKeyAtChildApexIsAChildUpdate(t *testing.T) {
	zd := zoneWithChildren(t, "example.", "child.example.")
	key := mustRR(t, "child.example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE=")

	isChild, childDel := zd.classifyDelegationUpdate([]dns.RR{key})
	if !isChild {
		t.Fatal("a KEY at the child's apex was not classified as a child update; " +
			"the parent will judge it against updatepolicy.zone and refuse it")
	}
	if childDel != "child.example." {
		t.Errorf("childDel = %q, want child.example.", childDel)
	}
}

// The shapes that already worked must keep working -- a fix that classified
// everything as a child update would pass the test above and be far worse.
func TestDelegationUpdateClassification(t *testing.T) {
	zd := zoneWithChildren(t, "example.", "child.example.")

	for _, tc := range []struct {
		name      string
		rrs       []string
		wantChild bool
		wantDel   string
	}{
		{"NS at the delegation point", []string{"child.example. 3600 IN NS ns2.child.example."}, true, "child.example."},
		{"DS at the delegation point", []string{"child.example. 3600 IN DS 1 15 2 0000"}, true, "child.example."},
		{"glue below the delegation", []string{"ns.child.example. 3600 IN A 192.0.2.1"}, true, "child.example."},
		{"KEY plus glue, one child", []string{
			"child.example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE=",
			"ns.child.example. 3600 IN A 192.0.2.1",
		}, true, "child.example."},

		// The parent's own data is NOT a child update, whatever the type.
		{"TXT at the zone apex", []string{"example. 3600 IN TXT \"v=spf1 -all\""}, false, ""},
		{"KEY at the zone apex", []string{"example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE="}, false, ""},
		// A name inside the parent that is not under any delegation.
		{"A below the apex, no delegation", []string{"www.example. 3600 IN A 192.0.2.9"}, false, ""},
		// An empty update section is not a child update.
		{"no RRs", nil, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rrs []dns.RR
			for _, s := range tc.rrs {
				rrs = append(rrs, mustRR(t, s))
			}
			isChild, childDel := zd.classifyDelegationUpdate(rrs)
			if isChild != tc.wantChild {
				t.Fatalf("isChildUpdate = %v, want %v (childDel=%q)", isChild, tc.wantChild, childDel)
			}
			if tc.wantChild && childDel != tc.wantDel {
				t.Errorf("childDel = %q, want %q", childDel, tc.wantDel)
			}
		})
	}
}

// An update spanning two delegations is not a child update: the responder
// authorises against ONE child's policy, so accepting a mixed message would
// approve changes to a delegation nobody checked.
func TestUpdateSpanningTwoChildrenIsNotAChildUpdate(t *testing.T) {
	zd := zoneWithChildren(t, "example.", "child.example.", "other.example.")

	rrs := []dns.RR{
		mustRR(t, "child.example. 3600 IN KEY 256 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE="),
		mustRR(t, "other.example. 3600 IN NS ns2.other.example."),
	}
	if isChild, del := zd.classifyDelegationUpdate(rrs); isChild {
		t.Fatalf("an update spanning two delegations was classified as a child update (childDel=%q)", del)
	}
}
