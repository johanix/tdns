/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

func delegationTestZone() *ZoneData {
	return &ZoneData{ZoneName: "example."}
}

func TestDsyncApiBuildActionsReplaceAndRemove(t *testing.T) {
	zd := delegationTestZone()

	actions, err := dsyncApiBuildActions(zd, "child1.example.", []DsyncApiRRset{
		{Owner: "child1.example.", Type: "NS", RRs: []string{
			"child1.example. 3600 IN NS ns1.child1.example.",
			"child1.example. 3600 IN NS ns2.child1.example.",
		}},
		{Owner: "ns1.child1.example.", Type: "A", RRs: []string{
			"ns1.child1.example. 3600 IN A 192.0.2.1",
		}},
		// An empty list removes the RRset. This is the case a map keyed by
		// type alone could not express, because there would be no record to
		// take the owner from.
		{Owner: "child1.example.", Type: "DS", RRs: []string{}},
	})
	if err != nil {
		t.Fatalf("dsyncApiBuildActions: %v", err)
	}

	var delRRsets, adds int
	for _, rr := range actions {
		switch rr.Header().Class {
		case dns.ClassANY:
			delRRsets++
		case dns.ClassINET:
			adds++
		}
	}
	// Two replaces (each a delete-RRset plus its records) and one removal.
	if delRRsets != 3 {
		t.Errorf("got %d RRset deletions, want 3 (two replaces + one removal)", delRRsets)
	}
	if adds != 3 {
		t.Errorf("got %d added records, want 3", adds)
	}
}

// An RRset not mentioned is left alone. This is what makes the endpoint safe
// for a client that only manages DS: omitting NS must not wipe the delegation.
func TestDsyncApiBuildActionsTouchesOnlyWhatIsListed(t *testing.T) {
	zd := delegationTestZone()

	actions, err := dsyncApiBuildActions(zd, "child1.example.", []DsyncApiRRset{
		{Owner: "child1.example.", Type: "DS", RRs: []string{
			"child1.example. 3600 IN DS 12345 15 2 " + strings.Repeat("ab", 32),
		}},
	})
	if err != nil {
		t.Fatalf("dsyncApiBuildActions: %v", err)
	}
	for _, rr := range actions {
		if rr.Header().Rrtype == dns.TypeNS {
			t.Errorf("a request that mentioned only DS produced an NS action: %s", rr.String())
		}
	}
}

func TestDsyncApiBuildActionsRejects(t *testing.T) {
	zd := delegationTestZone()

	for _, tc := range []struct {
		name   string
		rrsets []DsyncApiRRset
		want   string
	}{
		{
			// The policy would also catch this, but a child naming a sibling
			// delegation is a malformed request rather than a policy question,
			// and 400 says that more usefully than 403.
			name:   "owner outside the child",
			rrsets: []DsyncApiRRset{{Owner: "other.example.", Type: "NS", RRs: []string{"other.example. 60 IN NS ns1.other.example."}}},
			want:   "not at or below",
		},
		{
			// Otherwise a client could smuggle a change to another name into
			// an entry that looks like it is about this one.
			name: "record not at the declared owner",
			rrsets: []DsyncApiRRset{{Owner: "child1.example.", Type: "A", RRs: []string{
				"elsewhere.child1.example. 60 IN A 192.0.2.1"}}},
			want: "not at the declared owner",
		},
		{
			name: "record not of the declared type",
			rrsets: []DsyncApiRRset{{Owner: "child1.example.", Type: "NS", RRs: []string{
				"child1.example. 60 IN A 192.0.2.1"}}},
			want: "not a NS record",
		},
		{
			name:   "unmanaged type",
			rrsets: []DsyncApiRRset{{Owner: "child1.example.", Type: "TXT", RRs: []string{`child1.example. 60 IN TXT "hi"`}}},
			want:   "does not manage",
		},
		{
			name:   "unknown type",
			rrsets: []DsyncApiRRset{{Owner: "child1.example.", Type: "NOTATYPE", RRs: nil}},
			want:   "unknown RR type",
		},
		{
			// Two entries for one RRset means the client has two opinions
			// about it and the result would depend on ordering.
			name: "same rrset twice",
			rrsets: []DsyncApiRRset{
				{Owner: "child1.example.", Type: "NS", RRs: []string{"child1.example. 60 IN NS ns1.child1.example."}},
				{Owner: "CHILD1.EXAMPLE.", Type: "NS", RRs: []string{"child1.example. 60 IN NS ns2.child1.example."}},
			},
			want: "appears twice",
		},
		{
			name:   "no owner",
			rrsets: []DsyncApiRRset{{Owner: "", Type: "NS", RRs: nil}},
			want:   "no owner",
		},
		{
			name:   "unparseable record",
			rrsets: []DsyncApiRRset{{Owner: "child1.example.", Type: "NS", RRs: []string{"this is not a record"}}},
			want:   "cannot parse",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := dsyncApiBuildActions(zd, "child1.example.", tc.rrsets)
			if err == nil {
				t.Fatalf("accepted; want an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// The endpoint manages delegation records, and that is decided here rather
// than by the zone's updatepolicy.child.rrtypes. A parent that allows TXT in
// its child policy still does not want this endpoint used to manage arbitrary
// text records at a delegation point.
func TestDsyncApiManagedTypesAreDelegationTypes(t *testing.T) {
	for _, rrtype := range []uint16{dns.TypeNS, dns.TypeDS, dns.TypeA, dns.TypeAAAA} {
		if !dsyncApiTypeManaged(rrtype) {
			t.Errorf("%s is not managed but should be", dns.TypeToString[rrtype])
		}
	}
	for _, rrtype := range []uint16{dns.TypeTXT, dns.TypeMX, dns.TypeSOA, dns.TypeDNSKEY, dns.TypeCDS} {
		if dsyncApiTypeManaged(rrtype) {
			t.Errorf("%s is managed but should not be", dns.TypeToString[rrtype])
		}
	}
}

// The whole request is one UpdateRequest, so the policy verdict has to be
// all-or-nothing too: a delegation change that moved NS but not glue, because
// the second half was refused, is worse than one refused entirely.
func TestDsyncApiPolicyAppliesToTheWholeRequest(t *testing.T) {
	zd := delegationTestZone()
	policy := policyDetail("selfsub", dns.TypeNS, dns.TypeA, dns.TypeDS)

	actions, err := dsyncApiBuildActions(zd, "child1.example.", []DsyncApiRRset{
		{Owner: "child1.example.", Type: "NS", RRs: []string{"child1.example. 60 IN NS ns1.child1.example."}},
		{Owner: "ns1.child1.example.", Type: "A", RRs: []string{"ns1.child1.example. 60 IN A 192.0.2.1"}},
	})
	if err != nil {
		t.Fatalf("dsyncApiBuildActions: %v", err)
	}

	if ok, ede := zd.ApproveActionsForPrincipal(policy, "child1.example.", actions, "test"); !ok {
		t.Errorf("the child's own delegation was refused (ede=%d)", ede)
	}
	// A principal for a different child must not be able to change this one --
	// including via the label-boundary case the old suffix match allowed.
	for _, princ := range []string{"child2.example.", "1.example.", "hild1.example."} {
		if ok, _ := zd.ApproveActionsForPrincipal(policy, princ, actions, "test"); ok {
			t.Errorf("principal %q was allowed to change child1.example.'s delegation", princ)
		}
	}
}

// A type the policy does not list is refused even though the endpoint manages
// it: the endpoint decides what it is about, the policy decides what this
// principal may do.
func TestDsyncApiPolicyStillGatesRRtypes(t *testing.T) {
	zd := delegationTestZone()
	dsOnly := policyDetail("selfsub", dns.TypeDS)

	actions, err := dsyncApiBuildActions(zd, "child1.example.", []DsyncApiRRset{
		{Owner: "child1.example.", Type: "NS", RRs: []string{"child1.example. 60 IN NS ns1.child1.example."}},
	})
	if err != nil {
		t.Fatalf("dsyncApiBuildActions: %v", err)
	}

	ok, ede := zd.ApproveActionsForPrincipal(dsOnly, "child1.example.", actions, "test")
	if ok {
		t.Fatal("an NS change was allowed under a DS-only policy")
	}
	if ede != edns0.EDEZoneUpdateRRtypeNotAllowed {
		t.Errorf("ede = %d, want EDEZoneUpdateRRtypeNotAllowed (%d)", ede, edns0.EDEZoneUpdateRRtypeNotAllowed)
	}
	// And the 403 body says which of the two it was, so the client can tell a
	// policy that forbids the type from one that forbids the name.
	if reason := dsyncApiPolicyReason(ede); !strings.Contains(reason, "RR type") {
		t.Errorf("reason %q does not mention the RR type", reason)
	}
}

func TestDsyncApiPolicyReasonsAreExplained(t *testing.T) {
	for _, ede := range []uint16{
		edns0.EDEZoneUpdateRRtypeNotAllowed,
		edns0.EDEZoneUpdateOwnerOutsidePolicy,
		edns0.EDEZoneUpdatesNotAllowed,
	} {
		reason := dsyncApiPolicyReason(ede)
		if reason == "" || !strings.Contains(reason, "policy") {
			t.Errorf("ede %d renders as %q; want something naming the policy", ede, reason)
		}
	}
	// An unmapped code still produces something rather than an empty body.
	if dsyncApiPolicyReason(64999) == "" {
		t.Error("an unmapped EDE produced an empty reason")
	}
}
