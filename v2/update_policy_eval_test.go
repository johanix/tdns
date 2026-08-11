/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// preExtractionEval is the policy check exactly as it was written inline, twice,
// in ApproveChildUpdate and ApproveAuthUpdate before evalUpdatePolicyRR existed.
// Kept verbatim so the extraction can be checked against it rather than against
// a reading of it.
//
// The two copies differed only in log wording and in the zone copy having an
// explicit "none" case that did what its default case did anyway, so one
// replica covers both.
func preExtractionEval(policy UpdatePolicyDetail, principal string, rr dns.RR) (bool, uint16) {
	if !policy.RRtypes[rr.Header().Rrtype] {
		return false, edns0.EDEZoneUpdateRRtypeNotAllowed
	}
	switch policy.Type {
	case "selfsub":
		if !strings.HasSuffix(rr.Header().Name, principal) {
			return false, edns0.EDEZoneUpdateOwnerOutsidePolicy
		}
	case "self":
		if rr.Header().Name != principal {
			return false, edns0.EDEZoneUpdateOwnerOutsidePolicy
		}
	default:
		return false, edns0.EDEZoneUpdatesNotAllowed
	}
	return true, 0
}

func policyDetail(ptype string, rrtypes ...uint16) UpdatePolicyDetail {
	d := UpdatePolicyDetail{Type: ptype, RRtypes: map[uint16]bool{}}
	for _, t := range rrtypes {
		d.RRtypes[t] = true
	}
	return d
}

func policyTestRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("cannot parse %q: %v", s, err)
	}
	return rr
}

type policyCase struct {
	name      string
	policy    UpdatePolicyDetail
	principal string
	rr        string
}

func policyCases() []policyCase {
	selfsub := policyDetail("selfsub", dns.TypeA, dns.TypeNS, dns.TypeDS)
	self := policyDetail("self", dns.TypeA, dns.TypeNS, dns.TypeDS)

	return []policyCase{
		{"selfsub: own name", selfsub, "child1.example.", "child1.example. 60 IN NS ns1.child1.example."},
		{"selfsub: below own name", selfsub, "child1.example.", "ns1.child1.example. 60 IN A 192.0.2.1"},
		{"selfsub: deep below own name", selfsub, "child1.example.", "a.b.c.child1.example. 60 IN A 192.0.2.1"},
		{"selfsub: unrelated name", selfsub, "child1.example.", "other.example. 60 IN A 192.0.2.1"},
		{"selfsub: parent of own name", selfsub, "child1.example.", "example. 60 IN NS ns1.example."},
		{"selfsub: rrtype not allowed", selfsub, "child1.example.", "child1.example. 60 IN MX 10 mail.example."},
		{"selfsub: delete RR (class NONE)", selfsub, "child1.example.", "child1.example. 0 NONE NS ns1.child1.example."},

		{"self: exact name", self, "child1.example.", "child1.example. 60 IN NS ns1.child1.example."},
		{"self: below own name", self, "child1.example.", "ns1.child1.example. 60 IN A 192.0.2.1"},
		{"self: unrelated name", self, "child1.example.", "other.example. 60 IN A 192.0.2.1"},
		{"self: rrtype not allowed", self, "child1.example.", "child1.example. 60 IN MX 10 mail.example."},

		{"policy none", policyDetail("none", dns.TypeA), "child1.example.", "child1.example. 60 IN A 192.0.2.1"},
		{"policy empty", policyDetail("", dns.TypeA), "child1.example.", "child1.example. 60 IN A 192.0.2.1"},
		{"policy unknown", policyDetail("selfsubb", dns.TypeA), "child1.example.", "child1.example. 60 IN A 192.0.2.1"},
		{"policy with no rrtypes at all", policyDetail("selfsub"), "child1.example.", "child1.example. 60 IN A 192.0.2.1"},
	}
}

// The extraction must not change any verdict. Anything it does change has to be
// listed in intentionalDivergence with a reason, so a behaviour change can
// never arrive as a silent side effect of moving code.
var intentionalDivergence = map[string]string{}

func TestUpdatePolicyEvalMatchesPreExtractionBehaviour(t *testing.T) {
	for _, tc := range policyCases() {
		t.Run(tc.name, func(t *testing.T) {
			rr := policyTestRR(t, tc.rr)

			wantOk, wantEde := preExtractionEval(tc.policy, tc.principal, rr)
			gotOk, gotEde := evalUpdatePolicyRR(tc.policy, tc.principal, rr, "test")

			if reason, ok := intentionalDivergence[tc.name]; ok {
				if gotOk == wantOk && gotEde == wantEde {
					t.Errorf("listed as an intentional divergence (%s) but behaves identically;"+
						" remove it from intentionalDivergence", reason)
				}
				return
			}

			if gotOk != wantOk || gotEde != wantEde {
				t.Errorf("verdict changed: was (approved=%v, ede=%d), now (approved=%v, ede=%d)",
					wantOk, wantEde, gotOk, gotEde)
			}
		})
	}
}

// The verdicts themselves, independent of the replica: if both the replica and
// the extraction were wrong in the same way, the test above would pass.
func TestUpdatePolicyEvalVerdicts(t *testing.T) {
	selfsub := policyDetail("selfsub", dns.TypeA, dns.TypeNS)

	for _, tc := range []struct {
		name    string
		policy  UpdatePolicyDetail
		princ   string
		rr      string
		wantOk  bool
		wantEde uint16
	}{
		{"own name approved", selfsub, "child1.example.",
			"child1.example. 60 IN NS ns1.child1.example.", true, 0},
		{"name below approved", selfsub, "child1.example.",
			"ns1.child1.example. 60 IN A 192.0.2.1", true, 0},
		{"unrelated name refused", selfsub, "child1.example.",
			"other.example. 60 IN A 192.0.2.1", false, edns0.EDEZoneUpdateOwnerOutsidePolicy},
		{"disallowed rrtype refused", selfsub, "child1.example.",
			"child1.example. 60 IN MX 10 mail.example.", false, edns0.EDEZoneUpdateRRtypeNotAllowed},
		{"policy none refuses everything", policyDetail("none", dns.TypeA), "child1.example.",
			"child1.example. 60 IN A 192.0.2.1", false, edns0.EDEZoneUpdatesNotAllowed},
		// The RRtype gate runs first: a disallowed type is reported as such
		// even when the owner is also outside the tree. Both copies did this,
		// and the DSYNC API's 403 reason depends on it.
		{"rrtype checked before owner", selfsub, "child1.example.",
			"other.example. 60 IN MX 10 mail.example.", false, edns0.EDEZoneUpdateRRtypeNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotOk, gotEde := evalUpdatePolicyRR(tc.policy, tc.princ, policyTestRR(t, tc.rr), "test")
			if gotOk != tc.wantOk || gotEde != tc.wantEde {
				t.Errorf("got (approved=%v, ede=%d), want (approved=%v, ede=%d)",
					gotOk, gotEde, tc.wantOk, tc.wantEde)
			}
		})
	}
}

func TestApproveActionsForPrincipal(t *testing.T) {
	zd := &ZoneData{ZoneName: "example."}
	policy := policyDetail("selfsub", dns.TypeA, dns.TypeNS)

	inTree := []dns.RR{
		policyTestRR(t, "child1.example. 60 IN NS ns1.child1.example."),
		policyTestRR(t, "ns1.child1.example. 60 IN A 192.0.2.1"),
	}
	if ok, ede := zd.ApproveActionsForPrincipal(policy, "child1.example.", inTree, "test"); !ok {
		t.Errorf("in-tree actions refused with ede=%d", ede)
	}

	// One bad record refuses the whole set: an update is all or nothing, so
	// approving the good half would apply a change nobody asked for.
	mixed := append([]dns.RR{}, inTree...)
	mixed = append(mixed, policyTestRR(t, "other.example. 60 IN A 192.0.2.1"))
	if ok, _ := zd.ApproveActionsForPrincipal(policy, "child1.example.", mixed, "test"); ok {
		t.Error("a set containing an out-of-tree record was approved")
	}

	// An empty principal must never be treated as a wildcard. On the API path
	// this is what an unauthenticated request would look like if the handler
	// ever forgot to check.
	for _, princ := range []string{"", "   "} {
		if ok, ede := zd.ApproveActionsForPrincipal(policy, princ, inTree, "test"); ok {
			t.Errorf("empty principal %q was approved (ede=%d)", princ, ede)
		}
	}
}

// Both approval paths must reach the same verdict for the same inputs, since
// that is the entire point of there being one evaluator. Belt and braces: this
// compares the two exported entry points rather than the internals.
func TestChildAndZonePoliciesEvaluateIdentically(t *testing.T) {
	zd := &ZoneData{ZoneName: "example."}
	policy := policyDetail("selfsub", dns.TypeA)

	for _, owner := range []string{"child1.example.", "ns1.child1.example.", "other.example."} {
		rr := policyTestRR(t, fmt.Sprintf("%s 60 IN A 192.0.2.1", owner))

		direct, directEde := evalUpdatePolicyRR(policy, "child1.example.", rr, "test")
		viaSet, viaSetEde := zd.ApproveActionsForPrincipal(policy, "child1.example.", []dns.RR{rr}, "test")

		if direct != viaSet || directEde != viaSetEde {
			t.Errorf("%s: single (%v,%d) != set (%v,%d)", owner, direct, directEde, viaSet, viaSetEde)
		}
	}
}
