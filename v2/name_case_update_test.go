/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The UPDATE path, and the child update policy in particular.
 */
package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// approvalFor drives ApproveTrustUpdate for one KEY RR under one child policy,
// with the update already validated by a trusted key so the check under test is
// the only thing that can reject it.
func approvalFor(t *testing.T, policyType, signer, owner string) bool {
	t.Helper()

	zd := &ZoneData{
		ZoneName: "example.",
		UpdatePolicy: UpdatePolicy{
			Child: UpdatePolicyDetail{
				Type:    policyType,
				RRtypes: map[uint16]bool{dns.TypeKEY: true},
			},
		},
	}
	rr, err := dns.NewRR(owner + " 3600 IN KEY 512 3 15 kR7NlEmXPWWDCFZmJqFhOJjHtBSKuLnCJHBTLzNJnUE=")
	if err != nil {
		t.Fatalf("building the update RR for %q: %v", owner, err)
	}
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{rr}

	us := &UpdateStatus{
		SignerName:            signer,
		Validated:             true,
		ValidatedByTrustedKey: true,
		ValidationRcode:       dns.RcodeSuccess,
	}
	approved, _, err := zd.ApproveTrustUpdate("example.", us, msg)
	if err != nil {
		t.Fatalf("ApproveTrustUpdate(%s, signer=%q, owner=%q): %v", policyType, signer, owner, err)
	}
	return approved && us.Approved
}

// THE AUTHORISATION BUG. selfsub means "the signer may update names inside its
// own subtree". The check was strings.HasSuffix(owner, signerName), which
// compares bytes and knows nothing about label boundaries -- so
// evilchild.example. ends with child.example. and a signer holding a key for
// child.example. was authorised to write a name it has no claim to.
//
// This is a boundary test on a security decision, so both directions matter:
// the names outside the subtree must be refused AND the names inside it must
// still be allowed, or "fixing" it by refusing everything would pass.
func TestSelfsubPolicyIsBoundedByLabels(t *testing.T) {
	const signer = "child.example."

	for _, tc := range []struct {
		owner string
		want  bool
		why   string
	}{
		{"child.example.", true, "the signer's own name is inside its subtree"},
		{"sub.child.example.", true, "a genuine subdomain"},
		{"deep.sub.child.example.", true, "an indirect subdomain"},

		// Case must not decide authorisation either way.
		{"CHILD.EXAMPLE.", true, "the signer's own name, upper case"},
		{"SUB.child.example.", true, "a subdomain, left label upper"},
		{"sub.CHILD.EXAMPLE.", true, "a subdomain, signer part upper"},

		// The bug: a byte-wise suffix match calls all of these inside.
		{"evilchild.example.", false, "ends with the signer name but is a DIFFERENT name"},
		{"xchild.example.", false, "same, one letter"},
		{"notchild.example.", false, "same"},
		{"EVILCHILD.EXAMPLE.", false, "same, and upper case must not rescue it"},

		// And plain outsiders.
		{"other.example.", false, "unrelated name in the zone"},
		{"child.example.org.", false, "same labels, different tree"},
	} {
		t.Run(tc.owner, func(t *testing.T) {
			if got := approvalFor(t, "selfsub", signer, tc.owner); got != tc.want {
				verb := "refused"
				if got {
					verb = "APPROVED"
				}
				t.Errorf("selfsub signer=%s: %s %q -- %s", signer, verb, tc.owner, tc.why)
			}
		})
	}
}

// self means "the signer may update exactly its own name". Case-sensitivity
// here fails closed rather than open, so it denies legitimate updates instead
// of permitting illegitimate ones -- still wrong, just less alarming.
func TestSelfPolicyComparesNamesNotBytes(t *testing.T) {
	const signer = "child.example."

	for _, tc := range []struct {
		owner string
		want  bool
	}{
		{"child.example.", true},
		{"CHILD.EXAMPLE.", true},
		{"Child.Example.", true},
		{"sub.child.example.", false},
		{"evilchild.example.", false},
		{"other.example.", false},
	} {
		t.Run(tc.owner, func(t *testing.T) {
			if got := approvalFor(t, "self", signer, tc.owner); got != tc.want {
				t.Errorf("self signer=%s owner=%q: approved=%v, want %v", signer, tc.owner, got, tc.want)
			}
		})
	}
}
