/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"testing"

	"github.com/miekg/dns"
)

func nsecRR(t *testing.T, owner, next string) *dns.NSEC {
	t.Helper()
	rr, err := dns.NewRR(owner + " 300 IN NSEC " + next + " A RRSIG NSEC")
	if err != nil {
		t.Fatal(err)
	}
	return rr.(*dns.NSEC)
}

func TestCanonicalNameCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"example.", "a.example.", -1},        // the apex sorts before what is below it
		{"a.b.example.", "z.example.", -1},    // labels from the right: b < z
		{"a.zzz.example.", "b.example.", 1},   // ... which string order gets backwards
		{"*.example.", "a.example.", -1},      // '*' is an octet like any other
		{"Z.example.", "z.EXAMPLE.", 0},       // A-Z fold
		{"\\065.example.", "a.example.", 0},   // \065 is 'A', folded
		{"\\000.a.example.", "a.example.", 1}, // a zero octet label is still a label
		{"unbound.x.nl.", "org.", -1},         // nl < org
		{"example.com.", "unbound.x.nl.", -1}, // com < nl
	}
	for _, c := range cases {
		if got := canonicalNameCompare(c.a, c.b); got != c.want {
			t.Errorf("compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// THE FORGERY. A genuine signed NSEC from a zone's chain -- here one that
// crosses TLDs, the shape a root zone has -- was accepted as covering names it
// does not cover, because coverage compared names as strings: "example.com."
// sorts before "org." as a string, so the wrap-around branch said "covered".
// Replayed, it denies any such name with a valid signature.
func TestNsecCoverageUsesCanonicalOrder(t *testing.T) {
	root := nsecRR(t, "unbound.x.nl.", "org.")
	if nsecCoversName("example.com.", root) {
		t.Error("an NSEC from unbound.x.nl. to org. was taken as proof that example.com. does not exist")
	}
	if !nsecCoversName("nosuchtld.", root) {
		t.Error("nosuchtld. lies between unbound.x.nl. and org. and should be covered")
	}

	apex := nsecRR(t, "zone.example.", "b.zone.example.")
	if !nsecCoversName("*.zone.example.", apex) {
		t.Error("the apex NSEC must cover the apex wildcard, which sorts between the apex and b")
	}
	if !nsecCoversName("a.zone.example.", apex) {
		t.Error("a.zone.example. lies between the apex and b and should be covered")
	}

	mid := nsecRR(t, "a.zone.example.", "c.zone.example.")
	if nsecCoversName("a.zone.example.", mid) {
		t.Error("an NSEC proved its own owner absent")
	}
	if nsecCoversName("c.zone.example.", mid) {
		t.Error("an NSEC proved its next name absent")
	}

	last := nsecRR(t, "z.zone.example.", "zone.example.")
	if !nsecCoversName("zz.zone.example.", last) {
		t.Error("the chain-closing NSEC must cover names after its owner")
	}
	if nsecCoversName("b.zone.example.", last) {
		t.Error("the chain-closing NSEC covered a name before its owner")
	}
}

// RFC 4035 §5.4: the wildcard whose absence an NXDOMAIN must prove is the one at
// the closest encloser. A name under an existing name needs no apex wildcard
// proof, and a single NSEC can cover both.
func TestClosestEncloserFromTheCoveringNsec(t *testing.T) {
	nsec := nsecRR(t, "b.zone.example.", "c.zone.example.")
	if ce := closestEncloser("x.b.zone.example.", nsec, "zone.example."); ce != "b.zone.example." {
		t.Fatalf("closest encloser %q, want b.zone.example.", ce)
	}
	if !nsecCoversName(wildcardAt("b.zone.example."), nsec) {
		t.Error("b -> c should cover *.b.zone.example.")
	}
	if ce := closestEncloser("q.zone.example.", nsec, "zone.example."); ce != "zone.example." {
		t.Errorf("closest encloser %q, want the apex", ce)
	}
	if w := wildcardAt("."); w != "*." {
		t.Errorf("wildcard at the root %q, want *.", w)
	}
}
