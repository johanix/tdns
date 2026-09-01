/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Delegation maintenance: which nameserver names are inside the child zone.
 *
 * "In bailiwick" is what decides whether a nameserver needs glue in the parent,
 * and therefore which A/AAAA records a delegation change adds or deletes. Asked
 * with strings.HasSuffix it is wrong in both directions at once: it says yes to
 * a name that merely ends with the child's, and no to one that differs only in
 * case. The first deletes another delegation's glue.
 */
package tdns

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// glueTargets returns the owner names whose A/AAAA the update deletes wholesale
// (RemoveRRset: class ANY, empty rdata).
func glueTargets(m *dns.Msg) map[string]bool {
	out := map[string]bool{}
	for _, rr := range m.Ns {
		h := rr.Header()
		if h.Class != dns.ClassANY {
			continue
		}
		if h.Rrtype == dns.TypeA || h.Rrtype == dns.TypeAAAA {
			out[h.Name] = true
		}
	}
	return out
}

// THE DAMAGING DIRECTION. ns1.evilchild.example. ends with child.example., so a
// byte-wise bailiwick test called it in-bailiwick and the update deleted its
// A and AAAA -- glue belonging to a DIFFERENT delegation in the same parent,
// removed as a side effect of touching this one.
func TestChildUpdateDeletesOnlyItsOwnGlue(t *testing.T) {
	removes := []dns.RR{
		nsRR(t, "child.example.", "ns1.child.example."),     // in bailiwick
		nsRR(t, "child.example.", "ns1.CHILD.example."),     // in bailiwick, other case
		nsRR(t, "child.example.", "ns1.evilchild.example."), // NOT in bailiwick
		nsRR(t, "child.example.", "ns1.elsewhere.example."), // plainly out of bailiwick
	}

	m, err := CreateChildUpdate("example.", "child.example.", nil, removes)
	if err != nil {
		t.Fatalf("CreateChildUpdate: %v", err)
	}
	targets := glueTargets(m)

	for _, want := range []string{"ns1.child.example.", "ns1.CHILD.example."} {
		if !targets[want] {
			t.Errorf("glue for %q was not deleted, though it is inside the child zone: "+
				"the parent keeps serving glue for a nameserver that is gone", want)
		}
	}
	for _, mustNot := range []string{"ns1.evilchild.example.", "ns1.elsewhere.example."} {
		if targets[mustNot] {
			t.Errorf("glue for %q was deleted: it is NOT inside child.example., and that "+
				"glue belongs to another delegation", mustNot)
		}
	}
}

// The replace path builds the same in-bailiwick decision from the NEW records,
// deciding which glue to clear before inserting. Same trap, opposite list.
func TestChildReplaceUpdateGlueIsBoundedByLabels(t *testing.T) {
	aRR := func(owner, addr string) dns.RR {
		rr, err := dns.NewRR(owner + " 3600 IN A " + addr)
		if err != nil {
			t.Fatalf("building A: %v", err)
		}
		return rr
	}

	newNS := []dns.RR{
		nsRR(t, "child.example.", "ns1.child.example."),
		nsRR(t, "child.example.", "ns1.evilchild.example."),
		nsRR(t, "child.example.", "NS2.Child.Example."),
	}
	newA := []dns.RR{
		aRR("ns1.child.example.", "192.0.2.1"),
		aRR("ns1.evilchild.example.", "192.0.2.66"),
	}

	m, err := CreateChildReplaceUpdateWithDS("example.", "child.example.", newNS, newA, nil, nil, false)
	if err != nil {
		t.Fatalf("CreateChildReplaceUpdateWithDS: %v", err)
	}
	targets := glueTargets(m)

	for _, want := range []string{"ns1.child.example.", "NS2.Child.Example."} {
		if !targets[want] {
			t.Errorf("glue for in-bailiwick %q was not cleared before the replace", want)
		}
	}
	if targets["ns1.evilchild.example."] {
		t.Error("glue for ns1.evilchild.example. was cleared: it is not inside child.example.")
	}
}

// The shared predicate, on its own. Used by the scanner and the CSYNC path to
// decide whether a nameserver needs glue at all.
func TestNSInBailiwick(t *testing.T) {
	for _, tc := range []struct {
		zone, ns string
		want     bool
		why      string
	}{
		{"child.example.", "ns1.child.example.", true, "plain in-bailiwick nameserver"},
		{"child.example.", "NS1.CHILD.EXAMPLE.", true, "case must not decide it"},
		{"child.example.", "child.example.", true, "the zone name itself"},
		{"child.example.", "a.b.child.example.", true, "deeper"},

		{"child.example.", "ns1.evilchild.example.", false, "ends with the zone name but is not inside it"},
		{"child.example.", "ns1.example.", false, "the parent's own nameserver"},
		{"child.example.", "ns1.other.example.", false, "unrelated"},
		{"child.example.", "ns1.child.example.org.", false, "same labels, different tree"},
	} {
		ns := &dns.NS{Ns: tc.ns}
		if got := NSInBailiwick(tc.zone, ns); got != tc.want {
			t.Errorf("NSInBailiwick(%q, %q) = %v, want %v -- %s", tc.zone, tc.ns, got, tc.want, tc.why)
		}
	}
}

// A DSYNC API principal is the name a self/selfsub policy compares owner names
// against, so it decides what a credential may write. Canonicalising it with
// strings.ToLower folds by UNICODE, which maps U+212A KELVIN SIGN onto "k" --
// so two distinct DNS names would reduce to one principal and share whatever
// authority it carries. RFC 4343 folds US-ASCII A-Z and nothing else.
func TestDsyncApiPrincipalFoldsOnlyASCII(t *testing.T) {
	const kelvin = "K.example." // U+212A, not the letter K
	const ascii = "k.example."

	if strings.ToLower(kelvin) != ascii {
		t.Skip("this Go version no longer folds U+212A onto k; the hazard is gone")
	}

	if canonDsyncApiUser(kelvin) == canonDsyncApiUser(ascii) {
		t.Errorf("canonDsyncApiUser collapses %q and %q to one principal %q: "+
			"two different names would share a credential",
			kelvin, ascii, canonDsyncApiUser(ascii))
	}

	// The ordinary case still has to work, or "fixing" it by folding nothing
	// would pass the check above.
	for _, spelling := range []string{"Child.Example.", "CHILD.EXAMPLE.", "child.example."} {
		if got := canonDsyncApiUser(spelling); got != "child.example." {
			t.Errorf("canonDsyncApiUser(%q) = %q, want child.example.", spelling, got)
		}
	}
	// And the same for the zone and the parent-zone lookup key.
	if canonDsyncApiZone("Example.COM.") != "example.com." {
		t.Errorf("canonDsyncApiZone did not fold ASCII: %q", canonDsyncApiZone("Example.COM."))
	}
	if canonDsyncApiZone(kelvin) == canonDsyncApiZone(ascii) {
		t.Error("canonDsyncApiZone collapses two distinct names to one zone key")
	}
}
