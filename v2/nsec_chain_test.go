package tdns

import (
	"sort"
	"testing"

	"github.com/miekg/dns"
)

// The NSEC chain is built by walking the owner-name list and linking each name
// to the next, so that list's order IS the chain's order. It must therefore be
// RFC 4034 §6.1 canonical order, not a lexicographic sort of the presentation
// names -- the two disagree exactly when a label boundary falls inside a shared
// prefix, which is the common case for a zone whose apex is a prefix of its
// own child names.
func TestWorkingOwnerNamesAreInCanonicalOrder(t *testing.T) {
	zd := &ZoneData{ZoneName: "clean.example."}
	zd.workingSet = map[string]*OwnerData{}
	for _, n := range []string{
		"clean.example.",
		"ns.clean.example.",
		"alpha.clean.example.",
		"bravo.clean.example.",
		"charlie.clean.example.",
	} {
		zd.workingSet[n] = &OwnerData{Name: n, RRtypes: NewRRTypeStore()}
	}

	got := zd.workingOwnerNamesLocked()
	want := []string{
		"clean.example.", // the apex sorts FIRST; lexicographically it lands mid-list
		"alpha.clean.example.",
		"bravo.clean.example.",
		"charlie.clean.example.",
		"ns.clean.example.",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d names, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("position %d: got %q, want %q\nfull order: %v", i, got[i], want[i], got)
		}
	}

	// And state the difference explicitly, so a future change back to
	// sort.Strings fails here with the reason rather than somewhere downstream.
	lex := append([]string(nil), want...)
	sort.Strings(lex)
	same := true
	for i := range lex {
		if lex[i] != want[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("this fixture no longer distinguishes canonical from lexicographic order;" +
			" pick names where the two disagree or the test proves nothing")
	}
}

// The chain the GENERATOR produces must be a single cycle covering every
// authoritative name once and closing on the apex.
//
// Built from the generated NSEC records, not from a sorted slice: deriving the
// successor relation from the same ordering the test asserts would only prove
// that sorting is self-consistent.
func TestNsecChainIsACanonicalCycle(t *testing.T) {
	const z = `cycle.example.	300	IN	SOA	ns.cycle.example. hostmaster.cycle.example. 1 1800 900 604800 300
cycle.example.	300	IN	NS	ns.cycle.example.
ns.cycle.example.	300	IN	A	127.0.0.1
alpha.cycle.example.	300	IN	A	10.0.0.1
deep.sub.cycle.example.	300	IN	A	10.0.0.2
`
	zd := testZone(t, "cycle.example.", z)
	zd.ensureWorkingSet()
	zd.Options = map[ZoneOption]bool{OptAllowUpdates: true}
	if err := zd.GenerateNsecChainWithDak(&DnssecKeys{}); err != nil {
		t.Fatalf("GenerateNsecChainWithDak: %v", err)
	}

	next := map[string]string{}
	for _, name := range zd.workingOwnerNamesLocked() {
		od := zd.stagedOwner(name)
		if od == nil || len(od.NSEC.RRs) == 0 {
			continue
		}
		nsec, ok := od.NSEC.RRs[0].(*dns.NSEC)
		if !ok {
			t.Fatalf("%s: NSEC property holds a %T", name, od.NSEC.RRs[0])
		}
		next[name] = nsec.NextDomain
	}
	if len(next) == 0 {
		t.Fatal("the generator produced no chain at all")
	}

	apex := "cycle.example."
	if _, ok := next[apex]; !ok {
		t.Fatal("the apex has no NSEC")
	}
	seen := map[string]bool{}
	cur := apex
	for range next {
		if seen[cur] {
			t.Fatalf("the chain revisits %q before closing", cur)
		}
		seen[cur] = true
		nxt, ok := next[cur]
		if !ok {
			t.Fatalf("%q points at %q, which has no NSEC", cur, nxt)
		}
		if nxt != apex && !canonicalOwnerLess(cur, nxt) {
			t.Errorf("%q -> %q goes backwards in canonical order", cur, nxt)
		}
		cur = nxt
	}
	if cur != apex {
		t.Fatalf("the chain does not close on the apex; ended at %q", cur)
	}
	if len(seen) != len(next) {
		t.Fatalf("the chain covers %d of %d names -- it is not one cycle", len(seen), len(next))
	}
	// The apex sorts first in canonical order; lexicographically it would not.
	if first := next[apex]; first != "alpha.cycle.example." {
		t.Fatalf("apex points at %q, want alpha.cycle.example.", first)
	}
}
