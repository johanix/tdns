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

// The chain built from that order must be a single cycle covering every name
// exactly once and returning to the apex -- which is what a validator checks
// and what a lexicographic order silently breaks.
func TestNsecChainIsACanonicalCycle(t *testing.T) {
	names := []string{
		"clean.example.",
		"ns.clean.example.",
		"alpha.clean.example.",
		"deep.sub.clean.example.",
		"sub.clean.example.",
	}
	sort.Slice(names, func(i, j int) bool { return canonicalOwnerLess(names[i], names[j]) })

	// Walk the chain the generator would build and verify it returns to the
	// start after exactly len(names) hops, visiting each name once.
	next := map[string]string{}
	for i, n := range names {
		next[n] = names[(i+1)%len(names)]
	}

	seen := map[string]bool{}
	cur := names[0]
	for range names {
		if seen[cur] {
			t.Fatalf("chain revisits %q before closing: %v", cur, names)
		}
		seen[cur] = true
		cur = next[cur]
	}
	if cur != names[0] {
		t.Fatalf("chain does not close on the first name: ended at %q, want %q", cur, names[0])
	}
	if names[0] != dns.Fqdn("clean.example.") {
		t.Fatalf("the apex must sort first in canonical order; got %q", names[0])
	}
}
