package tdns

import (
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The predecessor is what has to be rewritten when a name joins or leaves the
// chain, so it must be found for a name that is NOT in the chain as well as
// one that is -- and the chain is a cycle, so the first name's predecessor is
// the last.
func TestChainPredecessor(t *testing.T) {
	chain := []string{
		"example.",
		"alpha.example.",
		"charlie.example.",
		"ns.example.",
	}

	for _, tc := range []struct {
		name, target, want string
	}{
		{"present, mid-chain", "charlie.example.", "alpha.example."},
		{"present, first (wraps to last)", "example.", "ns.example."},
		{"present, last", "ns.example.", "charlie.example."},
		{"absent, would sort mid-chain", "bravo.example.", "alpha.example."},
		{"absent, would sort last", "zulu.example.", "ns.example."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := chainPredecessor(chain, tc.target)
			if !ok {
				t.Fatalf("no predecessor found for %q", tc.target)
			}
			if got != tc.want {
				t.Fatalf("predecessor of %q = %q, want %q", tc.target, got, tc.want)
			}
			if got == tc.target {
				t.Fatalf("%q was returned as its own predecessor", tc.target)
			}
		})
	}
}

func TestChainPredecessorOnAnEmptyChain(t *testing.T) {
	if _, ok := chainPredecessor(nil, "alpha.example."); ok {
		t.Fatal("an empty chain reported a predecessor")
	}
}

// NSEC is regenerated on every publish, so journalling it would replay derived
// records onto a zone file as though someone had written them -- and put NSEC
// back into an owner's RRtypes on replay, reinstating the ghosts the property
// model removes. The same delta feeds IXFR, where it must be kept.
func TestJournalDeltaExcludesNsecButKeepsEverythingElse(t *testing.T) {
	mk := func(name string, rrtype uint16) core.RRset {
		return core.RRset{Name: name, RRtype: rrtype, Class: dns.ClassINET}
	}
	in := []core.RRset{
		mk("alpha.example.", dns.TypeA),
		mk("alpha.example.", dns.TypeNSEC),
		mk("example.", dns.TypeNSEC),
		mk("bravo.example.", dns.TypeTXT),
	}
	// A zone that does NOT manage its own ZONEMD: the exclusion is
	// NSEC-only, and an apex ZONEMD would be operator data belonging in the
	// journal. See TestJournalDeltaExcludesManagedZonemd for the other half.
	zd := &ZoneData{ZoneName: "example.", Options: map[ZoneOption]bool{}}
	out := zd.withoutDerivedRecords(in)

	if len(out) != 2 {
		t.Fatalf("expected the two authored RRsets, got %d: %+v", len(out), out)
	}
	for _, rs := range out {
		if rs.RRtype == dns.TypeNSEC {
			t.Fatalf("an NSEC RRset survived into the journal delta: %+v", rs)
		}
	}
	// ...and the input is not mutated, since the caller still hands the
	// unfiltered set to the IXFR chain.
	if len(in) != 4 {
		t.Fatalf("the input slice was modified: %+v", in)
	}
	sawA, sawTXT := false, false
	for _, rs := range out {
		switch rs.RRtype {
		case dns.TypeA:
			sawA = true
		case dns.TypeTXT:
			sawTXT = true
		}
	}
	if !sawA || !sawTXT {
		t.Fatalf("authored records were dropped: %+v", out)
	}
}

// The restitch reacts to changes in authoritative data. It must not react to
// changes in the NSEC property itself, or it responds to its own output.
func TestChangedChainNamesIgnoresTheNsecProperty(t *testing.T) {
	nsecOf := func(name string) core.RRset {
		rr, err := dns.NewRR(name + " 300 IN NSEC next.example. A RRSIG NSEC")
		if err != nil {
			t.Fatal(err)
		}
		return core.RRset{Name: name, RRtype: dns.TypeNSEC, RRs: []dns.RR{rr}}
	}
	withA := func(name string) *OwnerData {
		od := &OwnerData{Name: name, RRtypes: NewRRTypeStore()}
		rr, err := dns.NewRR(name + " 300 IN A 10.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		od.RRtypes.Set(dns.TypeA, core.RRset{Name: name, RRtype: dns.TypeA, RRs: []dns.RR{rr}})
		return od
	}

	pub := withA("alpha.example.")
	ws := withA("alpha.example.")
	ws.NSEC = nsecOf("alpha.example.") // only the derived record differs

	got := changedChainNames(&zoneSnapshot{Data: map[string]*OwnerData{"alpha.example.": pub}},
		map[string]*OwnerData{"alpha.example.": ws})
	if len(got) != 0 {
		t.Fatalf("a change confined to the NSEC property was reported as a zone change: %v", got)
	}

	// A real change is still reported.
	ws2 := withA("alpha.example.")
	ws2.RRtypes.Delete(dns.TypeA)
	got = changedChainNames(&zoneSnapshot{Data: map[string]*OwnerData{"alpha.example.": pub}},
		map[string]*OwnerData{"alpha.example.": ws2})
	if len(got) != 1 || got[0] != "alpha.example." {
		t.Fatalf("a real change was not reported: %v", got)
	}
}
