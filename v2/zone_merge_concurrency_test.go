package tdns

import (
	"os"
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A delta persisted after the merge read the journal is in neither the merged
// snapshot nor the new file. An unbounded replacement deletes every row for the
// zone, so that change would survive in nothing at all.
func TestReplaceZoneJournalKeepsRowsItDidNotObserve(t *testing.T) {
	kdb := newTestKeyDB(t)

	rr := func(s string) core.RRset {
		t.Helper()
		r, err := dns.NewRR(s)
		if err != nil {
			t.Fatalf("NewRR(%q): %v", s, err)
		}
		return core.RRset{Name: r.Header().Name, RRtype: r.Header().Rrtype, RRs: []dns.RR{r}}
	}

	// What the merge reads.
	if err := kdb.PersistZoneDelta("example.", 1, 2, nil,
		[]core.RRset{rr("observed.example. 3600 IN A 10.0.0.1")}); err != nil {
		t.Fatalf("PersistZoneDelta (observed): %v", err)
	}
	observed, err := kdb.LoadZoneDeltas("example.")
	if err != nil {
		t.Fatalf("LoadZoneDeltas: %v", err)
	}
	var observedMax int64
	for _, d := range observed {
		if d.MaxID > observedMax {
			observedMax = d.MaxID
		}
	}

	// What lands while the merge is still working.
	if err := kdb.PersistZoneDelta("example.", 2, 3, nil,
		[]core.RRset{rr("concurrent.example. 3600 IN A 10.0.0.2")}); err != nil {
		t.Fatalf("PersistZoneDelta (concurrent): %v", err)
	}

	if err := kdb.ReplaceZoneJournal("example.", 9, 10, nil,
		[]core.RRset{rr("merged.example. 3600 IN A 10.0.0.3")}, observedMax); err != nil {
		t.Fatalf("ReplaceZoneJournal: %v", err)
	}

	deltas, err := kdb.LoadZoneDeltas("example.")
	if err != nil {
		t.Fatalf("LoadZoneDeltas: %v", err)
	}
	var all []string
	for _, d := range deltas {
		for _, r := range d.RRs {
			all = append(all, r.RR)
		}
	}
	joined := strings.Join(all, "\n")
	if !strings.Contains(joined, "concurrent.example.") {
		t.Fatalf("the delta persisted after the merge read the journal was erased;"+
			" it is in neither the file nor the journal. Journal now holds:\n%s", joined)
	}
	if !strings.Contains(joined, "merged.example.") {
		t.Fatalf("the replacement delta is missing. Journal now holds:\n%s", joined)
	}
	if strings.Contains(joined, "observed.example.") {
		t.Fatalf("the observed delta should have been replaced. Journal now holds:\n%s", joined)
	}
}

// An artefact whose name is taken by DIFFERENT content must not be clobbered:
// the operator may be part-way through replaying it, and the records it names
// exist nowhere else. Identical content is the retry case and may rewrite.
func TestRejectedArtefactDoesNotClobberDifferentContent(t *testing.T) {
	dir := t.TempDir()
	zonefile := dir + "/example.zone"

	first := []ZoneDeltaRR{{Action: ZoneDeltaAdd, RR: "one.example. 3600 IN A 10.0.0.1"}}
	p1, err := writeRejectedArtefactInstructions(zonefile, "example.", 7, ConflictDBWins, first)
	if err != nil {
		t.Fatalf("first artefact: %v", err)
	}

	// The retry: same serial, same content. Same path, no proliferation.
	p2, err := writeRejectedArtefactInstructions(zonefile, "example.", 7, ConflictDBWins, first)
	if err != nil {
		t.Fatalf("rewriting identical content: %v", err)
	}
	if p1 != p2 {
		t.Fatalf("identical content produced a second file: %q then %q", p1, p2)
	}

	// A different merge reusing the serial must not overwrite the first.
	second := []ZoneDeltaRR{{Action: ZoneDeltaAdd, RR: "two.example. 3600 IN A 10.0.0.2"}}
	p3, err := writeRejectedArtefactInstructions(zonefile, "example.", 7, ConflictDBWins, second)
	if err != nil {
		t.Fatalf("second artefact: %v", err)
	}
	if p3 == p1 {
		t.Fatal("different content overwrote the existing artefact")
	}
	original, err := os.ReadFile(p1)
	if err != nil {
		t.Fatalf("re-reading the first artefact: %v", err)
	}
	if !strings.Contains(string(original), "one.example.") {
		t.Fatalf("the first artefact no longer holds its own records:\n%s", original)
	}
}
