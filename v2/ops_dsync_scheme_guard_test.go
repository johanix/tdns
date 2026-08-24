package tdns

import (
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func mustDsyncRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return rr
}

// The guard on an existing DSYNC RRset is per scheme, so adding a scheme to a
// zone that already publishes DSYNC records actually publishes it. All-or-
// nothing meant that did nothing at all, silently -- no record, no error.
func TestPublishedDsyncSchemesFindsWhatIsThere(t *testing.T) {
	rrs := []dns.RR{
		mustDsyncRR(t, "_dsync.example. 7200 IN DSYNC CDS NOTIFY 53 notifications.example."),
		mustDsyncRR(t, "_dsync.example. 7200 IN DSYNC CSYNC NOTIFY 53 notifications.example."),
		mustDsyncRR(t, "_dsync.example. 7200 IN DSYNC ANY UPDATE 53 updates.example."),
	}

	got := publishedDsyncSchemes(rrs)

	if !got[core.SchemeNotify] {
		t.Error("NOTIFY not detected as published")
	}
	if !got[core.SchemeUpdate] {
		t.Error("UPDATE not detected as published")
	}
	// The point of the whole change: API is NOT there, so it must be publishable.
	if got[core.SchemeAPI] {
		t.Error("API reported as published when no API record exists;" +
			" adding the scheme would silently do nothing")
	}
}

// Two records of the same scheme (one per RRtype) must collapse to one entry,
// not confuse the caller.
func TestPublishedDsyncSchemesDeduplicates(t *testing.T) {
	rrs := []dns.RR{
		mustDsyncRR(t, "_dsync.example. 7200 IN DSYNC CDS API 443 dsync-api.example."),
		mustDsyncRR(t, "_dsync.example. 7200 IN DSYNC CSYNC API 443 dsync-api.example."),
	}
	got := publishedDsyncSchemes(rrs)
	if len(got) != 1 || !got[core.SchemeAPI] {
		t.Fatalf("want exactly {API}, got %v", got)
	}
}

// An empty RRset means nothing is published, so every configured scheme is
// synthesized -- the original first-publication behaviour, unchanged.
func TestPublishedDsyncSchemesEmpty(t *testing.T) {
	if got := publishedDsyncSchemes(nil); len(got) != 0 {
		t.Fatalf("want empty, got %v", got)
	}
}

// Non-DSYNC records at the same owner are ignored rather than treated as an
// error: the job is to add what is missing, not to police what the operator put
// there.
func TestPublishedDsyncSchemesIgnoresOtherTypes(t *testing.T) {
	rrs := []dns.RR{
		mustDsyncRR(t, "_dsync.example. 7200 IN TXT \"not a dsync record\""),
		mustDsyncRR(t, "_dsync.example. 7200 IN DSYNC CDS NOTIFY 53 notifications.example."),
	}
	got := publishedDsyncSchemes(rrs)
	if len(got) != 1 || !got[core.SchemeNotify] {
		t.Fatalf("want exactly {NOTIFY}, got %v", got)
	}
}

// Regression guard for a slice-aliasing bug that could write into the LIVE
// DSYNC RRset with no serial bump and no journal entry.
//
// PublishDsyncRRs seeds its working set from the published RRset and then
// appends synthesized records to it. Assigning the published slice directly
// means those appends land in its spare capacity -- and a zone-file load sizes
// slices generously, so the capacity is usually there. The published RRset then
// silently gains records that never went through the update path, which is
// invisible until a zone happens to have the capacity for it.
//
// Asserted on the property rather than through PublishDsyncRRs, which needs a
// running updater: appending to the working copy must not disturb the source.
func TestPublishedDsyncSliceIsCopiedNotAliased(t *testing.T) {
	// A published slice with spare capacity, as a zone-file load produces.
	published := make([]dns.RR, 1, 4)
	published[0] = mustDsyncRR(t, "_dsync.example. 7200 IN DSYNC ANY UPDATE 5359 upd.example.")

	// What PublishDsyncRRs now does with it.
	working := append(make([]dns.RR, 0, len(published)), published...)
	working = append(working, mustDsyncRR(t, "_dsync.example. 7200 IN DSYNC ANY API 443 api.example."))

	if len(published) != 1 {
		t.Fatalf("the published slice grew to %d records", len(published))
	}
	if got := published[0].String(); !strings.Contains(got, "upd.example.") {
		t.Errorf("the published record was overwritten: %q", got)
	}
	if len(working) != 2 {
		t.Errorf("the working copy has %d records, want 2", len(working))
	}
	if &working[0] == &published[0] {
		t.Error("the working copy shares its backing array with the published RRset")
	}
}

// _dsync.<zone> can exist without a DSYNC RRset -- carrying only a TXT, say --
// and an owner with no RRtypes at all is a dereference away from taking the
// process down. Neither is a reason to fail publication: both mean "nothing
// published yet", which is precisely the case PublishDsyncRRs exists to fix.
func TestPublishedDsyncSchemesHandlesAnOwnerWithoutDsync(t *testing.T) {
	t.Run("no DSYNC RRset at the owner", func(t *testing.T) {
		od := &OwnerData{Name: "_dsync.example.", RRtypes: NewRRTypeStore()}
		od.RRtypes.Set(dns.TypeTXT, core.RRset{RRs: []dns.RR{
			mustDsyncRR(t, "_dsync.example. 7200 IN TXT \"not a dsync record\""),
		}})

		var published []dns.RR
		if od.RRtypes != nil {
			if existing, ok := od.RRtypes.Get(core.TypeDSYNC); ok {
				published = existing.RRs
			}
		}
		if len(published) != 0 {
			t.Errorf("an owner with no DSYNC RRset yielded %d records", len(published))
		}
		if got := publishedDsyncSchemes(published); len(got) != 0 {
			t.Errorf("schemes from an absent RRset = %v, want none", got)
		}
	})

	t.Run("owner with nil RRtypes", func(t *testing.T) {
		od := &OwnerData{Name: "_dsync.example."}
		var published []dns.RR
		if od.RRtypes != nil {
			if existing, ok := od.RRtypes.Get(core.TypeDSYNC); ok {
				published = existing.RRs
			}
		}
		if len(published) != 0 {
			t.Errorf("an owner with nil RRtypes yielded %d records", len(published))
		}
	})
}
