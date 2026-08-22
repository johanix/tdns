package tdns

import (
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
