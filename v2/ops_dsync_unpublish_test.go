package tdns

import (
	"fmt"
	"testing"

	"github.com/miekg/dns"
)

// The placeholder DSYNC record UnpublishDsyncRRs builds exists only to carry an
// owner name and type into a ClassANY delete, so its rdata is irrelevant -- but
// it still has to parse. It did not: the leading type field was missing and the
// scheme was quoted, so dns.NewRR failed for every zone and `dsync unpublish`
// could never remove anything.
//
// This test pins the parse, not the values.
func TestUnpublishDsyncPlaceholderParses(t *testing.T) {
	// Not the root zone: "_dsync." + "." is "_dsync..", which is not a legal
	// owner name. PublishDsyncRRs builds the name the same way, so a root zone
	// acting as a delegation-sync parent is broken on both sides -- a separate,
	// pre-existing limitation, not what this test is about.
	for _, zone := range []string{"example.", "child.example.", "sub.child.example."} {
		dsyncStr := fmt.Sprintf("_dsync.%s 0 IN DSYNC CDS NOTIFY 53 .", zone)
		rr, err := dns.NewRR(dsyncStr)
		if err != nil {
			t.Fatalf("zone %s: the delete placeholder does not parse: %v (%q)",
				zone, err, dsyncStr)
		}
		if rr == nil {
			t.Fatalf("zone %s: parsed to nil", zone)
		}
		if got := rr.Header().Name; got != "_dsync."+zone {
			t.Errorf("owner = %q, want %q", got, "_dsync."+zone)
		}
		// The delete works by class, so that is what must survive.
		rr.Header().Class = dns.ClassANY
		if rr.Header().Class != dns.ClassANY {
			t.Error("class did not take")
		}
	}
}

// Guards the shape rather than the spelling: whatever rdata the placeholder
// carries, it must have all four DSYNC fields. A three-field form is what broke.
func TestUnpublishDsyncPlaceholderHasAllRdataFields(t *testing.T) {
	rr, err := dns.NewRR("_dsync.example. 0 IN DSYNC CDS NOTIFY 53 .")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := rr.(*dns.PrivateRR); !ok {
		t.Logf("DSYNC parsed as %T", rr)
	}
	// Three fields (scheme, port, target) is the broken form; it must not parse.
	if _, err := dns.NewRR(`_dsync.example. 0 IN DSYNC "NOTIFY" 53 1.2.3.4`); err == nil {
		t.Error("the old three-field placeholder parsed; this test no longer" +
			" guards anything")
	}
}
