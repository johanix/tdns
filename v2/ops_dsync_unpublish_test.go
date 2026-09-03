package tdns

import (
	"context"
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
	for _, zone := range []string{".", "example.", "child.example.", "sub.child.example."} {
		owner := dsyncOwnerName(zone)
		dsyncStr := fmt.Sprintf("%s 0 IN DSYNC CDS NOTIFY 53 .", owner)
		rr, err := dns.NewRR(dsyncStr)
		if err != nil {
			t.Fatalf("zone %s: the delete placeholder does not parse: %v (%q)",
				zone, err, dsyncStr)
		}
		if rr == nil {
			t.Fatalf("zone %s: parsed to nil", zone)
		}
		if got := rr.Header().Name; got != owner {
			t.Errorf("owner = %q, want %q", got, owner)
		}
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

// Unpublish must remove the bootstrap SVCB and the receiver KEY at the DSYNC
// UPDATE target — the same owner PublishDsyncRRs uses — not the apex KEY.
func TestUnpublishDsyncRemovesBootstrapSVCBAndReceiverKEY(t *testing.T) {
	t.Cleanup(func() { SetDelegationSyncConfig(DelegationSyncConf{}) })
	SetDelegationSyncConfig(DelegationSyncConf{
		Parent: DelegationSyncParentConf{
			Update: DsyncUpdateSchemeConf{
				DsyncDnsSchemeConf: DsyncDnsSchemeConf{Target: "updates.{ZONENAME}"},
			},
		},
	})
	q := make(chan UpdateRequest, 1)
	zd := &ZoneData{
		ZoneName: "example.",
		KeyDB:    &KeyDB{UpdateQ: q},
	}
	if err := zd.UnpublishDsyncRRs(context.Background()); err != nil {
		t.Fatal(err)
	}
	ur := <-q
	target := DsyncUpdateTargetName("example.")
	if target != "updates.example." {
		t.Fatalf("DsyncUpdateTargetName = %q", target)
	}
	var sawSVCB, sawKEY, sawApexKEY bool
	for _, rr := range ur.Actions {
		h := rr.Header()
		if h.Name == "example." && h.Rrtype == dns.TypeKEY {
			sawApexKEY = true
		}
		if h.Name != target {
			continue
		}
		if h.Class != dns.ClassANY {
			t.Errorf("%s at %s: class %d, want ANY", dns.TypeToString[h.Rrtype], target, h.Class)
		}
		switch h.Rrtype {
		case dns.TypeSVCB:
			sawSVCB = true
		case dns.TypeKEY:
			sawKEY = true
		}
	}
	if !sawSVCB || !sawKEY {
		t.Fatalf("unpublish missing SVCB or KEY at %s", target)
	}
	if sawApexKEY {
		t.Fatal("unpublish deleted the apex KEY; that is the parent's own SIG(0) identity")
	}
}

func TestUnpublishDsyncSkipsApexSVCBAndKEY(t *testing.T) {
	t.Cleanup(func() { SetDelegationSyncConfig(DelegationSyncConf{}) })
	SetDelegationSyncConfig(DelegationSyncConf{
		Parent: DelegationSyncParentConf{
			Update: DsyncUpdateSchemeConf{
				DsyncDnsSchemeConf: DsyncDnsSchemeConf{Target: "{ZONENAME}"},
			},
		},
	})
	q := make(chan UpdateRequest, 1)
	zd := &ZoneData{
		ZoneName: "example.",
		KeyDB:    &KeyDB{UpdateQ: q},
	}
	if err := zd.UnpublishDsyncRRs(context.Background()); err != nil {
		t.Fatal(err)
	}
	ur := <-q
	for _, rr := range ur.Actions {
		h := rr.Header()
		if h.Name == "example." && h.Class == dns.ClassANY &&
			(h.Rrtype == dns.TypeSVCB || h.Rrtype == dns.TypeKEY) {
			t.Fatalf("unpublish ClassANY %s at apex", dns.TypeToString[h.Rrtype])
		}
	}
}
