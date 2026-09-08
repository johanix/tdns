/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// allSchemesChildSync installs a childsync configuration offering every scheme,
// with addresses on each, and restores the previous one afterwards.
func allSchemesChildSync(t *testing.T) {
	t.Helper()
	prevCS, prevPS := *ChildSyncConfig(), *ParentSyncConfig()
	t.Cleanup(func() { _ = SetDelegationSyncConfig(prevCS, prevPS) })
	if err := SetDelegationSyncConfig(ChildSyncConf{
		Schemes: []string{"notify", "update", "api"},
		Notify: DsyncDnsSchemeConf{
			Types:     []string{"CDS", "CSYNC"},
			Port:      5302,
			Target:    "notifications.{ZONENAME}",
			Addresses: []string{"192.0.2.53", "2001:db8::53"},
		},
		Update: DsyncUpdateSchemeConf{
			DsyncDnsSchemeConf: DsyncDnsSchemeConf{
				Types:     []string{"ANY"},
				Port:      5302,
				Target:    "updates.{ZONENAME}",
				Addresses: []string{"192.0.2.53"},
			},
		},
		Api: DsyncApiSchemeConf{
			Target:    "api.{ZONENAME}",
			Port:      8443,
			Addresses: []string{"192.0.2.80"},
		},
	}, ParentSyncConf{}); err != nil {
		t.Fatal(err)
	}
}

// A zone that already publishes the UPDATE scheme and already carries one of
// the NOTIFY target's addresses: what PublishDsyncRRs sends is the delta.
const partiallyAdvertisedParent = `example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200
example. 3600 IN NS ns.example.
ns.example. 3600 IN A 192.0.2.1
_dsync.example. 7200 IN DSYNC ANY UPDATE 5302 updates.example.
notifications.example. 7200 IN A 192.0.2.53
`

func actionStrings(rrs []dns.RR) []string {
	out := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		out = append(out, dns.ClassToString[rr.Header().Class]+" "+rr.String())
	}
	return out
}

// The exact update PublishDsyncRRs sends for a partially advertised parent,
// record for record and in order. This pins the tdns-auth behaviour across
// the split into BuildDsyncPublication + install (childsync-proxy design,
// C-2): the split must not change what a parent publishes.
func TestPublishDsyncRRsSendsExactlyTheDelta(t *testing.T) {
	allSchemesChildSync(t)

	q := make(chan UpdateRequest, 1)
	zd := testZone(t, "example.", partiallyAdvertisedParent)
	zd.KeyDB = &KeyDB{UpdateQ: q}
	p := DefaultDelegationPolicy()
	zd.DelegationPolicy = &p

	if err := zd.PublishDsyncRRs(context.Background()); err != nil {
		t.Fatalf("PublishDsyncRRs: %v", err)
	}
	ur := <-q
	if ur.Cmd != "ZONE-UPDATE" || !ur.InternalUpdate || ur.ZoneName != "example." {
		t.Fatalf("unexpected request shape: %+v", ur)
	}

	got := actionStrings(ur.Actions)
	// The already-published UPDATE record is re-sent with the RRset: the
	// _dsync RRset is sent whole once anything in it is new, and re-adding a
	// record the zone has is a no-op there. The UPDATE target's address is
	// NOT sent -- that scheme was skipped -- and the NOTIFY target's A is
	// filtered out because the zone already carries it.
	want := []string{
		"IN _dsync.example.\t7200\tIN\tDSYNC\tANY\tUPDATE 5302 updates.example.",
		"IN _dsync.example.\t7200\tIN\tDSYNC\tCDS\tNOTIFY 5302 notifications.example.",
		"IN _dsync.example.\t7200\tIN\tDSYNC\tCSYNC\tNOTIFY 5302 notifications.example.",
		"IN _dsync.example.\t7200\tIN\tDSYNC\tCDS\tAPI 8443 api.example.",
		"IN _dsync.example.\t7200\tIN\tDSYNC\tCSYNC\tAPI 8443 api.example.",
		"IN api.example.\t7200\tIN\tURI\t1 1 \"https://api.example:8443/dsync/v1\"",
		"IN api.example.\t7200\tIN\tTXT\t\"tdns-child-api-v1.0\"",
		"IN updates.example.\t7200\tIN\tSVCB\t1 . key65282=\"at-apex,at-ns\"",
		"IN notifications.example.\t7200\tIN\tAAAA\t2001:db8::53",
		"IN api.example.\t7200\tIN\tA\t192.0.2.80",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("actions differ.\n--- got ---\n%s\n--- want ---\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// The builder is the compute half of PublishDsyncRRs: same delta, nothing
// sent. A childsync-proxy runs it on every refresh, so a zone that already
// carries the whole advertisement must build an empty publication.
func TestBuildDsyncPublicationIsTheDeltaAndNothingElse(t *testing.T) {
	allSchemesChildSync(t)

	q := make(chan UpdateRequest, 1)
	zd := testZone(t, "example.", partiallyAdvertisedParent)
	zd.KeyDB = &KeyDB{UpdateQ: q}
	p := DefaultDelegationPolicy()
	zd.DelegationPolicy = &p

	pub, err := zd.BuildDsyncPublication()
	if err != nil {
		t.Fatalf("BuildDsyncPublication: %v", err)
	}
	if pub.Empty() {
		t.Fatal("a partially advertised parent has a delta")
	}
	if pub.Synthesized != 4 || pub.Published != 1 {
		t.Errorf("synthesized=%d published=%d, want 4 (2 NOTIFY + 2 API) and 1", pub.Synthesized, pub.Published)
	}
	if len(q) != 0 {
		t.Fatal("the builder sent an update; only PublishDsyncRRs may")
	}

	if err := zd.PublishDsyncRRs(context.Background()); err != nil {
		t.Fatalf("PublishDsyncRRs: %v", err)
	}
	sent := actionStrings((<-q).Actions)
	if built := actionStrings(pub.Actions()); strings.Join(built, "\n") != strings.Join(sent, "\n") {
		t.Fatalf("Actions() differs from what PublishDsyncRRs sent.\n--- built ---\n%s\n--- sent ---\n%s",
			strings.Join(built, "\n"), strings.Join(sent, "\n"))
	}
}

// A zone carrying every configured record builds nothing. The published
// records are counted, which is how PublishDsyncRRs tells "nothing to do"
// from "nothing configured".
func TestBuildDsyncPublicationIsEmptyWhenFullyAdvertised(t *testing.T) {
	allSchemesChildSync(t)

	const fully = `example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200
example. 3600 IN NS ns.example.
ns.example. 3600 IN A 192.0.2.1
_dsync.example. 7200 IN DSYNC ANY UPDATE 5302 updates.example.
_dsync.example. 7200 IN DSYNC CDS NOTIFY 5302 notifications.example.
_dsync.example. 7200 IN DSYNC CSYNC NOTIFY 5302 notifications.example.
_dsync.example. 7200 IN DSYNC CDS API 8443 api.example.
_dsync.example. 7200 IN DSYNC CSYNC API 8443 api.example.
api.example. 7200 IN URI 1 1 "https://api.example:8443/dsync/v1"
api.example. 7200 IN TXT "tdns-child-api-v1.0"
updates.example. 7200 IN SVCB 1 . key65282="at-apex,at-ns"
updates.example. 7200 IN A 192.0.2.53
notifications.example. 7200 IN A 192.0.2.53
notifications.example. 7200 IN AAAA 2001:db8::53
api.example. 7200 IN A 192.0.2.80
`
	zd := testZone(t, "example.", fully)
	zd.KeyDB = &KeyDB{UpdateQ: make(chan UpdateRequest, 1)}
	p := DefaultDelegationPolicy()
	zd.DelegationPolicy = &p

	pub, err := zd.BuildDsyncPublication()
	if err != nil {
		t.Fatalf("BuildDsyncPublication: %v", err)
	}
	if !pub.Empty() {
		t.Fatalf("a fully advertised parent built a delta: %v", actionStrings(pub.Actions()))
	}
	if pub.Published != 5 || pub.Synthesized != 0 {
		t.Errorf("published=%d synthesized=%d, want 5 and 0", pub.Published, pub.Synthesized)
	}

	// And PublishDsyncRRs on it sends nothing and reports no error: the
	// "nothing to do" branch, distinct from "nothing configured".
	if err := zd.PublishDsyncRRs(context.Background()); err != nil {
		t.Fatalf("PublishDsyncRRs on a fully advertised zone: %v", err)
	}
	if len(zd.KeyDB.UpdateQ) != 0 {
		t.Fatal("PublishDsyncRRs sent an update for a fully advertised zone")
	}
}
