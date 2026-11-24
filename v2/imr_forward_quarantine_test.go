/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Forward-table quarantine (#475). What these pin down is the behaviour the
 * old build-fails-whole path could not have: the daemon STARTS with a broken
 * forward zone, the broken part is inert rather than absent, and the parts
 * that still work still work.
 */

package tdns

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// The headline of #475: one misconfigured forward zone must not stop the
// resolver. With the quarantine removed and the old `return err` restored,
// InitImrEngine fails here and every assertion below is unreachable.
func TestInitImrEngineStartsWithABadForwardZone(t *testing.T) {
	addr, port, _, stop := startTestUpstream(t)
	defer stop()

	savedImr := Globals.ImrEngine
	defer func() { Globals.ImrEngine = savedImr }()

	conf := &Config{}
	conf.Internal.ServerErrors = NewServerErrorRegistry()
	conf.Imr.Forward = []ImrForwardConf{
		{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}},
		// trust-ad over plaintext: used to abort the whole daemon.
		{Zone: "bad.example.", TrustAD: true, Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.9"}}},
	}
	if err := conf.InitImrEngine(context.Background(), true); err != nil {
		t.Fatalf("InitImrEngine refused to start over one bad forward zone: %v", err)
	}
	imr := conf.Internal.ImrEngine
	if imr == nil {
		t.Fatal("no engine after InitImrEngine")
	}

	zones := map[string]ImrForwardZoneInfo{}
	for _, z := range imr.ForwardZoneList() {
		zones[z.Zone] = z
	}
	bad, ok := zones["bad.example."]
	if !ok || !imr.Cache.Forwarded("www.bad.example.", dns.TypeA) {
		t.Fatal("quarantined zone left the table: names under it would fall back to iteration")
	}
	if !bad.Quarantined {
		t.Error("bad.example. is serving; want quarantined")
	}
	if good, ok := zones["."]; !ok || good.Quarantined || !imr.Cache.Forwarded("www.other.example.", dns.TypeA) {
		t.Errorf("the healthy root forward did not survive: %+v", good)
	}

	// And the operator can see it, service-impacting half separated from the
	// still-serving half.
	var sawZone bool
	for _, e := range conf.Internal.ServerErrors.List() {
		if e.Category == ErrCatConfig && e.Subtype == ErrSubImrForwardZone {
			sawZone = true
			if !strings.Contains(e.Message, "bad.example.") {
				t.Errorf("zone-quarantine error does not name the zone: %s", e.Message)
			}
		}
	}
	if !sawZone {
		t.Error("no Config/ImrForwardZone error for a quarantined forward zone")
	}
}
