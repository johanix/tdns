package cli

import (
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// §7 serial visibility. The condition that motivated the MUST-NOT-MODIFY work
// — two masters serving one zone at different serials — was previously
// invisible from tdns. These pin that it is now rendered, and that adding it
// did not disturb the `zone list -v` golden.

// TestZoneBaseDetailShowsSerials covers the free half: outbound vs inbound,
// shown side by side wherever the base block is rendered.
func TestZoneBaseDetailShowsSerials(t *testing.T) {
	zconf := tdns.ZoneConf{
		Name: "example.", Type: "secondary", Store: "MapZone",
		CurrentSerial: 42, IncomingSerial: 42,
		EffectiveOutboundSoaSerial: "keep", OutboundSoaSerialSource: "global",
	}
	out := zoneBaseDetail("example.", zconf)

	if !strings.Contains(out, "Serial: outbound 42\tinbound 42") {
		t.Errorf("serials not rendered:\n%s", out)
	}
	if !strings.Contains(out, "Outbound serial mode: keep (from: global)") {
		t.Errorf("outbound mode/source not rendered:\n%s", out)
	}
}

// TestZoneBaseDetailOmitsUnsetSerials pins the conditional: a zone with no
// serial information prints no serial line. This is also what keeps the
// `zone list -v` golden (a fixture with zero serials) byte-identical.
func TestZoneBaseDetailOmitsUnsetSerials(t *testing.T) {
	zconf := tdns.ZoneConf{Name: "example.", Type: "primary", Store: "MapZone"}
	out := zoneBaseDetail("example.", zconf)

	if strings.Contains(out, "Serial:") {
		t.Errorf("serial line rendered for a zone with no serials:\n%s", out)
	}
	if strings.Contains(out, "Outbound serial mode:") {
		t.Errorf("outbound mode rendered when unset:\n%s", out)
	}
}

// TestDescribeZoneShowsUpstreamDisagreement is the diagnostic itself: per
// primary, with the one that disagrees with our inbound serial flagged.
func TestDescribeZoneShowsUpstreamDisagreement(t *testing.T) {
	zconf := tdns.ZoneConf{
		Name: "example.", Type: "secondary", Store: "MapZone",
		CurrentSerial: 42, IncomingSerial: 42,
		UpstreamSerials: []tdns.UpstreamSerial{
			{Addr: "192.0.2.1:53", Serial: 42},   // agrees
			{Addr: "192.0.2.2:53", Serial: 5000}, // the split-brain
			{Addr: "192.0.2.3:53", Err: "i/o timeout"},
		},
	}
	out := DescribeZone(zconf)

	if !strings.Contains(out, "Upstream serials:") {
		t.Fatalf("no upstream serial section:\n%s", out)
	}
	if !strings.Contains(out, "192.0.2.2:53: 5000\t<-- differs") {
		t.Errorf("disagreeing primary not flagged:\n%s", out)
	}
	if strings.Contains(out, "192.0.2.1:53: 42\t<-- differs") {
		t.Errorf("agreeing primary wrongly flagged:\n%s", out)
	}
	// An unreachable primary is itself diagnostic and must be listed, not
	// silently dropped.
	if !strings.Contains(out, "192.0.2.3:53: (probe failed: i/o timeout)") {
		t.Errorf("failed probe not surfaced:\n%s", out)
	}
}

// TestDescribeZoneOmitsEmptyUpstreamSection keeps `zone desc` quiet for a
// primary, which has no upstreams to probe.
func TestDescribeZoneOmitsEmptyUpstreamSection(t *testing.T) {
	zconf := tdns.ZoneConf{Name: "example.", Type: "primary", Store: "MapZone"}
	if out := DescribeZone(zconf); strings.Contains(out, "Upstream serials:") {
		t.Errorf("upstream section rendered with no upstreams:\n%s", out)
	}
}
