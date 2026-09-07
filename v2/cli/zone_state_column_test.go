/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * `zone list` answers "which of my zones are not OK".
 */
package cli

import (
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// zoneResponse builds a listing from (name, type, state, error) tuples.
func zoneResponse(zones ...tdns.ZoneConf) tdns.ZoneResponse {
	m := map[string]tdns.ZoneConf{}
	for _, z := range zones {
		m[z.Name] = z
	}
	return tdns.ZoneResponse{Zones: m}
}

func withHeaders(t *testing.T) {
	t.Helper()
	prev := tdns.Globals.ShowHeaders
	tdns.Globals.ShowHeaders = true
	t.Cleanup(func() { tdns.Globals.ShowHeaders = prev })
}

// THE REGRESSION. A secondary whose primary has never answered holds no data
// and SERVFAILs every query, and rendered as an ordinary healthy row. The
// listing must say so in a column, not in a trailing annotation that only
// appears once the first probe has timed out.
func TestListZonesShowsStateForANeverLoadedSecondary(t *testing.T) {
	withHeaders(t)
	out := captureStdout(t, func() {
		ListZones(zoneResponse(
			tdns.ZoneConf{Name: "good.example.", Type: "secondary", Store: "MapZone", Provisioning: "ready"},
			tdns.ZoneConf{Name: "broken.example.", Type: "secondary", Store: "MapZone", Provisioning: "error",
				Error: true, ErrorType: tdns.RefreshError, ErrorMsg: "SOA probe failed"},
		))
	})

	if !strings.Contains(out, "State") {
		t.Fatalf("no State column in the header:\n%s", out)
	}
	if strings.Contains(out, "Store") {
		t.Errorf("Store column is still rendered; it carries no information in practice:\n%s", out)
	}
	for _, want := range []string{"good.example.", "ready", "broken.example.", "error"} {
		if !strings.Contains(out, want) {
			t.Errorf("listing does not mention %q:\n%s", want, out)
		}
	}
}

// A service-impacting error no longer masquerades as a zone TYPE. It keeps its
// real type and says `error` where the state goes.
func TestListZonesRendersServiceImpactingErrorAsState(t *testing.T) {
	withHeaders(t)
	out := captureStdout(t, func() {
		ListZones(zoneResponse(tdns.ZoneConf{
			Name: "broken.example.", Type: "primary", Store: "MapZone", Provisioning: "error",
			Error: true, ErrorType: tdns.ConfigError, ErrorMsg: "no such file",
		}))
	})

	if !strings.Contains(out, "primary") {
		t.Errorf("the zone's real type is gone from the row:\n%s", out)
	}
	if !strings.Contains(out, "error") {
		t.Errorf("the row does not report state error:\n%s", out)
	}
	if strings.Contains(out, "Error[") {
		t.Errorf("the redundant Error[ prefix is still in the annotation; the State column already says which severity this is:\n%s", out)
	}
	if !strings.Contains(out, "[config: no such file]") {
		t.Errorf("the annotation lost the error type or message:\n%s", out)
	}
}

// The collapsed ERROR row emitted a fixed six fields and skipped the optional
// columns, so its cells landed under the wrong headers whenever -p, -n or -f
// was in play. Uniform rows mean every row has the same field count.
func TestListZonesRowsHaveUniformFieldCountUnderOptionalColumns(t *testing.T) {
	withHeaders(t)
	prev := showprimary
	showprimary = true
	t.Cleanup(func() { showprimary = prev })

	out := captureStdout(t, func() {
		ListZones(zoneResponse(
			tdns.ZoneConf{Name: "good.example.", Type: "secondary", Provisioning: "ready",
				Primaries: []tdns.PeerConf{{Addr: "192.0.2.1:53"}}},
			tdns.ZoneConf{Name: "broken.example.", Type: "secondary", Provisioning: "error",
				Error: true, ErrorType: tdns.ConfigError, ErrorMsg: "bad",
				Primaries: []tdns.PeerConf{{Addr: "192.0.2.2:53"}}},
		))
	})

	// columnize has already aligned the output, so compare the column at which
	// each row's primary address starts.
	var lines []string
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if strings.Contains(l, "192.0.2.") {
			lines = append(lines, l)
		}
	}
	if len(lines) != 2 {
		t.Fatalf("expected both rows to carry a primary address, got %d:\n%s", len(lines), out)
	}
	if a, b := strings.Index(lines[0], "192.0.2."), strings.Index(lines[1], "192.0.2."); a != b {
		t.Errorf("primary address starts at column %d in one row and %d in the other; the rows do not share a shape:\n%s", a, b, out)
	}
}

// A zone with no state reported renders as unknown rather than as a blank cell
// in the column the operator is scanning.
func TestListZonesRendersMissingStateAsUnknown(t *testing.T) {
	out := captureStdout(t, func() {
		ListZones(zoneResponse(tdns.ZoneConf{Name: "mystery.example.", Type: "primary"}))
	})
	if !strings.Contains(out, "unknown") {
		t.Errorf("a ZoneConf carrying no Provisioning rendered without a state:\n%s", out)
	}
}

// `zone desc` and `zone list -v` share zoneBaseDetail, so State is now present
// for a healthy zone too -- it used to appear only for a zone with an error.
func TestZoneDetailAlwaysCarriesState(t *testing.T) {
	healthy := tdns.ZoneConf{Name: "good.example.", Type: "primary", Store: "MapZone", Provisioning: "ready"}
	if got := zoneBaseDetail(healthy.Name, healthy); !strings.Contains(got, "State: ready") {
		t.Errorf("a healthy zone's detail block carries no State line:\n%s", got)
	}

	// And the false statement from the report: a never-loaded secondary
	// describing itself as serving.
	broken := tdns.ZoneConf{Name: "broken.example.", Type: "secondary", Store: "MapZone", Provisioning: "error",
		Error: true, ErrorType: tdns.RefreshError, ErrorMsg: "SOA probe failed"}
	got := zoneBaseDetail(broken.Name, broken)
	if strings.Contains(got, "serving") {
		t.Errorf("a zone that holds no data still describes itself as serving:\n%s", got)
	}
	if !strings.Contains(got, "State: error [refresh: SOA probe failed]") {
		t.Errorf("detail block does not report the state and its reason:\n%s", got)
	}
}
