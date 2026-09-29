/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

func authTransportsTestReport() tdns.ImrAuthTransportsReport {
	at := time.Date(2026, 9, 29, 11, 23, 47, 0, time.UTC)
	return tdns.ImrAuthTransportsReport{
		Since: at.Add(-time.Hour), Servers: 4,
		Rows: []tdns.ImrAuthTransportsRow{
			{Server: "ns1.example.net.", Shared: true, Zones: []string{"example.net."},
				Signal:   map[string]uint8{"doh": 0, "dot": 40, "do53": 100, "doq": 30},
				Counts:   map[string]uint64{"do53/udp": 345, "dot": 12, "doq": 1},
				LastUsed: map[string]time.Time{"do53/udp": at.Add(-time.Minute), "dot": at}, LastAny: at,
				Total: 358, FailedTotal: 7, Truncated: 2},
			{Server: "ns2.example.net.", Shared: true, Zones: []string{"example.net.", "sub.example.net."},
				Counts:   map[string]uint64{"do53/udp": 900},
				LastUsed: map[string]time.Time{"do53/udp": at.Add(-time.Hour)}, LastAny: at.Add(-time.Hour),
				Total: 900},
			{Server: "ns1.example.net.", Src: "stub", Zones: []string{"stub.test."},
				Signal: map[string]uint8{"do53": 100}, Counts: map[string]uint64{}},
		},
		Reset: true,
	}
}

func lineStarting(out, prefix string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

func TestFormatAuthTransports(t *testing.T) {
	out := formatAuthTransports(authTransportsTestReport(), "name", false)
	for _, want := range []string{
		"4 servers held, 3 shown",
		"AUTH SERVER", "ZONES", "DO53/UDP", "DO53/TCP", "DOH", "FAIL", "TC", "LAST USED", "OOTS",
		"11:23:47 (dot)",
		"ns1.example.net. (stub)",
		"a new period starts now",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// The signal follows the column order, and a zero is what the server said.
	if !strings.Contains(out, "do53:100 dot:40 doq:30 doh:0") {
		t.Errorf("signal not in column order with its zero:\n%s", out)
	}
	// No signal says so, rather than looking like an explicit do53:100.
	if line := lineStarting(out, "ns2.example.net."); !strings.HasSuffix(strings.TrimSpace(line), "none") {
		t.Errorf("ns2 line %q, want the signal none", line)
	}
	// ns2 serves two zones; TOTAL adds Do53/UDP over the rows.
	if f := strings.Fields(lineStarting(out, "ns2.example.net.")); len(f) < 3 || f[1] != "2" {
		t.Errorf("ns2 fields %v, want ZONES 2", f)
	}
	if f := strings.Fields(lineStarting(out, "TOTAL")); len(f) != 9 || f[1] != "1245" || f[6] != "1258" || f[7] != "7" || f[8] != "2" {
		t.Errorf("TOTAL fields %v, want do53/udp 1245, total 1258, fail 7, tc 2", f)
	}
}

func TestFormatAuthTransportsPct(t *testing.T) {
	out := formatAuthTransports(authTransportsTestReport(), "name", true)
	f := strings.Fields(lineStarting(out, "ns1.example.net. "))
	// ns1.example.net. 1 | 96% 0% 3% <1% 0% | 358 7 2 ...
	if len(f) < 10 || f[2] != "96%" || f[3] != "0%" || f[4] != "3%" || f[5] != "<1%" || f[6] != "0%" || f[7] != "358" {
		t.Errorf("ns1 --pct fields %v, want 96%% 0%% 3%% <1%% 0%% then the count 358", f)
	}
	if f := strings.Fields(lineStarting(out, "ns2.example.net.")); len(f) < 3 || f[2] != "100%" {
		t.Errorf("ns2 --pct fields %v, want 100%% do53/udp", f)
	}
	if f := strings.Fields(lineStarting(out, "ns1.example.net. (stub)")); len(f) < 4 || f[3] != "-" {
		t.Errorf("stub --pct fields %v, want - for a server with no answers", f)
	}
	if got := countOrShare(999, 1000, true); got != ">99%" {
		t.Errorf("999 of 1000 = %q, want >99%%", got)
	}
}

func TestFormatAuthTransportsSort(t *testing.T) {
	out := formatAuthTransports(authTransportsTestReport(), "total", false)
	if strings.Index(out, "ns2.example.net.") > strings.Index(out, "ns1.example.net.") {
		t.Errorf("sort by total: ns2 (900) should come before ns1 (358):\n%s", out)
	}
	out = formatAuthTransports(authTransportsTestReport(), "last", false)
	if strings.Index(out, "ns1.example.net.") > strings.Index(out, "ns2.example.net.") {
		t.Errorf("sort by last: ns1 (11:23:47) should come before ns2 (10:23:47):\n%s", out)
	}
}
