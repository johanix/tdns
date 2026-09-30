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
				Signal: map[string]uint8{"doh": 0, "dot": 40, "do53": 100, "doq": 30}, SignalSource: "oots",
				Counts: map[string]uint64{"do53/udp": 345, "dot": 12, "doq": 1},
				ByPrivacy: map[string]map[string]uint64{
					"none":     {"do53/udp": 300, "dot": 2},
					"strict":   {"dot": 10, "doq": 1},
					"internal": {"do53/udp": 45},
				},
				Expected: map[string]map[string]uint8{
					"none":          {"do53": 30, "dot": 40, "doq": 30},
					"opportunistic": {"dot": 57, "doq": 43},
					"strict":        {"dot": 57, "doq": 43},
				},
				LastUsed: map[string]time.Time{"do53/udp": at.Add(-time.Minute), "dot": at}, LastAny: at,
				Total: 358, FailedTotal: 7, Truncated: 2},
			{Server: "ns2.example.net.", Shared: true, Zones: []string{"example.net.", "sub.example.net."},
				Counts:    map[string]uint64{"do53/udp": 900},
				ByPrivacy: map[string]map[string]uint64{"none": {"do53/udp": 900}},
				Expected:  map[string]map[string]uint8{"none": {"do53": 100}, "opportunistic": {"do53": 100}},
				LastUsed:  map[string]time.Time{"do53/udp": at.Add(-time.Hour)}, LastAny: at.Add(-time.Hour),
				Total: 900},
			{Server: "ns1.example.net.", Src: "stub", Zones: []string{"stub.test."},
				Signal: map[string]uint8{"do53": 100}, SignalSource: "config", Counts: map[string]uint64{}},
		},
		Reset: true,
	}
}

// lineStarting is the first line of out that starts with prefix.
func lineStarting(out, prefix string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

// linesAfter is the n lines that follow the first line starting with prefix.
func linesAfter(out, prefix string, n int) []string {
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, prefix) && i+n < len(lines) {
			return lines[i+1 : i+1+n]
		}
	}
	return nil
}

func TestFormatAuthTransports(t *testing.T) {
	out := formatAuthTransports(authTransportsTestReport(), "name", false, false)
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
	for _, unwanted := range []string{"EXPECTED", "PRIVACY"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("output has %s without --pct/--privacy:\n%s", unwanted, out)
		}
	}
	// The signal as given, in column order, with the zero the server sent.
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
	out := formatAuthTransports(authTransportsTestReport(), "name", true, false)
	f := strings.Fields(lineStarting(out, "ns1.example.net. "))
	// ns1.example.net. 1 | 96% 0% 3% <1% 0% | 358 7 2 ...
	if len(f) < 10 || f[2] != "96%" || f[3] != "0%" || f[4] != "3%" || f[5] != "<1%" || f[6] != "0%" || f[7] != "358" {
		t.Errorf("ns1 --pct fields %v, want 96%% 0%% 3%% <1%% 0%% then the count 358", f)
	}
	// EXPECTED is the no-PRIVACY shares, the transports that get none left out.
	if !strings.Contains(out, "EXPECTED") || !strings.Contains(lineStarting(out, "ns1.example.net. "), "do53:30 dot:40 doq:30") {
		t.Errorf("ns1 --pct lacks EXPECTED do53:30 dot:40 doq:30:\n%s", out)
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

// --privacy: a row per class used, in order, the server's own columns on the
// first; with --pct each row's EXPECTED is its level's, and none for internal.
func TestFormatAuthTransportsPrivacy(t *testing.T) {
	out := formatAuthTransports(authTransportsTestReport(), "name", true, true)
	first := strings.Fields(lineStarting(out, "ns1.example.net. "))
	// ns1.example.net. 1 none 99% 0% <1% 0% 0% 302 7 2 11:23:47 (dot) do53:30 dot:40 doq:30 ...
	if len(first) < 10 || first[2] != "none" || first[3] != "99%" || first[8] != "302" || first[9] != "7" {
		t.Errorf("ns1 first row %v, want none, 99%% do53/udp, 302 answers, FAIL 7", first)
	}
	next := linesAfter(out, "ns1.example.net. ", 2)
	if len(next) != 2 {
		t.Fatalf("no rows after ns1's first:\n%s", out)
	}
	strict, internal := strings.Fields(next[0]), strings.Fields(next[1])
	// strict 0% 0% 91% 9% 0% 11 dot:57 doq:43
	if len(strict) != 9 || strict[0] != "strict" || strict[3] != "91%" || strict[6] != "11" || strict[7] != "dot:57" {
		t.Errorf("ns1 strict row %v, want 91%% DoT of 11, EXPECTED dot:57 doq:43", strict)
	}
	// internal 100% 0% 0% 0% 0% 45 -- no EXPECTED
	if len(internal) != 7 || internal[0] != "internal" || internal[6] != "45" {
		t.Errorf("ns1 internal row %v, want 45 answers and no EXPECTED", internal)
	}
	// TOTAL rows per class: none 1200, strict 11, internal 45.
	if f := strings.Fields(lineStarting(out, "TOTAL")); len(f) < 8 || f[1] != "none" || f[7] != "1202" {
		t.Errorf("TOTAL none row %v, want 1202", f)
	}
	// The stub, with no answers, is one row.
	if f := strings.Fields(lineStarting(out, "ns1.example.net. (stub)")); len(f) < 4 || f[3] != "-" {
		t.Errorf("stub row %v, want one row with privacy -", f)
	}
}

// A resolver that predates the split: --privacy says so instead of making up
// rows.
func TestFormatAuthTransportsPrivacyFromAnOlderResolver(t *testing.T) {
	rep := authTransportsTestReport()
	for i := range rep.Rows {
		rep.Rows[i].ByPrivacy, rep.Rows[i].Expected = nil, nil
	}
	out := formatAuthTransports(rep, "name", true, true)
	if !strings.Contains(out, "predates --privacy") {
		t.Errorf("no note that the resolver predates the split:\n%s", out)
	}
	if f := strings.Fields(lineStarting(out, "ns2.example.net.")); len(f) < 3 || f[2] != "-" {
		t.Errorf("ns2 fields %v, want one unsplit row", f)
	}
}

// The OOTS column: the signal as given, a weight of 1 marked, an ALPN-only
// signal and an override said as such, and no signal told from an empty one.
func TestFormatOOTSSignal(t *testing.T) {
	for _, tc := range []struct {
		signal map[string]uint8
		source string
		want   string
	}{
		{nil, "", "none"},
		{nil, "oots", "empty"},
		{map[string]uint8{"do53": 100, "dot": 10, "doq": 10, "doh": 1}, "oots", "do53:100 dot:10 doq:10 doh:1 (ignored)"},
		{map[string]uint8{"doq": 50, "doh": 30}, "oots", "doq:50 doh:30"},
		{map[string]uint8{"doq": 100, "dot": 100}, "alpn", "alpn:dot,doq"},
		{map[string]uint8{"dot": 50}, "operator", "set: dot:50"},
	} {
		if got := formatOOTSSignal(tc.signal, tc.source); got != tc.want {
			t.Errorf("formatOOTSSignal(%v, %q) = %q, want %q", tc.signal, tc.source, got, tc.want)
		}
	}
}

func TestFormatAuthTransportsSort(t *testing.T) {
	out := formatAuthTransports(authTransportsTestReport(), "total", false, false)
	if strings.Index(out, "ns2.example.net.") > strings.Index(out, "ns1.example.net.") {
		t.Errorf("sort by total: ns2 (900) should come before ns1 (358):\n%s", out)
	}
	out = formatAuthTransports(authTransportsTestReport(), "last", false, false)
	if strings.Index(out, "ns1.example.net.") > strings.Index(out, "ns2.example.net.") {
		t.Errorf("sort by last: ns1 (11:23:47) should come before ns2 (10:23:47):\n%s", out)
	}
}
