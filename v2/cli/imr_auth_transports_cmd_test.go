/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"fmt"
	"slices"
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
		// udp and tcp apart, cleartext first; a cleartext weight of 1 is
		// not a share, so not marked.
		{map[string]uint8{"udp": 100, "tcp": 1, "dot": 50}, "oots", "udp:100 tcp:1 dot:50"},
		{map[string]uint8{"udp": 100, "tcp": 100, "doq": 100}, "alpn", "alpn:udp,tcp,doq"},
		{map[string]uint8{"doq": 50, "doh": 30}, "oots", "doq:50 doh:30"},
		{map[string]uint8{"doq": 100, "dot": 100}, "alpn", "alpn:dot,doq"},
		{map[string]uint8{"dot": 50}, "operator", "set: dot:50"},
	} {
		if got := formatOOTSSignal(tc.signal, nil, tc.source); got != tc.want {
			t.Errorf("formatOOTSSignal(%v, %q) = %q, want %q", tc.signal, tc.source, got, tc.want)
		}
	}
	got := formatOOTSSignal(
		map[string]uint8{"dot": 30, "doq": 20},
		map[string]uint16{"dot": 1234, "doq": 1235},
		"oots",
	)
	if got != "dot:30 port:1234 doq:20 port:1235" {
		t.Errorf("formatOOTSSignal with ports = %q", got)
	}
	got = formatOOTSSignal(
		map[string]uint8{"dot": 100, "doh": 100},
		map[string]uint16{"dot": 1234},
		"alpn",
	)
	if got != "alpn:dot port:1234,doh" {
		t.Errorf("formatOOTSSignal alpn with ports = %q", got)
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

// sortTestRows is auth servers in no order: the root and gtld servers a
// resolver always has, a stub whose name is a single label (a TLD of its own),
// and a provider's servers one label deeper. Those that give a signal: all
// kinds of it (a weighted one, ALPN only, an operator's override, one that
// names no transport).
func sortTestRows() []tdns.ImrAuthTransportsRow {
	rows := []tdns.ImrAuthTransportsRow{
		{Server: "ns1.ts.example.net.", Shared: true, Total: 5},
		{Server: "ns1.prov-b.ts.example.net.", Shared: true, Total: 9,
			Signal: map[string]uint8{"dot": 20, "doq": 40}, SignalSource: "oots"},
		{Server: "a.root-servers.net.", Shared: true, Total: 7},
		{Server: "h.root-servers-net.", Src: "stub", Total: 1},
		{Server: "a.gtld-servers.net.", Shared: true, Total: 7},
		{Server: "b.root-servers.net.", Shared: true, Total: 3,
			Signal: map[string]uint8{"dot": 50}, SignalSource: "operator"},
		{Server: "b.gtld-servers.net.", Shared: true, Total: 2, SignalSource: "oots"},
		{Server: "ns2.ts.example.net.", Shared: true, Total: 4,
			Signal: map[string]uint8{"udp": 100, "doq": 100}, SignalSource: "alpn"},
	}
	for i := range rows {
		n := rows[i].Total
		rows[i].Counts = map[string]uint64{"do53/udp": n}
		// Split by privacy level, so that --privacy shows the rows and not a
		// note that the resolver does not split them; some servers have two.
		rows[i].ByPrivacy = map[string]map[string]uint64{"none": {"do53/udp": n}}
		if i%2 == 0 {
			rows[i].ByPrivacy["internal"] = map[string]uint64{"do53/udp": 1}
		}
	}
	return rows
}

// tableServers is the servers of a formatted table, in the order of its rows:
// the first word of each line from the header to the TOTAL row, which must be
// the last. The lines under a server (--privacy) have an empty first cell.
func tableServers(t *testing.T, out string) []string {
	t.Helper()
	var names []string
	inTable, total := false, false
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case strings.HasPrefix(line, " "):
		case total:
			t.Errorf("line %q follows the TOTAL row:\n%s", line, out)
		case f[0] == "AUTH" && len(f) > 1 && f[1] == "SERVER":
			inTable = true
		case !inTable:
		case f[0] == "TOTAL":
			total = true
		default:
			names = append(names, f[0])
		}
	}
	if !total {
		t.Errorf("no TOTAL row:\n%s", out)
	}
	return names
}

func TestFormatAuthTransportsSortOrders(t *testing.T) {
	for _, tc := range []struct {
		name   string
		sortBy string
		want   []string
	}{
		// From the TLD down: every *.example.net. server together, the gtld
		// servers, the root servers; within a domain by the labels to the
		// left. The stub's name has a TLD of its own, root-servers-net., which
		// sorts after net. like any other.
		{"label", "label", []string{
			"ns1.ts.example.net.", "ns2.ts.example.net.", "ns1.prov-b.ts.example.net.",
			"a.gtld-servers.net.", "b.gtld-servers.net.",
			"a.root-servers.net.", "b.root-servers.net.",
			"h.root-servers-net.",
		}},
		// The servers that gave a signal first, whatever its kind and even if
		// it names no transport; label order within both groups.
		{"oots", "oots", []string{
			"ns2.ts.example.net.", "ns1.prov-b.ts.example.net.",
			"b.gtld-servers.net.", "b.root-servers.net.",
			"ns1.ts.example.net.", "a.gtld-servers.net.", "a.root-servers.net.",
			"h.root-servers-net.",
		}},
		{"name", "name", []string{
			"a.gtld-servers.net.", "a.root-servers.net.",
			"b.gtld-servers.net.", "b.root-servers.net.",
			"h.root-servers-net.",
			"ns1.prov-b.ts.example.net.", "ns1.ts.example.net.", "ns2.ts.example.net.",
		}},
		// The busiest first; a.gtld and a.root, 7 each, by name.
		{"total", "total", []string{
			"ns1.prov-b.ts.example.net.",
			"a.gtld-servers.net.", "a.root-servers.net.",
			"ns1.ts.example.net.", "ns2.ts.example.net.",
			"b.root-servers.net.", "b.gtld-servers.net.",
			"h.root-servers-net.",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := tdns.ImrAuthTransportsReport{Servers: len(sortTestRows()), Rows: sortTestRows()}
			got := tableServers(t, formatAuthTransports(rep, tc.sortBy, false, false))
			if !slices.Equal(got, tc.want) {
				t.Errorf("--sort %s:\n got %v\nwant %v", tc.sortBy, got, tc.want)
			}
			// The order the rows arrive in does not matter.
			rev := slices.Clone(sortTestRows())
			slices.Reverse(rev)
			rep.Rows = rev
			if again := tableServers(t, formatAuthTransports(rep, tc.sortBy, false, false)); !slices.Equal(again, tc.want) {
				t.Errorf("--sort %s on the rows reversed:\n got %v\nwant %v", tc.sortBy, again, tc.want)
			}
			// Nor does --privacy, which adds rows under a server.
			rep.Rows = sortTestRows()
			if priv := tableServers(t, formatAuthTransports(rep, tc.sortBy, false, true)); !slices.Equal(priv, tc.want) {
				t.Errorf("--sort %s --privacy:\n got %v\nwant %v", tc.sortBy, priv, tc.want)
			}
		})
	}
}

// The stub row is marked and sorts by its name; a name found by resolution and
// the same name in a stub zone are two rows, the shared one first, in any mode.
func TestFormatAuthTransportsSortStubAndCase(t *testing.T) {
	rep := tdns.ImrAuthTransportsReport{Rows: []tdns.ImrAuthTransportsRow{
		{Server: "h.root-servers-net.", Src: "stub"},
		{Server: "ns.example.net.", Src: "stub"},
		{Server: "ns.example.net.", Shared: true},
		{Server: "b.example.net.", Shared: true},
		{Server: "A.example.net.", Shared: true},
	}}
	out := formatAuthTransports(rep, "label", false, false)
	// Case is folded in label order: A sorts with a, before b.
	if got, want := tableServers(t, out), []string{
		"A.example.net.", "b.example.net.", "ns.example.net.", "ns.example.net.", "h.root-servers-net.",
	}; !slices.Equal(got, want) {
		t.Errorf("label order %v, want %v", got, want)
	}
	lines := strings.Split(out, "\n")
	var ns []string
	for _, l := range lines {
		if strings.HasPrefix(l, "ns.example.net.") {
			ns = append(ns, l)
		}
	}
	if len(ns) != 2 || strings.Contains(ns[0], "(stub)") || !strings.Contains(ns[1], "(stub)") {
		t.Errorf("want the shared ns.example.net. row, then the stub's:\n%s", out)
	}
	if !strings.Contains(out, "h.root-servers-net. (stub)") {
		t.Errorf("the stub row is not marked (stub):\n%s", out)
	}
	// Case is folded: B sorts between a and C, not before a.
	rows := []tdns.ImrAuthTransportsRow{{Server: "B.example."}, {Server: "a.example."}, {Server: "C.example."}}
	sortAuthTransportRows(rows, "label")
	if got := []string{rows[0].Server, rows[1].Server, rows[2].Server}; !slices.Equal(got, []string{"a.example.", "B.example.", "C.example."}) {
		t.Errorf("label order with mixed case %v, want a, B, C", got)
	}
}

// advertisesOOTS is the OOTS column's "none", seen from the row.
func TestAdvertisesOOTSMatchesTheColumn(t *testing.T) {
	for _, r := range sortTestRows() {
		col := formatOOTSSignal(r.Signal, r.SignalPorts, r.SignalSource)
		if got, want := advertisesOOTS(r), col != "none"; got != want {
			t.Errorf("%s: advertisesOOTS = %v, but the OOTS column says %q", r.Server, got, col)
		}
	}
}

func TestCheckAuthTransportsSort(t *testing.T) {
	for _, tc := range []struct {
		value   string
		wantErr bool
	}{
		{"label", false}, {"oots", false}, {"name", false}, {"total", false}, {"last", false},
		{"", true}, {"Label", true}, {"lable", true}, {"labels", true}, {"addr", true},
	} {
		err := checkAuthTransportsSort(tc.value)
		if (err != nil) != tc.wantErr {
			t.Errorf("--sort %q: error %v, want error: %v", tc.value, err, tc.wantErr)
			continue
		}
		if err == nil {
			continue
		}
		// The error names the value, and every value there is.
		for _, want := range []string{fmt.Sprintf("%q", tc.value), "label", "oots", "name", "total", "last"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("--sort %q: error %q lacks %s", tc.value, err, want)
			}
		}
	}
	if got := authTransportsSortFlagDefault(); got != "label" {
		t.Errorf("--sort defaults to %q, want label", got)
	}
}

// authTransportsSortFlagDefault is --sort's default as the command declares it.
func authTransportsSortFlagDefault() string {
	return imrStatsAuthTransportsCmd.Flags().Lookup("sort").DefValue
}
