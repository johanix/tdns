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

func TestFormatClientStats(t *testing.T) {
	at := time.Date(2026, 9, 28, 9, 41, 13, 0, time.UTC)
	rep := tdns.ImrClientStatsReport{
		Since: at.Add(-time.Hour), Clients: 3, EvictedClients: 1,
		EvictedCounts: map[string]uint64{"do53/udp": 5},
		Rows: []tdns.ImrClientStatsRow{
			{Client: "192.0.2.10", Counts: map[string]uint64{"do53/udp": 12, "dot": 340}, Total: 352,
				LastSeen: map[string]time.Time{"do53/udp": at.Add(-time.Minute), "dot": at}, LastAny: at},
			{Client: "2001:db8::53", Counts: map[string]uint64{"doq": 118}, Total: 118,
				LastSeen: map[string]time.Time{"doq": at.Add(-15 * time.Second)}, LastAny: at.Add(-15 * time.Second)},
		},
		Reset: true,
	}
	out := formatClientStats(rep, "total", false, false)
	for _, want := range []string{
		"3 clients held, 2 shown, 1 evicted",
		"DO53/UDP", "DOH",
		"192.0.2.10", "09:41:13 (dot)",
		"(1 evicted)",
		"a new period starts now",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// The TOTAL line adds the evicted counts: 12+5 over Do53/UDP.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "TOTAL") && !strings.Contains(line, "17") {
			t.Errorf("TOTAL line %q lacks the Do53/UDP total 17", line)
		}
	}
	// --sort total puts the busiest client first.
	if strings.Index(out, "192.0.2.10") > strings.Index(out, "2001:db8::53") {
		t.Errorf("sort by total: 192.0.2.10 (352) should come before 2001:db8::53 (118):\n%s", out)
	}
}

// #855's example: a client that uses all three levels is three rows, one that
// never asks for privacy stays one.
func TestFormatClientStatsPrivacy(t *testing.T) {
	at := time.Date(2026, 9, 30, 9, 16, 42, 0, time.UTC)
	rep := tdns.ImrClientStatsReport{
		Since: at.Add(-time.Hour), Clients: 2,
		Rows: []tdns.ImrClientStatsRow{
			{Client: "192.0.2.1", Counts: map[string]uint64{"do53/udp": 1500}, Total: 1500,
				ByPrivacy: map[string]map[string]uint64{"none": {"do53/udp": 1500}},
				LastSeen:  map[string]time.Time{"do53/udp": at}, LastAny: at},
			{Client: "192.0.2.6", Counts: map[string]uint64{"do53/udp": 99, "doh": 901}, Total: 1000,
				ByPrivacy: map[string]map[string]uint64{
					"none":          {"do53/udp": 99, "doh": 541},
					"opportunistic": {"doh": 230},
					"strict":        {"doh": 130},
				},
				LastSeen: map[string]time.Time{"doh": at}, LastAny: at},
		},
	}
	out := formatClientStats(rep, "addr", false, true)
	if f := strings.Fields(lineStarting(out, "192.0.2.6")); len(f) < 9 || f[1] != "none" || f[2] != "99" || f[6] != "541" || f[7] != "640" {
		t.Errorf("192.0.2.6 none row %v, want 99 over Do53/UDP, 541 over DoH, 640", f)
	}
	next := linesAfter(out, "192.0.2.6", 2)
	if len(next) != 2 || !strings.HasPrefix(strings.TrimSpace(next[0]), "opp.") || !strings.HasPrefix(strings.TrimSpace(next[1]), "strict") {
		t.Errorf("rows after 192.0.2.6: %q, want opp. then strict", next)
	}
	if f := strings.Fields(next[1]); len(f) != 7 || f[5] != "130" || f[6] != "130" {
		t.Errorf("strict row %v, want 130 over DoH", f)
	}
	// A client that never asked for privacy is one row.
	if after := linesAfter(out, "192.0.2.1", 1); len(after) != 1 || !strings.HasPrefix(after[0], "192.0.2.6") {
		t.Errorf("192.0.2.1 is followed by %q, want the next client", after)
	}
	// TOTAL: none 1640, opp. 230, strict 130.
	if f := strings.Fields(lineStarting(out, "TOTAL")); len(f) < 8 || f[1] != "none" || f[7] != "2140" {
		t.Errorf("TOTAL none row %v, want 2140", f)
	}

	out = formatClientStats(rep, "addr", true, false)
	if f := strings.Fields(lineStarting(out, "192.0.2.6")); len(f) < 7 || f[1] != "10%" || f[5] != "90%" || f[6] != "1000" {
		t.Errorf("192.0.2.6 --pct fields %v, want 10%% Do53/UDP, 90%% DoH, 1000", f)
	}
}
