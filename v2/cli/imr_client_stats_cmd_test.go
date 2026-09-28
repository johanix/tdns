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
	out := formatClientStats(rep, "total")
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
