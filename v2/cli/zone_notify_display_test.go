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

// `zone desc` shows one line per NOTIFY target (#528): whether it answers, and
// what happened last.
func TestDescribeZoneShowsDownstreamNotifies(t *testing.T) {
	now := time.Now()
	zconf := tdns.ZoneConf{
		Name: "example.", Type: "primary", Store: "MapZone",
		DownstreamNotifies: []tdns.NotifyTargetStatus{
			{Target: "192.0.2.1:53", RRtype: "SOA", State: "ok", LastSuccess: now.Add(-time.Minute)},
			{Target: "192.0.2.2:53", RRtype: "SOA", State: "given up", Attempts: 6, Failures: 6,
				LastError: "i/o timeout"},
			{Target: "192.0.2.3:53", RRtype: "SOA", State: "retrying", Attempts: 2, Failures: 2,
				NextAttempt: now.Add(20 * time.Second), LastError: "i/o timeout"},
			{Target: "198.51.100.1:53", RRtype: "CDS", State: "ok", LastSuccess: now},
		},
	}
	out := DescribeZone(zconf)
	for _, want := range []string{
		"Downstream notifies:",
		"192.0.2.1:53: ok; last answer 1m0s ago",
		"192.0.2.2:53: given up after 6 attempts; last answer never; 6 unanswered in a row; last error: i/o timeout",
		"192.0.2.3:53: retrying (attempt 2, next in ",
		"NOTIFY(CDS) 198.51.100.1:53: ok",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("zone desc lacks %q:\n%s", want, out)
		}
	}
}

func TestDescribeZoneOmitsEmptyNotifySection(t *testing.T) {
	out := DescribeZone(tdns.ZoneConf{Name: "example.", Type: "primary", Store: "MapZone"})
	if strings.Contains(out, "Downstream notifies:") {
		t.Errorf("a zone with no NOTIFY state shows the section:\n%s", out)
	}
}
