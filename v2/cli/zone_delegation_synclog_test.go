/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2"
)

func TestFormatSyncLog(t *testing.T) {
	at := time.Date(2026, 9, 28, 9, 41, 7, 0, time.UTC)
	rep := &tdns.SyncLogReport{
		Enabled: true, Size: 10000, Since: at.Add(-time.Hour), Dropped: 3,
		Events: []tdns.SyncLogEvent{
			{Time: at, Parent: "example.", Child: "child.example.", Mechanism: tdns.SyncMechNotifyCSYNC,
				Outcome: tdns.SyncApplied, Changes: "ns +1 -0, glue +2 -0"},
			{Time: at.Add(-time.Minute), Child: "orphan.test.", Mechanism: tdns.SyncMechNotifyCDS,
				Outcome: tdns.SyncRefused, Rcode: "NOTAUTH", Reason: "server is not authoritative for parent of orphan.test."},
		},
	}
	out := formatSyncLog(rep)
	for _, want := range []string{
		"2 events shown, 10000 kept at most, 3 dropped",
		"MECHANISM",
		"child.example.",
		"NOTIFY(CSYNC)",
		"ns +1 -0, glue +2 -0",
		"NOTAUTH; server is not authoritative",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// An event without a parent shows "-", not an empty column.
	if !strings.Contains(out, " -  ") {
		t.Errorf("an event without a parent should show '-':\n%s", out)
	}
	if got := formatSyncLog(&tdns.SyncLogReport{Enabled: true, Size: 10}); !strings.Contains(got, "(no events)") {
		t.Errorf("empty report: %q", got)
	}
}
