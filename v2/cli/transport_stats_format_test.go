/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cli

import (
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
)

// TestFormatTransportStats_IncludesDo53TCPAndTotal guards the P3 fix: Do53TCP
// must appear and the totals must include it (the old renderers dropped it).
func TestFormatTransportStats_IncludesDo53TCPAndTotal(t *testing.T) {
	ts := cache.TransportStats{
		Attempted: map[core.Transport]uint64{
			core.TransportDo53:    90,
			core.TransportDo53TCP: 10, // must NOT be dropped
			core.TransportDoQ:     5,
		},
		Used:      map[core.Transport]uint64{core.TransportDo53TCP: 12},
		Failed:    map[core.Transport]uint64{core.TransportDoQ: 3},
		Truncated: 7,
	}
	out := formatTransportStats(ts)

	for _, want := range []string{
		"do53-tcp:10",     // Do53TCP attempted is rendered
		"total: 105",      // attempted total includes do53-tcp (90+10+5)
		"used=[do53-tcp:12", // used Do53TCP rendered
		"failed=[doq:3",
		"truncated=7",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("formatTransportStats missing %q in output:\n%s", want, out)
		}
	}
}

// TestFormatTransportCountMap_EmptyIsNone: an empty counter map renders "none".
func TestFormatTransportCountMap_EmptyIsNone(t *testing.T) {
	if got := formatTransportCountMap(nil); got != "none" {
		t.Fatalf(`empty map should render "none", got %q`, got)
	}
}
