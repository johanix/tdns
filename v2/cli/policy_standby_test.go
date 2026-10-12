/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cli

import (
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// The zone description shows a policy's standby counts, and says so when the
// global kasp count applies.
func TestDescribeZoneShowsStandbyCounts(t *testing.T) {
	two := 2
	zconf := tdns.ZoneConf{
		Name:                  "sb.example.",
		EffectiveDnssecPolicy: "pol",
		PolicyDetail:          &tdns.DnssecPolicyView{Name: "pol", Mode: tdns.DnssecPolicyModeKSKZSK, StandbyZSKs: &two},
	}
	out := DescribeZone(zconf)
	if want := "Standby keys: ZSKs=2 KSKs=kasp"; !strings.Contains(out, want) {
		t.Fatalf("DescribeZone missing %q in output:\n%s", want, out)
	}
}
