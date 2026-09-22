/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// A forwarded root is reported as forwarded, not as a root NS that is absent:
// nothing is iterated, so "iteration cannot start" would be a false alarm.
func TestImrRootStatusForAForwardedRoot(t *testing.T) {
	got := imrRootStatusLines(&tdns.ImrStatus{RootForwarded: true})
	if got != "IMR: root forwarded: not primed, no root NS kept\n" {
		t.Errorf("forwarded root: %q", got)
	}
	if got := imrRootStatusLines(&tdns.ImrStatus{}); !strings.Contains(got, "root NS: ABSENT") {
		t.Errorf("iterated root with no root NS: %q", got)
	}
}
