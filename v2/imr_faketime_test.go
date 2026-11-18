/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The test clock needs its file, cannot be combined with a root refresh, and
// implies none. A resolver asked for it without a file does not start.
func TestFaketimeActivation(t *testing.T) {
	t.Cleanup(func() { cache.SetDataClock(nil) })
	t.Setenv("FAKETIME_TIMESTAMP_FILE", "")
	on, off := true, false
	ctx := context.Background()

	for name, tc := range map[string]ImrTestingConf{
		"no file named":             {Faketime: true},
		"a missing file":            {FaketimeFile: filepath.Join(t.TempDir(), "missing")},
		"root-refresh beside it":    {Faketime: true, FaketimeFile: startTestDataClock(t, faketime2010), RootRefresh: &on},
		"root-refresh without file": {Faketime: true, RootRefresh: &on},
	} {
		cache.SetDataClock(nil)
		if err := startDataClock(ctx, tc); err == nil {
			t.Errorf("%s: the clock started", name)
		}
	}

	conf := &Config{}
	conf.Imr.Testing.Faketime = true
	if err := conf.InitImrEngine(ctx, true); err == nil || !strings.Contains(err.Error(), "faketime") {
		t.Errorf("InitImrEngine with faketime and no file: %v; want a faketime error", err)
	}

	if !(ImrTestingConf{Faketime: true}).SkipRootRefresh() || !(ImrTestingConf{RootRefresh: &off}).SkipRootRefresh() ||
		(ImrTestingConf{}).SkipRootRefresh() || (ImrTestingConf{RootRefresh: &on}).SkipRootRefresh() {
		t.Error("the root refresh is off exactly when root-refresh is false or the test clock is on")
	}
}
