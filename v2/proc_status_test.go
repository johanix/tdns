/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"os"
	"runtime"
	"testing"
)

func TestCollectProcStatus(t *testing.T) {
	ps := CollectProcStatus()
	if ps.Goroutines <= 0 {
		t.Errorf("goroutines = %d, want > 0", ps.Goroutines)
	}
	if ps.FDLimit == 0 {
		t.Error("RLIMIT_NOFILE not reported")
	}
	if ps.FDMethod == "unavailable" {
		t.Skipf("no fd counting on %s", runtime.GOOS)
	}
	if ps.OpenFDs <= 0 {
		t.Fatalf("open fds = %d (method %s), want > 0", ps.OpenFDs, ps.FDMethod)
	}

	// Opening descriptors must move the reading. Exact-count methods see
	// the full delta; the NetBSD watermark ("maxfd") must at least not
	// shrink while ten more descriptors are open.
	var files []*os.File
	for i := 0; i < 10; i++ {
		f, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		files = append(files, f)
	}
	ps2 := CollectProcStatus()
	switch ps.FDMethod {
	case "procfs", "devfd":
		if ps2.OpenFDs < ps.OpenFDs+10 {
			t.Errorf("after 10 opens: %d -> %d, want +10", ps.OpenFDs, ps2.OpenFDs)
		}
	case "maxfd":
		if ps2.OpenFDs < ps.OpenFDs {
			t.Errorf("watermark shrank with descriptors open: %d -> %d", ps.OpenFDs, ps2.OpenFDs)
		}
	}
	for _, f := range files {
		f.Close()
	}
	if ps3 := CollectProcStatus(); (ps.FDMethod == "procfs" || ps.FDMethod == "devfd") && ps3.OpenFDs >= ps2.OpenFDs {
		t.Errorf("count did not drop after closing: %d -> %d", ps2.OpenFDs, ps3.OpenFDs)
	}
}
