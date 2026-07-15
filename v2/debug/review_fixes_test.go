/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// TestArtifactMarker covers the `cleanup --rm` ownership guard that replaced
// the old path-substring check: a marker written for one id is recognized only
// for that id, and an unmarked dir is never recognized (so cleanup refuses it).
func TestArtifactMarker(t *testing.T) {
	dir := t.TempDir()
	if IsToolArtifactDir(dir, "test001") {
		t.Fatal("unmarked dir must not be recognized as a tool artifact dir")
	}
	if err := WriteArtifactMarker(dir, "test001"); err != nil {
		t.Fatalf("WriteArtifactMarker: %v", err)
	}
	if !IsToolArtifactDir(dir, "test001") {
		t.Error("marker for test001 should be recognized")
	}
	if IsToolArtifactDir(dir, "test999") {
		t.Error("marker for test001 must not match a different id")
	}
	if IsToolArtifactDir(t.TempDir(), "test001") {
		t.Error("a dir without the marker must not be recognized")
	}
}

// TestRunChurnRejectsZeroDuration covers the guard against a zero Duration,
// which would otherwise make the run's context expire immediately and return a
// near-empty (falsely clean) report instead of a setup error.
func TestRunChurnRejectsZeroDuration(t *testing.T) {
	if _, err := RunChurn(context.Background(), ChurnConfig{Duration: 0}); err == nil || !strings.Contains(err.Error(), "duration") {
		t.Fatalf("expected a duration setup error, got: %v", err)
	}
}

// TestCapabilityMatrixConcurrentAccess guards the data-race fix: once actors
// run, Degrade (write) races Get/Available/Render (read). Meaningful under
// -race; without the mutex this trips the detector.
func TestCapabilityMatrixConcurrentAccess(t *testing.T) {
	m := &CapabilityMatrix{}
	m.set(CapApi, CapAvailable, "seed")
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); m.Degrade(CapApi, "mid-run") }()
		go func() { defer wg.Done(); _ = m.Available(CapApi); _ = m.Render() }()
	}
	wg.Wait()
}
