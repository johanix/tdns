/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadChaserAnchors says where the anchors came from, so that a chase run with
// other anchors than the operator meant says so in its output (#876, #379).
func TestLoadChaserAnchorsSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "anchors")
	ds := ". 3600 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n"
	if err := os.WriteFile(path, []byte(ds), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := trustAnchorFile
	t.Cleanup(func() { trustAnchorFile = saved })
	trustAnchorFile = path

	dss, source := loadChaserAnchors()
	if len(dss) != 1 {
		t.Fatalf("%d DS, want 1", len(dss))
	}
	if want := "file " + path + " (1 DS)"; source != want {
		t.Errorf("source %q, want %q", source, want)
	}

	// A file that cannot be read is not the source: the one fallen back to
	// is, whichever it is on this host.
	missing := filepath.Join(t.TempDir(), "missing")
	trustAnchorFile = missing
	if _, source := loadChaserAnchors(); source == "" || strings.Contains(source, missing) {
		t.Errorf("source %q for a missing file: want the source fallen back to", source)
	}
}
