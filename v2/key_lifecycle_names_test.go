/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// T4.2 (key lifecycle ownership test plan §4.5): tdns names no multi-provider
// key state, DS model or lifecycle hook any more. The owner (tdns-mp) carries
// its state names and registers them with RegisterKeyStateFlags; tdns reads
// its rows by their columns. A grep gate in the style of the Makefile's
// check-no-mutators, as a test so that `go test` runs it: every non-test Go
// file of this package and of the CLI is scanned for the identifiers S4
// removed and for the state names as quoted literals. The wire format in
// core carries the owner's signals by name and is not scanned.
func TestNoMultiProviderNamesLeftInTdns(t *testing.T) {
	forbidden := []string{
		"DnskeyStateMpdist", "DnskeyStateForeign", "DnskeyStateMpremove",
		"DSModelMultiProvider",
		"KeyLifecycleHooks", "RegisterKeyLifecycleHooks",
		`"mpdist"`, `'mpdist'`, `"mpremove"`, `'mpremove'`, `"foreign"`, `'foreign'`,
	}
	for _, dir := range []string{".", "cli"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 0 {
			t.Fatalf("no Go files under %s; the scan runs from the package directory", dir)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for i, line := range strings.Split(string(src), "\n") {
				for _, name := range forbidden {
					if strings.Contains(line, name) {
						t.Errorf("%s:%d names %s, which S4 removed from tdns: %s", f, i+1, name, strings.TrimSpace(line))
					}
				}
			}
		}
	}
}
