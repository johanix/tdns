/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

const costsFixture = `
costs:
   arm64:
      MLDSA44:    { signing: 8.5, validation: 2.0 }
      RSASHA256:  { signing: 48,  validation: 0.8 }
   amd64:
      MLDSA44:    { signing: 5.9, validation: 2.1 }
`

func writeCosts(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "algorithm-costs.yaml")
	if err := os.WriteFile(path, []byte(costsFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAlgorithmProfiles_ArchSelection(t *testing.T) {
	path := writeCosts(t)
	t.Cleanup(viper.Reset)

	// Select amd64 explicitly.
	viper.Reset()
	viper.Set("algorithms.costsfile", path)
	viper.Set("algorithms.costarch", "amd64")
	got := loadAlgorithmProfiles()
	if len(got) != 1 {
		t.Fatalf("amd64 block: got %d entries, want 1", len(got))
	}
	// Keyed by lower-cased name; 5.9 rounds to 6, 2.1 rounds to 2.
	if p := got["mldsa44"]; p.SigningCost != 6 || p.ValidationCost != 2 {
		t.Errorf("amd64 MLDSA44 = %+v; want {6, 2}", p)
	}

	// Select arm64 explicitly.
	viper.Reset()
	viper.Set("algorithms.costsfile", path)
	viper.Set("algorithms.costarch", "arm64")
	got = loadAlgorithmProfiles()
	if len(got) != 2 {
		t.Fatalf("arm64 block: got %d entries, want 2", len(got))
	}
	// A sub-1 cost (RSA verify 0.8) rounds UP to 1, not down to 0, so it
	// does not read as "unspecified".
	if p := got["rsasha256"]; p.SigningCost != 48 || p.ValidationCost != 1 {
		t.Errorf("arm64 RSASHA256 = %+v; want {48, 1}", p)
	}
}

func TestLoadAlgorithmProfiles_MissingArchAndFile(t *testing.T) {
	t.Cleanup(viper.Reset)

	// No costsfile configured → nil (no cost columns).
	viper.Reset()
	if got := loadAlgorithmProfiles(); got != nil {
		t.Errorf("no costsfile: got %v, want nil", got)
	}

	// costsfile set but arch absent from the file → nil (not an error).
	path := writeCosts(t)
	viper.Reset()
	viper.Set("algorithms.costsfile", path)
	viper.Set("algorithms.costarch", "riscv64")
	if got := loadAlgorithmProfiles(); got != nil {
		t.Errorf("unknown arch: got %v, want nil", got)
	}

	// costsfile points at a nonexistent path → nil (warn + omit).
	viper.Reset()
	viper.Set("algorithms.costsfile", filepath.Join(t.TempDir(), "nope.yaml"))
	if got := loadAlgorithmProfiles(); got != nil {
		t.Errorf("missing file: got %v, want nil", got)
	}
}
