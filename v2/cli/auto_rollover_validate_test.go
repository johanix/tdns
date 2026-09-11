package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// auto-rollover validate re-parses one policy offline. It has to apply the
// file's dnssec.split-algorithms, or a KSK/ZSK split the daemon accepted
// reads as "not listed" here.
func TestLoadPolicyFromYAMLFileHonoursSplitAlgorithms(t *testing.T) {
	policy := `
  policies:
    mixed:
      algorithm: ED25519
      ksk: { lifetime: forever, algorithm: ECDSAP256SHA256 }
      zsk: { lifetime: forever }
      csk: { lifetime: none }
      sigvalidity: { default: 14d }
`
	dir := t.TempDir()
	with := filepath.Join(dir, "with.yaml")
	without := filepath.Join(dir, "without.yaml")
	if err := os.WriteFile(with, []byte("dnssec:\n  split-algorithms:\n    ECDSAP256SHA256: [ ED25519 ]\n"+policy), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(without, []byte("dnssec:\n"+policy), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, name, err := loadPolicyFromYAMLFile(with, "", "mixed"); err != nil || name != "mixed" {
		t.Fatalf("allowlisted split rejected: name=%q err=%v", name, err)
	}
	if _, _, err := loadPolicyFromYAMLFile(without, "", "mixed"); err == nil || !strings.Contains(err.Error(), "split-algorithms") {
		t.Fatalf("unlisted split accepted or wrong error: %v", err)
	}
}
