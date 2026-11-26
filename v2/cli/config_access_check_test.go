package cli

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// The offline `config check` runs the daemon's own validator over the access
// file, so a file the daemon would refuse is found before the reload.
func TestConfigCheckValidatesTheAccessFile(t *testing.T) {
	sum := sha256.Sum256([]byte("anna"))
	pin := base64.StdEncoding.EncodeToString(sum[:])
	dir := t.TempDir()
	for _, tc := range []struct {
		name, body string
		want       ccLevel
	}{
		{"valid", "clients:\n  - {name: anna, pin: " + pin + ", role: read-only}\n", ccPASS},
		{"admin over the network", "clients:\n  - {name: anna, pin: " + pin + ", role: admin}\n", ccFAIL},
		{"misspelt key", "clients:\n  - {name: anna, pin: " + pin + ", role: read-only, disable: true}\n", ccFAIL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name+".yaml")
			if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := &tdns.Config{}
			cfg.ApiServer.AccessFile = p
			rep := newCCReport()
			checkApiAccessFile(cfg, rep)
			if !hasLevel(rep, "API access file", "access-file", tc.want) {
				t.Errorf("want level %v; report %+v", tc.want, rep.byGroup["API access file"])
			}
		})
	}
}
