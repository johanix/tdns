/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// config check parses a zone file as the server's loader does: a name whose
// trailing dot is missing fails here too, unless the zone allows doubled
// suffixes (#1009).
func TestConfigCheckRefusesADoubledSuffixAsTheLoaderDoes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r1.test.zone")
	if err := os.WriteFile(path, []byte(`$TTL 300
@	IN SOA	ns hostmaster 1 600 600 604800 600
@	IN NS	ns
ns	IN A	192.0.2.53
sub	IN NS	ns1.sub.r1.test
`), 0644); err != nil {
		t.Fatalf("write zone: %v", err)
	}
	err := parseZonefile(path, "r1.test", false)
	if err == nil || !strings.Contains(err.Error(), "trailing dot is probably missing") {
		t.Errorf("config check passed a file the loader refuses: %v", err)
	}
	if err := parseZonefile(path, "r1.test", true); err != nil {
		t.Errorf("with allow-doubled-suffix the file should parse: %v", err)
	}
}
