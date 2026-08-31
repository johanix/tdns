/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The imrengine: half of the zone-reload path (#436): what a SIGHUP re-reads,
 * and — more importantly — what it refuses to act on.
 */

package tdns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeImrConfig(t *testing.T, body string) *Config {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "tdns-imr.yaml")
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	conf := &Config{}
	conf.Internal.CfgFile = cfg
	return conf
}

// TestReloadImrEngineFromFile_RereadsAndReplaces: the reloadable half is read
// from the file, replacing whatever the last parse left in memory.
func TestReloadImrEngineFromFile_RereadsAndReplaces(t *testing.T) {
	conf := writeImrConfig(t, `imrengine:
   active: true
   stubs:
      - zone: internal.example.
        servers:
           - name: ns.internal.example.
             addrs: [ "192.0.2.5" ]
             alpn: [ "do53" ]
   forward:
      - zone: .
        upstreams:
           - addr: 192.0.2.1
             transport: do53
   tuning:
      query-budget: 8s
`)
	// Stale in-memory state, to prove the re-read replaces rather than merges.
	conf.Imr.Forward = []ImrForwardConf{fwdConf("stale.example.", "192.0.2.99", 0)}
	conf.Imr.Stubs = []ImrStubConf{stubConf("stale.example.", "ns.stale.example.", "192.0.2.98")}

	if err := conf.reloadImrEngineFromFile(); err != nil {
		t.Fatalf("reloadImrEngineFromFile: %v", err)
	}
	if len(conf.Imr.Forward) != 1 || conf.Imr.Forward[0].Zone != "." {
		t.Errorf("forward zones = %+v, want the root from the file", conf.Imr.Forward)
	}
	if len(conf.Imr.Stubs) != 1 || conf.Imr.Stubs[0].Zone != "internal.example." {
		t.Errorf("stub zones = %+v, want internal.example. from the file", conf.Imr.Stubs)
	}
}

// TestReloadImrEngineFromFile_RejectsUnknownKey is the one that matters: a
// misspelled key must fail the re-read, NOT decode to an empty list.
//
// With a lenient decode, `forwrd:` is silently ignored, Forward comes back
// empty, and the reload that follows deletes every forward zone the resolver
// is running on — a typo, on a SIGHUP, taking out forwarding.
func TestReloadImrEngineFromFile_RejectsUnknownKey(t *testing.T) {
	conf := writeImrConfig(t, `imrengine:
   active: true
   forwrd:
      - zone: .
        upstreams:
           - addr: 192.0.2.1
`)
	live := []ImrForwardConf{fwdConf(".", "192.0.2.1", 0)}
	conf.Imr.Forward = live

	err := conf.reloadImrEngineFromFile()
	if err == nil {
		t.Fatalf("misspelled imrengine key accepted; forward zones would be silently deleted")
	}
	if !strings.Contains(err.Error(), "forwrd") {
		t.Errorf("error does not name the offending key: %v", err)
	}
	if len(conf.Imr.Forward) != 1 || conf.Imr.Forward[0].Zone != "." {
		t.Errorf("running forward config was modified by a failed re-read: %+v", conf.Imr.Forward)
	}
}

// TestReloadImrEngineFromFile_NoBlock: a config with no imrengine: block is a
// legitimate "no resolver zones", distinct from a mistyped one.
func TestReloadImrEngineFromFile_NoBlock(t *testing.T) {
	conf := writeImrConfig(t, "zones:\n   - name: a.example.\n     type: primary\n")
	conf.Imr.Forward = []ImrForwardConf{fwdConf(".", "192.0.2.1", 0)}
	if err := conf.reloadImrEngineFromFile(); err != nil {
		t.Fatalf("reloadImrEngineFromFile: %v", err)
	}
	if len(conf.Imr.Forward) != 0 {
		t.Errorf("forward zones = %+v, want none once the block is gone from the file", conf.Imr.Forward)
	}
}
