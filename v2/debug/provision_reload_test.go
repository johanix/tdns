/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateReloadConfig(t *testing.T) {
	st, err := LoadState(filepath.Join(t.TempDir(), "state.yaml"))
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	out := t.TempDir()
	prov, err := GenerateReloadConfig(st, ReloadProvisionInput{
		BaseZone:  "test.axfr.net.",
		DnsServer: "127.0.0.1:5354",
		OutDir:    out,
		ZoneSize:  5,
		Algorithm: "SQISIGN1",
	})
	if err != nil {
		t.Fatalf("GenerateReloadConfig: %v", err)
	}

	// Zone file: apex + marker + exactly ZoneSize filler A RRsets.
	zoneBytes, err := os.ReadFile(prov.ZoneFile)
	if err != nil {
		t.Fatalf("read zone file: %v", err)
	}
	zone := string(zoneBytes)
	if n := strings.Count(zone, " IN A 192.0.2.1\n"); n != 5 {
		t.Errorf("expected 5 filler A records, got %d", n)
	}
	for _, want := range []string{"IN SOA", "IN NS", MarkerLabel, "host00001", "host00005"} {
		if !strings.Contains(zone, want) {
			t.Errorf("zone file missing %q", want)
		}
	}

	// Snippet: single-algorithm signed policy + online-signing zone referencing it.
	snipBytes, err := os.ReadFile(prov.SnippetFile)
	if err != nil {
		t.Fatalf("read snippet: %v", err)
	}
	snip := string(snipBytes)
	for _, want := range []string{
		"dnssec:", "policies:", "algorithm: SQISIGN1",
		"options: [ online-signing ]", "dnssecpolicy: " + prov.Record.Id + "-sqisign1",
		"type: primary", "downstreams:",
	} {
		if !strings.Contains(snip, want) {
			t.Errorf("snippet missing %q\n---\n%s", want, snip)
		}
	}

	// Reload provisioning drives no updates, so no SIG(0) key is generated.
	if prov.Record.Sig0KeyFile != "" {
		t.Errorf("reload test should not provision a SIG(0) key, got %q", prov.Record.Sig0KeyFile)
	}
	// Artifact marker written for cleanup --rm.
	if !IsToolArtifactDir(out, prov.Record.Id) {
		t.Error("artifact marker not written")
	}
}
