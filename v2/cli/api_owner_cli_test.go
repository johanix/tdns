/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */

package cli

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

// zone list-dynamic: the API owner in a column, rows that fit 72 characters
// for usual names, and under a row what has no column: the catalog a
// member came from, a catalog zone, the template, the error.
func TestZoneListDynamicShowsTheApiOwner(t *testing.T) {
	zones := map[string]tdns.ZoneConf{
		"a.example.": {Type: "secondary", Provisioning: "ready", ApiOwner: "cert:provisioner",
			Primaries: []tdns.PeerConf{{Addr: "192.0.2.1:53"}}},
		"b.example.": {Type: "secondary", Provisioning: "pending", ApiOwner: "api",
			Primaries: []tdns.PeerConf{{Addr: "192.0.2.2:53"}}, Template: "sec-out"},
		"m.example.": {Type: "secondary", Provisioning: "ready", ApiOwner: "config", SourceCatalog: "cat.example.",
			Primaries: []tdns.PeerConf{{Addr: "192.0.2.3:53"}}},
		"cat.example.": {Type: "primary", Provisioning: "ready", ApiOwner: "api", OptionsStrs: []string{"catalog-zone"}},
		"p.example.": {Type: "primary", Provisioning: "error", ApiOwner: "api", Template: "dyn-primary",
			Error: true, ErrorType: tdns.ConfigError, ErrorMsg: "template expansion failed"},
	}
	got := formatZoneListDynamic(zones)
	want := "" +
		"Zone          Type       State    API owner         Primary\n" +
		"a.example.    secondary  ready    cert:provisioner  192.0.2.1:53\n" +
		"b.example.    secondary  pending  api               192.0.2.2:53\n" +
		"    template sec-out\n" +
		"cat.example.  primary    ready    api               -\n" +
		"    catalog zone\n" +
		"m.example.    secondary  ready    config            192.0.2.3:53\n" +
		"    from catalog cat.example.\n" +
		"p.example.    primary    error    api               -\n" +
		"    template dyn-primary\n" +
		"    config: template expansion failed\n"
	if got != want {
		t.Errorf("list-dynamic:\n--- got ---\n%s--- want ---\n%s", got, want)
	}
	for _, l := range strings.Split(got, "\n") {
		if len(l) > 72 {
			t.Errorf("line over 72 characters: %q", l)
		}
	}
}

// A long zone error under a list-dynamic row wraps within 72 characters,
// its continuation lines indented two more.
func TestZoneListDynamicWrapsALongError(t *testing.T) {
	msg := "catalog zone cat.example. failed validation: member m1.example. has no version property and the zone is not a valid catalog"
	got := formatZoneListDynamic(map[string]tdns.ZoneConf{
		"cat.example.": {Type: "secondary", Provisioning: "error", ApiOwner: "api",
			Primaries: []tdns.PeerConf{{Addr: "192.0.2.1:53"}},
			Error:     true, ErrorType: tdns.ConfigError, ErrorMsg: msg},
	})
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) < 4 || !strings.HasPrefix(lines[2], "    config: catalog zone") || !strings.HasPrefix(lines[3], "      ") {
		t.Errorf("a long error:\n%s", got)
	}
	var words []string
	for _, l := range lines[2:] {
		if len(l) > 72 {
			t.Errorf("line over 72 characters: %q", l)
		}
		words = append(words, strings.Fields(l)...)
	}
	if strings.Join(words, " ") != "config: "+msg {
		t.Errorf("the error lost words:\n%s", got)
	}
}

// zone setowner prints the verdict first, then any warning.
func TestZoneSetOwnerOutput(t *testing.T) {
	got := formatZoneSetOwner(tdns.ZoneResponse{
		Msg:      "zone a.example.: API owner cert:nobody (was api)",
		Warnings: []string{`the access file has no client "nobody"`},
	})
	want := "zone a.example.: API owner cert:nobody (was api)\n" +
		"warning: the access file has no client \"nobody\"\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// zone list -v and zone desc show the API owner the listing carries.
func TestZoneDetailShowsTheApiOwner(t *testing.T) {
	zconf := parityZoneResponse().Zones["example."]
	zconf.ApiOwner = "cert:provisioner"
	if got := zoneBaseDetail("example.", zconf); !strings.HasSuffix(got, "\tAPI owner: cert:provisioner\n") {
		t.Errorf("no API owner line:\n%s", got)
	}
}

// Both trees, and so tdns-cli and tdns-ncli, have zone setowner with its
// two arguments.
func TestZoneSetOwnerCommand(t *testing.T) {
	for parent, p := range map[string]*cobra.Command{
		"auth":  NewZoneCmd("auth"),
		"agent": findSub(t, AgentCmd, "zone"),
	} {
		c := findSub(t, p, "setowner")
		if err := c.Args(c, []string{"a.example."}); err == nil {
			t.Errorf("%s zone setowner takes one argument; want two required", parent)
		}
		if err := c.Args(c, []string{"a.example.", "api"}); err != nil {
			t.Errorf("%s zone setowner refuses two arguments: %v", parent, err)
		}
	}
}

// config check runs the daemon's check over api-owner: and warns about a
// grant to a client the access file does not have, and about api-owner: on
// a template.
func TestConfigCheckApiOwners(t *testing.T) {
	sum := sha256.Sum256([]byte("provisioner"))
	pin := base64.StdEncoding.EncodeToString(sum[:])
	access := filepath.Join(t.TempDir(), "access.yaml")
	if err := os.WriteFile(access, []byte("clients:\n  - {name: provisioner, pin: "+pin+", role: read-write}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &tdns.Config{
		Zones: []tdns.ZoneConf{
			{Name: "plain.example."},
			{Name: "granted.example.", ApiOwner: "cert:provisioner"},
			{Name: "unknown.example.", ApiOwner: "cert:nobody"},
			{Name: "bad.example.", ApiOwner: "api"},
		},
		Templates: []tdns.ZoneConf{{Name: "tmpl", ApiOwner: "cert:provisioner"}},
	}
	cfg.ApiServer.AccessFile = access
	rep := newCCReport()
	checkApiOwners(cfg, rep)
	if l := levelsFor(rep, "Zones", "plain.example."); len(l) != 0 {
		t.Errorf("plain zone: %v, want nothing", l)
	}
	if l := levelsFor(rep, "Zones", "granted.example."); len(l) != 0 {
		t.Errorf("grant to an enrolled client: %v, want nothing", l)
	}
	if !hasLevel(rep, "Zones", "unknown.example.", ccWARN) {
		t.Errorf("grant to an unknown client: want a WARN; %+v", rep.byGroup["Zones"])
	}
	if !hasLevel(rep, "Zones", "bad.example.", ccFAIL) {
		t.Errorf("api-owner: api on a config-file zone: want a FAIL; %+v", rep.byGroup["Zones"])
	}
	if !hasLevel(rep, "Zones", "template tmpl", ccWARN) {
		t.Errorf("api-owner on a template: want a WARN; %+v", rep.byGroup["Zones"])
	}
}
