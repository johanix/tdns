/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */

package cli

import (
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
	"github.com/spf13/cobra"
)

// zone delete has --keep-keys, off unless given, in the auth tree and in the
// agent's.
func TestZoneDeleteKeepKeysFlag(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{args: []string{"-z", "example."}, want: false},
		{args: []string{"-z", "example.", "--keep-keys"}, want: true},
	} {
		// Fresh trees per case: a parsed command keeps its flag values.
		for tree, zoneCmd := range map[string]*cobra.Command{
			"auth":  NewZoneCmd("auth"),
			"agent": NewAgentZoneCmd("agent"),
		} {
			del := findSub(t, zoneCmd, "delete")
			// Parse only: Run would talk to a daemon.
			if err := del.ParseFlags(tc.args); err != nil {
				t.Fatalf("%s zone delete %v: %v", tree, tc.args, err)
			}
			if got, err := del.Flags().GetBool("keep-keys"); err != nil || got != tc.want {
				t.Errorf("%s zone delete %v: --keep-keys = %v (error %v), want %v", tree, tc.args, got, err, tc.want)
			}
		}
	}
}

func zoneDeleteOutput(r tdns.ZoneRemoval) []string {
	return zoneDeleteLines(tdns.ZoneResponse{Msg: r.Msg(), Warnings: r.Warnings(), Removal: &r})
}

// What the operator reads: verdict first, then the warning.
func TestZoneDeleteLines(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    tdns.ZoneRemoval
		want []string
	}{
		{
			name: "keys deleted, DS not known",
			r:    tdns.ZoneRemoval{Zone: "example.com.", DnssecKeys: 3, Sig0Keys: 1},
			want: []string{
				"zone example.com. deleted, with its keys: 3 DNSSEC, 1 SIG(0)",
				"WARNING: if the parent has a DS for example.com., it matches no key here",
				"  now: validating resolvers treat the zone as bogus until the DS is",
				"  removed or replaced",
			},
		},
		{
			name: "keys deleted, DS seen",
			r: tdns.ZoneRemoval{Zone: "example.com.", DnssecKeys: 2,
				ParentDS: tdns.ParentDSSeen, ParentDSAt: "2026-11-24T10:00:00Z"},
			want: []string{
				"zone example.com. deleted, with its keys: 2 DNSSEC, 0 SIG(0)",
				"WARNING: the parent had a DS for example.com. at the last poll",
				"  (2026-11-24T10:00:00Z); it matches no key here now: validating",
				"  resolvers treat the zone as bogus until the DS is removed or replaced",
			},
		},
		{
			name: "keys kept",
			r:    tdns.ZoneRemoval{Zone: "example.com.", KeepKeys: true, DnssecKeys: 3, Sig0Keys: 1},
			want: []string{
				"zone example.com. deleted; its keys were kept: 3 DNSSEC, 1 SIG(0)",
				"the kept keys belong to no zone now; a re-add takes them back",
			},
		},
		{
			name: "keys not deleted",
			r:    tdns.ZoneRemoval{Zone: "example.com.", KeysError: "KeyDB.Begin timed out waiting"},
			want: []string{
				"zone example.com. deleted, but its keys were not: KeyDB.Begin timed out",
				"  waiting",
				"delete them by hand; \"keystore sig0 list\" shows the SIG(0) key IDs:",
				"  keystore dnssec clear --zone example.com. --force",
				"  keystore sig0 delete --zone example.com. --keyid <keyid>",
			},
		},
		{
			name: "no keys",
			r:    tdns.ZoneRemoval{Zone: "example.com."},
			want: []string{"zone example.com. deleted; it had no DNSSEC or SIG(0) keys"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := zoneDeleteOutput(tc.r)
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Errorf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
			}
		})
	}
}

// No line is wider than 72 characters, whatever the zone's name, and the
// first one is the verdict.
func TestZoneDeleteLinesWidth(t *testing.T) {
	zone := "a-rather-long-label.customer-zones.provisioning.example.com."
	for _, r := range []tdns.ZoneRemoval{
		{Zone: zone, DnssecKeys: 3, Sig0Keys: 1},
		{Zone: zone, DnssecKeys: 3, ParentDS: tdns.ParentDSSeen, ParentDSAt: "2026-11-24T10:00:00Z"},
		{Zone: zone, DnssecKeys: 3, ParentDS: tdns.ParentDSNone, ParentDSAt: "2026-11-24T10:00:00Z"},
		{Zone: zone, KeepKeys: true, DnssecKeys: 3, Sig0Keys: 1},
		{Zone: zone, KeysError: "KeyDB.Begin timed out waiting"},
		{Zone: zone, KeepKeys: true, KeysError: "count DNSSEC keys: disk I/O error"},
		{Zone: zone},
	} {
		lines := zoneDeleteOutput(r)
		// A name this long can push "deleted" onto the continuation line.
		if text := strings.Join(strings.Fields(strings.Join(lines, " ")), " "); !strings.HasPrefix(text, "zone "+zone+" deleted") {
			t.Errorf("%+v: the first line is not the verdict:\n%s", r, strings.Join(lines, "\n"))
		}
		for _, l := range lines {
			// A command to copy stays whole (TestZoneDeleteCommandsStayWhole).
			if len(l) > zoneDeleteLineWidth && !strings.HasPrefix(l, "  keystore ") {
				t.Errorf("%+v: line of %d characters: %q", r, len(l), l)
			}
		}
	}
}

// The commands that finish a failed key delete are printed whole, however
// long the zone's name: a wrapped one would run without its zone.
func TestZoneDeleteCommandsStayWhole(t *testing.T) {
	zone := "a-rather-long-label.customer-zones.provisioning.example.com."
	lines := zoneDeleteOutput(tdns.ZoneRemoval{Zone: zone, KeysError: "KeyDB.Begin timed out waiting"})
	for _, want := range []string{
		"  keystore dnssec clear --zone " + zone + " --force",
		"  keystore sig0 delete --zone " + zone + " --keyid <keyid>",
	} {
		found := false
		for _, l := range lines {
			if l == want {
				found = true
			}
		}
		if !found {
			t.Errorf("no line %q in:\n%s", want, strings.Join(lines, "\n"))
		}
	}
}
