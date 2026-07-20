/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cli

import (
	"io"
	"os"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// captureStdout runs f with os.Stdout redirected and returns what it printed.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	f()
	w.Close()
	os.Stdout = old
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return string(b)
}

// parityZoneResponse is the fixed input for the VerboseListZone/DescribeZone
// parity guard: one zone exercising the shared base block (no error, empty
// options → manual config, effective policy with a config-base override,
// primaries/notify/file, frozen/dirty).
func parityZoneResponse() tdns.ZoneResponse {
	return tdns.ZoneResponse{
		Zones: map[string]tdns.ZoneConf{
			"example.": {
				Name:                   "example.",
				Type:                   "primary",
				Store:                  "MapZone",
				EffectiveDnssecPolicy:  "default",
				DnssecPolicyOverridden: true,
				DnssecPolicyConfigBase: "base",
				Primaries:              []tdns.PeerConf{{Addr: "192.0.2.1:53"}},
				Notify:                 []tdns.PeerConf{{Addr: "192.0.2.2:53"}},
				Zonefile:               "/etc/tdns/example.zone",
				Dirty:                  true,
			},
		},
	}
}

// TestVerboseListZone_GoldenParity pins VerboseListZone's exact stdout so the
// shared base-renderer (zoneBaseDetail, used by both VerboseListZone and
// DescribeZone) cannot silently change `zone list -v` output.
func TestVerboseListZone_GoldenParity(t *testing.T) {
	got := captureStdout(t, func() { VerboseListZone(parityZoneResponse()) })
	// Golden captured from VerboseListZone BEFORE the zoneBaseDetail extraction;
	// it must remain byte-for-byte identical afterwards.
	const golden = "zone: example.\n\tType: primary\tStore: MapZone\tOptions: []\n" +
		"\tDNSSEC policy: default (override from config: base)\n" +
		"\tPrimary: 192.0.2.1:53\tNotify: 192.0.2.2:53\tFile: /etc/tdns/example.zone\n" +
		"\tFrozen: false\tDirty: true\tConfig: manual\n"
	if got != golden {
		t.Fatalf("VerboseListZone output changed.\n--- got ---\n%s\n--- quoted ---\n%q", got, got)
	}
}

// TestDescribeZone_SharesBaseWithList proves DescribeZone's base block is exactly
// the shared zoneBaseDetail output for the same zone (its extra applied-policy /
// DNSSEC-detail sections are appended after). This is what structurally prevents
// the two renderers from drifting.
func TestDescribeZone_SharesBaseWithList(t *testing.T) {
	zconf := parityZoneResponse().Zones["example."]
	base := zoneBaseDetail(zconf.Name, zconf)
	out := DescribeZone(zconf)
	if len(out) < len(base) || out[:len(base)] != base {
		t.Fatalf("DescribeZone must start with the shared base block.\n--- base ---\n%s\n--- out ---\n%s", base, out)
	}
}
