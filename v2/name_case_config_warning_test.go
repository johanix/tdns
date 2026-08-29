/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// A zone whose configured name is not canonical is SERVED correctly -- every
// index folds it -- but two things keyed by the name outside those indexes do
// not follow: keystore rows written by an older tdns (which folded the zone name
// only under the fold-case option, default off) and the zone file path.
//
// The outgoing-serial read treats a missing row as "nothing served yet" rather
// than as an error, so the failure is silent: the zone can republish below a
// serial a secondary already holds and that secondary serves stale data
// indefinitely. This warning is the only thing that says so.
func TestNonCanonicalZoneNameIsWarnedAbout(t *testing.T) {
	parse := func(t *testing.T, names ...string) string {
		t.Helper()
		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
		t.Cleanup(func() { slog.SetDefault(prev) })

		conf := &Config{}
		for _, n := range names {
			conf.Zones = append(conf.Zones, ZoneConf{
				Name: n, Type: "primary", Store: "map", Zonefile: "/nonexistent",
			})
		}
		conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 10)
		if _, _, err := conf.ParseZones(context.Background(), false); err != nil {
			t.Fatalf("ParseZones: %v", err)
		}
		for _, n := range names {
			Zones.Remove(n)
		}
		return buf.String()
	}

	out := parse(t, "Example.COM.")
	if !strings.Contains(out, "zone name is not canonical") {
		t.Errorf("no warning for a zone declared Example.COM.\n--- log ---\n%s", out)
	}
	// The warning has to carry both spellings, or an operator cannot act on it.
	if !strings.Contains(out, "Example.COM.") || !strings.Contains(out, "example.com.") {
		t.Errorf("the warning does not name both spellings\n--- log ---\n%s", out)
	}

	// And it must NOT fire for the ordinary case, or it is noise every operator
	// learns to ignore -- which would make it worthless for the case it exists
	// for.
	if out := parse(t, "example.com.", "child.example.com."); strings.Contains(out, "zone name is not canonical") {
		t.Errorf("warned about an already-canonical zone name\n--- log ---\n%s", out)
	}
}
