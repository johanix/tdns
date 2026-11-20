/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// captureZoneLog sends the zone updater's logger to a buffer, at debug, for
// the rest of the test.
func captureZoneLog(t *testing.T) *syncBuffer {
	t.Helper()
	var buf syncBuffer
	prev := lg
	lg = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() { lg = prev })
	return &buf
}

// logLine returns the first line of out that holds msg, or "".
func logLine(out, msg string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, `msg="`+msg+`"`) {
			return line
		}
	}
	return ""
}

func wantAttrs(t *testing.T, line string, attrs ...string) {
	t.Helper()
	for _, a := range attrs {
		if !strings.Contains(line, a) {
			t.Errorf("log line %q; want %s in it", line, a)
		}
	}
}

// A ZONE-UPDATE that deletes one record says, through the zone updater's
// logger, which record it removed, at what owner and of what type. RemoveRR
// used to say so on the log package.
func TestZoneUpdateLogsTheRemovedRR(t *testing.T) {
	const zone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	192.0.2.53
www.example.	3600	IN	A	192.0.2.1
www.example.	3600	IN	A	192.0.2.2
`
	zd := testZone(t, "example.", zone)
	registerZones(t, zd)
	kdb := newTestKeyDB(t)

	del := func(s string) dns.RR {
		rr := mustRR(t, s)
		rr.Header().Class = dns.ClassNONE
		rr.Header().Ttl = 0
		return rr
	}
	for _, tc := range []struct {
		rr, removed string
	}{
		{"www.example. 3600 IN A 192.0.2.1", "removed=true"},
		{"www.example. 3600 IN A 192.0.2.99", "removed=false"},
	} {
		logbuf := captureZoneLog(t)
		if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
			Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: []dns.RR{del(tc.rr)}, InternalUpdate: true,
		}, kdb); err != nil {
			t.Fatalf("ApplyZoneUpdateToZoneData(%s): %v", tc.rr, err)
		}
		line := logLine(logbuf.String(), "ApplyZoneUpdateToZoneData: Remove RR")
		if line == "" {
			t.Fatalf("delete of %s: no Remove RR line in %q", tc.rr, logbuf.String())
		}
		ip := tc.rr[strings.LastIndex(tc.rr, " ")+1:]
		wantAttrs(t, line, "owner=www.example.", "rrtype=A", ip, tc.removed)
	}
}

// A CHILD-UPDATE that deletes a DS says which one, at what owner and of what
// type, on the line that reports the removal done.
func TestChildUpdateLogsTheRemovedRR(t *testing.T) {
	withNotifyQ(t, 8)
	zd, kdb := dsdParentZone(t)
	if updated, err := dsdApply(t, zd, kdb, dsdReceived(t, []string{dsdNewDS}, nil)); err != nil || !updated {
		t.Fatalf("adding the new DS: updated=%v err=%v", updated, err)
	}

	logbuf := captureZoneLog(t)
	if updated, err := dsdApply(t, zd, kdb, dsdReceived(t, nil, []string{dsdOldDS})); err != nil || !updated {
		t.Fatalf("deleting the old DS: updated=%v err=%v", updated, err)
	}
	line := logLine(logbuf.String(), "ApplyChildUpdateToZoneData: Remove RR done")
	if line == "" {
		t.Fatalf("no Remove RR done line in %q", logbuf.String())
	}
	wantAttrs(t, line, "owner="+dsdChild, "rrtype=DS", "53763")
}
