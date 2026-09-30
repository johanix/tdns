/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func authTransportsTestCache(t *testing.T) *cache.RRsetCacheT {
	t.Helper()
	rc := cache.NewRRsetCache(log.New(io.Discard, "", 0), false, false)
	ns1 := rc.GetOrCreateAuthServer("ns1.example.net.")
	ns1.SetTransportWeights(map[core.Transport]uint8{core.TransportDo53: 100, core.TransportDoT: 50})
	ns1.IncrementUsedCounter(core.TransportDo53)
	ns1.IncrementUsedCounter(core.TransportDo53TCP)
	ns1.IncrementUsedCounter(core.TransportDoT)
	ns1.IncrementFailedCounter(core.TransportDoT)
	ns1.IncrementFailedCounter(core.TransportDoQ)
	ns1.IncrementTruncated()
	rc.GetOrCreateAuthServer("ns2.example.net.").IncrementUsedCounter(core.TransportDo53)
	rc.GetOrCreateAuthServer("x.test.") // known, never used
	if err := rc.AddServers("example.net.", map[string]*cache.AuthServer{"ns1.example.net.": ns1}); err != nil {
		t.Fatalf("AddServers: %v", err)
	}
	return rc
}

// Rows carry the counts under the client-stats column names, Do53 over UDP and
// TCP apart, the signal as given, and "no signal" as no signal.
func TestImrAuthTransportsSnapshot(t *testing.T) {
	rep := ImrAuthTransportsSnapshot(authTransportsTestCache(t), nil, "", false)
	if rep.Servers != 3 || len(rep.Rows) != 3 {
		t.Fatalf("report %+v, want 3 servers held and shown", rep)
	}
	ns1 := rep.Rows[0]
	if ns1.Server != "ns1.example.net." {
		t.Fatalf("first row %q, want ns1.example.net. (rows by name)", ns1.Server)
	}
	for col, want := range map[string]uint64{"do53/udp": 1, "do53/tcp": 1, "dot": 1} {
		if ns1.Counts[col] != want {
			t.Errorf("ns1 %s = %d, want %d (counts %v)", col, ns1.Counts[col], want, ns1.Counts)
		}
	}
	if ns1.Total != 3 || ns1.FailedTotal != 2 || ns1.Failed["doq"] != 1 || ns1.Truncated != 1 {
		t.Errorf("ns1 total %d failed %d (%v) truncated %d, want 3, 2 (doq 1), 1", ns1.Total, ns1.FailedTotal, ns1.Failed, ns1.Truncated)
	}
	if ns1.Signal["dot"] != 50 || ns1.Signal["do53"] != 100 || len(ns1.Zones) != 1 || !ns1.Shared {
		t.Errorf("ns1 signal %v zones %v shared %v, want do53:100 dot:50, [example.net.], shared", ns1.Signal, ns1.Zones, ns1.Shared)
	}
	if ns1.LastAny.IsZero() || ns1.LastUsed["dot"].IsZero() {
		t.Errorf("ns1 last used %v / %v, want set", ns1.LastAny, ns1.LastUsed)
	}
	if q := rep.Rows[2]; q.Server != "x.test." || q.Signal != nil || q.Total != 0 || !q.LastAny.IsZero() {
		t.Errorf("x.test. row %+v, want no signal, no traffic", q)
	}
}

// A name selects the servers at and below it, never a partial label.
func TestImrAuthTransportsFilter(t *testing.T) {
	filter, err := ParseServerFilter([]string{"example.net", " "})
	if err != nil || len(filter) != 1 || filter[0] != "example.net." {
		t.Fatalf("ParseServerFilter = %v, %v; want [example.net.]", filter, err)
	}
	rep := ImrAuthTransportsSnapshot(authTransportsTestCache(t), filter, "", false)
	if rep.Servers != 3 || len(rep.Rows) != 2 || rep.Rows[0].Server != "ns1.example.net." || rep.Rows[1].Server != "ns2.example.net." {
		t.Errorf("filter example.net.: %d held, rows %+v; want 3 held, ns1 and ns2 shown", rep.Servers, rep.Rows)
	}
	filter, _ = ParseServerFilter([]string{"ample.net."})
	if rep := ImrAuthTransportsSnapshot(authTransportsTestCache(t), filter, "", false); len(rep.Rows) != 0 {
		t.Errorf("filter ample.net. matched %+v; a partial label must not match", rep.Rows)
	}
	if _, err := ParseServerFilter([]string{"bad..name"}); err == nil {
		t.Error("ParseServerFilter accepted bad..name")
	}
	// A zone selects the servers it lists, whatever the case it is typed in.
	rep = ImrAuthTransportsSnapshot(authTransportsTestCache(t), nil, "EXAMPLE.NET.", false)
	if len(rep.Rows) != 1 || rep.Rows[0].Server != "ns1.example.net." || rep.Zone != "EXAMPLE.NET." {
		t.Errorf("zone example.net.: rows %+v, want ns1.example.net. alone (ns2 serves no zone)", rep.Rows)
	}
}

// A reset through a filter still clears every server.
func TestImrAuthTransportsResetIgnoresFilter(t *testing.T) {
	rc := authTransportsTestCache(t)
	filter, _ := ParseServerFilter([]string{"ns2.example.net."})
	if rep := ImrAuthTransportsSnapshot(rc, filter, "", true); !rep.Reset || len(rep.Rows) != 1 {
		t.Fatalf("reset report %+v, want Reset and one row", rep)
	}
	for _, r := range ImrAuthTransportsSnapshot(rc, nil, "", false).Rows {
		if r.Total != 0 || r.FailedTotal != 0 || r.Truncated != 0 {
			t.Errorf("%s after a filtered reset: %+v, want all counters cleared", r.Server, r)
		}
	}
}

// The API command: filters, refuses a bad name, and says so without an engine.
func TestImrAuthTransportsAPI(t *testing.T) {
	prev := Globals.ImrEngine
	t.Cleanup(func() { Globals.ImrEngine = prev })
	call := func(zone string, servers ...string) (ImrMgmtResponse, string) {
		t.Helper()
		body, _ := json.Marshal(ImrMgmtPost{Command: "imr-auth-transports", Data: map[string]interface{}{"servers": servers, "zone": zone}})
		rec := httptest.NewRecorder()
		(&Config{}).APIimr()(rec, httptest.NewRequest(http.MethodPost, "/imr", bytes.NewReader(body)))
		var resp ImrMgmtResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v (%s)", err, rec.Body.String())
		}
		return resp, rec.Body.String()
	}

	Globals.ImrEngine = &Imr{}
	if resp, _ := call(""); !resp.Error {
		t.Error("no cache, yet the command answered without an error")
	}

	Globals.ImrEngine = &Imr{Cache: authTransportsTestCache(t)}
	if resp, _ := call("", "bad..name"); !resp.Error {
		t.Error("a bad server name was accepted")
	}
	resp, body := call("", "x.test.")
	raw, _ := json.Marshal(resp.Data)
	var rep ImrAuthTransportsReport
	if err := json.Unmarshal(raw, &rep); err != nil || resp.Error {
		t.Fatalf("response %+v: %v", resp, err)
	}
	if rep.Servers != 3 || len(rep.Rows) != 1 || rep.Rows[0].Server != "x.test." || rep.Rows[0].Signal != nil {
		t.Errorf("report %+v, want x.test. alone of 3, with no signal", rep)
	}
	if strings.Contains(body, "last_any") {
		t.Errorf("an idle server carries a last_any: %s", body)
	}
	resp, _ = call("example.net")
	raw, _ = json.Marshal(resp.Data)
	rep = ImrAuthTransportsReport{}
	if err := json.Unmarshal(raw, &rep); err != nil || len(rep.Rows) != 1 || rep.Rows[0].Server != "ns1.example.net." || rep.Zone != "example.net." {
		t.Errorf("zone example.net over the API: %+v (%v), want ns1.example.net. alone", rep, err)
	}
}

// The join: an answer from a real query lands in the report, under the server
// that gave it. The stub's server is a private instance, marked as such.
func TestImrAuthTransportsCountsARealQuery(t *testing.T) {
	const zone = "counted.example."
	port, _ := startDenialAuthDouble(t, zone, "nope."+zone, "www."+zone, dns.TypeTXT, 60)
	imr := denialTestImr(t, zone, port)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if resp, err := imr.ImrQuery(ctx, "www."+zone, dns.TypeTXT, dns.ClassINET, nil); err != nil || resp == nil || resp.Error {
		t.Fatalf("query: err=%v resp=%+v", err, resp)
	}

	filter, _ := ParseServerFilter([]string{zone})
	rep := ImrAuthTransportsSnapshot(imr.Cache, filter, "", false)
	if len(rep.Rows) != 1 {
		t.Fatalf("rows %+v, want the one server of %s", rep.Rows, zone)
	}
	r := rep.Rows[0]
	if r.Server != "ns."+zone || r.Shared || r.Src != "stub" || len(r.Zones) != 1 || r.Zones[0] != zone {
		t.Errorf("row %+v, want ns.%s, a stub instance serving %s", r, zone, zone)
	}
	if r.Counts["do53/udp"] == 0 || r.Total != r.Counts["do53/udp"] || r.LastAny.IsZero() || r.LastUsed["do53/udp"].IsZero() {
		t.Errorf("row counts %v total %d last %v, want the answers over do53/udp, last used set", r.Counts, r.Total, r.LastUsed)
	}
}
