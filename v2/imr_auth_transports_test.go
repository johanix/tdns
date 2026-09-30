/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

func authTransportsTestCache(t *testing.T) *cache.RRsetCacheT {
	t.Helper()
	rc := cache.NewRRsetCache(log.New(io.Discard, "", 0), false, false)
	ns1 := rc.GetOrCreateAuthServer("ns1.example.net.")
	// The signal as a server sends it, through the path a received one takes.
	if !applyTransportMapToServer(ns1, map[string]uint8{"do53": 100, "dot": 50}) {
		t.Fatal("applyTransportMapToServer refused the signal")
	}
	ns1.IncrementUsedCounter(core.TransportDo53, cache.ClassNone)
	ns1.IncrementUsedCounter(core.TransportDo53TCP, cache.ClassInternal)
	ns1.IncrementUsedCounter(core.TransportDoT, cache.ClassStrict)
	ns1.IncrementFailedCounter(core.TransportDoT)
	ns1.IncrementFailedCounter(core.TransportDoQ)
	ns1.IncrementTruncated()
	rc.GetOrCreateAuthServer("ns2.example.net.").IncrementUsedCounter(core.TransportDo53, cache.ClassNone)
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
	// The signal as received: what the server named, not the defaults.
	if len(ns1.Signal) != 2 || ns1.Signal["dot"] != 50 || ns1.Signal["do53"] != 100 || ns1.SignalSource != "oots" || len(ns1.Zones) != 1 || !ns1.Shared {
		t.Errorf("ns1 signal %v (%s) zones %v shared %v, want do53:100 dot:50 as given, [example.net.], shared", ns1.Signal, ns1.SignalSource, ns1.Zones, ns1.Shared)
	}
	// The answers by class, under the same column names.
	if ns1.ByPrivacy["none"]["do53/udp"] != 1 || ns1.ByPrivacy["internal"]["do53/tcp"] != 1 || ns1.ByPrivacy["strict"]["dot"] != 1 || len(ns1.ByPrivacy) != 3 {
		t.Errorf("ns1 by privacy %v, want none do53/udp 1, internal do53/tcp 1, strict dot 1", ns1.ByPrivacy)
	}
	// What selection gives: DoT its weight, Do53 the rest (not its own 100).
	if e := ns1.Expected; e["none"]["do53"] != 50 || e["none"]["dot"] != 50 || e["opportunistic"]["dot"] != 100 || e["strict"]["dot"] != 100 {
		t.Errorf("ns1 expected %v, want none do53 50 dot 50, opportunistic and strict dot 100", e)
	}
	if ns1.LastAny.IsZero() || ns1.LastUsed["dot"].IsZero() {
		t.Errorf("ns1 last used %v / %v, want set", ns1.LastAny, ns1.LastUsed)
	}
	if q := rep.Rows[2]; q.Server != "x.test." || q.Signal != nil || q.Total != 0 || !q.LastAny.IsZero() || q.ByPrivacy != nil {
		t.Errorf("x.test. row %+v, want no signal, no traffic", q)
	}
	// Without a signal: Do53 unless the query asks for strict privacy, which
	// such a server cannot carry.
	if e := rep.Rows[2].Expected; e["none"]["do53"] != 100 || e["opportunistic"]["do53"] != 100 || e["strict"] != nil {
		t.Errorf("x.test. expected %v, want do53 100 without and with opportunistic privacy, no strict", e)
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
	// ImrQuery is not a DNS client's query: its answers are the resolver's own.
	if len(r.ByPrivacy) != 1 || r.ByPrivacy["internal"]["do53/udp"] != r.Total {
		t.Errorf("row by privacy %v, want all %d answers internal", r.ByPrivacy, r.Total)
	}
	// The stub's configured ALPN, as the signal.
	if r.SignalSource != "config" || r.Signal["do53"] != 100 {
		t.Errorf("stub signal %v (%s), want its configured do53", r.Signal, r.SignalSource)
	}
}

// The join for a client: a query that carries PRIVACY opportunistic, through
// ImrResponder, is counted under opportunistic. The stub's server has only
// Do53, which opportunistic privacy falls back to.
func TestImrAuthTransportsCountsAClientsPrivacy(t *testing.T) {
	const zone = "private.example."
	port, _ := startDenialAuthDouble(t, zone, "nope."+zone, "www."+zone, dns.TypeTXT, 60)
	imr := denialTestImr(t, zone, port)

	r := new(dns.Msg)
	r.SetQuestion("www."+zone, dns.TypeTXT)
	r.SetEdns0(4096, false)
	if err := edns0.AddPrivacyLevelToMessage(r, edns0.PrivacyOpportunistic); err != nil {
		t.Fatalf("AddPrivacyLevelToMessage: %v", err)
	}
	msgo, err := edns0.ExtractFlagsAndEDNS0Options(r)
	if err != nil || msgo.Privacy != edns0.PrivacyOpportunistic {
		t.Fatalf("ExtractFlagsAndEDNS0Options: %+v, %v", msgo, err)
	}
	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, r.Question[0].Name, r.Question[0].Qtype, msgo)
	if cw.got == nil {
		t.Fatal("no response written")
	}

	filter, _ := ParseServerFilter([]string{zone})
	rep := ImrAuthTransportsSnapshot(imr.Cache, filter, "", false)
	if len(rep.Rows) != 1 {
		t.Fatalf("rows %+v, want the one server of %s", rep.Rows, zone)
	}
	bp := rep.Rows[0].ByPrivacy
	if bp["opportunistic"]["do53/udp"] == 0 || bp["none"] != nil || bp["strict"] != nil {
		t.Errorf("by privacy %v, want the client's answer under opportunistic, none under none or strict", bp)
	}
}

// #840: the signal is kept as the server gave it, beside the weights with the
// absence defaults that selection uses; an ALPN-only signal says so.
func TestReceivedSignalIsWhatTheServerSaid(t *testing.T) {
	svcb := &dns.SVCB{Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{
		&dns.SVCBOots{Oots: []dns.SVCBOotsEntry{{Proto: "do53", Weight: 100}, {Proto: "doq", Weight: 50}, {Proto: "doh", Weight: 30}}},
	}}
	raw, ok, err := GetTransportParamRaw(svcb)
	if !ok || err != nil || len(raw) != 3 {
		t.Fatalf("GetTransportParamRaw = %v, %v, %v; want the three transports named", raw, ok, err)
	}
	if full, _, _ := GetTransportParam(svcb); len(full) != 4 || full["dot"] != 0 {
		t.Errorf("GetTransportParam = %v, want the absence defaults as before (dot:0 added)", full)
	}
	server := cache.NewAuthServer("ns.example.")
	applyTransportMapToServer(server, raw)
	got := server.GetReceivedSignal()
	if got == nil || got.Source != "oots" || len(got.Weights) != 3 {
		t.Fatalf("received %+v, want the three transports named, source oots", got)
	}
	if _, named := got.Weights[core.TransportDoT]; named {
		t.Errorf("received %v names DoT, which the server did not", got.Weights)
	}
	if w := server.GetTransportWeights(); w[core.TransportDoT] != 0 || w[core.TransportDoQ] != 50 || len(w) != 4 {
		t.Errorf("weights %v, want the defaults filled in for selection", w)
	}

	imr := &Imr{}
	if !imr.applyTransportSignalToServer(server, "do53:100,dot:50") {
		t.Fatal("applyTransportSignalToServer refused a TSYNC-style signal")
	}
	if got := server.GetReceivedSignal(); len(got.Weights) != 2 || got.Weights[core.TransportDoT] != 50 {
		t.Errorf("received %+v after a TSYNC-style signal, want do53:100 dot:50", got)
	}

	applyAlpnSignalToServer(server, "dot,doq")
	if got := server.GetReceivedSignal(); got.Source != "alpn" || len(got.Weights) != 2 {
		t.Errorf("received %+v after an ALPN signal, want source alpn, dot and doq", got)
	}
}

// expectedShares mirrors candidateTransports: over many names, the first
// picks fall in the proportions it states. #854's example signal.
func TestExpectedSharesMatchSelection(t *testing.T) {
	server := cache.NewAuthServer("ns.example.")
	applyTransportMapToServer(server, map[string]uint8{"do53": 100, "dot": 10, "doq": 10, "doh": 1})
	transports, weights := server.GetTransportSignal()
	for _, tc := range []struct {
		level edns0.PrivacyLevel
		want  map[core.Transport]uint8
	}{
		{edns0.PrivacyNone, map[core.Transport]uint8{core.TransportDo53: 80, core.TransportDoT: 10, core.TransportDoQ: 10}},
		{edns0.PrivacyOpportunistic, map[core.Transport]uint8{core.TransportDoT: 50, core.TransportDoQ: 50}},
		{edns0.PrivacyStrict, map[core.Transport]uint8{core.TransportDoT: 50, core.TransportDoQ: 50}},
	} {
		got := expectedShares(transports, weights, tc.level)
		if len(got) != len(tc.want) {
			t.Errorf("%s: expected %v, want %v (DoH's weight of 1 is not used)", tc.level, got, tc.want)
			continue
		}
		for tr, w := range tc.want {
			if got[tr] != w {
				t.Errorf("%s: expected %v, want %v", tc.level, got, tc.want)
			}
		}
		const n = 20000
		picks := map[core.Transport]int{}
		for i := 0; i < n; i++ {
			picks[candidateTransports(server, fmt.Sprintf("q%d.example.", i), tc.level)[0]]++
		}
		for tr, w := range tc.want {
			if share := picks[tr] * 100 / n; share < int(w)-3 || share > int(w)+3 {
				t.Errorf("%s: %s picked %d%% of %d names, expected %d%%", tc.level, core.TransportToString[tr], share, n, w)
			}
		}
	}
}

// Whose query: a client's by its level, the resolver's own otherwise, and an
// own lookup inside a client's query is the resolver's.
func TestTrafficClass(t *testing.T) {
	ctx := context.Background()
	client := withClientQuery(ctx)
	for _, tc := range []struct {
		ctx     context.Context
		privacy edns0.PrivacyLevel
		want    cache.TrafficClass
	}{
		{ctx, edns0.PrivacyNone, cache.ClassInternal},
		{ctx, edns0.PrivacyStrict, cache.ClassInternal},
		{client, edns0.PrivacyNone, cache.ClassNone},
		{client, edns0.PrivacyOpportunistic, cache.ClassOpportunistic},
		{client, edns0.PrivacyStrict, cache.ClassStrict},
		{withOwnTraffic(client), edns0.PrivacyNone, cache.ClassInternal},
		{nil, edns0.PrivacyNone, cache.ClassInternal},
	} {
		if got := trafficClass(tc.ctx, tc.privacy); got != tc.want {
			t.Errorf("trafficClass(%v, %s) = %s, want %s", tc.ctx, tc.privacy, got, tc.want)
		}
	}
}
