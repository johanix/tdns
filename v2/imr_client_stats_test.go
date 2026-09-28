/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func udpFrom(ip string) net.Addr { return &net.UDPAddr{IP: net.ParseIP(ip), Port: 5353} }
func tcpFrom(ip string) net.Addr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: 5353} }

func rowFor(t *testing.T, rep ImrClientStatsReport, client string) ImrClientStatsRow {
	t.Helper()
	for _, r := range rep.Rows {
		if r.Client == client {
			return r
		}
	}
	t.Fatalf("no row for %s in %+v", client, rep.Rows)
	return ImrClientStatsRow{}
}

// A client seen as 192.0.2.10 and as ::ffff:192.0.2.10 is one client (S2).
func TestClientStatsCountsOneClientOnce(t *testing.T) {
	s := newImrClientStats(10)
	now := time.Now()
	s.record(udpFrom("192.0.2.10"), ctDo53UDP, now)
	s.record(tcpFrom("::ffff:192.0.2.10"), ctDoT, now.Add(time.Second))
	s.record(tcpFrom("::ffff:192.0.2.10"), ctDoT, now.Add(2*time.Second))

	rep := s.Snapshot(nil, false)
	if len(rep.Rows) != 1 {
		t.Fatalf("%d rows, want one client: %+v", len(rep.Rows), rep.Rows)
	}
	r := rowFor(t, rep, "192.0.2.10")
	if r.Counts["do53/udp"] != 1 || r.Counts["dot"] != 2 || r.Total != 3 {
		t.Errorf("counts %v total %d, want do53/udp 1, dot 2, total 3", r.Counts, r.Total)
	}
	if !r.LastSeen["dot"].Equal(now.Add(2*time.Second)) || !r.LastAny.Equal(now.Add(2*time.Second)) {
		t.Errorf("last seen %v, any %v, want the DoT query's time", r.LastSeen, r.LastAny)
	}
	if _, ok := r.Counts["doh"]; ok {
		t.Error("a transport never used has a count")
	}
}

// Eviction goes by the latest time a client was seen on any transport (S2), and
// the evicted client's counts stay in the totals.
func TestClientStatsEvictsTheLeastRecentlySeenOnAnyTransport(t *testing.T) {
	s := newImrClientStats(2)
	t0 := time.Now()
	s.record(udpFrom("192.0.2.1"), ctDo53UDP, t0)                  // A: UDP long ago...
	s.record(udpFrom("192.0.2.2"), ctDo53UDP, t0.Add(time.Second)) // B
	s.record(tcpFrom("192.0.2.1"), ctDoT, t0.Add(2*time.Second))   // ...but A was on DoT just now
	s.record(udpFrom("192.0.2.3"), ctDo53UDP, t0.Add(3*time.Second))

	rep := s.Snapshot(nil, false)
	if rep.Clients != 2 || rep.EvictedClients != 1 {
		t.Fatalf("%d clients, %d evicted; want 2 and 1", rep.Clients, rep.EvictedClients)
	}
	rowFor(t, rep, "192.0.2.1") // A kept: its DoT query is recent
	rowFor(t, rep, "192.0.2.3")
	if rep.EvictedCounts["do53/udp"] != 1 {
		t.Errorf("evicted counts %v, want B's one Do53/UDP query", rep.EvictedCounts)
	}
}

// A filter chooses what is returned; reset clears everything, whatever the
// filter (S3).
func TestClientStatsResetClearsTheWholeStore(t *testing.T) {
	s := newImrClientStats(10)
	now := time.Now()
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "198.51.100.1"} {
		s.record(udpFrom(ip), ctDo53UDP, now)
	}
	filter, err := ParseClientFilter([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	before := s.Snapshot(nil, false).Since

	rep := s.Snapshot(filter, true)
	if len(rep.Rows) != 2 || !rep.Reset {
		t.Fatalf("filtered snapshot: %d rows, reset %v; want the two in 192.0.2.0/24, and reset", len(rep.Rows), rep.Reset)
	}
	after := s.Snapshot(nil, false)
	if after.Clients != 0 || len(after.Rows) != 0 || after.EvictedClients != 0 {
		t.Errorf("after a filtered reset: %+v, want every client gone, 198.51.100.1 included", after)
	}
	if !after.Since.After(before) {
		t.Error("reset did not start a new period")
	}
}

func TestParseClientFilter(t *testing.T) {
	ps, err := ParseClientFilter([]string{"192.0.2.7", "2001:db8::/32", "::ffff:198.51.100.0/120", " "})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.7/32", "2001:db8::/32", "198.51.100.0/24"}
	if len(ps) != len(want) {
		t.Fatalf("got %v, want %v", ps, want)
	}
	for i, p := range ps {
		if p.String() != want[i] {
			t.Errorf("filter %d: %s, want %s", i, p, want[i])
		}
	}
	if !prefixesContain(ps, netip.MustParseAddr("198.51.100.9")) {
		t.Error("an IPv4-mapped prefix does not match the unmapped client")
	}
	if _, err := ParseClientFilter([]string{"not-an-address"}); err == nil {
		t.Error("garbage accepted")
	}
}

// Off: every listener gets the handler itself, not a wrapper. On: each
// transport's handler counts into its own column -- DoH by the HTTP peer.
func TestListenerHandlers(t *testing.T) {
	var served int
	handler := func(dns.ResponseWriter, *dns.Msg) { served++ }
	ptr := func(f func(dns.ResponseWriter, *dns.Msg)) uintptr { return reflect.ValueOf(f).Pointer() }

	off := listenerHandlers(handler, nil)
	for name, h := range map[string]func(dns.ResponseWriter, *dns.Msg){
		"udp": off.udp, "tcp": off.tcp, "dot": off.dot, "doh": off.doh, "doq": off.doq,
	} {
		if ptr(h) != ptr(handler) {
			t.Errorf("counters off: the %s listener's handler is not the resolver's own", name)
		}
	}

	s := newImrClientStats(10)
	on := listenerHandlers(handler, s)
	q := queryMsg()
	on.udp(&fakeRW{remote: udpFrom("192.0.2.1")}, q)
	on.tcp(&fakeRW{remote: tcpFrom("192.0.2.1")}, q)
	on.dot(&fakeRW{remote: tcpFrom("192.0.2.1")}, q)
	on.doq(&fakeRW{remote: udpFrom("192.0.2.1")}, q)
	on.doh(dohWriterFrom(t, "192.0.2.1:44321", q), q)
	if served != 5 {
		t.Fatalf("the resolver's handler ran %d times, want 5", served)
	}
	r := rowFor(t, s.Snapshot(nil, false), "192.0.2.1")
	for _, tr := range ImrClientTransports {
		if r.Counts[tr] != 1 {
			t.Errorf("column %s = %d, want 1 (counts %v)", tr, r.Counts[tr], r.Counts)
		}
	}
}

func TestClientStatsConcurrentUse(t *testing.T) {
	s := newImrClientStats(64)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				s.record(udpFrom(fmt.Sprintf("10.0.%d.%d", g, i%100)), clientTransport(i%int(numClientTransports)), time.Now())
				if i%100 == 0 {
					s.Snapshot(nil, i%200 == 0)
				}
			}
		}(g)
	}
	wg.Wait()
	if rep := s.Snapshot(nil, false); rep.Clients > 64 {
		t.Errorf("%d clients held, cap is 64", rep.Clients)
	}
}

// The API command: filters, and says so when the counters are off.
func TestImrClientStatsAPI(t *testing.T) {
	prev := Globals.ImrEngine
	t.Cleanup(func() { Globals.ImrEngine = prev })
	call := func() ImrMgmtResponse {
		t.Helper()
		body, _ := json.Marshal(ImrMgmtPost{Command: "imr-client-stats", Data: map[string]interface{}{"clients": []string{"192.0.2.0/24"}}})
		rec := httptest.NewRecorder()
		(&Config{}).APIimr()(rec, httptest.NewRequest(http.MethodPost, "/imr", bytes.NewReader(body)))
		var resp ImrMgmtResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v (%s)", err, rec.Body.String())
		}
		return resp
	}

	Globals.ImrEngine = &Imr{}
	if resp := call(); !resp.Error {
		t.Error("counters off, yet the command answered without an error")
	}

	Globals.ImrEngine = &Imr{ClientStats: newImrClientStats(10)}
	Globals.ImrEngine.ClientStats.record(udpFrom("192.0.2.1"), ctDo53UDP, time.Now())
	Globals.ImrEngine.ClientStats.record(udpFrom("198.51.100.1"), ctDo53UDP, time.Now())
	resp := call()
	raw, _ := json.Marshal(resp.Data)
	var rep ImrClientStatsReport
	if err := json.Unmarshal(raw, &rep); err != nil || resp.Error {
		t.Fatalf("response %+v: %v", resp, err)
	}
	if len(rep.Rows) != 1 || rep.Rows[0].Client != "192.0.2.1" || rep.Clients != 2 {
		t.Errorf("report %+v, want only 192.0.2.1 of the two held", rep)
	}
}

// The cost of the wrapper, when the counters are on. When they are off there
// is nothing to measure: the listeners get the handler itself (see
// TestListenerHandlers).
func BenchmarkImrHandlerWithClientStats(b *testing.B) {
	handler := func(dns.ResponseWriter, *dns.Msg) {}
	w := &fakeRW{remote: udpFrom("192.0.2.1")}
	q := queryMsg()
	b.Run("off", func(b *testing.B) {
		h := listenerHandlers(handler, nil).udp
		for i := 0; i < b.N; i++ {
			h(w, q)
		}
	})
	b.Run("on", func(b *testing.B) {
		h := listenerHandlers(handler, newImrClientStats(4096)).udp
		for i := 0; i < b.N; i++ {
			h(w, q)
		}
	})
}
