/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// startCountingBlackholeUDP binds a UDP port that never answers and counts the
// datagrams that reach it. A refresh of a zone whose only upstream is this port
// sends exactly one probe per refresh and then waits out the probe budget, so
// the count is the number of refreshes that actually ran against the zone.
func startCountingBlackholeUDP(t *testing.T) (string, func() int) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var n atomic.Int64
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, _, err := pc.ReadFromUDP(buf); err != nil {
				return
			}
			n.Add(1)
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String(), func() int { return int(n.Load()) }
}

// One zone is refreshed one at a time, whatever the spelling of the name that
// asked for the refresh.
//
// The in-flight check used to be keyed by the name as spelled, while Zones is
// keyed by the folded name. A NOTIFY- or API-driven refresh carries the spelling
// it arrived with, a ticker refresh the counter's, so for a zone requested in
// mixed case two refreshes of the same ZoneData were dispatched at once: two
// transfers, two replacements of zd.Data, two persists, the last to finish
// winning (#1005).
//
// Driven through the engine, because the bug lives in the join between the
// dispatch sites and the completion handler: a key that is folded at one of
// them and not at the others either lets the second refresh in or leaves the
// zone in flight for good.
func TestAZoneRefreshesOneAtATimeInEverySpelling(t *testing.T) {
	authApp(t)
	withRefreshBudgets(t, 1, 5)
	upstream, probes := startCountingBlackholeUDP(t)

	// What one refresh of this zone costs in probes, measured on a copy outside
	// the engine so the figure does not rest on a number written in the test.
	baseline := &ZoneData{ZoneName: "baseline.refresh.test.", ZoneType: Secondary, ZoneStore: MapZone,
		Upstreams: []PeerConf{{Addr: upstream}}, Logger: discardLogger()}
	if _, err := runZoneRefresh(context.Background(),
		refreshJob{zd: baseline, zone: baseline.ZoneName, gen: baseline.generation.Load()}, &Config{}); err == nil {
		t.Fatal("a refresh against a blackhole succeeded")
	}
	perRefresh := probes()
	if perRefresh < 1 {
		t.Fatalf("a refresh sent %d probes, want at least 1", perRefresh)
	}

	const zone = "inflight-key.refresh.test."
	zd := &ZoneData{ZoneName: zone, ZoneType: Secondary, ZoneStore: MapZone,
		Upstreams: []PeerConf{{Addr: upstream}}, Logger: discardLogger()}
	Zones.Set(zone, zd)
	t.Cleanup(func() { Zones.Remove(zone) })

	conf := &Config{}
	conf.Internal.KeyDB = Conf.Internal.KeyDB
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 1)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)
	runRefreshEngine(t, conf)

	// send queues a refresh that the caller waits on, as `zone reload` does.
	send := func(spelling string) chan RefresherResponse {
		resp := make(chan RefresherResponse, 1)
		conf.Internal.RefreshZoneCh <- ZoneRefresher{Name: spelling, Wait: true, Response: resp}
		return resp
	}
	answer := func(spelling string, resp chan RefresherResponse) RefresherResponse {
		t.Helper()
		select {
		case r := <-resp:
			return r
		case <-time.After(10 * time.Second):
			t.Fatalf("the refresh requested as %q was never answered", spelling)
			return RefresherResponse{}
		}
	}
	busy := func(r RefresherResponse) bool {
		return r.Error && strings.Contains(r.ErrorMsg, "already in progress")
	}

	// Two requests for one zone, in two spellings, one behind the other. The
	// first is still waiting out its probe when the engine reads the second.
	const first, second = "Inflight-Key.Refresh.TEST.", "inflight-key.refresh.test."
	r1 := send(first)
	r2 := send(second)
	if got := answer(second, r2); !busy(got) {
		t.Errorf("a refresh requested as %q while one requested as %q was running was answered %+v, "+
			"want it refused as already in progress", second, first, got)
	}
	if got := answer(first, r1); busy(got) {
		t.Errorf("the refresh that was first in was refused: %+v", got)
	}
	if got, want := probes()-perRefresh, perRefresh; got != want {
		t.Errorf("two requests for one zone sent %d probes, want %d: one refresh, not two", got, want)
	}

	// The completion clears the entry whatever spelling it comes back under: a
	// request in a third spelling is dispatched once the first has finished. The
	// answer reaches the caller before the engine has read the outcome, so a
	// request sent in that gap is refused as busy and is sent again.
	const third = "INFLIGHT-key.refresh.Test."
	deadline := time.Now().Add(10 * time.Second)
	for {
		got := answer(third, send(third))
		if !busy(got) {
			if !got.Error {
				t.Errorf("a refresh against a blackhole answered success: %+v", got)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the zone stayed in flight after its refresh finished; " +
				"the completion did not clear the entry the dispatch set")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got, want := probes()-perRefresh, 2*perRefresh; got != want {
		t.Errorf("a refresh after the first had finished sent %d probes in all, want %d", got, want)
	}
}
