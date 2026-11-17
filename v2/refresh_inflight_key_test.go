/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startGatedUDP binds a UDP port that holds every query it receives until the
// test calls release, and then answers each with REFUSED, which a refresh takes
// as a quiet back-off and completes on. A query that arrives after release is
// answered at once. probes counts the queries that reached the port, held or
// not.
//
// A refresh of a zone whose only upstream is this port sends one probe, and is
// then held in flight for exactly as long as the test wants: the test decides
// when it ends, not a timeout, so no ordering between two requests depends on
// how fast the test goroutine runs.
func startGatedUDP(t *testing.T) (addr string, probes func() int, release func()) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gate := make(chan struct{})
	var once sync.Once
	var n atomic.Int64
	go func() {
		buf := make([]byte, 4096)
		for {
			size, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req := new(dns.Msg)
			if req.Unpack(buf[:size]) != nil {
				continue
			}
			n.Add(1)
			// Counted as it arrives, answered when the gate opens: a second probe
			// must show in the count while the first is still being held.
			go func() {
				<-gate
				resp := new(dns.Msg)
				resp.SetRcode(req, dns.RcodeRefused)
				if out, err := resp.Pack(); err == nil {
					_, _ = pc.WriteToUDP(out, from)
				}
			}()
		}
	}()
	release = func() { once.Do(func() { close(gate) }) }
	t.Cleanup(func() { release(); _ = pc.Close() })
	return pc.LocalAddr().String(), func() int { return int(n.Load()) }, release
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
	// A probe budget far longer than the test: the first refresh ends when the
	// test releases the gate, never because a timeout fired first.
	withRefreshBudgets(t, 30, 30)

	// What one refresh of this zone costs in probes, measured on a copy outside
	// the engine, against an upstream that answers at once, so the figure does
	// not rest on a number written in the test.
	baseAddr, baseProbes, baseRelease := startGatedUDP(t)
	baseRelease()
	baseline := &ZoneData{ZoneName: "baseline.refresh.test.", ZoneType: Secondary, ZoneStore: MapZone,
		Upstreams: []PeerConf{{Addr: baseAddr}}, Logger: discardLogger()}
	if _, err := runZoneRefresh(context.Background(),
		refreshJob{zd: baseline, zone: baseline.ZoneName, gen: baseline.generation.Load()}, &Config{}); err != nil {
		t.Fatalf("a refresh against a refusing upstream failed: %v", err)
	}
	perRefresh := baseProbes()
	if perRefresh < 1 {
		t.Fatalf("a refresh sent %d probes, want at least 1", perRefresh)
	}

	upstream, probes, release := startGatedUDP(t)
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

	// Two requests for one zone, in two spellings. The first is held in flight
	// at the upstream, and only sent for the second once the first has reached
	// it, so the engine reads the second request while the first cannot have
	// finished.
	const first, second = "Inflight-Key.Refresh.TEST.", "inflight-key.refresh.test."
	r1 := send(first)
	waitFor(t, 5*time.Second, "the first refresh to reach the upstream", func() bool { return probes() >= 1 })
	r2 := send(second)
	select {
	case got := <-r2:
		if !busy(got) {
			t.Errorf("a refresh requested as %q while one requested as %q was running was answered %+v, "+
				"want it refused as already in progress", second, first, got)
		}
	case <-time.After(5 * time.Second):
		t.Errorf("a refresh requested as %q while one requested as %q was held was not refused; "+
			"it was dispatched as well", second, first)
	}
	if got := probes(); got != 1 {
		t.Errorf("two requests for one zone had sent %d probes by the time the second was answered, "+
			"want 1: one refresh, not two", got)
	}

	// Now the first may finish. A REFUSED probe is a quiet back-off, not a
	// failure: the refresh completes and says so.
	release()
	if got := answer(first, r1); got.Error {
		t.Errorf("the refresh that was first in was not run to completion: %+v", got)
	}
	if got := probes(); got != perRefresh {
		t.Errorf("two requests for one zone sent %d probes in all, want %d: one refresh, not two", got, perRefresh)
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
			if got.Error {
				t.Errorf("a refresh after the first had finished failed: %+v", got)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the zone stayed in flight after its refresh finished; " +
				"the completion did not clear the entry the dispatch set")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got, want := probes(), 2*perRefresh; got != want {
		t.Errorf("a refresh after the first had finished sent %d probes in all, want %d", got, want)
	}
}
