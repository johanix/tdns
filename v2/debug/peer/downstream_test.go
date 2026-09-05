/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package peer

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The upstream peer is a complete authoritative server, so it can stand in for
// the SUT here. That makes R2+R3 testable end to end with no daemon in the
// loop — and it is the only configuration in which the rig's two halves can be
// held to a known-correct counterpart.
func startPair(t *testing.T, historyCap int) (*Upstream, *Downstream) {
	t.Helper()
	u := startUpstream(t, historyCap)
	d, err := NewDownstream("relay.test.", "127.0.0.1:0", u.Addr())
	if err != nil {
		t.Fatalf("NewDownstream: %v", err)
	}
	d.Start()
	t.Cleanup(d.Stop)
	return u, d
}

func waitForTransfers(t *testing.T, d *Downstream, n int) []DownstreamXfer {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if x := d.Transfers(); len(x) >= n {
			return x
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d transfers; got %d", n, len(d.Transfers()))
	return nil
}

func TestDownstreamBaselineTransferIsAXFR(t *testing.T) {
	u, d := startPair(t, 8)
	x, err := d.Transfer(context.Background())
	if err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	if x.RequestedIXFR {
		t.Fatal("the first transfer asked for IXFR, but the peer holds no serial to ask from")
	}
	if x.Kind != KindAXFR || x.Serial != 1 {
		t.Fatalf("Kind=%s Serial=%d, want axfr/1", x.Kind, x.Serial)
	}
	got, serial := d.Zone()
	if serial != 1 {
		t.Fatalf("held serial = %d, want 1", serial)
	}
	if cd := CompareContent(u.Current().Zone, got); !cd.Equal() {
		t.Fatalf("baseline zone differs from upstream:\n%s", cd)
	}
}

func TestDownstreamNotifyTriggersIncrementalTransfer(t *testing.T) {
	u, d := startPair(t, 8)
	if _, err := d.Transfer(context.Background()); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	d.Reset()

	c := Change{
		Label:  "swap",
		Add:    []dns.RR{mustRR(t, "host2.relay.test. 3600 IN A 10.0.0.2")},
		Remove: []dns.RR{mustRR(t, "host1.relay.test. 3600 IN A 10.0.0.1")},
	}
	if _, err := u.Apply(c); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := u.Notify(context.Background(), d.Addr()); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	xfers := waitForTransfers(t, d, 1)
	if len(xfers) != 1 {
		t.Fatalf("got %d transfers for one NOTIFY, want 1", len(xfers))
	}
	x := xfers[0]
	if x.Kind != KindIXFR {
		t.Fatalf("Kind = %s, want ixfr (Err=%q)", x.Kind, x.Err)
	}
	if x.RequestSerial != 1 || x.Serial != 2 {
		t.Fatalf("transfer went %d->%d, want 1->2", x.RequestSerial, x.Serial)
	}
	if cd := CompareDelta(c, x.Deltas); !cd.Equal() {
		t.Fatalf("the delta does not express the authored change:\n%s", cd)
	}

	obs := d.Notifies()
	if len(obs) != 1 {
		t.Fatalf("got %d NOTIFYs, want 1", len(obs))
	}
	if obs[0].ProbeErr != "" || obs[0].ProbeSerial != 2 {
		t.Fatalf("probe = %d (err %q), want serial 2", obs[0].ProbeSerial, obs[0].ProbeErr)
	}
	if obs[0].Raced {
		t.Fatal("a single NOTIFY was flagged as raced")
	}

	// The held zone is REBUILT from the delta, not refetched. That is what
	// makes a delta which does not say what it should show up as content drift.
	got, serial := d.Zone()
	if serial != 2 {
		t.Fatalf("held serial = %d, want 2", serial)
	}
	if cd := CompareContent(u.Current().Zone, got); !cd.Equal() {
		t.Fatalf("zone rebuilt from the delta differs from upstream:\n%s", cd)
	}
}

// Several changes, one NOTIFY each: the peer must converge and stay
// incremental, because a rig that quietly AXFRed would score a broken delta
// path as healthy.
func TestDownstreamStaysIncrementalOverASeries(t *testing.T) {
	u, d := startPair(t, 32)
	if _, err := d.Transfer(context.Background()); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	d.Reset()

	const rounds = 6
	for i := 0; i < rounds; i++ {
		if _, err := u.Apply(Change{
			Label: "add-" + strconv.Itoa(i),
			Add:   []dns.RR{mustRR(t, "s"+strconv.Itoa(i)+".relay.test. 3600 IN A 10.0.8."+strconv.Itoa(i))},
		}); err != nil {
			t.Fatalf("Apply %d: %v", i, err)
		}
		if _, err := u.Notify(context.Background(), d.Addr()); err != nil {
			t.Fatalf("Notify %d: %v", i, err)
		}
		waitForTransfers(t, d, i+1)
	}

	for i, x := range d.Transfers() {
		if x.Kind != KindIXFR {
			t.Fatalf("transfer %d was %s, want ixfr (Err=%q)", i, x.Kind, x.Err)
		}
	}
	got, serial := d.Zone()
	if serial != rounds+1 {
		t.Fatalf("held serial = %d, want %d", serial, rounds+1)
	}
	if cd := CompareContent(u.Current().Zone, got); !cd.Equal() {
		t.Fatalf("after %d incremental rounds the zone has drifted:\n%s", rounds, cd)
	}
}

// When the peer's serial has aged out of the upstream's history it must
// recover by whole-zone transfer, and the recovery must be visible as a
// fallback rather than pass as an ordinary AXFR.
func TestDownstreamRecoversViaFallback(t *testing.T) {
	u, d := startPair(t, 2)
	if _, err := d.Transfer(context.Background()); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	d.Reset()

	for i := 0; i < 4; i++ {
		if _, err := u.Apply(Change{
			Label: "add",
			Add:   []dns.RR{mustRR(t, "g"+strconv.Itoa(i)+".relay.test. 3600 IN A 10.0.9."+strconv.Itoa(i))},
		}); err != nil {
			t.Fatalf("Apply %d: %v", i, err)
		}
	}
	x, err := d.Transfer(context.Background())
	if err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	if x.Kind != KindFallback {
		t.Fatalf("Kind = %s, want fallback", x.Kind)
	}
	got, _ := d.Zone()
	if cd := CompareContent(u.Current().Zone, got); !cd.Equal() {
		t.Fatalf("did not converge after the fallback:\n%s", cd)
	}
}

// Two NOTIFYs whose probes cannot both describe a distinct later state must be
// flagged, not merged. This is the honesty requirement in design §5.3: the
// packet count stays exact and only the attribution is marked uncertain.
func TestDownstreamFlagsRacedProbes(t *testing.T) {
	u, d := startPair(t, 8)
	if _, err := d.Transfer(context.Background()); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	d.Reset()

	// One change, announced twice — the shape §2.3 predicts of the SUT, where
	// several NOTIFYs describe the same or a superseded state.
	if _, err := u.Apply(Change{Label: "one", Add: []dns.RR{mustRR(t, "r.relay.test. 3600 IN A 10.0.10.1")}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := u.Notify(context.Background(), d.Addr()); err != nil {
			t.Fatalf("Notify %d: %v", i, err)
		}
	}
	waitForTransfers(t, d, 2)

	obs := d.Notifies()
	if len(obs) != 2 {
		t.Fatalf("got %d NOTIFYs, want 2 — the packet count must stay exact", len(obs))
	}
	if !obs[0].Raced {
		t.Fatal("two NOTIFYs at one serial did not flag the first as raced")
	}
	if obs[0].ProbeSerial != obs[1].ProbeSerial {
		t.Fatalf("probes disagree (%d vs %d) though only one change was made",
			obs[0].ProbeSerial, obs[1].ProbeSerial)
	}
}

func TestDownstreamRefusesForeignNotify(t *testing.T) {
	_, d := startPair(t, 8)
	m := new(dns.Msg)
	m.SetNotify("elsewhere.test.")
	r, err := dns.Exchange(m, d.Addr())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if r.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED", dns.RcodeToString[r.Rcode])
	}
	if n := len(d.Notifies()); n != 0 {
		t.Fatalf("a NOTIFY for another zone was counted: %d observations", n)
	}
}

// The delay knob exists to provoke the SUT's lock-holding hazard (design
// §2.2), so it has to actually delay the RESPONSE — not the probe, and not the
// transfer.
func TestDownstreamDelayHoldsTheResponse(t *testing.T) {
	u, d := startPair(t, 8)
	d.Delay = 300 * time.Millisecond

	start := time.Now()
	if _, err := u.Notify(context.Background(), d.Addr()); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if elapsed := time.Since(start); elapsed < d.Delay {
		t.Fatalf("NOTIFY answered in %v, want at least %v", elapsed, d.Delay)
	}
}
