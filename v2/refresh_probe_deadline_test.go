package tdns

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startBlackholeUDP binds a UDP port and never answers. A probe against it can
// only end by timing out -- which is the failure mode #502 is about, and the one
// a "connection refused" port does NOT reproduce.
func startBlackholeUDP(t *testing.T) (string, func()) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return pc.LocalAddr().String(), func() { _ = pc.Close() }
}

// withRefreshBudgets installs probe/transfer budgets for one test and restores
// whatever was published before.
func withRefreshBudgets(t *testing.T, probeSecs, transferSecs int) {
	t.Helper()
	prev := ConfLive()
	cfg := *prev
	cfg.ProbeTimeout = probeSecs
	cfg.TransferTimeout = transferSecs
	liveConfig.Store(&cfg)
	t.Cleanup(func() { liveConfig.Store(prev) })
}

// The bound that applies to an unreachable primary must be the PROBE budget,
// not the transfer budget. This is the assertion that stops the stopgap being
// implemented as one generous timeout around Refresh: with that shape a
// blackholed upstream would cost transfertimeout (300s by default) on the
// caller's goroutine, which at first load is the refresh engine's.
//
// Two-sided on purpose. The upper bound catches "the transfer budget applied,
// or nothing did"; the lower bound catches "miekg's own 2s default applied and
// service.probetimeout is inert", which is what happens if the client's Timeout
// is left unset (miekg only ever TIGHTENS to the context deadline).
func TestProbeDeadlineBoundsAnUnreachableUpstream(t *testing.T) {
	withRefreshBudgets(t, 1, 300)
	blackhole, stop := startBlackholeUDP(t)
	defer stop()

	zd := &ZoneData{ZoneName: "example.test.", Upstreams: []PeerConf{{Addr: blackhole}}}

	start := time.Now()
	_, _, err := zd.DoTransfer(context.Background(), &Config{})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("an unreachable primary must be an error")
	}
	if elapsed > 1800*time.Millisecond {
		t.Fatalf("probe took %v; the 1s probe budget did not bound it "+
			"(a transfer-sized bound around Refresh would look like this)", elapsed)
	}
	if elapsed < 900*time.Millisecond {
		t.Fatalf("probe took %v, less than the configured 1s budget; "+
			"service.probetimeout is not reaching the client", elapsed)
	}
}

// Criterion 2: the operator has to learn WHICH primary is unreachable. The
// error becomes the zone's RefreshError, and "i/o timeout" on its own names
// nothing.
func TestProbeFailureNamesTheUpstream(t *testing.T) {
	withRefreshBudgets(t, 1, 300)
	blackhole, stop := startBlackholeUDP(t)
	defer stop()

	zd := &ZoneData{ZoneName: "example.test.", Upstreams: []PeerConf{{Addr: blackhole}}}
	_, _, err := zd.DoTransfer(context.Background(), &Config{})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), blackhole) {
		t.Fatalf("error does not name the upstream that was tried:\n  got: %v\n want it to contain: %s",
			err, blackhole)
	}
}

// The per-attempt deadline must not abandon the walk. Before the deadline was
// per attempt, DoTransfer returned on any DeadlineExceeded -- so once the bound
// exists, reading it off the error instead of off the parent context would make
// one quiet primary hide every healthy sibling behind it.
func TestProbeDeadlineAdvancesToNextUpstream(t *testing.T) {
	withRefreshBudgets(t, 1, 300)
	zone := "example.test."
	blackhole, stop1 := startBlackholeUDP(t)
	defer stop1()
	good, stop2 := startTestSOAServer(t, zone, 99, dns.RcodeSuccess)
	defer stop2()

	zd := &ZoneData{ZoneName: zone, Upstreams: []PeerConf{{Addr: blackhole}, {Addr: good}}}
	xfr, serial, err := zd.DoTransfer(context.Background(), &Config{})
	if err != nil {
		t.Fatalf("a timed-out first primary must not end the walk: %v", err)
	}
	if serial != 99 {
		t.Fatalf("serial: got %d, want 99 (should have advanced past the blackhole)", serial)
	}
	if !xfr {
		t.Fatal("expected a transfer to be warranted (serial 99 > incoming 0)")
	}
}

// Parent cancellation still aborts, and is still reported as cancellation --
// noteRefreshFailure keys on that to avoid marking a zone sick during shutdown.
// The interesting case is cancellation arriving while an exchange is in flight,
// because that is where the per-attempt deadline and a real cancellation both
// surface as an error from the same call.
func TestParentCancellationAbortsTheProbeWalk(t *testing.T) {
	withRefreshBudgets(t, 30, 300) // long budget: cancellation must win, not the deadline
	blackhole1, stop1 := startBlackholeUDP(t)
	defer stop1()
	blackhole2, stop2 := startBlackholeUDP(t)
	defer stop2()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	zd := &ZoneData{ZoneName: "example.test.",
		Upstreams: []PeerConf{{Addr: blackhole1}, {Addr: blackhole2}}}

	start := time.Now()
	_, _, err := zd.DoTransfer(ctx, &Config{})
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation must surface as context.Canceled, got: %v", err)
	}
	// Promptly, not "at the next attempt boundary". ExchangeContext would have
	// run the in-flight read out to the 30s probe budget before the walk could
	// notice; exchangeCancellable closes the connection instead.
	if elapsed > 3*time.Second {
		t.Fatalf("cancellation took %v; an in-flight probe was not interrupted "+
			"(30s probe budget was configured, so this waited out the deadline)", elapsed)
	}
}
