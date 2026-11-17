package tdns

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// withProbeRetry installs the lost-probe retry policy for one test and restores
// the default afterwards.
func withProbeRetry(t *testing.T, retries int, delay time.Duration) {
	t.Helper()
	prev := probeRetry.Load()
	probeRetry.Store(&probeRetryPolicy{retries: retries, delay: delay})
	t.Cleanup(func() { probeRetry.Store(prev) })
}

// startLossySOAServer is a UDP responder that reads every datagram, counts it,
// and ANSWERS ONLY once it has dropped the first drop of them: the upstream of
// issue #1010, whose receive buffer is full when a herd of probes arrives and
// has room again a moment later. The datagram is read and thrown away, which is
// as far as the prober can tell what a full socket buffer does to it.
//
// The count is what separates "retried" from "did not retry"; the zone data
// the answer carries is whatever the caller asks for.
func startLossySOAServer(t *testing.T, zone string, serial uint32, drop int) (addr string, queries func() int, stop func()) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var seen atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return // the socket was closed by stop
			}
			req := new(dns.Msg)
			if req.Unpack(buf[:n]) != nil {
				continue
			}
			if int(seen.Add(1)) <= drop {
				continue
			}
			m := new(dns.Msg)
			m.SetReply(req)
			m.Answer = append(m.Answer, &dns.SOA{
				Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
				Ns:      "ns." + zone,
				Mbox:    "hostmaster." + zone,
				Serial:  serial,
				Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
			})
			if wire, perr := m.Pack(); perr == nil {
				_, _ = pc.WriteToUDP(wire, from)
			}
		}
	}()
	return pc.LocalAddr().String(),
		func() int { return int(seen.Load()) },
		func() { _ = pc.Close(); <-done }
}

// The issue's failure, in one upstream: the first probe is dropped, the retry
// is answered. Before the retry the refresh failed here and the zone stayed
// stale until the next one; now it carries on and decides on the serial.
func TestALostSOAProbeIsRetriedAndTheRefreshSucceeds(t *testing.T) {
	withRefreshBudgets(t, 1, 300)
	withProbeRetry(t, 1, 50*time.Millisecond)
	const zone = "lost.retry.test."
	addr, queries, stop := startLossySOAServer(t, zone, 77, 1)
	defer stop()

	zd := &ZoneData{ZoneName: zone, Upstreams: []PeerConf{{Addr: addr}}}
	xfr, serial, err := zd.DoTransfer(context.Background(), &Config{})
	if err != nil {
		t.Fatalf("one lost probe failed the refresh; it should have been retried: %v", err)
	}
	if serial != 77 || !xfr {
		t.Fatalf("got xfr=%v serial=%d, want the retry's answer (xfr=true serial=77)", xfr, serial)
	}
	if n := queries(); n != 2 {
		t.Fatalf("the upstream saw %d probes, want 2 (the lost one and its retry)", n)
	}
}

// The retry is bounded: an upstream that never answers is probed once more and
// then the refresh fails exactly as it did, with ONE failure entry for the
// upstream and ONE address in the message, not one per attempt. The failure
// shape is what the one ERROR per refresh is built from (#1004).
func TestAProbeThatStaysLostFailsOnceAfterOneRetry(t *testing.T) {
	withRefreshBudgets(t, 1, 300)
	withProbeRetry(t, 1, 50*time.Millisecond)
	const zone = "gone.retry.test."
	addr, queries, stop := startLossySOAServer(t, zone, 1, 1000)
	defer stop()

	zd := &ZoneData{ZoneName: zone, Upstreams: []PeerConf{{Addr: addr}}}
	start := time.Now()
	_, _, err := zd.DoTransfer(context.Background(), &Config{})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("an upstream that never answers must still fail the refresh")
	}
	if n := queries(); n != 2 {
		t.Fatalf("the upstream saw %d probes, want 2: one retry, no more", n)
	}
	// Two attempts of the 1s budget plus the spacing: well above one attempt,
	// well below a third.
	if elapsed < 1900*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("took %v, want about two 1s probes and the retry spacing", elapsed)
	}
	var uf *upstreamsFailedError
	if !errors.As(err, &uf) || uf.stage != refreshStageProbe {
		t.Fatalf("want the probe-stage upstreamsFailedError, got %T: %v", err, err)
	}
	if len(uf.failures) != 1 || uf.failures[0].addr != addr {
		t.Fatalf("failures = %+v, want one entry, for %s", uf.failures, addr)
	}
	// The list of who was asked holds the upstream once, not once per attempt.
	if !strings.Contains(err.Error(), "["+addr+"]") {
		t.Fatalf("the tried list should be exactly [%s]: %v", addr, err)
	}
}

// The walk reaches the sibling before anything is retried: a retry only ever
// follows a pass that produced no usable SOA, so a quiet first upstream does
// not hold up a healthy second one by a second probe budget.
func TestARetryDoesNotDelayAHealthySibling(t *testing.T) {
	withRefreshBudgets(t, 1, 300)
	withProbeRetry(t, 1, 5*time.Second) // a retry would be unmistakable
	const zone = "sibling.retry.test."
	quiet, queries, stop1 := startLossySOAServer(t, zone, 1, 1000)
	defer stop1()
	good, stop2 := startTestSOAServer(t, zone, 99, dns.RcodeSuccess)
	defer stop2()

	zd := &ZoneData{ZoneName: zone, Upstreams: []PeerConf{{Addr: quiet}, {Addr: good}}}
	start := time.Now()
	_, serial, err := zd.DoTransfer(context.Background(), &Config{})
	if err != nil || serial != 99 {
		t.Fatalf("serial=%d err=%v, want the sibling's 99", serial, err)
	}
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Fatalf("took %v: the healthy sibling waited for a retry of the quiet one", elapsed)
	}
	if n := queries(); n != 1 {
		t.Fatalf("the quiet upstream saw %d probes, want 1: the sibling answered, nothing to retry", n)
	}
}

// A sibling that ANSWERS with a refusal is not a reason to give up on the one
// whose probe was lost: only a usable SOA ends the walk, so the lost probe is
// retried even though the pass saw a response. Without that the refresh backs
// off quietly and the zone waits a full refresh interval for a copy the first
// upstream could have given it.
func TestALostProbeIsRetriedEvenWhenASiblingRefused(t *testing.T) {
	withRefreshBudgets(t, 1, 300)
	withProbeRetry(t, 1, 50*time.Millisecond)
	const zone = "refused.retry.test."
	lossy, queries, stop1 := startLossySOAServer(t, zone, 55, 1)
	defer stop1()
	refusing, stop2 := startTestSOAServer(t, zone, 0, dns.RcodeRefused)
	defer stop2()

	zd := &ZoneData{ZoneName: zone, Upstreams: []PeerConf{{Addr: lossy}, {Addr: refusing}}}
	xfr, serial, err := zd.DoTransfer(context.Background(), &Config{})
	if err != nil || !xfr || serial != 55 {
		t.Fatalf("xfr=%v serial=%d err=%v, want the retried upstream's answer (true, 55, nil)", xfr, serial, err)
	}
	if n := queries(); n != 2 {
		t.Fatalf("the lossy upstream saw %d probes, want 2", n)
	}
}

// A shutdown during the wait ends the refresh at once and as a cancellation,
// the same as one during a probe does (noteRefreshFailure keys on it): the wait
// must not run its spacing out on a process that is stopping.
func TestCancellationDuringTheRetryWaitAbortsTheRefresh(t *testing.T) {
	withRefreshBudgets(t, 1, 300)
	withProbeRetry(t, 1, time.Minute)
	blackhole, stop := startBlackholeUDP(t)
	defer stop()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(1500 * time.Millisecond) // after the first probe's 1s, inside the wait
		cancel()
	}()

	zd := &ZoneData{ZoneName: "cancel.retry.test.", Upstreams: []PeerConf{{Addr: blackhole}}}
	start := time.Now()
	_, _, err := zd.DoTransfer(ctx, &Config{})
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation during the wait must surface as context.Canceled, got: %v", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("took %v; the retry wait ignored the cancellation", elapsed)
	}
}

// What counts as a probe worth retrying: a datagram that got no answer inside
// the probe's budget, on UDP, and nothing else. A refused connection, a TSIG
// failure or a TLS failure will give the same answer again; a stream that timed
// out is not a lost datagram (TCP retransmits for itself).
func TestWhichFailedProbesAreRetried(t *testing.T) {
	timeout := &net.OpError{Op: "read", Net: "udp", Err: &timeoutErr{}}
	closed := &net.OpError{Op: "read", Net: "udp", Err: net.ErrClosed}
	for _, tc := range []struct {
		name        string
		network     string
		err         error
		budgetSpent bool
		want        bool
	}{
		{"udp, socket deadline", "", timeout, false, true},
		{"udp, closed when the budget ran out", "", closed, true, true},
		{"udp, explicit net", "udp4", closed, true, true},
		{"udp, closed with the budget unspent", "", closed, false, false},
		{"udp, connection refused", "", &net.OpError{Op: "read", Net: "udp", Err: syscall.ECONNREFUSED}, false, false},
		{"udp, tsig failure", "", dns.ErrSig, false, false},
		{"tls, timed out", "tcp-tls", timeout, true, false},
		{"tcp, closed at the budget", "tcp", closed, true, false},
	} {
		if got := soaProbeUnanswered(tc.network, tc.err, tc.budgetSpent); got != tc.want {
			t.Errorf("%s: soaProbeUnanswered=%v, want %v", tc.name, got, tc.want)
		}
	}
}

// timeoutErr is a net.Error that reports a timeout.
type timeoutErr struct{}

func (*timeoutErr) Error() string   { return "i/o timeout" }
func (*timeoutErr) Timeout() bool   { return true }
func (*timeoutErr) Temporary() bool { return true }
