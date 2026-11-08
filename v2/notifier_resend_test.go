/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// #1007: an unanswered NOTIFY is sent again.

// startCountingSink runs a receiver that ignores the first drop NOTIFYs (no
// reply at all, as a lost packet looks to the sender) and answers the rest with
// rcode. network is "udp" or "tcp".
func startCountingSink(t *testing.T, network string, drop int32, rcode int) (string, *atomic.Int32) {
	t.Helper()
	var seen atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if seen.Add(1) <= drop {
			return
		}
		m := new(dns.Msg)
		m.SetRcode(r, rcode)
		_ = w.WriteMsg(m)
	})
	ready := make(chan struct{})
	srv := &dns.Server{Handler: handler, NotifyStartedFunc: func() { close(ready) }}
	var addr string
	if network == "tcp" {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		srv.Listener, addr = l, l.Addr().String()
	} else {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		srv.PacketConn, addr = pc, pc.LocalAddr().String()
	}
	go func() { _ = srv.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = srv.Shutdown() })
	return addr, &seen
}

// runNotifier starts a Notifier with fast resends: retries resends, the first
// after interval.
func runNotifier(t *testing.T, retries int, interval string) (*Config, chan NotifyRequest) {
	t.Helper()
	prevTimeout := notifyTimeout
	notifyTimeout = 150 * time.Millisecond
	t.Cleanup(func() { notifyTimeout = prevTimeout })

	conf := &Config{}
	conf.Internal.NotifyTracker = NewNotifyTracker()
	conf.AuthEngine.NotifyRetries = &retries
	conf.AuthEngine.NotifyRetryInterval = interval
	q := make(chan NotifyRequest, 8)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = Notifier(ctx, conf, q); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return conf, q
}

func soaRequest(zd *ZoneData, targets ...string) NotifyRequest {
	return NotifyRequest{ZoneName: zd.ZoneName, ZoneData: zd, RRtype: dns.TypeSOA, Targets: targets}
}

func notifyState(conf *Config, zd *ZoneData) []NotifyTargetStatus {
	return conf.Internal.NotifyTracker.Status(zd.ZoneName)
}

func stateIs(conf *Config, zd *ZoneData, state string) func() bool {
	return func() bool {
		st := notifyState(conf, zd)
		return len(st) == 1 && st[0].State == state
	}
}

func TestNotifyIsResentUntilAnswered(t *testing.T) {
	addr, seen := startCountingSink(t, "udp", 2, dns.RcodeSuccess)
	conf, _ := runNotifier(t, 5, "30ms")
	zd := loadIxfrTestZone(t, basicZone)

	conf.Internal.NotifyTracker.Mark(soaRequest(zd, addr))
	waitFor(t, 5*time.Second, "an answered third NOTIFY", stateIs(conf, zd, "ok"))
	if got := seen.Load(); got != 3 {
		t.Errorf("the receiver saw %d NOTIFYs, want 3 (two lost, one answered)", got)
	}
	time.Sleep(300 * time.Millisecond)
	if got := seen.Load(); got != 3 {
		t.Errorf("NOTIFYs went on after the answer: %d", got)
	}
	if st := notifyState(conf, zd)[0]; st.Failures != 0 || st.LastSuccess.IsZero() {
		t.Errorf("state after the answer: %+v", st)
	}
}

func TestNotifyGivesUpAfterItsRetries(t *testing.T) {
	addr, seen := startCountingSink(t, "udp", 1000, dns.RcodeSuccess)
	conf, _ := runNotifier(t, 2, "30ms")
	zd := loadIxfrTestZone(t, basicZone)

	conf.Internal.NotifyTracker.Mark(soaRequest(zd, addr))
	waitFor(t, 5*time.Second, "the tries to run out", stateIs(conf, zd, "given up"))
	time.Sleep(300 * time.Millisecond)
	if got := seen.Load(); got != 3 {
		t.Errorf("the receiver saw %d NOTIFYs, want 3 (the first and two resends)", got)
	}
	if st := notifyState(conf, zd)[0]; st.Failures != 3 || st.LastError == "" {
		t.Errorf("state after giving up: %+v", st)
	}

	// The next change is tried in full again.
	conf.Internal.NotifyTracker.Mark(soaRequest(zd, addr))
	waitFor(t, 5*time.Second, "a second round", func() bool { return seen.Load() == 6 })
}

// A reply of any kind ends the tries: asking again gets the same reply.
func TestNotifyRefusedIsNotResent(t *testing.T) {
	addr, seen := startCountingSink(t, "udp", 0, dns.RcodeRefused)
	conf, _ := runNotifier(t, 5, "30ms")
	zd := loadIxfrTestZone(t, basicZone)

	conf.Internal.NotifyTracker.Mark(soaRequest(zd, addr))
	waitFor(t, 5*time.Second, "the REFUSED reply", stateIs(conf, zd, "ok"))
	time.Sleep(200 * time.Millisecond)
	if got := seen.Load(); got != 1 {
		t.Errorf("a refused NOTIFY was sent %d times, want once", got)
	}
	if st := notifyState(conf, zd)[0]; st.LastError != "REFUSED" {
		t.Errorf("state after REFUSED: %+v", st)
	}
}

// ICMP port unreachable on UDP gets one immediate try over TCP.
func TestNotifyFallsBackToTCPWhenUDPIsRefused(t *testing.T) {
	addr, seen := startCountingSink(t, "tcp", 0, dns.RcodeSuccess)
	if pc, err := net.ListenPacket("udp", addr); err != nil {
		t.Skipf("the UDP port beside the TCP listener is in use: %v", err)
	} else {
		pc.Close()
	}
	conf, _ := runNotifier(t, 5, "10s")
	zd := loadIxfrTestZone(t, basicZone)

	conf.Internal.NotifyTracker.Mark(soaRequest(zd, addr))
	waitFor(t, 5*time.Second, "the NOTIFY over TCP", stateIs(conf, zd, "ok"))
	if got := seen.Load(); got != 1 {
		t.Errorf("the TCP receiver saw %d NOTIFYs, want 1", got)
	}
}

// A caller waiting for the answer gets one try per target and does its own
// retrying; the Notifier must not retry behind it.
func TestNotifyWithAWaitingCallerIsSentOnce(t *testing.T) {
	addr, seen := startCountingSink(t, "udp", 1000, dns.RcodeSuccess)
	_, q := runNotifier(t, 5, "30ms")
	zd := loadIxfrTestZone(t, basicZone)

	resp := make(chan NotifyResponse, 1)
	q <- NotifyRequest{ZoneName: zd.ZoneName, ZoneData: zd, RRtype: dns.TypeDNSKEY, Targets: []string{addr}, Response: resp}
	select {
	case r := <-resp:
		if !r.Error {
			t.Errorf("a NOTIFY nobody answered reported success: %+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no response to a waiting caller")
	}
	time.Sleep(300 * time.Millisecond)
	if got := seen.Load(); got != 1 {
		t.Errorf("a NOTIFY with a waiting caller was sent %d times, want once", got)
	}
}

// The pending set keeps the latest request per zone and never blocks.
func TestNotifyMarkCoalescesPerZone(t *testing.T) {
	tr := NewNotifyTracker()
	zd := &ZoneData{ZoneName: "a.example."}
	tr.Mark(soaRequest(zd, "192.0.2.1:53"))
	tr.Mark(soaRequest(zd, "192.0.2.2:53"))
	tr.Mark(soaRequest(&ZoneData{ZoneName: "b.example."}, "192.0.2.3:53"))
	got := tr.takePending()
	if len(got) != 2 {
		t.Fatalf("got %d pending requests, want one per zone", len(got))
	}
	for _, r := range got {
		if r.ZoneName == "a.example." && r.Targets[0] != "192.0.2.2:53" {
			t.Errorf("the pending request is not the latest: %v", r.Targets)
		}
	}
	if len(tr.takePending()) != 0 {
		t.Error("taking the pending set did not empty it")
	}
}

// A publish hands its NOTIFY to the tracker when there is one.
func TestPublishHandsNotifyToTheTracker(t *testing.T) {
	prev := Conf.Internal.NotifyTracker
	tr := NewNotifyTracker()
	Conf.Internal.NotifyTracker = tr
	t.Cleanup(func() { Conf.Internal.NotifyTracker = prev })
	q := withNotifyQ(t, 4)

	zd := loadIxfrTestZone(t, basicZone)
	zd.Notify = []PeerConf{{Addr: aDownstream}}
	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))
	stageAndPublish(t, zd, stageAddA(t, zd, "two.example.test.", "192.0.2.12"))

	if len(q) != 0 {
		t.Errorf("%d NOTIFYs went to the queue with a tracker present", len(q))
	}
	if got := tr.takePending(); len(got) != 1 || got[0].ZoneName != zd.ZoneName {
		t.Errorf("want one coalesced pending NOTIFY for %s, got %v", zd.ZoneName, got)
	}
}

func TestNotifyRetryPolicyPrefersTheZone(t *testing.T) {
	tr := NewNotifyTracker()
	five := 5
	tr.setDefaults(&five, "20s")
	zd := &ZoneData{ZoneName: "example."}
	if r, i := notifyRetryPolicy(zd, tr); r != 5 || i != 20*time.Second {
		t.Errorf("server settings: %d, %s", r, i)
	}
	one := 1
	zd.notifyRetries, zd.notifyRetryInterval = &one, time.Second
	if r, i := notifyRetryPolicy(zd, tr); r != 1 || i != time.Second {
		t.Errorf("zone settings: %d, %s", r, i)
	}
}
