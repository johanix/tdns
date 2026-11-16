/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// #1062: NOTIFY leaves from the zone's effective transfer source -- the zone's
// transfer-src, else authengine.transfer-src -- as AXFR and the SOA probe do.
//
// A NOTIFY to loopback from a loopback source passes whether or not anything
// is bound: the kernel picks a loopback source anyway. So, as in the probe's
// tests, the case with teeth is a source the host does NOT have: bound, the
// send must fail with EADDRNOTAVAIL; unbound, it would succeed. Every case goes
// through notifyOne or notifyOneOver, so dropping the bind from the send path
// reddens them, not only a test of the helper.

// startNotifySrcSink runs a NOTIFY receiver on host ("127.0.0.1" or "::1")
// that answers NOERROR and reports each sender's address on the channel.
func startNotifySrcSink(t *testing.T, network, host string) (string, <-chan string) {
	t.Helper()
	from := make(chan string, 16)
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if h, _, err := net.SplitHostPort(w.RemoteAddr().String()); err == nil {
			select {
			case from <- h:
			default:
			}
		}
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})
	ready := make(chan struct{})
	srv := &dns.Server{Handler: handler, NotifyStartedFunc: func() { close(ready) }}
	var addr string
	var err error
	if network == "tcp" {
		var l net.Listener
		if l, err = net.Listen("tcp", net.JoinHostPort(host, "0")); err == nil {
			srv.Listener, addr = l, l.Addr().String()
		}
	} else {
		var pc net.PacketConn
		if pc, err = net.ListenPacket("udp", net.JoinHostPort(host, "0")); err == nil {
			srv.PacketConn, addr = pc, pc.LocalAddr().String()
		}
	}
	if err != nil {
		if host == "::1" {
			t.Skipf("IPv6 loopback unavailable here: %v", err)
		}
		t.Fatalf("listen %s on %s: %v", network, host, err)
	}
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("NOTIFY sink did not start")
	}
	t.Cleanup(func() { _ = srv.Shutdown() })
	return addr, from
}

func notifySrcZone(zone, global []string) *ZoneData {
	zd := &ZoneData{ZoneName: "notifysrc.example.", TransferSrc: zone}
	if global != nil {
		kdb := &KeyDB{}
		kdb.SetTransferSrc(global)
		zd.KeyDB = kdb
	}
	return zd
}

type notifySrcCase struct {
	name   string
	zone   []string // the zone's transfer-src
	global []string // authengine.transfer-src
	// wantFrom is the source the receiver must see. "" means the source bound
	// is one the host lacks, so the send must fail and nothing arrive.
	wantFrom string
}

func runNotifySrcCases(t *testing.T, from <-chan string, send func(*ZoneData) notifyAttempt, cases []notifySrcCase) {
	t.Helper()
	prev := notifyTimeout
	notifyTimeout = 2 * time.Second
	t.Cleanup(func() { notifyTimeout = prev })

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for len(from) > 0 {
				<-from
			}
			a := send(notifySrcZone(tc.zone, tc.global))
			if a.setupErr != nil {
				t.Fatalf("setup failed, nothing was sent: %v", a.setupErr)
			}
			if tc.wantFrom == "" {
				if a.err == nil {
					t.Fatal("NOTIFY with a source the host lacks was answered; the source is not being bound")
				}
				if !errors.Is(a.err, syscall.EADDRNOTAVAIL) {
					t.Errorf("NOTIFY failed, but not on the bind: %v", a.err)
				}
				if len(from) != 0 {
					t.Errorf("the receiver saw a NOTIFY from %s", <-from)
				}
				return
			}
			if a.err != nil {
				t.Fatalf("NOTIFY failed: %v", a.err)
			}
			if a.rcode != dns.RcodeSuccess {
				t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[a.rcode])
			}
			select {
			case got := <-from:
				if !net.ParseIP(got).Equal(net.ParseIP(tc.wantFrom)) {
					t.Errorf("NOTIFY came from %s, want %s", got, tc.wantFrom)
				}
			default:
				t.Error("answered, but the receiver recorded no sender")
			}
		})
	}
}

func TestNotifyBindsTransferSrc(t *testing.T) {
	addr, from := startNotifySrcSink(t, "udp", "127.0.0.1")
	send := func(zd *ZoneData) notifyAttempt {
		return zd.notifyOne(context.Background(), &Config{}, dns.TypeSOA, addr)
	}
	runNotifySrcCases(t, from, send, []notifySrcCase{
		{name: "no transfer-src: unbound, as before", wantFrom: "127.0.0.1"},
		{name: "zone source the host has", zone: []string{"127.0.0.1"}, wantFrom: "127.0.0.1"},
		{name: "zone source the host lacks", zone: []string{"192.0.2.1"}},
		{name: "global source the host lacks", global: []string{"192.0.2.1"}},
		{name: "zone overrides global", zone: []string{"127.0.0.1"}, global: []string{"192.0.2.1"}, wantFrom: "127.0.0.1"},
		// The v4 target takes the v4 source, wherever it is in the list.
		{name: "picks the v4 source past a v6 one", zone: []string{"2001:db8::1", "192.0.2.1"}},
		{name: "picks the bindable v4 source past a v6 one", zone: []string{"2001:db8::1", "127.0.0.1"}, wantFrom: "127.0.0.1"},
		// Naming only v6 must not break a v4 target.
		{name: "only a v6 source: unbound", zone: []string{"2001:db8::1"}, wantFrom: "127.0.0.1"},
	})
}

func TestNotifyBindsTransferSrcV6(t *testing.T) {
	addr, from := startNotifySrcSink(t, "udp", "::1")
	send := func(zd *ZoneData) notifyAttempt {
		return zd.notifyOne(context.Background(), &Config{}, dns.TypeSOA, addr)
	}
	runNotifySrcCases(t, from, send, []notifySrcCase{
		{name: "picks the v6 source past a v4 one", zone: []string{"192.0.2.1", "::1"}, wantFrom: "::1"},
		{name: "v6 source the host lacks", zone: []string{"192.0.2.1", "2001:db8::1"}},
		{name: "only a v4 source: unbound", zone: []string{"192.0.2.1"}, wantFrom: "::1"},
	})
}

// The TCP attempt binds too, with a TCP address: a *net.UDPAddr there would
// fail the dial.
func TestNotifyOverTCPBindsTransferSrc(t *testing.T) {
	addr, from := startNotifySrcSink(t, "tcp", "127.0.0.1")
	send := func(zd *ZoneData) notifyAttempt {
		return zd.notifyOneOver(context.Background(), &Config{}, dns.TypeSOA, addr, "tcp")
	}
	runNotifySrcCases(t, from, send, []notifySrcCase{
		{name: "no transfer-src: unbound, as before", wantFrom: "127.0.0.1"},
		{name: "source the host has", zone: []string{"127.0.0.1"}, wantFrom: "127.0.0.1"},
		{name: "source the host lacks", zone: []string{"192.0.2.1"}},
	})
}

// A NOTIFY refused over UDP and retried over TCP keeps its source: the bound
// UDP attempt still sees the ICMP port unreachable, and the TCP retry binds.
func TestNotifyTCPFallbackKeepsTransferSrc(t *testing.T) {
	addr, from := startNotifySrcSink(t, "tcp", "127.0.0.1")
	if pc, err := net.ListenPacket("udp", addr); err != nil {
		t.Skipf("the UDP port beside the TCP listener is in use: %v", err)
	} else {
		pc.Close()
	}
	prev := notifyTimeout
	notifyTimeout = 2 * time.Second
	t.Cleanup(func() { notifyTimeout = prev })

	a := notifySrcZone([]string{"127.0.0.1"}, nil).notifyOne(context.Background(), &Config{}, dns.TypeSOA, addr)
	if a.err != nil || a.setupErr != nil {
		t.Fatalf("NOTIFY failed: err=%v setupErr=%v", a.err, a.setupErr)
	}
	if !a.overTCP {
		t.Error("the NOTIFY was not retried over TCP")
	}
	select {
	case got := <-from:
		if got != "127.0.0.1" {
			t.Errorf("NOTIFY came from %s, want 127.0.0.1", got)
		}
	default:
		t.Error("the TCP receiver recorded no sender")
	}
}
