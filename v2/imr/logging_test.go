/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package imr

import (
	"bytes"
	"context"
	"log"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A resolver built with a logger logs through it, the engine and the cache
// both, and through neither of the process-wide loggers.
func TestTheResolverLogsThroughItsOwnLogger(t *testing.T) {
	restoreProcessWideTuning(t)
	var global bytes.Buffer
	prevSlog, prevLog := slog.Default(), log.Writer()
	slog.SetDefault(slog.New(slog.NewTextHandler(&global, nil)))
	log.SetOutput(&global)
	t.Cleanup(func() { slog.SetDefault(prevSlog); log.SetOutput(prevLog) })

	var own bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&own, nil))
	ic := Config{}
	off := false
	ic.Testing.Priming = &off // seeds from the hints, which the cache logs
	if _, err := New(context.Background(), ic, Options{Logger: lg}); err != nil {
		t.Fatalf("New: %v", err)
	}

	logged := own.String()
	for _, want := range []string{
		"imrengine.testing.priming is false",               // the engine
		"no root-hints config provided, using compiled-in", // the cache
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("the resolver's logger did not get %q:\n%s", want, logged)
		}
	}
	if global.Len() != 0 {
		t.Errorf("the process-wide loggers got:\n%s", global.String())
	}
}

// Per-RRset lines are at Debug: the cache's line for an RRset it validates
// reaches the resolver's logger at Debug, and not at Info.
func TestTheCachesPerRRsetLinesAreAtDebug(t *testing.T) {
	restoreProcessWideTuning(t)
	rr, err := dns.NewRR("www.example. 300 IN A 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	rrset := &core.RRset{Name: "www.example.", RRtype: dns.TypeA, Class: dns.ClassINET, RRs: []dns.RR{rr}}
	for _, level := range []slog.Level{slog.LevelInfo, slog.LevelDebug} {
		var own bytes.Buffer
		lg := slog.New(slog.NewTextHandler(&own, &slog.HandlerOptions{Level: level}))
		imr, err := New(context.Background(), Config{}, Options{Logger: lg})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		_, _ = imr.Cache.ValidateRRset(context.Background(), rrset, nil)
		logged := strings.Contains(own.String(), "ValidateRRset: start: owner=")
		if logged != (level == slog.LevelDebug) {
			t.Errorf("logger at %v: the per-RRset line logged = %v:\n%s", level, logged, own.String())
		}
	}
}

// The DNS clients' per-exchange lines are at Debug: the resolver's clients and
// a forward upstream's, given a truncated UDP answer, say they retried over TCP
// to the resolver's logger at Debug, and not at Info.
func TestTheDNSClientsPerExchangeLinesAreAtDebug(t *testing.T) {
	restoreProcessWideTuning(t)
	addr, port := startTruncatingUpstream(t)
	const tcLine = "truncated (TC=1); retrying over TCP"
	for _, level := range []slog.Level{slog.LevelInfo, slog.LevelDebug} {
		var own bytes.Buffer
		lg := slog.New(slog.NewTextHandler(&own, &slog.HandlerOptions{Level: level}))
		ic := Config{Forward: []ForwardConf{fwdConf("fwd.example.", addr, port)}}
		imr, err := New(context.Background(), ic, Options{Logger: lg})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		fz := imr.forwardZoneFor("www.fwd.example.")
		if fz == nil || len(fz.Upstreams) != 1 {
			t.Fatalf("logger at %v: no forward upstream for fwd.example.", level)
		}
		for name, c := range map[string]core.DNSClienter{
			"the resolver's Do53 client": imr.Cache.DNSClient[core.TransportDo53],
			"the forward upstream's":     fz.Upstreams[0].Client,
		} {
			own.Reset()
			m := new(dns.Msg)
			m.SetQuestion("www.fwd.example.", dns.TypeA)
			if _, _, res, err := c.ExchangeWithResult(m, net.JoinHostPort(addr, strconv.Itoa(int(port))), false); err != nil || !res.Truncated {
				t.Fatalf("logger at %v, %s: %+v, %v; want the truncated answer retried over TCP", level, name, res, err)
			}
			logged := own.String()
			if strings.Contains(logged, tcLine) != (level == slog.LevelDebug) {
				t.Errorf("logger at %v, %s: the truncation line logged = %v:\n%s", level, name, strings.Contains(logged, tcLine), logged)
			}
			if level == slog.LevelDebug && !strings.Contains(logged, "level=DEBUG") {
				t.Errorf("logger at %v, %s: the truncation line is not at Debug:\n%s", level, name, logged)
			}
		}
	}
}

// startTruncatingUpstream serves 127.0.0.1 on one port over UDP and TCP: UDP
// answers with TC=1 and nothing else, TCP with the answer.
func startTruncatingUpstream(t *testing.T) (string, uint16) {
	t.Helper()
	var pc net.PacketConn
	var l net.Listener
	for i := 0; i < 10 && l == nil; i++ {
		var err error
		if pc, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		if l, err = net.Listen("tcp", pc.LocalAddr().String()); err != nil {
			pc.Close() // the port is taken over TCP: try another
			l = nil
		}
	}
	if l == nil {
		t.Fatal("no port free over both UDP and TCP")
	}
	host, port := splitHostPort(t, pc.LocalAddr().String())
	reply := func(tc bool) dns.HandlerFunc {
		return func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			if tc {
				m.Truncated = true
			} else if rr, err := dns.NewRR(r.Question[0].Name + " 300 IN A 192.0.2.1"); err == nil {
				m.Answer = []dns.RR{rr}
			}
			_ = w.WriteMsg(m)
		}
	}
	for _, srv := range []*dns.Server{
		{PacketConn: pc, Handler: reply(true)},
		{Listener: l, Handler: reply(false)},
	} {
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }
		go func() { _ = srv.ActivateAndServe() }()
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("test upstream did not start")
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.ShutdownContext(ctx)
		})
	}
	return host, port
}
