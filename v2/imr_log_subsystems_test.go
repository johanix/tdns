/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// subsystemLine is one line a subsystem logger wrote.
type subsystemLine struct{ level, msg, subsystem string }

// A subsystem logger's line names its subsystem right after the message.
var subsystemLineRE = regexp.MustCompile(`level=(\S+) msg=("(?:[^"\\]|\\.)*"|\S+) subsystem=(\S+)`)

func subsystemLines(s string) []subsystemLine {
	var out []subsystemLine
	for _, l := range strings.Split(s, "\n") {
		if m := subsystemLineRE.FindStringSubmatch(l); m != nil {
			out = append(out, subsystemLine{level: m[1], msg: m[2], subsystem: m[3]})
		}
	}
	return out
}

// captureSubsystemLogs sets the subsystems' levels and catches what the
// subsystem loggers write (they write through slog.Default), until the test
// ends.
func captureSubsystemLogs(t *testing.T, levels map[string]slog.Level) *syncBuffer {
	t.Helper()
	for name, level := range levels {
		was := getOrCreateLevel(name).Level()
		SetSubsystemLevel(name, level)
		t.Cleanup(func() { SetSubsystemLevel(name, was) })
	}
	buf := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// runDaemonResolver starts the resolver as the daemons do (InitImrEngine), with
// imrengine.debug on and the root forwarded to a test upstream, and asks it two
// questions: one the upstream answers, and one for a zone forwarded to a port
// nothing listens on, whose lookup logs the upstream's error.
func runDaemonResolver(t *testing.T) {
	t.Helper()
	restoreProcessWideTuning(t)
	prevGlobal := Globals.ImrEngine
	t.Cleanup(func() { Globals.ImrEngine = prevGlobal })
	addr, port, _, stop := startTestUpstream(t)
	defer stop()
	closed, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, deadPort := splitHostPort(t, closed.LocalAddr().String())
	closed.Close()

	conf := &Config{}
	conf.Imr = ImrEngineConf{Debug: true, Forward: append(rootForward(addr, port),
		ImrForwardConf{Zone: "dead.example.", Upstreams: []ImrUpstreamConf{{Addr: "127.0.0.1", Port: deadPort}}})}
	refreshing := goroutinesIn("(*Imr).refreshRootLoop(")
	ctx, cancel := context.WithCancel(context.Background())
	if err := conf.InitImrEngine(ctx); err != nil {
		cancel()
		t.Fatalf("InitImrEngine: %v", err)
	}
	imr := conf.Internal.ImrEngine
	imr.Start(ctx)
	resp, err := imr.ImrQuery(ctx, "www.fwd.example.", dns.TypeA, dns.ClassINET)
	if err != nil || resp == nil || resp.RRset == nil {
		cancel()
		t.Fatalf("www.fwd.example. A: %+v (err %v), want the upstream's answer", resp, err)
	}
	_, _ = imr.ImrQuery(ctx, "www.dead.example.", dns.TypeA, dns.ClassINET)
	cancel()
	waitUntil(t, "Start's goroutines to end with its context", func() bool { return goroutinesIn("(*Imr).refreshRootLoop(") <= refreshing })
}

// The daemon's resolver logs as imr, and its lookups as imr-lookups, so
// log.subsystems sets its level apart from engine and dns (#1196).
func TestDaemonResolverLogsUnderItsOwnSubsystems(t *testing.T) {
	// The resolver's messages: InitImrEngine's, which it always logs at Info,
	// and those the first subtest sees under imr and imr-lookups.
	const initMsg = `"InitImrEngine: IMR initialized"`
	resolverMsgs := map[string]bool{initMsg: true}

	t.Run("imr and imr-lookups at Debug, engine and dns at Warn", func(t *testing.T) {
		buf := captureSubsystemLogs(t, map[string]slog.Level{
			"engine": slog.LevelWarn, "dns": slog.LevelWarn,
			"imr": slog.LevelDebug, "imr-lookups": slog.LevelDebug,
		})
		runDaemonResolver(t)

		seen := map[string]int{}
		initUnderImr := false
		for _, l := range subsystemLines(buf.String()) {
			seen[l.subsystem]++
			if l.subsystem == "imr" || l.subsystem == "imr-lookups" {
				initUnderImr = initUnderImr || (l.subsystem == "imr" && l.msg == initMsg)
				resolverMsgs[l.msg] = true
			}
		}
		if seen["imr"] == 0 || seen["imr-lookups"] == 0 {
			t.Errorf("lines per subsystem %v; want the resolver's under imr and its lookups' under imr-lookups", seen)
		}
		if !initUnderImr {
			t.Error("InitImrEngine's line is not under imr")
		}
	})

	t.Run("imr and imr-lookups at Warn, engine at Info, dns at Debug", func(t *testing.T) {
		buf := captureSubsystemLogs(t, map[string]slog.Level{
			"engine": slog.LevelInfo, "dns": slog.LevelDebug,
			"imr": slog.LevelWarn, "imr-lookups": slog.LevelWarn,
		})
		runDaemonResolver(t)

		for _, l := range subsystemLines(buf.String()) {
			if l.level != "INFO" && l.level != "DEBUG" {
				continue
			}
			if l.subsystem == "imr" || l.subsystem == "imr-lookups" {
				t.Errorf("%s line under %s at Warn: %s", l.level, l.subsystem, l.msg)
			} else if resolverMsgs[l.msg] {
				t.Errorf("the resolver's %s line %s is under %s", l.level, l.msg, l.subsystem)
			}
		}
	})
}
