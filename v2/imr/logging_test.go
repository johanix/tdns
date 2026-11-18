/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package imr

import (
	"bytes"
	"context"
	"log"
	"log/slog"
	"strings"
	"testing"

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
	if _, err := NewImr(context.Background(), ic, Options{Logger: lg}); err != nil {
		t.Fatalf("NewImr: %v", err)
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
		imr, err := NewImr(context.Background(), Config{}, Options{Logger: lg})
		if err != nil {
			t.Fatalf("NewImr: %v", err)
		}
		_, _ = imr.Cache.ValidateRRset(context.Background(), rrset, nil)
		logged := strings.Contains(own.String(), "ValidateRRset: start: owner=")
		if logged != (level == slog.LevelDebug) {
			t.Errorf("logger at %v: the per-RRset line logged = %v:\n%s", level, logged, own.String())
		}
	}
}
