/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// imrengine.testing.priming: false (docs/2026-09-28-imr-deckard-test-clock-and-switches.md, S4).

// With priming off, InitImrEngine takes the root from the hints and sends no
// priming query. The hints name an address that never answers, so a priming
// query would wait out its timeout; the start completes well inside it.
func TestInitImrEngineWithoutPrimingUsesTheHints(t *testing.T) {
	savedImr := Globals.ImrEngine
	defer func() { Globals.ImrEngine = savedImr }()

	hints := filepath.Join(t.TempDir(), "hints.zone")
	// 192.0.2.1 is TEST-NET-1: nothing answers there.
	if err := os.WriteFile(hints, []byte(". 3600000 NS a.root.test.\na.root.test. 3600000 A 192.0.2.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	conf := &Config{}
	conf.Internal.ServerErrors = NewServerErrorRegistry()
	conf.Imr.RootHints = hints
	off := false
	conf.Imr.Testing.Priming = &off

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	start := time.Now()
	if err := conf.InitImrEngine(ctx, true); err != nil {
		t.Fatalf("InitImrEngine with priming off: %v", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("InitImrEngine took %v: it waited for a root that never answers", took)
	}

	imr := Globals.ImrEngine
	if imr == nil || imr.Cache == nil {
		t.Fatal("InitImrEngine left no resolver")
	}
	if !imr.Cache.IsPrimed() {
		t.Error("the cache is not marked primed")
	}
	if imr.PrimedVia != "hints only (testing.priming: false)" {
		t.Errorf("PrimedVia = %q, want the hints-only marker", imr.PrimedVia)
	}
	ns := imr.Cache.Get(".", dns.TypeNS)
	if ns == nil || ns.RRset == nil || len(ns.RRset.RRs) != 1 {
		t.Fatalf("root NS in the cache: %+v, want the one NS from the hints", ns)
	}
	if got := ns.RRset.RRs[0].(*dns.NS).Ns; got != "a.root.test." {
		t.Errorf("root NS = %q, want a.root.test. from the hints", got)
	}
}

// The switch is a known key, including for the strict decode a reload uses.
func TestReloadImrEngineFromFileAcceptsTestingPriming(t *testing.T) {
	conf := writeImrConfig(t, `imrengine:
   testing:
      priming: false
`)
	block, err := conf.reloadImrEngineFromFile()
	if err != nil {
		t.Fatalf("reloadImrEngineFromFile: %v", err)
	}
	if block == nil || !block.Testing.SkipPriming() {
		t.Fatalf("testing.priming: false did not decode: %+v", block)
	}
}

func TestImrTestingConfSkipPriming(t *testing.T) {
	on, off := true, false
	for _, tc := range []struct {
		priming *bool
		want    bool
	}{{nil, false}, {&on, false}, {&off, true}} {
		if got := (ImrTestingConf{Priming: tc.priming}).SkipPriming(); got != tc.want {
			t.Errorf("Priming=%v: SkipPriming() = %v, want %v", tc.priming, got, tc.want)
		}
	}
}
