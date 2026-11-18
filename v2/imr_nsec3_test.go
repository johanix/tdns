/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"testing"

	cache "github.com/johanix/tdns/v2/cache"
)

// The key decodes, 0 included, and a changed value is reported as needing a
// restart like every other tuning key.
func TestNSEC3MaxIterationsDecodesAndNeedsRestart(t *testing.T) {
	boot := ImrEngineConf{}
	imr := runningImr(t, boot)
	conf := writeImrConfig(t, `imrengine:
   tuning:
      nsec3-max-iterations: 0
   forward:
      - zone: .
        upstreams:
           - addr: 192.0.2.1
`)
	block, err := conf.reloadImrEngineFromFile()
	if err != nil {
		t.Fatalf("reloadImrEngineFromFile: %v", err)
	}
	if block.Tuning.NSEC3MaxIterations == nil || *block.Tuning.NSEC3MaxIterations != 0 {
		t.Fatalf("decoded nsec3-max-iterations %v, want 0", block.Tuning.NSEC3MaxIterations)
	}

	conf.Internal.ImrEngine = imr
	conf.Imr = boot
	res, err := conf.applyImrEngineReload()
	if err != nil {
		t.Fatalf("applyImrEngineReload: %v", err)
	}
	if len(res.RestartRequired) != 1 || res.RestartRequired[0] != "imrengine.tuning" {
		t.Errorf("RestartRequired = %v, want [imrengine.tuning]", res.RestartRequired)
	}
}

// The join: the limit set in the config is the one the cache validates with.
func TestNSEC3MaxIterationsReachesTheCache(t *testing.T) {
	addr, port, _, stop := startTestUpstream(t)
	defer stop()

	savedImr := Globals.ImrEngine
	savedLimits := cache.GetTTLLimits()
	t.Cleanup(func() {
		Globals.ImrEngine = savedImr
		cache.SetTTLLimits(savedLimits)
		cache.SetZoneStateRecheck(0)
		cache.SetNSEC3MaxIterations(cache.DefaultNSEC3MaxIterations)
	})

	conf := &Config{}
	conf.Imr.Forward = []ImrForwardConf{fwdConf(".", addr, port)}
	limit := uint16(20)
	conf.Imr.Tuning.NSEC3MaxIterations = &limit
	if err := conf.InitImrEngine(context.Background()); err != nil {
		t.Fatalf("InitImrEngine: %v", err)
	}
	if got := cache.NSEC3MaxIterations(); got != limit {
		t.Errorf("the cache validates with a limit of %d, want the configured %d", got, limit)
	}
}
