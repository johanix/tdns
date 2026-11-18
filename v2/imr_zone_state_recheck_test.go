/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * #636: a zone's Insecure or Indeterminate validation state is revisited, from
 * the config knob to the zone state a referral leaves behind.
 */
package tdns

import (
	"context"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
)

// The key decodes as a duration, and a changed value is reported as needing a
// restart like every other tuning key: the interval is installed once, at init.
func TestZoneStateRecheckDecodesAndNeedsRestart(t *testing.T) {
	boot := ImrEngineConf{}
	imr := runningImr(t, boot)
	conf := writeImrConfig(t, `imrengine:
   tuning:
      zone-state-recheck: 5m
   forward:
      - zone: .
        upstreams:
           - addr: 192.0.2.1
`)
	block, err := conf.reloadImrEngineFromFile()
	if err != nil {
		t.Fatalf("reloadImrEngineFromFile: %v", err)
	}
	if block.Tuning.ZoneStateRecheck != 5*time.Minute {
		t.Fatalf("decoded zone-state-recheck %s, want 5m", block.Tuning.ZoneStateRecheck)
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

// The join: the interval set in the config is the one the cache runs on.
func TestZoneStateRecheckReachesTheCache(t *testing.T) {
	addr, port, _, stop := startTestUpstream(t)
	defer stop()

	savedImr := Globals.ImrEngine
	savedLimits := cache.GetTTLLimits()
	t.Cleanup(func() {
		Globals.ImrEngine = savedImr
		cache.SetTTLLimits(savedLimits)
		cache.SetZoneStateRecheck(0)
	})

	conf := &Config{}
	conf.Imr.Forward = []ImrForwardConf{fwdConf(".", addr, port)}
	conf.Imr.Tuning.ZoneStateRecheck = 5 * time.Minute
	if err := conf.InitImrEngine(context.Background()); err != nil {
		t.Fatalf("InitImrEngine: %v", err)
	}
	if got := cache.ZoneStateRecheck(); got != 5*time.Minute {
		t.Errorf("the cache runs on a %s interval, want the configured 5m", got)
	}
}
