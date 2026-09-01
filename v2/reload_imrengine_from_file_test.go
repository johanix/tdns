/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The imrengine: half of the zone-reload path (#436): what a SIGHUP re-reads,
 * and — more importantly — what it refuses to act on.
 */

package tdns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeImrConfig(t *testing.T, body string) *Config {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "tdns-imr.yaml")
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	conf := &Config{}
	conf.Internal.CfgFile = cfg
	return conf
}

// TestReloadImrEngineFromFile_ReadsWithoutCommitting: the block comes back
// from the file whole, and conf.Imr is left alone until something applies it.
func TestReloadImrEngineFromFile_ReadsWithoutCommitting(t *testing.T) {
	conf := writeImrConfig(t, `imrengine:
   active: true
   stubs:
      - zone: internal.example.
        servers:
           - name: ns.internal.example.
             addrs: [ "192.0.2.5" ]
             alpn: [ "do53" ]
   forward:
      - zone: .
        upstreams:
           - addr: 192.0.2.1
             transport: do53
   tuning:
      query-budget: 8s
`)
	// What the resolver is running, which the read must not disturb.
	conf.Imr.Forward = []ImrForwardConf{fwdConf("running.example.", "192.0.2.99", 0)}
	conf.Imr.Stubs = []ImrStubConf{stubConf("running.example.", "ns.running.example.", "192.0.2.98")}

	block, err := conf.reloadImrEngineFromFile()
	if err != nil {
		t.Fatalf("reloadImrEngineFromFile: %v", err)
	}
	if block == nil {
		t.Fatal("no block returned")
	}
	// The whole block comes back, not just the two reloadable fields: the
	// caller needs tuning and the trust anchors to report what a reload
	// cannot apply.
	if block.Tuning.QueryBudget != 8*time.Second {
		t.Errorf("returned block did not carry the file's tuning: %+v", block.Tuning)
	}
	if len(block.Forward) != 1 || block.Forward[0].Zone != "." {
		t.Errorf("block forward zones = %+v, want the root from the file", block.Forward)
	}
	if len(block.Stubs) != 1 || block.Stubs[0].Zone != "internal.example." {
		t.Errorf("block stub zones = %+v, want internal.example. from the file", block.Stubs)
	}
	// Reading is not applying: a block that decodes can still be refused by
	// ReloadZones, so conf.Imr must still describe what is running.
	if len(conf.Imr.Forward) != 1 || conf.Imr.Forward[0].Zone != "running.example." {
		t.Errorf("the read committed to conf.Imr: %+v", conf.Imr.Forward)
	}
	if len(conf.Imr.Stubs) != 1 || conf.Imr.Stubs[0].Zone != "running.example." {
		t.Errorf("the read committed to conf.Imr: %+v", conf.Imr.Stubs)
	}
}

// TestReloadImrEngineFromFile_RejectsUnknownKey is the one that matters: a
// misspelled key must fail the re-read, NOT decode to an empty list.
//
// With a lenient decode, `forwrd:` is silently ignored, Forward comes back
// empty, and the reload that follows deletes every forward zone the resolver
// is running on — a typo, on a SIGHUP, taking out forwarding.
func TestReloadImrEngineFromFile_RejectsUnknownKey(t *testing.T) {
	conf := writeImrConfig(t, `imrengine:
   active: true
   forwrd:
      - zone: .
        upstreams:
           - addr: 192.0.2.1
`)
	live := []ImrForwardConf{fwdConf(".", "192.0.2.1", 0)}
	conf.Imr.Forward = live

	_, err := conf.reloadImrEngineFromFile()
	if err == nil {
		t.Fatalf("misspelled imrengine key accepted; forward zones would be silently deleted")
	}
	if !strings.Contains(err.Error(), "forwrd") {
		t.Errorf("error does not name the offending key: %v", err)
	}
	if len(conf.Imr.Forward) != 1 || conf.Imr.Forward[0].Zone != "." {
		t.Errorf("running forward config was modified by a failed re-read: %+v", conf.Imr.Forward)
	}
}

// TestReloadImrEngineFromFile_NoBlock: a config with no imrengine: block is a
// legitimate "no resolver zones", distinct from a mistyped one — and applying
// the empty block it returns is what clears the running zones.
func TestReloadImrEngineFromFile_NoBlock(t *testing.T) {
	imr := runningImr(t, ImrEngineConf{})
	conf := writeImrConfig(t, "zones:\n   - name: a.example.\n     type: primary\n")
	conf.Internal.ImrEngine = imr
	conf.Imr.Forward = []ImrForwardConf{fwdConf(".", "192.0.2.1", 0)}

	block, err := conf.reloadImrEngineFromFile()
	if err != nil {
		t.Fatalf("reloadImrEngineFromFile: %v", err)
	}
	if block == nil || len(block.Forward) != 0 {
		t.Fatalf("block = %+v, want an empty one", block)
	}
	res, err := conf.applyImrEngineReload()
	if err != nil {
		t.Fatalf("applyImrEngineReload: %v", err)
	}
	if len(res.ForwardsRemoved) != 1 || res.ForwardsRemoved[0] != "." {
		t.Errorf("ForwardsRemoved = %v, want [.]", res.ForwardsRemoved)
	}
	if len(conf.Imr.Forward) != 0 {
		t.Errorf("forward zones = %+v, want none once the block is gone from the file", conf.Imr.Forward)
	}
	if len(imr.ForwardZones()) != 0 {
		t.Errorf("running forward table = %+v, want empty", imr.ForwardZones())
	}
}

// runningImr returns a resolver with one forward zone, as if it had booted
// from bootConf.
func runningImr(t *testing.T, boot ImrEngineConf) *Imr {
	t.Helper()
	imr := newReloadTestImr(t)
	imr.bootConf = boot
	if _, err := imr.ReloadZones(nil, []ImrForwardConf{fwdConf(".", "192.0.2.1", 0)}); err != nil {
		t.Fatalf("seeding the running forward table: %v", err)
	}
	return imr
}

// TestApplyImrEngineReload_RejectsUnknownKey twins the SIGHUP test through the
// apply path that BOTH reload commands share.
//
// The full-config parse only WARNS about an unknown key, so on `config reload`
// a misspelled `forwrd:` reached this function as an empty forward list and
// deleted every forward zone the resolver was running on. The strict re-read
// has to live here, not only on the zone-reload path, or the fix covers one of
// the two commands the guide names.
func TestApplyImrEngineReload_RejectsUnknownKey(t *testing.T) {
	imr := runningImr(t, ImrEngineConf{})
	conf := writeImrConfig(t, `imrengine:
   active: true
   forwrd:
      - zone: .
        upstreams:
           - addr: 192.0.2.1
`)
	conf.Internal.ImrEngine = imr
	// What ParseConfig leaves behind on the full-reload path: the typo'd key
	// was skipped, so the forward list decoded to nothing.
	conf.Imr.Forward = nil

	res, err := conf.applyImrEngineReload()
	if err == nil {
		t.Fatalf("misspelled key accepted; result was %+v", res)
	}
	if zones := imr.ForwardZones(); len(zones) != 1 || zones[0].Zone != "." {
		t.Fatalf("forwarding was wiped by a typo: %+v", zones)
	}
}

// TestApplyImrEngineReload_ReportsRestartRequiredFromFile: the restart-required
// report must come from the FILE, not from conf.Imr.
//
// On the zone-reload path conf.Imr still holds the boot values for everything
// except stubs and forwards, so diffing against it compared the boot config
// with itself: edit query-budget, send SIGHUP, and the operator was told
// nothing while the resolver kept the old budget.
func TestApplyImrEngineReload_ReportsRestartRequiredFromFile(t *testing.T) {
	boot := ImrEngineConf{
		TrustAnchorFile: "/etc/tdns/anchors",
		Tuning:          ImrTuningConf{QueryBudget: 8 * time.Second},
	}
	imr := runningImr(t, boot)
	conf := writeImrConfig(t, `imrengine:
   trust-anchor-file: /etc/tdns/anchors
   tuning:
      query-budget: 30s
   forward:
      - zone: .
        upstreams:
           - addr: 192.0.2.1
`)
	conf.Internal.ImrEngine = imr
	// conf.Imr as SIGHUP leaves it: the boot values, untouched by this reload.
	conf.Imr = boot

	res, err := conf.applyImrEngineReload()
	if err != nil {
		t.Fatalf("applyImrEngineReload: %v", err)
	}
	if len(res.RestartRequired) != 1 || res.RestartRequired[0] != "imrengine.tuning" {
		t.Fatalf("RestartRequired = %v, want [imrengine.tuning]", res.RestartRequired)
	}
	if !strings.Contains(res.Summary(), "restart required for imrengine.tuning") {
		t.Errorf("summary does not carry the restart notice: %q", res.Summary())
	}
}

// TestApplyImrEngineReload_RejectedTableLeavesConfigAlone: a block that
// DECODES cleanly can still be refused by ReloadZones — trust-ad over a
// plaintext upstream is the standing example — and when it is, conf.Imr must
// go on describing the zones the resolver is actually running.
//
// Committing at decode time, as the code used to, left conf.Imr advertising a
// forward zone that had been rejected: the resolver forwarded through the old
// table while the config struct described the new one.
func TestApplyImrEngineReload_RejectedTableLeavesConfigAlone(t *testing.T) {
	imr := runningImr(t, ImrEngineConf{})
	conf := writeImrConfig(t, `imrengine:
   forward:
      - zone: .
        upstreams:
           - addr: 192.0.2.1
      - zone: bad.example.
        trust-ad: true
        upstreams:
           - addr: 192.0.2.9
             transport: do53
`)
	conf.Internal.ImrEngine = imr
	// conf.Imr as the running resolver has it.
	running := []ImrForwardConf{fwdConf(".", "192.0.2.1", 0)}
	conf.Imr.Forward = running

	res, err := conf.applyImrEngineReload()
	if err == nil {
		t.Fatalf("trust-ad over a plaintext upstream was accepted: %+v", res)
	}
	if !strings.Contains(err.Error(), "trust-ad") {
		t.Errorf("error does not name the offending setting: %v", err)
	}
	if zones := imr.ForwardZones(); len(zones) != 1 || zones[0].Zone != "." {
		t.Fatalf("a refused table changed the running one: %+v", zones)
	}
	if len(conf.Imr.Forward) != 1 || conf.Imr.Forward[0].Zone != "." {
		t.Errorf("conf.Imr describes the rejected zones: %+v", conf.Imr.Forward)
	}
}
