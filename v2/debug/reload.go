/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"context"
	"fmt"
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// ReloadConfig parameterizes a `test reload` run. The reload test drives no
// dynamic updates: its stimulus is repeatedly reloading the zone (mgmt API),
// and its oracle is that a signed zone must never be served/transferred
// unsigned — the reload re-sign window (I10).
type ReloadConfig struct {
	Zone      string
	DnsServer string          // addr:port for the AXFR observer
	Api       *tdns.ApiClient // reload actor; nil disables it
	Target    string          // target name (informational, for the report)

	ReloadCapable bool // CapZoneReload probed available (gates the reload actor)
	DeclaredSigned bool // provisioned signed → surface "never observed signed" as a setup miss

	ReloadCadence time.Duration
	AxfrCadence   time.Duration
	Duration      time.Duration

	Tool   string
	TestId string
}

// RunReload executes a reload test to completion and returns the report. The
// reload actor is the only mgmt-API actor; the AXFR signedness observer is pure
// DNS. I10 is false-positive-free: it only asserts "unsigned" AFTER it has
// observed the zone signed at least once (the latch), so a zone that is simply
// mid-first-sign at startup never trips it.
func RunReload(ctx context.Context, cfg ReloadConfig) (*Report, error) {
	if cfg.Duration <= 0 {
		return nil, fmt.Errorf("duration must be positive (got %v); pass --duration", cfg.Duration)
	}
	if cfg.ReloadCadence <= 0 {
		cfg.ReloadCadence = 30 * time.Second
	}
	if cfg.AxfrCadence <= 0 {
		cfg.AxfrCadence = 500 * time.Millisecond
	}

	rep := NewReport(cfg.Tool, "reload")
	rep.TestId = cfg.TestId
	rep.Zone = cfg.Zone

	// Pre-flight: the zone must answer SOA, or this is a setup error (exit 2).
	if _, err := querySOASerial(ctx, cfg.DnsServer, cfg.Zone); err != nil {
		return nil, fmt.Errorf("pre-flight SOA query failed: %w", err)
	}

	check := &SignednessChecker{report: rep}

	runCtx, cancel := context.WithTimeout(ctx, cfg.Duration)
	defer cancel()

	var wg sync.WaitGroup

	// Reload actor (mgmt-API, capability-gated). Reloads can't be pre-probed
	// side-effect-free at the run scope, but the command already probed the
	// zone-reload command against ProbeZone; honour that verdict here.
	if cfg.Api != nil && cfg.ReloadCapable {
		wg.Add(1)
		go func() { defer wg.Done(); runReloader(runCtx, cfg, rep) }()
	} else {
		rep.Skip("reload-actor", "zone-reload capability unavailable — cannot force the reload window")
	}

	// AXFR signedness observer (pure DNS) → I10.
	wg.Add(1)
	go func() { defer wg.Done(); runSignednessObserver(runCtx, cfg, check, rep) }()

	wg.Wait()

	// A declared-signed zone we never once saw signed means the test could not
	// run its invariant (e.g. signing genuinely failed on the server) — report
	// it as a skip, never as a clean pass.
	if cfg.DeclaredSigned && !check.EverSigned() {
		rep.Skip("I10", "zone was never observed signed — signing may have failed on the server; I10 could not run")
	}

	return rep, nil
}

// runReloader reloads the test zone once per cadence via the mgmt API. Force=true
// so a static zone file is genuinely re-read and re-signed each time (that
// re-sign pass is the window I10 hunts). The ticker's first tick is one cadence
// in, by which time the observer has established the signed baseline (latch).
func runReloader(ctx context.Context, cfg ReloadConfig, rep *Report) {
	t := time.NewTicker(cfg.ReloadCadence)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			status, _, err := cfg.Api.RequestNGWithContext(ctx, "POST", "/zone",
				tdns.ZonePost{Command: "reload", Zone: dns.Fqdn(cfg.Zone), Force: true}, false)
			if err != nil || status != 200 {
				rep.Stat("reload.errors", 1)
				continue
			}
			rep.Stat("reload.issued", 1)
		}
	}
}

// runSignednessObserver transfers the zone each cadence and feeds each transfer
// to the I10 checker. A fast cadence relative to the re-sign window is what lets
// a transfer land inside the window.
func runSignednessObserver(ctx context.Context, cfg ReloadConfig, check *SignednessChecker, rep *Report) {
	t := time.NewTicker(cfg.AxfrCadence)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			obs, err := axfrSignedness(ctx, cfg.DnsServer, cfg.Zone)
			if err != nil {
				rep.Stat("axfr.errors", 1)
				continue
			}
			rep.Stat("axfr.count", 1)
			check.Observe(obs)
		}
	}
}

// SignednessChecker evaluates I10: a signed zone must never be served or
// transferred unsigned. It latches "signed" on the first fully-signed transfer
// and only then asserts — so it is false-positive-free (a zone still completing
// its first sign at startup does not trip it).
type SignednessChecker struct {
	mu     sync.Mutex
	report *Report
	signed bool // latched: the zone has been observed signed at least once
}

// Observe feeds one transfer's signedness through I10.
func (c *SignednessChecker) Observe(obs SignednessObs) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if obs.HasDNSKEY && obs.HasRRSIG {
		c.signed = true
		c.report.Stat("i10.signed-ok", 1)
		return
	}
	if !c.signed {
		// Not yet confirmed signed — don't assert (startup / first-sign in
		// progress). Counted so a run that never latches is visible.
		c.report.Stat("i10.unsigned-before-latch", 1)
		return
	}
	// Previously served signed, now transferred unsigned: the reload window.
	c.report.Violate("I10",
		"zone was served signed, then transferred UNSIGNED (missing DNSKEY/RRSIG) — reload re-sign window",
		fmt.Sprintf("serial=%d hasDNSKEY=%v hasRRSIG=%v", obs.Serial, obs.HasDNSKEY, obs.HasRRSIG))
}

// EverSigned reports whether the zone was observed signed at least once.
func (c *SignednessChecker) EverSigned() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.signed
}
