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

	ReloadCapable  bool // CapZoneReload probed available (gates the reload actor)
	DeclaredSigned bool // provisioned signed → surface "never observed signed" as a setup miss

	ReloadCadence time.Duration
	AxfrCadence   time.Duration
	QueryCadence  time.Duration // +dnssec query-signedness observer cadence
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
	if cfg.QueryCadence <= 0 {
		cfg.QueryCadence = 500 * time.Millisecond
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

	// AXFR signedness observer (pure DNS) → I10 latch rule.
	wg.Add(1)
	go func() { defer wg.Done(); runSignednessObserver(runCtx, cfg, check, rep) }()

	// Query signedness observer (pure DNS, +dnssec) → I10 query-vs-AXFR
	// cross-check. The tdns server can ephemerally sign query answers on the
	// fly, so a broken zone may answer queries SIGNED while its AXFR is UNSIGNED;
	// that divergence is what the AXFR-only latch cannot see.
	wg.Add(1)
	go func() { defer wg.Done(); runQuerySignednessObserver(runCtx, cfg, check, rep) }()

	wg.Wait()

	// I10 query-vs-AXFR cross-check: a zone that answered +dnssec queries signed
	// while its AXFR was only ever unsigned is masking a signing failure — the
	// AXFR-only latch never latches, so it would otherwise skip this as a false
	// clean. This must run before the skip decision below.
	check.CrossCheckSignedness()

	// A declared-signed zone we never once saw signed by EITHER stream means the
	// test could not run its invariant (e.g. signing genuinely failed on the
	// server) — report it as a skip, never as a clean pass. If the query stream
	// DID see it signed while the AXFR did not, CrossCheckSignedness already
	// raised the masked-failure violation above, so we do not also skip.
	if cfg.DeclaredSigned && !check.EverSigned() && !check.QueryEverSigned() {
		rep.Skip("I10", "zone was never observed signed (AXFR or query) — signing may have failed on the server; I10 could not run")
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

// runQuerySignednessObserver sends a +dnssec apex-SOA query each cadence and
// feeds the result to the I10 checker's query stream. This is the second
// signedness signal: the server can ephemerally sign query answers on the fly,
// so a broken zone can answer queries SIGNED while its AXFR is UNSIGNED. The
// divergence between the two streams — not the AXFR alone — is the
// masked-signing-failure signal the AXFR-only latch misses.
func runQuerySignednessObserver(ctx context.Context, cfg ReloadConfig, check *SignednessChecker, rep *Report) {
	t := time.NewTicker(cfg.QueryCadence)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			obs, err := queryApexSignedness(ctx, cfg.DnsServer, cfg.Zone)
			if err != nil {
				rep.Stat("query.errors", 1)
				continue
			}
			rep.Stat("query.count", 1)
			check.ObserveQuery(obs)
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
	signed bool // latched: an AXFR was observed fully signed at least once

	querySigned  bool // latched: a +dnssec query was observed signed at least once
	axfrUnsigned bool // an AXFR was observed unsigned at least once
}

// Observe feeds one transfer's signedness through I10 (the AXFR latch rule).
func (c *SignednessChecker) Observe(obs SignednessObs) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if obs.HasDNSKEY && obs.HasRRSIG {
		c.signed = true
		c.report.Stat("i10.signed-ok", 1)
		return
	}
	// This transfer is not fully signed. Record that fact for the end-of-run
	// query-vs-AXFR cross-check regardless of the latch state.
	c.axfrUnsigned = true
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

// ObserveQuery feeds one +dnssec query's signedness through I10's query stream.
// It only latches whether the zone was ever seen signed by a query; the
// divergence assertion is deferred to CrossCheckSignedness (end of run) so it
// cannot false-positive on a transient startup first-sign window.
func (c *SignednessChecker) ObserveQuery(obs QuerySignednessObs) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if obs.HasRRSIG {
		c.querySigned = true
		c.report.Stat("i10.query-signed", 1)
		return
	}
	c.report.Stat("i10.query-unsigned", 1)
}

// CrossCheckSignedness applies the query-vs-AXFR divergence rule at end of run:
// if the zone answered +dnssec queries SIGNED (RRSIG(SOA) present) yet its AXFR
// was only ever UNSIGNED (never a stored DNSKEY/RRSIG), the server is masking a
// signing failure — it ephemerally signs query answers while transferring the
// zone unsigned. This is exactly the case the AXFR-only latch cannot see: it
// never latches, so it would otherwise skip as a false clean.
//
// It is false-positive-free. A genuinely-unsigned zone answers queries UNSIGNED
// too (querySigned stays false → no assert). A healthy signed zone latches its
// AXFR signed (signed becomes true → no assert; the reload-window latch rule
// governs it, and any transient startup first-sign window resolves into a
// signed AXFR). Only the "query signed AND AXFR never once signed" contradiction
// — which no timing window can explain — trips it.
func (c *SignednessChecker) CrossCheckSignedness() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.querySigned && !c.signed && c.axfrUnsigned {
		c.report.Violate("I10",
			"query-signed but AXFR transferred unsigned — masked signing failure (server ephemerally signs query answers while the stored zone is unsigned)",
			"a +dnssec query returned RRSIG(SOA) but no AXFR in the run ever carried DNSKEY/RRSIG")
	}
}

// EverSigned reports whether an AXFR observed the zone signed at least once.
func (c *SignednessChecker) EverSigned() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.signed
}

// QueryEverSigned reports whether a +dnssec query observed the zone signed at
// least once.
func (c *SignednessChecker) QueryEverSigned() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.querySigned
}
