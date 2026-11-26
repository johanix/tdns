/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Reloading the imrengine: stub and forward zones without a restart (#436).
 *
 * Before this, both were read exactly once: AddStub ran only inside the
 * !IsPrimed() branch of InitImrEngine and the forward table was built once
 * and never touched again, so adding an upstream -- or removing a stub that
 * pointed at a decommissioned server -- meant restarting the resolver and
 * throwing away its whole cache.
 *
 * Two properties make that safe to change:
 *
 *   - The table is IMMUTABLE once published. A reload validates and builds a
 *     complete new table and swaps one pointer; readers hold a snapshot for
 *     the duration of a query. Nothing mutates under a query in flight.
 *
 *   - Live state survives what did not change. A forward upstream whose
 *     configuration is untouched keeps its object -- its reachability
 *     counters, its unreachable flag, its DNS client -- and an untouched stub
 *     keeps its AuthServers, and with them their transport counters and
 *     address backoffs. Rebuilding everything on every reload would silently
 *     clear a DEGRADED that is still true, which teaches operators to
 *     distrust the flag.
 */
package tdns

import (
	"strings"
)

// applyImrEngineReload hands the configured imrengine: stub and forward zones
// to the running resolver and reports the diff, including which edited keys
// are NOT reloadable.
//
// It re-reads and strictly validates the imrengine: block itself rather than
// trusting what the caller left in conf.Imr, so that BOTH reload paths get
// the same gate. That is load-bearing on the full-config path: ParseConfig
// reports an unknown key as a WARNING, so a misspelled `forwrd:` decodes to
// an empty list, and applying that would delete every forward zone the
// resolver is running on -- the very wipe reloadImrEngineFromFile refuses on
// the SIGHUP path. Same reasoning for a mistyped `stubs:`, which would drop
// the stub zones and, with them, their veto over a `zone: .` forward.
//
// Nil-safe on every axis: an app with no resolver (or one that never got
// past InitImrEngine) reloads nothing and reports nothing.
func (conf *Config) applyImrEngineReload() (ImrZoneReloadResult, error) {
	imr := conf.Internal.ImrEngine
	if imr == nil {
		return ImrZoneReloadResult{}, nil
	}
	block, err := conf.reloadImrEngineFromFile()
	if err != nil {
		return ImrZoneReloadResult{}, err
	}
	if block == nil {
		// No config file to re-read (embedded use): take what is in memory.
		block = &conf.Imr
	}
	res, err := imr.ReloadZones(block.Stubs, block.Forward)
	if err != nil {
		return res, err
	}
	// Committed only now. A block that decodes is not necessarily one that
	// applies -- ReloadZones refuses trust-ad over a plaintext upstream, among
	// others -- and committing at decode time left conf.Imr describing zones
	// the resolver had just rejected.
	conf.Imr.Stubs = block.Stubs
	conf.Imr.Forward = block.Forward
	// Diffed against the block just read from the FILE, not conf.Imr: on the
	// zone-reload path conf.Imr still holds the boot values for everything
	// except stubs and forwards, so that comparison would compare the boot
	// config with itself and never report anything.
	res.RestartRequired = imr.RestartRequiredKeys(*block)
	if len(res.RestartRequired) > 0 {
		lgResolver.Warn("imrengine keys changed but are not reloadable; the resolver keeps running on the values it started with",
			"keys", strings.Join(res.RestartRequired, ", "))
	}
	return res, nil
}
