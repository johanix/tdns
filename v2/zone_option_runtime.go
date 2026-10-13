/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

// Run-time zone options.
//
// A zone's options come from its configuration, and a config update (config
// reload-zones, a zone reload, a refresher that carries the configuration)
// replaces them with the configured ones: that is what lets an edit that
// removes an option take effect. A derived app may also decide an option by
// itself while it runs, from what the zone says rather than from what the
// operator wrote. One that signs some of its zones and relays the others
// switches inline-signing on for exactly the zones it signs, at a refresh.
// Such an option is in no configuration, so a config update used to take it
// away until the app set it again, which it does at the next transfer and not
// before. In between the zone was, by its options, one the daemon does not
// sign: with the origination rule (zoneMayOriginateContent) that is a zone
// whose serial mirrors its upstream's and that takes no change of the
// daemon's own (johanix/tdns-mp#144).
//
// SetRuntimeOption records such an option beside the configured ones, and
// the config update lays the record over what it was given.

// SetRuntimeOption sets an option the daemon decides by itself while it runs.
// It takes effect at once, and it stays as set across a config update until
// the daemon sets it otherwise: for that option the daemon's word replaces
// the configuration's, on or off.
//
// For a derived app's refresh callbacks (OnZonePreRefresh), on the zone that
// is served, not on the incoming one. It takes the zone's lock, which those
// callbacks run without.
//
// The zone gets a new options map with the option set; the map it had is not
// written to. That map is read without the zone's lock all over the query
// and refresh paths, and the incoming zone of a refresh in progress holds it
// too, so a write into it could meet a read of it. An option that already
// reads as asked for leaves the map alone.
func (zd *ZoneData) SetRuntimeOption(opt ZoneOption, on bool) {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.runtimeOptions == nil {
		zd.runtimeOptions = map[ZoneOption]bool{}
	}
	zd.runtimeOptions[opt] = on
	if zd.Options[opt] == on {
		return
	}
	next := make(map[ZoneOption]bool, len(zd.Options)+1)
	for o, v := range zd.Options {
		next[o] = v
	}
	next[opt] = on
	zd.Options = next
}

// withRuntimeOptionsLocked is opts with the zone's run-time options laid over
// them: what a config update installs in place of the bare configured set.
// opts itself is not changed, it may be the caller's; a copy is returned when
// anything differs. The caller holds zd.mu.
func (zd *ZoneData) withRuntimeOptionsLocked(opts map[ZoneOption]bool) map[ZoneOption]bool {
	differs := false
	for opt, on := range zd.runtimeOptions {
		if opts[opt] != on {
			differs = true
			break
		}
	}
	if !differs {
		return opts
	}
	out := make(map[ZoneOption]bool, len(opts)+len(zd.runtimeOptions))
	for opt, on := range opts {
		out[opt] = on
	}
	for opt, on := range zd.runtimeOptions {
		out[opt] = on
	}
	return out
}
