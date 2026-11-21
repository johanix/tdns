/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import "maps"

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
//
// Reading the options. The map a zone has is never written to once the zone
// has it: a config update replaces it whole (setOptionsLocked), and a store of
// one option, SetRuntimeOption or SetOption or the dirty flag, gives the zone
// a new map with that option set (setOptionLocked). A reader that got hold of
// a map can therefore go on reading it, whatever is stored after. Replacing
// it is still a write to the zone's Options field, and a reader's look at that
// field is a read of it, so a reader that holds no lock and a replacement are
// a data race however the map was copied (johanix/tdns#981). Option and
// OptionsSnapshot are the way to the field for a reader, and setOptionsLocked
// the way for a writer; they meet on the zone's optionsMu.
//
// optionsMu is a leaf lock. It is held only across the read or the write of
// the field, and nothing else is acquired while it is. A reader may therefore
// call Option holding zd.mu, or any other lock, or none: it never waits for
// one. A writer holds zd.mu, as every replacement does, and takes optionsMu
// inside it; that is the only order the two are ever taken in.
//
// The incoming zone of a refresh. A refresh builds a zone to receive the new
// content, and the OnZonePreRefresh callbacks get it beside the served zone.
// Its options are a copy of the served zone's as of the start of the refresh
// (optionsForIncoming). A callback may read them and write them, in place or
// through SetOption, and they are discarded with the zone: nothing a callback
// writes there reaches the served zone. (It was once the served zone's own map,
// which is read without a lock and is replaced at every store, so a write into
// it was a data race, and was lost whenever a store on the served zone came
// between the start of the refresh and the write.) An option a callback decides
// for good is set with SetRuntimeOption on the served zone.

// SetRuntimeOption sets an option the daemon decides by itself while it runs.
// It takes effect at once, and it stays as set across a config update until
// the daemon sets it otherwise: for that option the daemon's word replaces
// the configuration's, on or off.
//
// It is how a derived app's refresh callback (OnZonePreRefresh) decides an
// option for good: on the zone that is served, the callback's first argument,
// at once. An option written to the incoming zone's options is discarded with
// that zone. It takes the zone's lock, which those callbacks run without.
//
// The zone gets a new options map with the option set; the map it had is not
// written to. That map is read without the zone's lock all over the query
// and refresh paths, so a write into it could meet a read of it. An option
// that already reads as asked for leaves the map alone.
func (zd *ZoneData) SetRuntimeOption(opt ZoneOption, on bool) {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.setRuntimeOptionLocked(opt, on)
}

// setRuntimeOptionLocked is SetRuntimeOption for a caller that holds zd.mu.
func (zd *ZoneData) setRuntimeOptionLocked(opt ZoneOption, on bool) {
	if zd.runtimeOptions == nil {
		zd.runtimeOptions = map[ZoneOption]bool{}
	}
	zd.runtimeOptions[opt] = on
	zd.setOptionLocked(opt, on)
}

// setOptionLocked stores one option, by giving the zone a new options map with
// it set; the map the zone had is left as it was. A store into that map would
// meet every reader that indexes it, or ranges over a snapshot of it, and a
// concurrent map read and write stops the process. An option that already
// reads as asked for leaves the map alone, and a zone with no map gets one.
// The caller holds zd.mu, and with it every other writer of the field is out:
// the plain reads of the field here are safe for that reason.
func (zd *ZoneData) setOptionLocked(opt ZoneOption, on bool) {
	if zd.Options[opt] == on {
		return
	}
	next := make(map[ZoneOption]bool, len(zd.Options)+1)
	for o, v := range zd.Options {
		next[o] = v
	}
	next[opt] = on
	zd.setOptionsLocked(next)
}

// setOptionsLocked replaces the zone's options. It is the one way the field is
// replaced on a zone that is live: the caller holds zd.mu, and the lock a
// reader that holds no other takes is held across the write.
func (zd *ZoneData) setOptionsLocked(opts map[ZoneOption]bool) {
	zd.optionsMu.Lock()
	zd.Options = opts
	zd.optionsMu.Unlock()
}

// Option reports whether a zone option is on, for the caller that holds
// nothing or holds any lock but optionsMu: it takes no lock of the zone's but
// that one, held for the read alone.
func (zd *ZoneData) Option(opt ZoneOption) bool {
	zd.optionsMu.RLock()
	on := zd.Options[opt]
	zd.optionsMu.RUnlock()
	return on
}

// OptionsSnapshot is the zone's options as they are now, for a caller that
// needs the set and not one option: to range over it, to hand it on, to
// ask several questions of one answer. The map is a copy and the caller's
// own, to write to if it likes: it changes nothing the zone reads. It is the
// options as of the call; a store that follows does not reach it. A zone with
// no options map gives nil.
//
// The zone's own map is not handed out because a caller that wrote it would
// meet every reader. It is not written to once installed, so it is copied
// outside the lock, which is held for the load of the field alone.
func (zd *ZoneData) OptionsSnapshot() map[ZoneOption]bool {
	return maps.Clone(zd.optionsMap())
}

// optionsMap is the zone's own options map, not a copy: the one load of the
// field that takes the lock a replacement is made under. The caller reads the
// map and does not write to it, nor hands it on; what it needs to keep or to
// change is a copy of it.
func (zd *ZoneData) optionsMap() map[ZoneOption]bool {
	zd.optionsMu.RLock()
	opts := zd.Options
	zd.optionsMu.RUnlock()
	return opts
}

// optionsForIncoming is what the incoming zone of a refresh is built with: a
// copy of the zone's options, for it to own and for the callbacks to write. The
// copy is not nil: a zone with no options gives an empty map, so that a
// callback may always write it.
func (zd *ZoneData) optionsForIncoming() map[ZoneOption]bool {
	own := maps.Clone(zd.optionsMap())
	if own == nil {
		own = map[ZoneOption]bool{}
	}
	return own
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
