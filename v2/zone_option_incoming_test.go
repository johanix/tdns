/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"sync/atomic"
	"testing"
)

// johanix/tdns#981 review: a zone's options map is replaced whenever an option
// is stored, so the map the incoming zone of a refresh was built on is the
// served zone's only until the first store on the served zone. An option an
// OnZonePreRefresh callback sets on the incoming zone must reach the served
// zone all the same, whatever was stored on the served zone between the start
// of the refresh and the callback: `zone freeze` over the API does exactly
// that, and so does a config update.
//
// The callbacks below do what a callback may do: store on the served zone, and
// set an option on the incoming one, in place or through SetOption.

// incomingWrites are the ways a callback sets an option on the incoming zone.
var incomingWrites = map[string]func(incoming *ZoneData, opt ZoneOption, on bool){
	"in place":  func(incoming *ZoneData, opt ZoneOption, on bool) { incoming.Options[opt] = on },
	"SetOption": func(incoming *ZoneData, opt ZoneOption, on bool) { incoming.SetOption(opt, on) },
}

// A refresh through a running engine (the transfer path), in which the served
// zone changes first: its freeze must stay, and the callback's option must
// arrive beside it.
func TestAnOptionSetOnTheIncomingZoneReachesTheServedZoneAfterAServedChange(t *testing.T) {
	for name, write := range incomingWrites {
		t.Run(name, func(t *testing.T) {
			kdb := asDerivedApp(t, derivedSignerApp)
			registerTestOriginationRuleApp(t, derivedSignerApp)

			var armed atomic.Bool // set between refreshes, so only the refresh under test runs the callback
			prepare := func(zd *ZoneData) {
				zd.OnZonePreRefresh = append(zd.OnZonePreRefresh, func(served, incoming *ZoneData) {
					if !armed.Load() {
						return
					}
					served.SetOption(OptFrozen, true) // the served zone's map is replaced here
					write(incoming, OptInlineSigning, true)
					write(incoming, OptFoldCase, false) // a configured option the callback turns off
				})
			}
			up := startRelayUpstream(t, 40)
			z := startRelayedZone(t, kdb, up, map[ZoneOption]bool{OptFoldCase: true, OptAllowUpdates: true}, prepare)
			if optionOn(z.zd, OptInlineSigning) || optionOn(z.zd, OptFrozen) || !optionOn(z.zd, OptFoldCase) {
				t.Fatalf("before the refresh the options are %v", z.zd.OptionsSnapshot())
			}

			armed.Store(true)
			up.publish(t, 43)
			z.notified(t)

			if !optionOn(z.zd, OptInlineSigning) {
				t.Error("the option the callback set on the incoming zone did not reach the served zone")
			}
			if optionOn(z.zd, OptFoldCase) {
				t.Error("the option the callback turned off on the incoming zone is still on in the served zone")
			}
			if !optionOn(z.zd, OptFrozen) {
				t.Error("the freeze stored on the served zone during the refresh was lost")
			}
			if !optionOn(z.zd, OptAllowUpdates) {
				t.Error("an option the callback left alone was lost")
			}
		})
	}
}

// A callback that stores on the served zone and does not touch the incoming
// one changes nothing else: what the refresh handed over is not laid back over
// the served zone's options.
func TestACallbackThatLeavesTheIncomingOptionsAloneUndoesNoServedChange(t *testing.T) {
	kdb := asDerivedApp(t, derivedSignerApp)
	registerTestOriginationRuleApp(t, derivedSignerApp)

	var armed atomic.Bool
	prepare := func(zd *ZoneData) {
		zd.OnZonePreRefresh = append(zd.OnZonePreRefresh, func(served, _ *ZoneData) {
			if armed.Load() {
				served.SetOption(OptFrozen, true)
				served.SetOption(OptAllowUpdates, false)
			}
		})
	}
	up := startRelayUpstream(t, 40)
	z := startRelayedZone(t, kdb, up, map[ZoneOption]bool{OptAllowUpdates: true}, prepare)

	armed.Store(true)
	up.publish(t, 43)
	z.notified(t)

	if !optionOn(z.zd, OptFrozen) || optionOn(z.zd, OptAllowUpdates) {
		t.Fatalf("after the refresh the options are %v, want the two stores on the served zone kept", z.zd.OptionsSnapshot())
	}
}

// The same on the file path, which builds its incoming zone on its own.
func TestAnOptionSetOnTheIncomingZoneReachesTheServedZoneFromAFile(t *testing.T) {
	for name, write := range incomingWrites {
		t.Run(name, func(t *testing.T) {
			kdb := newTestKeyDB(t)
			zd, _ := firstLoadFileZone(t, kdb, reloadBase)
			zd.Options = map[ZoneOption]bool{OptFoldCase: true}
			zd.OnZonePreRefresh = append(zd.OnZonePreRefresh, func(served, incoming *ZoneData) {
				served.SetOption(OptFrozen, true)
				write(incoming, OptInlineSigning, true)
				write(incoming, OptFoldCase, false)
			})

			if _, err := zd.FetchFromFile(context.Background(), false, false, true, nil); err != nil {
				t.Fatalf("FetchFromFile: %v", err)
			}

			if !optionOn(zd, OptInlineSigning) {
				t.Error("the option the callback set on the incoming zone did not reach the served zone")
			}
			if optionOn(zd, OptFoldCase) {
				t.Error("the option the callback turned off on the incoming zone is still on in the served zone")
			}
			if !optionOn(zd, OptFrozen) {
				t.Error("the freeze stored on the served zone during the refresh was lost")
			}
		})
	}
}

// What the callbacks write into the incoming zone's options is not written
// into the map the served zone reads: that map is read without a lock, and a
// write into it is a data race whatever the writer meant.
func TestTheIncomingZoneDoesNotShareTheServedZonesOptionsMap(t *testing.T) {
	served := map[ZoneOption]bool{OptAllowUpdates: true}
	zd := &ZoneData{ZoneName: "example.", Options: served}

	incoming := newTransferScratchZone(zd)
	incoming.Options[OptInlineSigning] = true
	if served[OptInlineSigning] || zd.Option(OptInlineSigning) {
		t.Fatal("a write into the incoming zone's options reached the served zone's map")
	}
	if !incoming.Options[OptAllowUpdates] {
		t.Fatal("the incoming zone does not start from the served zone's options")
	}

	// A zone with no options map still hands over one a callback may write.
	bare := newTransferScratchZone(&ZoneData{ZoneName: "example."})
	bare.Options[OptInlineSigning] = true
}
