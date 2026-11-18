/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
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

// The options change with the data they describe. A refresh the zone refuses
// (an open transaction holds it, ErrRefreshHeld) is not adopted, so the
// options an OnZonePreRefresh callback set on the incoming zone are not the
// served zone's yet: work that runs before the hold clears would otherwise
// act under a role the served data does not have. Once the hold is gone and
// the refresh is adopted, they are.
func TestACallbackOptionIsNotTheServedZonesWhileTheRefreshIsRefusedUnderAHold(t *testing.T) {
	setsFrozen := func(_, incoming *ZoneData) { incoming.Options[OptFrozen] = true }

	t.Run("file", func(t *testing.T) {
		zd := reloadZone(t, newTestKeyDB(t), reloadBase)
		zd.OnZonePreRefresh = append(zd.OnZonePreRefresh, setsFrozen)
		id, err := zd.BeginTx(TxUrgent)
		if err != nil {
			t.Fatalf("BeginTx: %v", err)
		}
		operatorEdit(t, zd, reloadBase+"more.example.\t3600\tIN\tA\t192.0.2.9\n")
		if _, err := zd.FetchFromFile(context.Background(), false, false, true, nil); !errors.Is(err, ErrRefreshHeld) {
			t.Fatalf("a reload under a hold: err=%v, want ErrRefreshHeld", err)
		}
		if optionOn(zd, OptFrozen) {
			t.Fatal("the refused refresh changed the served zone's options")
		}
		if err := zd.CommitTx(id); err != nil {
			t.Fatalf("CommitTx: %v", err)
		}
		if _, err := zd.FetchFromFile(context.Background(), false, false, true, nil); err != nil {
			t.Fatalf("the reload after the hold: %v", err)
		}
		if !optionOn(zd, OptFrozen) {
			t.Fatal("the adopted refresh did not bring the option the callback set")
		}
	})

	t.Run("transfer", func(t *testing.T) {
		zd := ixSigningSecondary(t, ixApplyZone)
		zd.OnZonePreRefresh = append(zd.OnZonePreRefresh, setsFrozen)
		id, err := zd.BeginTx(TxUrgent)
		if err != nil {
			t.Fatalf("BeginTx: %v", err)
		}
		_, addr, stop := ixfrTestPrimary(t, ovUpstreamZone(20, srFresh))
		defer stop()
		zd.mu.Lock()
		zd.Upstreams = []PeerConf{{Addr: addr}}
		zd.mu.Unlock()
		if _, err := zd.FetchFromUpstream(context.Background(), false, false, true,
			zd.CollectDynamicRRs(&Config{}), &Config{}); !errors.Is(err, ErrRefreshHeld) {
			t.Fatalf("a refresh under a hold: err=%v, want ErrRefreshHeld", err)
		}
		if optionOn(zd, OptFrozen) {
			t.Fatal("the refused refresh changed the served zone's options")
		}
		if err := zd.CommitTx(id); err != nil {
			t.Fatalf("CommitTx: %v", err)
		}
		ovTransferFrom(t, zd, addr, true)
		if !optionOn(zd, OptFrozen) {
			t.Fatal("the adopted refresh did not bring the option the callback set")
		}
	})
}

// The same for a refusal that comes after the options were folded in: a zone
// file signed elsewhere that changed under the served serial is refused and
// the zone's state is put back (ErrSignedFileChangedUnderServedSerial), and
// the options with it. Adopted under a newer serial, it brings them.
func TestACallbackOptionIsNotKeptByARefusedReload(t *testing.T) {
	zd := reloadZone(t, newTestKeyDB(t), signedElsewhere("100", 'a'))
	zd.OnZonePreRefresh = append(zd.OnZonePreRefresh, func(_, incoming *ZoneData) {
		incoming.Options[OptFrozen] = true
	})

	operatorEdit(t, zd, signedElsewhere("100", 'b'))
	if _, err := zd.Refresh(context.Background(), false, false, false, &Config{}); !errors.Is(err, ErrSignedFileChangedUnderServedSerial) {
		t.Fatalf("a signed file changed under the served serial: reload error %v", err)
	}
	if optionOn(zd, OptFrozen) {
		t.Fatal("the refused reload left the option a callback set on the served zone")
	}
	if !optionOn(zd, OptAllowUpdates) {
		t.Fatal("putting the options back lost one the zone had")
	}

	operatorEdit(t, zd, signedElsewhere("101", 'b'))
	if _, err := zd.Refresh(context.Background(), false, false, false, &Config{}); err != nil {
		t.Fatalf("the reload under a newer serial: %v", err)
	}
	if !optionOn(zd, OptFrozen) || !optionOn(zd, OptAllowUpdates) {
		t.Fatalf("after the adopted reload the options are %v", zd.OptionsSnapshot())
	}
}

// A zone an OnZonePreRefresh callback makes a signer, refreshed by a delta, has
// none of its owners signed: the scoped signing pass of an IXFR refresh is for
// a zone that already signed what the delta extends. Its owners the delta never
// touched are unsigned in the snapshot the delta is applied to, and a signed
// apex over unsigned RRsets does not validate.
func TestAnIxfrRefreshThatMakesTheZoneASignerSignsEveryOwner(t *testing.T) {
	authApp(t)
	pzd, addr, stop := ixfrTestPrimary(t, ixApplyZone)
	defer stop()
	base := pzd.publishedSnapshot().Serial
	// A chain for the primary to serve a delta from (as TestIxfrInConvergesViaDelta).
	Zones.Set("example.", pzd)
	t.Cleanup(func() { Zones.Remove("example.") })
	stageAndPublish(t, pzd, stageAddA(t, pzd, "one.example.", "10.1.0.1"))
	stageAndPublish(t, pzd, stageAddA(t, pzd, "two.example.", "10.1.0.2"))
	Zones.Remove("example.")

	// An unsigned secondary that has keys and a policy but is no signer yet.
	zd := ixfrTestSecondary(t, ixApplyZone, addr, nil)
	zd.IncomingSerial, zd.CurrentSerial = base, base
	makeZoneSigning(t, zd)
	zd.Options[OptOnlineSigning] = false
	zd.OnZonePreRefresh = append(zd.OnZonePreRefresh, func(_, incoming *ZoneData) {
		incoming.Options[OptInlineSigning] = true
	})

	// The refresh must be a delta: a full zone takes the full pass anyway.
	if outcome, _, err := zd.ixfrTransferIn(context.Background(), zd.Upstreams[0], base, &Config{}); err != nil || outcome != ixfrDelta {
		t.Fatalf("precondition: the primary answered %v (err %v), want a delta", outcome, err)
	}
	if _, err := zd.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{}); err != nil {
		t.Fatalf("FetchFromUpstream: %v", err)
	}
	if !optionOn(zd, OptInlineSigning) {
		t.Fatal("the callback's option did not reach the zone")
	}

	snap := zd.publishedSnapshot()
	for _, name := range []string{"example.", "ns.example.", "www.example.", "one.example.", "two.example."} {
		od := getOwnerFrom(snap, name)
		if od == nil {
			t.Fatalf("%s is not in the published zone", name)
		}
		for _, rrt := range od.RRtypes.Keys() {
			if rs := od.RRtypes.GetOnlyRRSet(rrt); len(rs.RRSIGs) == 0 {
				t.Errorf("%s %s is published unsigned in a zone that signs", name, dns.TypeToString[rrt])
			}
		}
	}
}

// The dynamic RRsets are collected before the callbacks run. A callback that
// then says dont-publish-key for the zone has the adopted options rule: the
// SIG(0) KEY that was collected is not merged in. A KEY the replacement carries
// is its own content and stays.
func TestACollectedSig0KeyIsNotMergedOnceACallbackSaysDontPublishKey(t *testing.T) {
	keyText := func(b byte) string {
		return "example.\t3600\tIN\tKEY\t512 3 15 " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) + "\n"
	}
	collected := func(t *testing.T) []*core.RRset {
		return []*core.RRset{{
			Name: "example.", Class: dns.ClassINET, RRtype: dns.TypeKEY,
			RRs: []dns.RR{mustRR(t, keyText('c'))},
		}}
	}
	dontPublish := func(_, incoming *ZoneData) { incoming.Options[OptDontPublishKey] = true }
	keysServed := func(t *testing.T, zd *ZoneData) int {
		t.Helper()
		od := getOwnerFrom(zd.publishedSnapshot(), "example.")
		if od == nil {
			t.Fatal("the apex is not published")
		}
		return len(od.RRtypes.GetOnlyRRSet(dns.TypeKEY).RRs)
	}

	for _, tc := range []struct {
		name     string
		ownKey   bool
		callback bool
		want     int
	}{
		{"collected key, no callback", false, false, 1},
		{"collected key, callback says dont-publish-key", false, true, 0},
		{"own and collected key, no callback", true, false, 2},
		{"own and collected key, callback says dont-publish-key", true, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zd := reloadZone(t, newTestKeyDB(t), reloadBase)
			text := reloadBase
			if tc.ownKey {
				text += keyText('o')
			}
			if tc.callback {
				zd.OnZonePreRefresh = append(zd.OnZonePreRefresh, dontPublish)
			}
			operatorEdit(t, zd, text+"more.example.\t3600\tIN\tA\t192.0.2.9\n")
			if _, err := zd.FetchFromFile(context.Background(), false, false, true, collected(t)); err != nil {
				t.Fatalf("FetchFromFile: %v", err)
			}
			if got := keysServed(t, zd); got != tc.want {
				t.Fatalf("the apex serves %d KEY records, want %d", got, tc.want)
			}
		})
	}
}
