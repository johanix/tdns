/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// johanix/tdns#981 review: the contract for the options of a refresh's incoming
// zone. They are a copy of the served zone's as of the start of the refresh, a
// callback may read and write them, and they are discarded with the zone. An
// option to decide for good is set with SetRuntimeOption on the served zone.

// A callback's write to the incoming zone's options, in place or through
// SetOption, races with no reader of the served zone and does not reach it. (The
// map was once the served zone's own: a write into it met the readers that hold
// no lock, and was lost whenever a store on the served zone came first.) The
// transfer path runs through a running engine with readers on the served zone;
// the file path builds its incoming zone on its own and is run directly.
func TestACallbackWriteToTheIncomingOptionsRacesNothingAndReachesNoServedZone(t *testing.T) {
	writes := func(_, incoming *ZoneData) {
		incoming.Options[OptFrozen] = true
		incoming.SetOption(OptInlineSigning, true)
	}

	t.Run("transfer", func(t *testing.T) {
		kdb := asDerivedApp(t, derivedSignerApp)
		registerTestOriginationRuleApp(t, derivedSignerApp)
		prepare := func(zd *ZoneData) { zd.OnZonePreRefresh = append(zd.OnZonePreRefresh, writes) }
		up := startRelayUpstream(t, 40)
		z := startRelayedZone(t, kdb, up, map[ZoneOption]bool{OptFoldCase: true}, prepare)

		stop := readOptionsUntil(t, z.zd)
		const rounds = 10
		for i := 0; i < rounds; i++ {
			up.publish(t, uint32(41+i))
			z.notified(t)
		}
		stop()
		if optionOn(z.zd, OptFrozen) || optionOn(z.zd, OptInlineSigning) {
			t.Fatalf("what the callback wrote to the incoming zone's options reached the served zone: %v", z.zd.OptionsSnapshot())
		}
		if !optionOn(z.zd, OptFoldCase) {
			t.Fatal("an option the zone had was lost")
		}
	})

	t.Run("file", func(t *testing.T) {
		zd := reloadZone(t, newTestKeyDB(t), reloadBase)
		zd.OnZonePreRefresh = append(zd.OnZonePreRefresh, writes)
		stop := readOptionsUntil(t, zd)
		for i := 0; i < 10; i++ {
			operatorEdit(t, zd, reloadBase+"more.example.\t3600\tIN\tA\t192.0.2."+itoa(i+1)+"\n")
			if _, err := zd.FetchFromFile(context.Background(), false, false, true, nil); err != nil {
				stop()
				t.Fatalf("FetchFromFile: %v", err)
			}
		}
		stop()
		if optionOn(zd, OptFrozen) || optionOn(zd, OptInlineSigning) {
			t.Fatalf("what the callback wrote to the incoming zone's options reached the served zone: %v", zd.OptionsSnapshot())
		}
		if !optionOn(zd, OptAllowUpdates) {
			t.Fatal("an option the zone had was lost")
		}
	})
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

// A zone an OnZonePreRefresh callback makes a signer, refreshed by a delta, has
// none of its owners signed: the scoped signing pass of an IXFR refresh is for
// a zone that already signed what the delta extends, and it is asked when the
// refresh begins, which is when the delta's base is taken. Its owners the delta
// never touched are unsigned in that base, and a signed apex over unsigned
// RRsets does not validate. The callback makes the zone a signer the way a
// derived app does, with SetRuntimeOption on the served zone, which takes
// effect before the refresh is adopted.
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
	zd.OnZonePreRefresh = append(zd.OnZonePreRefresh, func(served, _ *ZoneData) {
		served.SetRuntimeOption(OptInlineSigning, true)
	})

	// The refresh must be a delta: a full zone takes the full pass anyway.
	if outcome, _, err := zd.ixfrTransferIn(context.Background(), zd.Upstreams[0], base, &Config{}); err != nil || outcome != ixfrDelta {
		t.Fatalf("precondition: the primary answered %v (err %v), want a delta", outcome, err)
	}
	if _, err := zd.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{}); err != nil {
		t.Fatalf("FetchFromUpstream: %v", err)
	}
	if !optionOn(zd, OptInlineSigning) {
		t.Fatal("the callback's option did not take effect")
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

// A zone that signed when the refresh began keeps the scoped pass: the owners a
// delta did not touch are not signed again. The owner added sorts last, so that
// the NSEC chain only re-links its neighbours, www.example. and the apex, and
// ns.example. is left alone.
func TestAnIxfrRefreshOfASigningZoneSignsOnlyWhatTheDeltaTouched(t *testing.T) {
	authApp(t)
	pzd, addr, stop := ixfrTestPrimary(t, ixApplyZone)
	defer stop()
	base := pzd.publishedSnapshot().Serial
	Zones.Set("example.", pzd)
	t.Cleanup(func() { Zones.Remove("example.") })
	stageAndPublish(t, pzd, stageAddA(t, pzd, "zz.example.", "10.1.0.1"))
	Zones.Remove("example.")

	zd := ixSigningSecondary(t, ixApplyZone)
	zd.Upstreams = []PeerConf{{Addr: addr}}
	zd.IncomingSerial, zd.CurrentSerial = base, base
	untouched := getOwnerFrom(zd.publishedSnapshot(), "ns.example.")
	if untouched == nil {
		t.Fatal("precondition: ns.example. is not published")
	}
	before := untouched.RRtypes
	if outcome, _, err := zd.ixfrTransferIn(context.Background(), zd.Upstreams[0], base, &Config{}); err != nil || outcome != ixfrDelta {
		t.Fatalf("precondition: the primary answered %v (err %v), want a delta", outcome, err)
	}

	if _, err := zd.FetchFromUpstream(context.Background(), false, false, false, nil, &Config{}); err != nil {
		t.Fatalf("FetchFromUpstream: %v", err)
	}
	after := getOwnerFrom(zd.publishedSnapshot(), "ns.example.")
	if after == nil || after.RRtypes != before {
		t.Fatal("an owner the delta never touched was signed again: the scoped pass was lost for a zone that already signed")
	}
	if od := getOwnerFrom(zd.publishedSnapshot(), "zz.example."); od == nil ||
		len(od.RRtypes.GetOnlyRRSet(dns.TypeA).RRSIGs) == 0 {
		t.Fatal("the owner the delta touched is not signed")
	}
}

// A signing secondary that is switched off keeps in its snapshot the signatures
// it made, and a delta is applied onto that snapshot. If the zone is a signer
// again when the delta is adopted (a callback's SetRuntimeOption), the RRset the
// delta changed still carries the old signature, which covers its previous
// contents: it must be signed again, and signed again for real, not kept as
// "already signed" because the key matches and no renewal is due. The refresh
// began with the zone not signing, so it is not the scoped pass, and the full
// pass that takes its place must still force what the delta touched. The check
// is cryptographic: the signature published must verify against the records
// published under it.
func TestAnIxfrRefreshOfAZoneSwitchedOffAndOnSignsWhatTheDeltaChangedAgain(t *testing.T) {
	zd := ixSigningSecondary(t, ixResignZone)
	assertPublishedAddresses(t, zd, "www.example.", []string{"10.0.0.3", "10.0.0.4"})
	assertPublishedRRsetVerifies(t, zd, "www.example.", dns.TypeA)

	zd.SetRuntimeOption(OptInlineSigning, false) // switched off; the snapshot is as it was
	incoming := newTransferScratchZone(zd)       // the refresh begins: no signer
	delta := ixDeltaStream(t, 7, 8, nil, []dns.RR{ixA(t, "www.example.", "10.0.0.5")})
	if err := zd.applyIxfrToScratch(&incoming, delta); err != nil {
		t.Fatalf("applyIxfrToScratch refused the delta: %v", err)
	}
	zd.SetRuntimeOption(OptInlineSigning, true) // the callback: a signer again
	zd.mu.Lock()
	err := zd.applyRefreshReplacementLocked(&incoming, nil, false, false)
	zd.mu.Unlock()
	if err != nil {
		t.Fatalf("applyRefreshReplacementLocked: %v", err)
	}

	assertPublishedAddresses(t, zd, "www.example.", []string{"10.0.0.3", "10.0.0.4", "10.0.0.5"})
	assertPublishedRRsetVerifies(t, zd, "www.example.", dns.TypeA)
}

// assertEveryPublishedRRsetVerifies checks every RRset of every owner the zone
// publishes against the zone's own published DNSKEYs: each must carry a
// signature, and the signature must cover the records published under it.
func assertEveryPublishedRRsetVerifies(t *testing.T, zd *ZoneData) {
	t.Helper()
	snap := zd.publishedSnapshot()
	if snap == nil {
		t.Fatal("no published snapshot")
	}
	for name, od := range snap.Data {
		if od == nil {
			continue
		}
		for _, rrt := range od.RRtypes.Keys() {
			assertPublishedRRsetVerifies(t, zd, name, rrt)
		}
	}
}

// The scoped signing pass of an IXFR refresh signs the owners the delta
// touched and the apex, and shares every other owner with the snapshot the
// delta was applied onto. That is only right if the snapshot's other owners
// carry signatures already. A signing zone can serve a snapshot that does not:
// its full pass could not run (the policy was not bound yet, or the publish was
// refused) and the zone kept, or published, unsigned content. A delta applied
// onto that snapshot must take the full pass, and every owner must verify after
// the publish, not only the ones the delta touched.
func TestAnIxfrDeltaOnASnapshotThatWasNeverSignedSignsEveryOwner(t *testing.T) {
	// A secondary with keys and a policy of its own, serving unsigned content,
	// signing switched off.
	newZone := func(t *testing.T) (*ZoneData, *DnssecPolicy) {
		authApp(t)
		zd := ixBase(t, ixResignZone)
		zd.ZoneType = Secondary
		Zones.Set(zd.ZoneName, zd)
		t.Cleanup(func() { Zones.Remove(zd.ZoneName) })
		makeZoneSigning(t, zd)
		zd.Options[OptOnlineSigning] = false
		return zd, zd.DnssecPolicy
	}
	// A delta from serial `from`, adding an address to www.example., adopted the
	// way a refresh adopts it: the incoming zone is built when the refresh begins.
	adoptDelta := func(t *testing.T, zd *ZoneData, from, to uint32) {
		t.Helper()
		zd.IncomingSerial, zd.CurrentSerial = from, from
		incoming := newTransferScratchZone(zd)
		delta := ixDeltaStream(t, from, to, nil, []dns.RR{ixA(t, "www.example.", "10.0.0.5")})
		if err := zd.applyIxfrToScratch(&incoming, delta); err != nil {
			t.Fatalf("applyIxfrToScratch refused the delta: %v", err)
		}
		zd.mu.Lock()
		err := zd.applyRefreshReplacementLocked(&incoming, nil, false, false)
		zd.mu.Unlock()
		if err != nil {
			t.Fatalf("applyRefreshReplacementLocked: %v", err)
		}
	}

	t.Run("the full replacement could not be signed yet", func(t *testing.T) {
		zd, policy := newZone(t)
		zd.DnssecPolicy = nil // not bound yet: the publish cannot sign
		zd.SetRuntimeOption(OptInlineSigning, true)

		full := &ZoneData{ZoneName: "example.", ZoneStore: MapZone, ZoneType: Secondary, Logger: discardLogger()}
		text := strings.Replace(ixResignZone, "hostmaster.example. 7 ", "hostmaster.example. 8 ", 1) +
			"extra.example.\t3600\tIN\tA\t10.0.0.8\n"
		if _, _, err := full.ReadZoneData(text, true); err != nil {
			t.Fatalf("ReadZoneData: %v", err)
		}
		zd.mu.Lock()
		err := zd.applyRefreshReplacementLocked(full, nil, false, false)
		zd.mu.Unlock()
		if err != nil {
			t.Fatalf("the full replacement: %v", err)
		}
		if soa := getOwnerFrom(zd.publishedSnapshot(), "example.").RRtypes.GetOnlyRRSet(dns.TypeSOA); len(soa.RRSIGs) != 0 {
			t.Fatal("precondition: the zone published signatures although its policy was not bound")
		}

		zd.DnssecPolicy = policy // bound now: the zone can sign
		adoptDelta(t, zd, 8, 9)
		assertPublishedAddresses(t, zd, "www.example.", []string{"10.0.0.3", "10.0.0.4", "10.0.0.5"})
		assertEveryPublishedRRsetVerifies(t, zd)
	})

	t.Run("signing was switched on over an unsigned snapshot", func(t *testing.T) {
		zd, _ := newZone(t)
		zd.SetRuntimeOption(OptInlineSigning, true) // no publish has followed: the snapshot is as it was
		adoptDelta(t, zd, 7, 8)
		assertPublishedAddresses(t, zd, "www.example.", []string{"10.0.0.3", "10.0.0.4", "10.0.0.5"})
		assertEveryPublishedRRsetVerifies(t, zd)
	})
}

// The dynamic RRsets are collected before the callbacks run. A callback that
// then says dont-publish-key for the zone (SetRuntimeOption on the served zone)
// has the options the zone has when the refresh is adopted rule: the SIG(0) KEY
// that was collected is not merged in. A KEY the replacement carries is its own
// content and stays.
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
	dontPublish := func(served, _ *ZoneData) { served.SetRuntimeOption(OptDontPublishKey, true) }
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
