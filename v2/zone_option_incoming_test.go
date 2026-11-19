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
// signature, and the signature must cover the records published under it. What
// is not the zone's own data is left out, as signing leaves it: the names below
// a delegation cut, and at the cut everything but the DS.
func assertEveryPublishedRRsetVerifies(t *testing.T, zd *ZoneData) {
	t.Helper()
	snap := zd.publishedSnapshot()
	if snap == nil {
		t.Fatal("no published snapshot")
	}
	var cuts []string
	for name, od := range snap.Data {
		if od == nil || core.EqualNames(name, zd.ZoneName) {
			continue
		}
		if rs := od.RRtypes.GetOnlyRRSet(dns.TypeNS); len(rs.RRs) > 0 {
			cuts = append(cuts, name)
		}
	}
	for name, od := range snap.Data {
		if od == nil {
			continue
		}
		occluded, atCut := false, false
		for _, cut := range cuts {
			switch {
			case core.EqualNames(name, cut):
				atCut = true
			case dns.IsSubDomain(cut, name):
				occluded = true
			}
		}
		if occluded {
			continue
		}
		for _, rrt := range od.RRtypes.Keys() {
			if atCut && rrt != dns.TypeDS {
				continue
			}
			assertPublishedRRsetVerifies(t, zd, name, rrt)
		}
	}
}

// The signing passes of an IXFR adoption, row by row (the table in
// applyRefreshReplacementLocked): what is signed is base+delta, so what the
// pass may assume is whether the BASE, the snapshot the delta was built on, was
// signed throughout, however the zone was signed before and whatever was
// published between the base being read and the delta being adopted. After each
// adoption every RRset of every owner must verify against the zone's published
// DNSKEYs, and the address the delta added must be there.
func TestAnIxfrAdoptionSignsByTheStateOfItsBase(t *testing.T) {
	const www = "www.example."
	wantAddrs := []string{"10.0.0.3", "10.0.0.4", "10.0.0.5"}

	// A secondary that serves unsigned content, has keys and a policy of its
	// own, and is no signer yet.
	unsigned := func(t *testing.T) (*ZoneData, *DnssecPolicy) {
		authApp(t)
		zd := ixBase(t, ixResignZone)
		zd.ZoneType = Secondary
		Zones.Set(zd.ZoneName, zd)
		t.Cleanup(func() { Zones.Remove(zd.ZoneName) })
		makeZoneSigning(t, zd)
		zd.Options[OptOnlineSigning] = false
		zd.IncomingSerial, zd.CurrentSerial = 7, 7
		return zd, zd.DnssecPolicy
	}
	// The same, a signer with a full pass published.
	signed := func(t *testing.T) *ZoneData {
		zd := ixSigningSecondary(t, ixResignZone)
		zd.IncomingSerial, zd.CurrentSerial = 7, 7
		return zd
	}
	// A refresh begins and its delta, from serial 7, is built on the snapshot
	// served now: the BASE.
	capture := func(t *testing.T, zd *ZoneData) *ZoneData {
		t.Helper()
		incoming := newTransferScratchZone(zd)
		delta := ixDeltaStream(t, 7, 8, nil, []dns.RR{ixA(t, www, "10.0.0.5")})
		if err := zd.applyIxfrToScratch(&incoming, delta); err != nil {
			t.Fatalf("applyIxfrToScratch refused the delta: %v", err)
		}
		return &incoming
	}
	adopt := func(t *testing.T, zd, incoming *ZoneData) {
		t.Helper()
		zd.mu.Lock()
		err := zd.applyRefreshReplacementLocked(incoming, nil, false, false)
		zd.mu.Unlock()
		if err != nil {
			t.Fatalf("applyRefreshReplacementLocked: %v", err)
		}
		assertPublishedAddresses(t, zd, www, wantAddrs)
		assertEveryPublishedRRsetVerifies(t, zd)
		// And it is recorded: the next delta onto this snapshot may take the
		// scoped pass instead of the full one.
		if !zd.publishedSnapshot().signed {
			t.Error("the adopted snapshot is signed throughout but not marked so: the next delta would take the full pass")
		}
	}
	// A publish that runs the full pass, as the one after a policy bind or a
	// forced re-sign does: the snapshot it installs is signed throughout.
	fullPassPublish := func(t *testing.T, zd *ZoneData) {
		t.Helper()
		zd.mu.Lock()
		zd.ensureWorkingSet()
		zd.wsNeedsFullSign = true
		zd.publishWorkingSetLocked(zd.generation.Load(), true)
		zd.mu.Unlock()
	}
	// A publish that cannot sign, because the zone is not a signer: the
	// snapshot it installs is unsigned, whatever signatures its RRsets still hold.
	unsignedPublish := func(t *testing.T, zd *ZoneData) {
		t.Helper()
		zd.mu.Lock()
		zd.ensureWorkingSet()
		zd.stageRRsetLocked("t.example.", core.RRset{Name: "t.example.", Class: dns.ClassINET,
			RRtype: dns.TypeTXT, RRs: []dns.RR{mustRR(t, `t.example. 3600 IN TXT "unsigned"`)}})
		zd.publishWorkingSetLocked(zd.generation.Load(), true)
		zd.mu.Unlock()
	}

	t.Run("base unsigned: the full replacement could not be signed yet", func(t *testing.T) {
		zd, policy := unsigned(t)
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

		zd.IncomingSerial, zd.CurrentSerial = 8, 8
		incoming := newTransferScratchZone(zd)
		delta := ixDeltaStream(t, 8, 9, nil, []dns.RR{ixA(t, www, "10.0.0.5")})
		if err := zd.applyIxfrToScratch(&incoming, delta); err != nil {
			t.Fatalf("applyIxfrToScratch refused the delta: %v", err)
		}
		adopt(t, zd, &incoming)
	})

	t.Run("base unsigned: signing was switched on over it", func(t *testing.T) {
		zd, _ := unsigned(t)
		zd.SetRuntimeOption(OptInlineSigning, true) // no publish has followed
		adopt(t, zd, capture(t, zd))
	})

	t.Run("base unsigned: a full pass publishes a signed snapshot before the adoption", func(t *testing.T) {
		zd, _ := unsigned(t)
		zd.SetRuntimeOption(OptInlineSigning, true)
		incoming := capture(t, zd) // built on the unsigned snapshot
		fullPassPublish(t, zd)     // the served snapshot is signed now, and marked
		if !zd.publishedSnapshot().signed {
			t.Fatal("precondition: the full pass did not mark the snapshot it published")
		}
		adopt(t, zd, incoming) // base+delta replaces it: the base's owners are unsigned
	})

	t.Run("base unsigned: SignZone publishes a signed snapshot before the adoption", func(t *testing.T) {
		zd, _ := unsigned(t)
		zd.SetRuntimeOption(OptInlineSigning, true)
		incoming := capture(t, zd)
		if _, err := zd.SignZone(context.Background(), zd.KeyDB, false); err != nil {
			t.Fatalf("SignZone: %v", err)
		}
		if _, err := zd.publishSync(); err != nil {
			t.Fatalf("publishSync: %v", err)
		}
		adopt(t, zd, incoming)
	})

	t.Run("base signed, served signed: the scoped pass", func(t *testing.T) {
		zd := signed(t)
		if !zd.publishedSnapshot().signed {
			t.Fatal("precondition: the full pass did not mark the snapshot it published")
		}
		adopt(t, zd, capture(t, zd))
	})

	t.Run("base signed: an unsigned snapshot is published before the adoption", func(t *testing.T) {
		zd := signed(t)
		incoming := capture(t, zd) // built on the signed snapshot
		zd.SetRuntimeOption(OptInlineSigning, false)
		unsignedPublish(t, zd) // served: unsigned, marked so
		if zd.publishedSnapshot().signed {
			t.Fatal("precondition: a publish that could not sign marked its snapshot signed")
		}
		zd.SetRuntimeOption(OptInlineSigning, true)
		adopt(t, zd, incoming) // base+delta replaces it, and the base was signed throughout
	})

	t.Run("base unsigned but carrying signatures of ours from before the zone was switched off", func(t *testing.T) {
		zd := signed(t)
		zd.SetRuntimeOption(OptInlineSigning, false)
		unsignedPublish(t, zd) // its RRsets keep their old signatures; the snapshot is unmarked
		if zd.publishedSnapshot().signed {
			t.Fatal("precondition: a publish that could not sign marked its snapshot signed")
		}
		zd.SetRuntimeOption(OptInlineSigning, true)
		// The delta adds an address to an RRset that holds an old signature:
		// the full pass alone would keep it as current.
		zd.IncomingSerial, zd.CurrentSerial = zd.publishedSnapshot().Serial, zd.publishedSnapshot().Serial
		from := zd.IncomingSerial
		incoming := newTransferScratchZone(zd)
		delta := ixDeltaStream(t, from, from+1, nil, []dns.RR{ixA(t, www, "10.0.0.5")})
		if err := zd.applyIxfrToScratch(&incoming, delta); err != nil {
			t.Fatalf("applyIxfrToScratch refused the delta: %v", err)
		}
		zd.mu.Lock()
		err := zd.applyRefreshReplacementLocked(&incoming, nil, false, false)
		zd.mu.Unlock()
		if err != nil {
			t.Fatalf("applyRefreshReplacementLocked: %v", err)
		}
		assertPublishedAddresses(t, zd, www, wantAddrs)
		assertEveryPublishedRRsetVerifies(t, zd)
	})
}

// ixfrRemovesDelegation says when the content being adopted has lost a
// delegation cut the base had: an owner below the apex that held NS holds none,
// whether the wire delta took it or a callback did afterwards.
func TestIxfrRemovesDelegation(t *testing.T) {
	zd := ixBase(t, ixDelegationZone)
	base := zd.publishedSnapshot()
	rm := func(rrs ...string) []dns.RR {
		var out []dns.RR
		for _, r := range rrs {
			out = append(out, mustRR(t, r))
		}
		return out
	}
	for _, tc := range []struct {
		what           string
		removed, added []dns.RR
		edit           func(data *core.NameMap[OwnerData]) // what a callback does to the content afterwards
		want           bool
	}{
		{"the NS RRset of a cut is removed", rm("sub.example. 3600 IN NS ns.sub.example."), nil, nil, true},
		{"the NS RRset is replaced", rm("sub.example. 3600 IN NS ns.sub.example."), rm("sub.example. 3600 IN NS ns2.sub.example."), nil, false},
		{"one of two NS is removed", rm("two.example. 3600 IN NS ns1.two.example."), nil, nil, false},
		{"an address is added", nil, rm("www.example. 3600 IN A 10.0.0.5"), nil, false},
		{"a record below a cut is removed", rm("deep.sub.example. 3600 IN A 10.0.0.21"), nil, nil, false},
		{"a cut is added", nil, rm("www.example. 3600 IN NS ns.www.example."), nil, false},
		{"the apex NS changes", rm("example. 3600 IN NS ns.example."), rm("example. 3600 IN NS ns9.example."), nil, false},
		{"a callback deletes the NS RRset of a cut", nil, rm("www.example. 3600 IN A 10.0.0.5"),
			func(data *core.NameMap[OwnerData]) { dropRRset(data, "sub.example.", dns.TypeNS) }, true},
		{"a callback deletes the owner of a cut", nil, rm("www.example. 3600 IN A 10.0.0.5"),
			func(data *core.NameMap[OwnerData]) { data.Remove("sub.example.") }, true},
		{"a callback edits an address", nil, rm("www.example. 3600 IN A 10.0.0.5"),
			func(data *core.NameMap[OwnerData]) { dropRRset(data, "www.example.", dns.TypeA) }, false},
	} {
		t.Run(tc.what, func(t *testing.T) {
			steps, err := parseIxfrDeltas("example.", ixDeltaStream(t, 7, 8, tc.removed, tc.added), 7)
			if err != nil {
				t.Fatalf("parseIxfrDeltas: %v", err)
			}
			touched := ixfrTouchedOwners("example.", steps)
			data, signed := materializeForIxfr(base, touched)
			if err := applyIxfrSteps("example.", data, signed, steps); err != nil {
				t.Fatalf("applyIxfrSteps: %v", err)
			}
			if tc.edit != nil {
				tc.edit(data)
			}
			if got := ixfrRemovesDelegation("example.", base, data); got != tc.want {
				t.Fatalf("ixfrRemovesDelegation = %v, want %v", got, tc.want)
			}
		})
	}
}

// dropRRset removes one RRset of one owner from data the way a draft does: the
// owner is copied first, because the owners a delta did not touch share their
// stores with the snapshot, and a write through the shared store would change
// the base the next case reads.
func dropRRset(data *core.NameMap[OwnerData], name string, rrtype uint16) {
	od, ok := data.Get(name)
	if !ok {
		return
	}
	nod := OwnerData{Name: od.Name, RRtypes: NewRRTypeStore()}
	for _, t := range od.RRtypes.Keys() {
		if t == rrtype {
			continue
		}
		rs, _ := od.RRtypes.Get(t)
		nod.RRtypes.Set(t, rs)
	}
	data.Set(name, nod)
}

const ixDelegationZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 7 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.3
sub.example.	3600	IN	NS	ns.sub.example.
ns.sub.example.	3600	IN	A	10.0.0.20
deep.sub.example.	3600	IN	A	10.0.0.21
two.example.	3600	IN	NS	ns1.two.example.
two.example.	3600	IN	NS	ns2.two.example.
ns1.two.example.	3600	IN	A	10.0.0.30
ns2.two.example.	3600	IN	A	10.0.0.31
`

// A delta that removes a delegation makes the names below the cut the zone's
// own data. They were occluded in the base, so they were skipped when it was
// signed and carry no signatures and no NSEC; the delta never names them, so a
// signing pass scoped to its touched owners does not reach them. The adoption
// takes the full pass for such a delta, and after it every name below the
// removed cut verifies, and has an NSEC the chain reaches. A delta that leaves
// the cuts alone keeps the scoped pass (the guard test above).
func TestAnIxfrDeltaThatRemovesADelegationSignsTheNamesBelowIt(t *testing.T) {
	zd := ixSigningSecondary(t, ixDelegationZone)
	zd.IncomingSerial, zd.CurrentSerial = 7, 7
	below := []string{"ns.sub.example.", "deep.sub.example."}
	for _, name := range below {
		od := getOwnerFrom(zd.publishedSnapshot(), name)
		if od == nil || len(od.RRtypes.GetOnlyRRSet(dns.TypeA).RRSIGs) != 0 {
			t.Fatalf("precondition: %s should be occluded and unsigned in the base", name)
		}
	}
	if !zd.publishedSnapshot().signed {
		t.Fatal("precondition: the base is not marked signed")
	}

	incoming := newTransferScratchZone(zd)
	delta := ixDeltaStream(t, 7, 8, []dns.RR{mustRR(t, "sub.example. 3600 IN NS ns.sub.example.")}, nil)
	if err := zd.applyIxfrToScratch(&incoming, delta); err != nil {
		t.Fatalf("applyIxfrToScratch refused the delta: %v", err)
	}
	zd.mu.Lock()
	err := zd.applyRefreshReplacementLocked(&incoming, nil, false, false)
	zd.mu.Unlock()
	if err != nil {
		t.Fatalf("applyRefreshReplacementLocked: %v", err)
	}

	assertEveryPublishedRRsetVerifies(t, zd)
	for _, name := range below {
		od := getOwnerFrom(zd.publishedSnapshot(), name)
		if od == nil {
			t.Fatalf("%s is gone from the published zone", name)
		}
		if len(od.NSEC.RRs) == 0 || len(od.NSEC.RRSIGs) == 0 {
			t.Errorf("%s is authoritative now and has no signed NSEC (%d records, %d signatures)",
				name, len(od.NSEC.RRs), len(od.NSEC.RRSIGs))
		}
	}
	if !zd.publishedSnapshot().signed {
		t.Error("the adopted snapshot is signed throughout but not marked so")
	}
}

// The pre-refresh callbacks run after the delta is built and may edit the
// incoming content. One that removes a delegation (the NS RRset of a cut, or its
// owner) makes the names below it authoritative, as a delta that removes it
// does, and the adoption must take the full pass for it: the rule reads the
// content being adopted against the base, not the paths that changed it. The
// owner delete of a draft does not join the touched owners, so it is a path the
// touched set alone would miss. After the adoption every name below the cut
// verifies and has a signed NSEC.
func TestACallbackThatRemovesADelegationHasTheNamesBelowItSigned(t *testing.T) {
	for name, remove := range map[string]func(incoming *ZoneData){
		"StageDelete of the NS RRset": func(incoming *ZoneData) { incoming.StageDelete("sub.example.", dns.TypeNS) },
		"StageOwnerDelete of the cut": func(incoming *ZoneData) { incoming.StageOwnerDelete("sub.example.") },
	} {
		t.Run(name, func(t *testing.T) {
			zd := ixSigningSecondary(t, ixDelegationZone)
			zd.IncomingSerial, zd.CurrentSerial = 7, 7
			below := []string{"ns.sub.example.", "deep.sub.example."}

			// The wire delta is an ordinary address edit: it leaves every cut alone.
			incoming := newTransferScratchZone(zd)
			delta := ixDeltaStream(t, 7, 8, nil, []dns.RR{ixA(t, "www.example.", "10.0.0.5")})
			if err := zd.applyIxfrToScratch(&incoming, delta); err != nil {
				t.Fatalf("applyIxfrToScratch refused the delta: %v", err)
			}
			if !ixfrScopedPassHolds("example.", &incoming) {
				t.Fatal("precondition: an address edit on a signed base is not on the scoped pass")
			}
			remove(&incoming) // the callback

			zd.mu.Lock()
			err := zd.applyRefreshReplacementLocked(&incoming, nil, false, false)
			zd.mu.Unlock()
			if err != nil {
				t.Fatalf("applyRefreshReplacementLocked: %v", err)
			}

			assertEveryPublishedRRsetVerifies(t, zd)
			for _, n := range below {
				od := getOwnerFrom(zd.publishedSnapshot(), n)
				if od == nil {
					t.Fatalf("%s is gone from the published zone", n)
				}
				if len(od.NSEC.RRs) == 0 || len(od.NSEC.RRSIGs) == 0 {
					t.Errorf("%s is authoritative now and has no signed NSEC (%d records, %d signatures)",
						n, len(od.NSEC.RRs), len(od.NSEC.RRSIGs))
				}
			}
		})
	}
}

// Ordinary edits keep the scoped pass: a delta that adds an address and a
// callback that edits an address leave every cut alone, so only the touched
// owners are signed again and an owner nobody touched is not re-materialised
// (its store is the base's). The new owner sorts last, so the NSEC chain only
// re-links its neighbours, www.example. and the apex, and ns.example. is left
// alone.
func TestOrdinaryEditsOfAnAdoptionKeepTheScopedPass(t *testing.T) {
	zd := ixSigningSecondary(t, ixDelegationZone)
	zd.IncomingSerial, zd.CurrentSerial = 7, 7
	untouched := getOwnerFrom(zd.publishedSnapshot(), "ns.example.")
	if untouched == nil {
		t.Fatal("precondition: ns.example. is not published")
	}
	before := untouched.RRtypes

	incoming := newTransferScratchZone(zd)
	delta := ixDeltaStream(t, 7, 8, nil, []dns.RR{ixA(t, "zz.example.", "10.1.0.1")})
	if err := zd.applyIxfrToScratch(&incoming, delta); err != nil {
		t.Fatalf("applyIxfrToScratch refused the delta: %v", err)
	}
	// The callback: an address edit in the content the delta produced.
	incoming.StageRRset("zz.example.", core.RRset{Name: "zz.example.", Class: dns.ClassINET, RRtype: dns.TypeA,
		RRs: []dns.RR{ixA(t, "zz.example.", "10.1.0.2")}})
	if !ixfrScopedPassHolds("example.", &incoming) {
		t.Fatal("ordinary edits took the adoption off the scoped pass")
	}

	zd.mu.Lock()
	err := zd.applyRefreshReplacementLocked(&incoming, nil, false, false)
	zd.mu.Unlock()
	if err != nil {
		t.Fatalf("applyRefreshReplacementLocked: %v", err)
	}
	if after := getOwnerFrom(zd.publishedSnapshot(), "ns.example."); after == nil || after.RRtypes != before {
		t.Fatal("an owner nobody touched was signed again: the scoped pass was lost for ordinary edits")
	}
	assertEveryPublishedRRsetVerifies(t, zd)
	if !zd.publishedSnapshot().signed {
		t.Error("the adopted snapshot is signed throughout but not marked so")
	}
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
