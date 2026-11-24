package tdns

import (
	"context"
	"sync/atomic"
	"testing"
)

// A tdns-agent zone that originates serves a serial of its own. When a config
// update takes its last origination option away it is a relay, and it must
// serve the upstream's copy although the upstream has not moved. The update
// here is not forced, like a reload whose forced refresh was skipped or
// failed: only the mark the update sets brings the transfer.
func TestAgentZoneThatStopsOriginatingServesTheUpstreamsCopy(t *testing.T) {
	kdb := asDerivedApp(t, AppTypeAgent)
	var transfers atomic.Int32
	count := func(zd *ZoneData) {
		zd.OnZonePreRefresh = append(zd.OnZonePreRefresh, func(_, _ *ZoneData) { transfers.Add(1) })
	}
	up := startRelayUpstream(t, 40)
	z := startRelayedZone(t, kdb, up, map[ZoneOption]bool{OptChildSync: true}, count)
	if !zoneMayOriginateContent(z.zd) {
		t.Fatal("setup: the childsync zone should originate")
	}
	up.publish(t, 50)
	z.notified(t)
	if got := z.served(t); got == 50 {
		t.Fatal("setup: the originating zone serves the upstream's 50, want a serial of its own")
	}

	z.opts = nil
	before := transfers.Load()
	z.run(t, z.configRefresher())
	if transfers.Load() == before {
		t.Fatal("the update that ended the zone's origination brought no transfer")
	}
	z.wantServed(t, 50, "after the update that ended its origination")
	if z.zd.relayCopyUnconfirmed.Load() {
		t.Error("the copy is still unconfirmed after the transfer")
	}

	// An update that ends nothing marks nothing: no transfer follows.
	before = transfers.Load()
	z.run(t, z.configRefresher())
	if got := transfers.Load(); got != before {
		t.Errorf("an update that left the relay a relay brought %d transfers, want none", got-before)
	}
	z.wantServed(t, 50, "after an update that changed nothing")
}

// The mark is set only on the change from originating to relaying, only for
// tdns-agent, and only on a zone that has published.
func TestMarkRelayCopyOnlyWhenOriginationEnds(t *testing.T) {
	childsync := map[ZoneOption]bool{OptChildSync: true}
	for _, tc := range []struct {
		name           string
		app            AppType
		wasOriginating bool
		opts           map[ZoneOption]bool
		published      bool
		want           bool
	}{
		{"agent, originating to relay", AppTypeAgent, true, nil, true, true},
		{"agent, relay stays relay", AppTypeAgent, false, nil, true, false},
		{"agent, originating stays originating", AppTypeAgent, true, childsync, true, false},
		{"agent, relay to originating", AppTypeAgent, false, childsync, true, false},
		{"agent, never published", AppTypeAgent, true, nil, false, false},
		{"auth, originating to secondary", AppTypeAuth, true, nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withAppType(t, tc.app)
			zd := &ZoneData{ZoneName: ovZone}
			if tc.published {
				zd = testSnapshotZone(t, ovZone, ovUpstreamZone(40))
			}
			zd.ZoneType, zd.Options = Secondary, tc.opts
			zd.markRelayCopyIfOriginationEnded(tc.wasOriginating)
			if got := zd.relayCopyUnconfirmed.Load(); got != tc.want {
				t.Errorf("marked = %v, want %v", got, tc.want)
			}
		})
	}
}

// A config reload swaps a zone's options in ParseZones, before it queues the
// refresher, so the refresh engine never sees the change: the mark is made
// there.
func TestAReloadThatEndsAnAgentZonesOriginationMarksItsCopy(t *testing.T) {
	withAppType(t, AppTypeAgent)
	for _, tc := range []struct {
		name  string
		after []string
		want  bool
	}{
		{"option removed", nil, true},
		{"option kept", []string{"allow-api-updates"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zd := testSnapshotZone(t, ovZone, ovUpstreamZone(40))
			zd.ZoneType = Secondary
			zd.Options = map[ZoneOption]bool{OptAllowApiUpdates: true}
			if !zoneMayOriginateContent(zd) {
				t.Fatal("setup: the allow-api-updates zone should originate")
			}
			conf := &Config{Zones: []ZoneConf{{Name: ovZone, Type: "secondary", Store: "map",
				Primaries: []PeerConf{{Addr: "127.0.0.1:53", Key: "NOKEY"}}, OptionsStrs: tc.after}}}
			conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 10)
			if _, _, err := conf.ParseZones(context.Background(), true); err != nil {
				t.Fatalf("reload: %v", err)
			}
			zd.mu.Lock()
			api := zd.Options[OptAllowApiUpdates]
			zd.mu.Unlock()
			if api != (len(tc.after) > 0) {
				t.Fatalf("setup: the reload did not apply the configured options (allow-api-updates %v)", api)
			}
			if got := zd.relayCopyUnconfirmed.Load(); got != tc.want {
				t.Errorf("marked = %v, want %v", got, tc.want)
			}
		})
	}
}

// The daemon switching an origination option off at run time ends origination
// the same way.
func TestARuntimeOptionThatEndsOriginationMarksTheCopy(t *testing.T) {
	withAppType(t, AppTypeAgent)
	zd := testSnapshotZone(t, ovZone, ovUpstreamZone(40))
	zd.ZoneType = Secondary
	zd.Options = map[ZoneOption]bool{OptChildSync: true}
	zd.SetRuntimeOption(OptChildSync, false)
	if !zd.relayCopyUnconfirmed.Load() {
		t.Error("switching the last origination option off did not mark the copy")
	}
}
