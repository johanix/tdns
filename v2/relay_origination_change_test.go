package tdns

import (
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

// The mark is set only on the change from originating to relaying, and only
// for tdns-agent.
func TestMarkRelayCopyOnlyWhenOriginationEnds(t *testing.T) {
	for _, tc := range []struct {
		name           string
		app            AppType
		wasOriginating bool
		opts           map[ZoneOption]bool
		want           bool
	}{
		{"agent, originating to relay", AppTypeAgent, true, nil, true},
		{"agent, relay stays relay", AppTypeAgent, false, nil, false},
		{"agent, originating stays originating", AppTypeAgent, true, map[ZoneOption]bool{OptChildSync: true}, false},
		{"agent, relay to originating", AppTypeAgent, false, map[ZoneOption]bool{OptChildSync: true}, false},
		{"auth, originating to secondary", AppTypeAuth, true, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withAppType(t, tc.app)
			zd := &ZoneData{ZoneName: "example.", ZoneType: Secondary, Options: tc.opts}
			zd.markRelayCopyIfOriginationEnded(tc.wasOriginating)
			if got := zd.relayCopyUnconfirmed.Load(); got != tc.want {
				t.Errorf("marked = %v, want %v", got, tc.want)
			}
		})
	}
}
