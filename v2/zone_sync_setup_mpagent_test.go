package tdns

import (
	"testing"
)

// T5.7: delegation-sync setup runs for the multi-provider agent. tdns-mp's
// agent runs under its own app type; once registered as a multi-provider
// agent app, a multi-provider zone with parentsync=agent gets its
// DELEGATION-SYNC-SETUP like a tdns-agent zone, and one with
// parentsync=owner (no parentsync option) gets nothing.
func TestZoneSyncSetupRunsForARegisteredMultiProviderAgentApp(t *testing.T) {
	oldConf := delegationSyncConf.Load()
	delegationSyncConf.Store(&delegationSyncRuntime{ParentSync: ParentSyncConf{Schemes: []string{"update"}}})
	t.Cleanup(func() { delegationSyncConf.Store(oldConf) })
	oldApp := Globals.App.Type
	t.Cleanup(func() { Globals.App.Type = oldApp })
	const mpAgent AppType = 250 // an app type tdns does not know, as tdns-mp's agent is to tdns

	kdb := newTestKeyDB(t)
	zd := testZone(t, "mpagent.example.", "mpagent.example. 3600 IN SOA ns.mpagent.example. hostmaster.mpagent.example. 1 7200 1800 604800 7200\nmpagent.example. 3600 IN NS ns.mpagent.example.\nns.mpagent.example. 3600 IN A 192.0.2.1\n")
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptMultiProvider: true, OptParentSync: true}

	setups := func(app AppType, parentsync bool) int {
		t.Helper()
		Globals.App.Type = app
		zd.Options[OptParentSync] = parentsync
		q := make(chan DelegationSyncRequest, 4)
		if err := zd.SetupZoneSync(q); err != nil {
			t.Fatalf("SetupZoneSync: %v", err)
		}
		n := 0
		for len(q) > 0 {
			if req := <-q; req.Command == "DELEGATION-SYNC-SETUP" && req.ZoneName == zd.ZoneName {
				n++
			}
		}
		return n
	}
	if n := setups(mpAgent, true); n != 0 {
		t.Errorf("an app type not registered as a multi-provider agent queued %d setups, want 0", n)
	}
	RegisterMultiProviderAgentAppType(mpAgent)
	if n := setups(mpAgent, true); n != 1 {
		t.Errorf("the registered multi-provider agent app with parentsync=agent queued %d setups, want 1", n)
	}
	if n := setups(mpAgent, false); n != 0 {
		t.Errorf("with parentsync=owner (no parentsync option) %d setups were queued, want 0", n)
	}
	if n := setups(AppTypeAgent, true); n != 1 {
		t.Errorf("tdns-agent itself queued %d setups, want 1 as before", n)
	}
}
