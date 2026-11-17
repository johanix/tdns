/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// A per-zone transfer-src from the config file has to survive the refresh
// engine. ParseZones sets zd.TransferSrc, and the engine then replaces it with
// the refresher's: on the first load of the pre-registered zone and on every
// config reload. The refresher ParseZones built did not carry it, so the zone
// fell back to authengine.transfer-src for NOTIFY, the SOA probe and AXFR while
// its config named another source. Found by the #1064 rig.
func TestConfigZoneTransferSrcSurvivesTheRefresher(t *testing.T) {
	authApp(t)
	kdb := Conf.Internal.KeyDB
	prevGlobal := kdb.TransferSrcList()
	kdb.SetTransferSrc([]string{"192.0.2.10"})
	t.Cleanup(func() { kdb.SetTransferSrc(prevGlobal) })

	const zone = "xfrsrc.config.example."
	file := filepath.Join(t.TempDir(), "zone")
	body := zone + "\t3600\tIN\tSOA\tns1." + zone + " hostmaster." + zone + " 1 7200 1800 604800 7200\n" +
		zone + "\t3600\tIN\tNS\tns1." + zone + "\n" +
		"ns1." + zone + "\t3600\tIN\tA\t192.0.2.53\n"
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// Registered before the engine starts, so it runs after the engine stops.
	t.Cleanup(func() {
		if zd, ok := Zones.Get(zone); ok {
			zd.stopPublisher()
		}
		Zones.Remove(zone)
	})

	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 4)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)
	runRefreshEngine(t, conf)

	// parse runs ParseZones with the zone's transfer-src set to zoneSrc, then
	// waits until the engine has handled the refresher it queued. A refresher
	// for a zone not held, sent after it on the same channel, is answered only
	// once the engine has got that far.
	parse := func(reload bool, zoneSrc []string) *ZoneData {
		t.Helper()
		conf.Zones = []ZoneConf{{Name: zone, Type: "primary", Store: "map", Zonefile: file, TransferSrc: zoneSrc}}
		if _, broken, err := conf.ParseZones(context.Background(), reload); err != nil || len(broken) > 0 {
			t.Fatalf("ParseZones(reload=%v): err=%v broken=%v", reload, err, broken)
		}
		resp := make(chan RefresherResponse, 1)
		conf.Internal.RefreshZoneCh <- ZoneRefresher{Name: "barrier.xfrsrc.example.", Response: resp}
		select {
		case <-resp:
		case <-time.After(10 * time.Second):
			t.Fatalf("ParseZones(reload=%v): the refresh engine did not get through its refresher", reload)
		}
		zd, ok := Zones.Get(zone)
		if !ok {
			t.Fatalf("ParseZones(reload=%v): zone %s is not held", reload, zone)
		}
		return zd
	}

	check := func(step string, zd *ZoneData, want []string, wantTier string) {
		t.Helper()
		zd.mu.Lock()
		srcs, tier := zd.EffectiveTransferSrcWithSource()
		srcs = append([]string(nil), srcs...)
		zd.mu.Unlock()
		if tier != wantTier || !slices.Equal(srcs, want) {
			t.Errorf("%s: effective transfer-src %v from %q, want %v from %q", step, srcs, tier, want, wantTier)
		}
	}

	zd := parse(false, []string{"192.0.2.11"})
	if !zd.HasPublishedData() {
		t.Fatal("the first load published nothing, so the engine never reached the zone")
	}
	check("first load", zd, []string{"192.0.2.11"}, "zone")
	check("config reload", parse(true, []string{"192.0.2.11"}), []string{"192.0.2.11"}, "zone")
	check("per-zone transfer-src removed", parse(true, nil), []string{"192.0.2.10"}, "global")
}
