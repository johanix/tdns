/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"strings"
	"testing"
	"time"
)

// runRefreshEngine starts the refresh engine on conf, and stops it when the
// test ends.
func runRefreshEngine(t *testing.T, conf *Config) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); RefreshEngine(ctx, conf) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("RefreshEngine did not shut down")
		}
	})
}

// A refresh of a name Zones does not hold, with nothing to build a zone
// from, creates no zone, and a caller waiting for the answer is told so. It
// is what a NOTIFY or a reload sends when the zone's removal lands between
// its lookup and the engine (#970). Before, the engine built a zone of type
// 0 that never loaded and was retried every minute.
func TestARefreshOfAZoneNotHeldCreatesNoZone(t *testing.T) {
	authApp(t)
	conf := &Config{}
	conf.Internal.KeyDB = Conf.Internal.KeyDB
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 1)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)
	runRefreshEngine(t, conf)

	const zone = "gone.refresh.example."
	t.Cleanup(func() { Zones.Remove(zone) })
	for _, c := range []struct {
		what string
		zr   ZoneRefresher
	}{
		{"a NOTIFY's refresh", ZoneRefresher{Name: zone, ZoneStore: MapZone}},
		{"a reload's refresh", ZoneRefresher{Name: zone, Force: true}},
		{"a config-bearing refresh with no zone type", ZoneRefresher{Name: zone, ZoneStore: MapZone, ConfigUpdate: true}},
	} {
		respch := make(chan RefresherResponse, 1)
		c.zr.Response = respch
		conf.Internal.RefreshZoneCh <- c.zr
		var resp *RefresherResponse
		select {
		case r := <-respch:
			resp = &r
		case <-time.After(2 * time.Second):
		}
		if zd, ok := Zones.Get(zone); ok {
			t.Fatalf("%s created a zone of type %d", c.what, zd.ZoneType)
		}
		if resp == nil || !resp.Error || !strings.Contains(resp.ErrorMsg, "not a zone this server holds") {
			t.Errorf("%s was answered %+v, want an error that the server does not hold the zone", c.what, resp)
		}
	}
}

// The refresher that names a zone type and carries the zone's config -- what
// LoadDynamicZoneFiles enqueues for a persisted dynamic zone -- still creates
// the zone it names.
func TestAConfigBearingRefreshStillCreatesItsDynamicZone(t *testing.T) {
	authApp(t)
	conf := &Config{}
	conf.Internal.KeyDB = Conf.Internal.KeyDB
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 1)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)
	runRefreshEngine(t, conf)

	const zone = "dynamic.refresh.example."
	t.Cleanup(func() { Zones.Remove(zone) })
	conf.Internal.RefreshZoneCh <- ZoneRefresher{Name: zone, ZoneType: Primary, ZoneStore: MapZone,
		Zonefile: t.TempDir() + "/absent.zone", ConfigUpdate: true}

	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if zd, ok := Zones.Get(zone); ok {
			if zd.ZoneType != Primary {
				t.Errorf("the zone was created as type %d, want primary", zd.ZoneType)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the config-bearing refresh created no zone")
		}
	}
}

// A persisted dynamic zone keeps its own NOTIFY resend settings across a
// restart: the refresher LoadDynamicZoneFiles enqueues carries them to the
// ZoneData the engine creates (#1007). notify-retries: 0 must stay 0, not
// become the server's default.
func TestARestoredDynamicZoneKeepsItsNotifyRetrySettings(t *testing.T) {
	authApp(t)
	conf := &Config{}
	conf.Internal.KeyDB = Conf.Internal.KeyDB
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 1)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)
	runRefreshEngine(t, conf)

	const zone = "retries.refresh.example."
	t.Cleanup(func() { Zones.Remove(zone) })
	zero := 0
	conf.Internal.RefreshZoneCh <- ZoneRefresher{Name: zone, ZoneType: Primary, ZoneStore: MapZone,
		Zonefile: t.TempDir() + "/absent.zone", ConfigUpdate: true,
		NotifyRetries: &zero, NotifyRetryInterval: 7 * time.Second}

	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if zd, ok := Zones.Get(zone); ok {
			retries, interval := notifyRetryPolicy(zd, NewNotifyTracker())
			if retries != 0 || interval != 7*time.Second {
				t.Errorf("restored zone resends %d times every %v, want 0 times every 7s", retries, interval)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the config-bearing refresh created no zone")
		}
	}
}
