/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Regression test for #1001: a SIGHUP reload that overlapped a child UPDATE
 * stopped the daemon applying updates and reloading.
 *
 * Applying an update publishes under the zone's zd.mu, and the publish
 * consulted the journal kill-switch through confMu. A config reload holds
 * confMu's write lock and takes zd.mu for every zone it parses. Either order
 * alone is harmless; an update inside its zone's lock when the reload arrives
 * at that zone is each side holding what the other wants.
 */

package tdns

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// deadlockBound is how long the test gives each step. The steps take
// milliseconds when the lock order is sound; the bound only decides how soon a
// deadlock is called one.
const deadlockBound = 10 * time.Second

// TestReloadDoesNotDeadlockAnUpdateInsideItsZone drives the overlap
// deterministically. The test goroutine plays the update, holding zd.mu as the
// applier does; a real ReloadZoneConfig (the SIGHUP path) is started and let
// take confMu and reach that zone; then the update goes on to publish, and
// must get through while the reload waits for zd.mu.
//
// Without the fix the publish blocks on confMu, which the reload holds, while
// the reload blocks on zd.mu, which the publish holds: both hang, and so does
// everything else that needs either lock afterwards.
func TestReloadDoesNotDeadlockAnUpdateInsideItsZone(t *testing.T) {
	authApp(t)
	kdb := newTestKeyDB(t)
	zd := journalTestZone(t, kdb)

	// The reload publishes a runtime-config snapshot and re-installs the
	// delegation-sync config; leave both as found.
	prevLive := liveConfig.Load()
	prevSync := delegationSyncConf.Load()
	t.Cleanup(func() {
		liveConfig.Store(prevLive)
		delegationSyncConf.Store(prevSync)
	})

	file := filepath.Join(t.TempDir(), "example.zone")
	if err := os.WriteFile(file, []byte(deltaZone), 0o644); err != nil {
		t.Fatal(err)
	}
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 10)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)
	conf.Zones = []ZoneConf{{Name: zd.ZoneName, Type: "primary", Store: "map", Zonefile: file}}

	// The update: inside the zone's lock, as every apply is.
	zd.mu.Lock()
	unlocked := false
	unlock := func() {
		if !unlocked {
			unlocked = true
			zd.mu.Unlock()
		}
	}
	defer unlock()

	// The reload, while the update is inside the zone.
	reloaded := make(chan error, 1)
	go func() {
		_, err := conf.ReloadZoneConfig(context.Background())
		reloaded <- err
	}()

	// Wait for the reload to hold confMu: a read lock is refused only while a
	// writer holds, or waits for, the lock.
	deadline := time.Now().Add(deadlockBound)
	for {
		if confMu.TryRLock() {
			confMu.RUnlock()
		} else {
			break
		}
		if time.Now().After(deadline) {
			unlock()
			t.Fatal("the reload never took the config lock")
		}
		time.Sleep(time.Millisecond)
	}

	// The update goes on to publish: stage a record and publish it, the part
	// of every update's apply that follows taking the zone lock
	// (stageAndPublishLocked is what applyChildUpdate and applyZoneUpdate call
	// there). A fresh change is journalled, which is what consults the switch.
	// Built here, not in the goroutine: the helper fails the test.
	const owner = "three.example."
	rs := journalRRset(t, owner+" 3600 IN A 10.0.0.3")[0]
	published := make(chan error, 1)
	go func() {
		updated, _, persistErr, err := zd.stageAndPublishLocked(
			UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: zd.ZoneName},
			func() bool {
				zd.stageRRsetLocked(owner, rs)
				return true
			}, nil)
		switch {
		case err != nil:
			published <- err
		case persistErr != nil:
			published <- persistErr
		case !updated:
			published <- errors.New("the update was not applied")
		default:
			published <- nil
		}
	}()

	select {
	case err := <-published:
		if err != nil {
			unlock()
			t.Fatalf("the update's publish failed: %v", err)
		}
	case <-time.After(deadlockBound):
		// Deadlocked. Let the reload through, so that the goroutines end and
		// the lock it holds is released rather than left to hang the rest of
		// the suite.
		unlock()
		select {
		case <-reloaded:
		case <-time.After(deadlockBound):
		}
		t.Fatal("deadlock: the update's publish, inside the zone's lock, never got through " +
			"while a reload held the config lock and waited for that zone")
	}
	unlock()

	select {
	case err := <-reloaded:
		if err != nil {
			t.Fatalf("the reload failed: %v", err)
		}
	case <-time.After(deadlockBound):
		t.Fatal("the reload never finished after the update released the zone")
	}

	// The change was journalled, so the publish went through the code that
	// asks whether the journal is on, not around it.
	info, err := zd.JournalInfo(false)
	if err != nil {
		t.Fatalf("JournalInfo: %v", err)
	}
	if info.Deltas != 3 {
		t.Fatalf("%d journal delta(s) after the update, want 3 (two from setup and this one)", info.Deltas)
	}

	// Neither lock is left held: a second reload completes at once.
	again := make(chan error, 1)
	go func() {
		_, err := conf.ReloadZoneConfig(context.Background())
		again <- err
	}()
	select {
	case err := <-again:
		if err != nil {
			t.Fatalf("the second reload failed: %v", err)
		}
	case <-time.After(deadlockBound):
		t.Fatal("a second reload did not finish: a lock was left held")
	}
}
