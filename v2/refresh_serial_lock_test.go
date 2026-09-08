/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"testing"
	"time"
)

// TestOutboundSerialIsSettledUnderTheZoneLock.
//
// CurrentSerial is guarded by zd.mu: publishWorkingSetLocked reads AND writes it
// under the lock, and logs "serial mirror drift" if it ever disagrees with the
// published snapshot. applyOutboundSerialAfterRefresh used to decide and assign
// outside the lock and take it only for the publish, so a concurrent publish
// could interleave between the assignment and the publish meant to carry it --
// leaving the zone advertising a serial that no snapshot has.
//
// Run this under -race; that is where the assignment against a locked reader
// shows up as what it is.
func TestOutboundSerialIsSettledUnderTheZoneLock(t *testing.T) {
	zd, kdb, _ := rolledZone(t)
	zd.KeyDB = kdb
	zd.OutboundSoaSerial = OutboundSoaSerialUnixtime

	ctx, cancel := context.WithCancel(context.Background())
	readerDone := make(chan struct{})

	// A reader that takes the lock, as every locked reader of this field does.
	go func() {
		defer close(readerDone)
		for ctx.Err() == nil {
			zd.mu.Lock()
			_ = zd.CurrentSerial
			zd.mu.Unlock()
		}
	}()

	for i := 0; i < 20; i++ {
		applyOutboundSerialAfterRefresh(zd, zd.ZoneName)
	}

	cancel()
	// Bounded: a reader wedged on zd.mu would otherwise hold this test until
	// the package timeout, reporting a lock bug as a hang.
	select {
	case <-readerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the locked reader did not exit; something is still holding zd.mu")
	}

	zd.mu.Lock()
	current := zd.CurrentSerial
	zd.mu.Unlock()
	if snap := zd.publishedSnapshot(); snap != nil && snap.Serial != current {
		t.Errorf("CurrentSerial is %d but the published snapshot carries %d; the zone is"+
			" advertising a serial no snapshot has", current, snap.Serial)
	}
}
