/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"

	"github.com/miekg/dns"
)

// ReplayPersistedDeltas re-applies the persisted deltas over a zone that has
// just been loaded from its file, and returns how many deltas were replayed.
//
// This is the other half of Phase 2's model. The zone file is the source of
// truth but lags behind: it holds the zone as of the last write-zone/sync/
// freeze, while the deltas hold everything that has happened since. Loading
// the file alone would silently roll the zone back to that point.
//
// Call it after the zone is Ready and its first snapshot is installed, on
// startup and on any reload that re-reads the file.
//
// Every delta is applied in ONE pass rather than one apply per delta. The
// result is identical -- the actions are already in order -- but it publishes
// once instead of once per delta, so secondaries see one serial step instead
// of a burst of intermediate ones that never existed as served states.
func (zd *ZoneData) ReplayPersistedDeltas(kdb *KeyDB) (int, error) {
	if zd == nil || kdb == nil || kdb.DB == nil {
		return 0, nil
	}

	deltas, err := kdb.LoadZoneDeltas(zd.ZoneName)
	if err != nil {
		return 0, err
	}
	if len(deltas) == 0 {
		return 0, nil
	}

	var actions []dns.RR
	for _, d := range deltas {
		acts, err := ZoneDeltaActions(d)
		if err != nil {
			// A delta we cannot parse means we cannot reconstruct the zone as
			// it was. Serving the file alone would silently roll back content
			// the operator believes is live, so refuse rather than guess.
			return 0, fmt.Errorf("zone %s: %v", zd.ZoneName, err)
		}
		actions = append(actions, acts...)
	}

	lastSerial := deltas[len(deltas)-1].ToSerial

	lg.Info("replaying persisted zone deltas over the zone file",
		"zone", zd.ZoneName, "deltas", len(deltas), "records", len(actions),
		"file_serial", zd.CurrentSerial, "target_serial", lastSerial)

	// InternalUpdate: these changes were authorized when they were first
	// applied; re-checking update-policy now would drop content on a policy
	// that has since been tightened, leaving the served zone quietly different
	// from what the operator last saw.
	//
	// Replay: suppresses re-persisting what we are replaying.
	if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        actions,
		InternalUpdate: true,
		Replay:         true,
		Description:    "replay of persisted deltas",
	}, kdb); err != nil {
		return 0, fmt.Errorf("zone %s: replaying deltas: %v", zd.ZoneName, err)
	}

	// Resume at the serial the zone actually had, not at file_serial + 1.
	// The replayed content IS the content of lastSerial; publishing it under a
	// lower number would look to a secondary like the zone had gone backwards,
	// and under a higher one would burn serials on every restart.
	zd.mu.Lock()
	if serialNewer(lastSerial, zd.CurrentSerial) {
		zd.CurrentSerial = lastSerial
		zd.ensureWorkingSet()
		// bumpSerial=false: CurrentSerial is already exactly what we want.
		zd.publishWorkingSetLocked(zd.generation.Load(), false)
	}
	zd.mu.Unlock()

	return len(deltas), nil
}
