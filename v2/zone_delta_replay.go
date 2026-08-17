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

	// The serial of the file we just loaded.
	//
	// zd.fileSerial, not zd.CurrentSerial. They are equal right now -- replay
	// runs before the load-time signing and republication that move
	// CurrentSerial -- but relying on that ordering is what made this fragile
	// in the first place. The journal is anchored to the file on the write
	// side (see LastZoneDeltaSerial); anchoring it to the file here too means
	// the two sides cannot drift apart no matter where replay is called from.
	zd.mu.Lock()
	fileSerial := zd.fileSerial
	zd.mu.Unlock()
	if fileSerial == 0 {
		fileSerial = zd.CurrentSerial
	}

	// Already replayed for THIS file load? Then say so quietly and stop.
	//
	// Replay can be reached twice for one load: initialLoadZone's `updated`
	// result is discarded by its caller, and FirstZoneLoad is cleared only on a
	// successful data replacement -- so a load that returns (false, nil) leaves
	// the flag set, the ticker retries the initial load, and completion runs a
	// second time.
	//
	// Without this the second pass falls into the chain validation below with a
	// serial the FIRST replay already advanced, and reports "the file has been
	// edited or replaced" -- accusing the operator of tampering with a file
	// nobody touched, and recording a ConfigWarning to match.
	//
	// Deliberately NOT inferred from the serial. "Current serial is ahead of
	// the delta chain" is equally true when the operator really did replace the
	// file with a newer one, which is exactly the case the chain check exists
	// to catch; a serial-based guard would silence a real detection to fix a
	// false one. The flag is set on a successful replay and cleared by
	// applyRefreshReplacementLocked whenever the zone is re-read from file, so
	// it means precisely "these deltas have already been applied on top of the
	// file currently loaded".
	zd.mu.Lock()
	alreadyReplayed := zd.deltasReplayed
	zd.mu.Unlock()
	if alreadyReplayed {
		lg.Debug("persisted zone deltas already replayed for this load; nothing to do",
			"zone", zd.ZoneName, "serial", fileSerial)
		return 0, nil
	}

	// Chain validation. Each delta was computed as the difference from one
	// specific base, and the first one's FromSerial names the file it was
	// computed against. If the file on disk is no longer that file -- an
	// operator edited it, or an older copy was restored from backup -- then
	// replaying this chain produces a zone that never existed at any point in
	// its history: some of the changes apply to content that is no longer
	// there, and content the operator has just added is silently overwritten.
	//
	// Refuse rather than proceed. Serving the file alone loses recent changes,
	// which is bad and is reported as such; replaying onto the wrong base
	// invents a zone, which is worse and is invisible.
	if deltas[0].FromSerial != fileSerial {
		return 0, fmt.Errorf(
			"zone %s: persisted deltas do not chain from this zone file"+
				" (deltas start at serial %d, file is at serial %d);"+
				" the file has been edited or replaced since the deltas were recorded."+
				" Reconcile deliberately: write the zone out to adopt the in-memory"+
				" state, or clear the stored deltas to adopt the file",
			zd.ZoneName, deltas[0].FromSerial, fileSerial)
	}

	// And every link after the first. Checking only deltas[0] proves the chain
	// STARTS at this file; it says nothing about whether it is continuous. A
	// sequence like A->B, C->D passes the first check and is then applied as
	// one update, so the zone lands on D while never having been C -- a serial
	// claiming a history that did not happen. That is the same "invents a zone"
	// failure the first check exists to prevent, one link further in.
	//
	// A gap means rows were lost or written from elsewhere; neither is
	// something to paper over by applying what remains.
	for i := 0; i < len(deltas); i++ {
		if i > 0 && deltas[i].FromSerial != deltas[i-1].ToSerial {
			return 0, fmt.Errorf(
				"zone %s: persisted deltas are not continuous (delta %d ends at serial %d,"+
					" delta %d starts at serial %d); refusing to apply a chain with a gap."+
					" Reconcile deliberately: write the zone out to adopt the in-memory"+
					" state, or clear the stored deltas to adopt the file",
				zd.ZoneName, i-1, deltas[i-1].ToSerial, i, deltas[i].FromSerial)
		}
		// Each link must also advance. A delta that does not move the serial
		// forward cannot be replayed into a coherent history, and would break
		// the strictly-greater guarantee the publish below relies on.
		if !serialNewer(deltas[i].ToSerial, deltas[i].FromSerial) {
			return 0, fmt.Errorf(
				"zone %s: persisted delta %d does not advance the serial (%d -> %d);"+
					" refusing to replay it",
				zd.ZoneName, i, deltas[i].FromSerial, deltas[i].ToSerial)
		}
	}

	// A signed zone that cannot re-sign will replay its content unsigned:
	// RRSIGs are deliberately not persisted (see zone_delta_store.go), they are
	// regenerated by the applier, and that needs online-signing or
	// inline-signing. Such a zone was already producing unsigned RRsets when
	// the update was first applied, so this is not new damage -- but it is
	// worth naming rather than leaving to be discovered by a validator.
	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] && zoneLooksSigned(zd) {
		lg.Warn("replaying deltas on a signed zone that cannot re-sign;"+
			" the replayed RRsets will have no valid RRSIGs",
			"zone", zd.ZoneName, "deltas", len(deltas))
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
	applied, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        actions,
		InternalUpdate: true,
		Replay:         true,
		Description:    "replay of persisted deltas",
	}, kdb)
	if err != nil {
		return 0, fmt.Errorf("zone %s: replaying deltas: %v", zd.ZoneName, err)
	}
	// The applier returns false when every action was skipped -- a stored
	// delete whose owner is no longer in the file, say, which it only logs at
	// warn level. Reporting the delta COUNT regardless would tell the operator
	// the changes are present when they are not: the chain-serial check
	// upstream only proves the deltas were computed against this file, not that
	// they landed. Say what actually happened.
	// Mark the replay done for this file load, whether or not the actions
	// changed anything: a second attempt on the same load must not re-run the
	// chain check against a serial this pass has already moved.
	zd.mu.Lock()
	zd.deltasReplayed = true
	zd.mu.Unlock()

	if !applied {
		lg.Warn("zone deltas replayed but nothing was applied; the zone is serving the file as-is",
			"zone", zd.ZoneName, "deltas", len(deltas))
		return 0, nil
	}

	// The published serial must end up STRICTLY GREATER than the highest serial
	// this zone ever published (lastSerial), never merely equal to it.
	//
	// Landing on lastSerial is tempting -- the replayed content is the content
	// of lastSerial, so reusing the number looks like the honest choice, and it
	// avoids burning a serial per restart. It is wrong. The replayed zone is
	// not byte-identical to what was published under that serial: RRSIGs are
	// regenerated here with fresh inception and expiration. Reusing the number
	// would leave secondaries holding a different image of "serial N" and,
	// because their SOA check sees no change, never transferring the
	// difference. A restart done specifically to refresh signatures nearing
	// expiry would refresh only the primary. It also breaks the
	// same-serial-implies-same-content invariant that updateIxfrChainLocked
	// treats as an error worth resetting IXFR history over -- and if anything
	// else differs (a delta that failed to replay, a key rollover since), that
	// serial names two materially different zones with nothing to reconcile
	// them.
	//
	// So: catch up to lastSerial and publish WITH a bump, landing past it.
	// In unixtime mode the replay has already produced a serial beyond
	// lastSerial, so the branch is skipped and nothing is burnt. The cost --
	// one serial, and one transfer to each secondary -- is paid only by a zone
	// that actually had unspooled changes, and buys those secondaries the
	// regenerated signatures.
	zd.mu.Lock()
	if !serialNewer(zd.CurrentSerial, lastSerial) {
		zd.CurrentSerial = lastSerial
		zd.ensureWorkingSet()
		zd.publishWorkingSetLocked(zd.generation.Load(), true)
	}
	finalSerial := zd.CurrentSerial
	zd.mu.Unlock()

	lg.Info("replayed persisted zone deltas",
		"zone", zd.ZoneName, "deltas", len(deltas),
		"file_serial", fileSerial, "last_published_serial", lastSerial,
		"serial", finalSerial)

	return len(deltas), nil
}

// zoneLooksSigned reports whether the zone carries a DNSKEY RRset at its apex,
// i.e. whether missing RRSIGs would matter to a validator.
func zoneLooksSigned(zd *ZoneData) bool {
	od, err := zd.GetOwner(zd.ZoneName)
	if err != nil || od == nil {
		return false
	}
	rrset, ok := od.RRtypes.Get(dns.TypeDNSKEY)
	return ok && len(rrset.RRs) > 0
}
