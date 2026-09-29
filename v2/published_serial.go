/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// The published-serial floor (#655, docs/2026-09-27-DONE-published-serial-floor.md).
//
// A zone that originates content must never publish, after a restart, a serial
// at or below one it published before the restart: a secondary holding that
// serial does not transfer, and a serial reused with other content is a change
// it never receives short of an AXFR. The journal cannot be the record of how
// far a zone got, because most publishes write nothing to it -- re-signs,
// DNSKEY publishes, serial bumps, signal synthesis. So every publish records
// its serial in OutgoingSerials, in every outbound-soa-serial mode, and the
// first load lifts the serial past it.

// serialRecordWarning prefixes the ConfigWarning raised when a published serial
// cannot be recorded, so a later successful record clears that warning and no
// other.
const serialRecordWarning = "the published serial could not be recorded"

// recordPublishedSerialLocked records serial as the highest this zone has
// published, unless the record already holds a newer one. The caller holds
// zd.mu and is about to make serial visible.
//
// A failed write does not refuse the publish. Refusing would stop re-signing,
// and a zone whose signatures expire goes bogus, which is worse than a
// possible serial regression at a later restart. It raises a ConfigWarning,
// visible on `zone status`, and leaves Ready alone. The next publish records
// its own serial, so one failed write corrects itself, and clears the warning.
//
// A zone that may not originate content records nothing: its serial is
// upstream's, and its row is deleted elsewhere (MUST-NOT-MODIFY).
func (zd *ZoneData) recordPublishedSerialLocked(serial uint32) {
	if zd.KeyDB == nil || zd.KeyDB.DB == nil || !zoneMayOriginateContent(zd) {
		return
	}
	if err := zd.KeyDB.RaiseOutgoingSerial(zd.ZoneName, serial); err != nil {
		lg.Error("publish: could not record the published serial; a restart may publish"+
			" serials this zone has already served",
			"zone", zd.ZoneName, "serial", serial, "err", err)
		if !zd.serialRecordFailed {
			zd.serialRecordPrevWarning = zd.snapshotErrorsLocked(ConfigWarning)
			zd.serialRecordFailed = true
		}
		zd.setErrorLocked(ConfigWarning, "%s (serial %d): %v", serialRecordWarning, serial, err)
		return
	}
	if zd.serialRecordFailed {
		// Put back what the warning displaced -- unless something else has
		// raised a ConfigWarning since, which is not ours to clear.
		if cur, ok := zd.Errors[ConfigWarning]; ok && strings.HasPrefix(cur.Msg, serialRecordWarning) {
			zd.restoreErrorsLocked(zd.serialRecordPrevWarning, ConfigWarning)
		}
		zd.serialRecordFailed = false
		zd.serialRecordPrevWarning = nil
	}
}

// PublishedSerialFloor returns the highest serial zone is known to have
// published, and whether anything is known at all: the newer, in RFC 1982
// order, of the recorded published serial and the journal's tail.
//
// The tail matters only for a database written by a build that recorded the
// serial in persist mode alone. Every serial in the journal was published, so
// the tail is a lower bound on the record, and on such a database it is the
// only bound there is -- for a file-backed zone and an overlay zone alike.
//
// A missing record is not an error; any other failure to read either is.
func (kdb *KeyDB) PublishedSerialFloor(zone string) (uint32, bool, error) {
	if kdb == nil || kdb.DB == nil {
		return 0, false, fmt.Errorf("PublishedSerialFloor: no database")
	}
	high, have := uint32(0), false
	recorded, err := kdb.LoadOutgoingSerial(zone)
	switch {
	case err == nil:
		high, have = recorded, true
	case !errors.Is(err, sql.ErrNoRows):
		return 0, false, err
	}
	tail, haveTail, err := kdb.LastZoneDeltaSerial(zone)
	if err != nil {
		return 0, false, err
	}
	if haveTail && (!have || serialNewer(tail, high)) {
		high, have = tail, true
	}
	return high, have, nil
}
