/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// ZoneRefreshState is the per-zone answer to "when did we last have proof this
// zone's primary was alive, and which copy was that proof about?".
//
// It is what RFC 1034 §4.3.5 measures SOA EXPIRE from, and it has to survive a
// restart: a process that has forgotten when it last heard from the primary
// cannot tell a copy that is minutes stale from one that expired last week.
//
// Deliberately its own table rather than a column on ZoneFileState, which is
// the obvious-looking home and the wrong one, twice over. SetZoneFileState
// writes with INSERT OR REPLACE naming every column, so a confirmation stamp
// parked there would be silently reset to its default by the very next
// file-identity record -- an expire clock that keeps forgetting. And the two
// are different facts with different lifetimes: "this is the file we hold"
// changes when the file changes, while "the primary was alive at T" changes on
// every confirmation, including the ones that change nothing at all.
type ZoneRefreshState struct {
	Zone string
	// LastConfirmed is when a usable SOA was last seen from a primary. Wall
	// clock, stored UTC. A clock step can expire a zone early or extend it;
	// that is accepted rather than designed around, and there is no injected
	// clock anywhere in this path.
	LastConfirmed time.Time
	// Serial is the copy that confirmation was about, so a restored stamp can
	// be matched against the copy that actually loaded. A cross-check, not a
	// shortcut: the copy is loaded first regardless.
	Serial uint32
}

// SetZoneRefreshState records that a usable SOA was seen for the zone.
func (kdb *KeyDB) SetZoneRefreshState(zone string, serial uint32, when time.Time) error {
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("SetZoneRefreshState: no database")
	}
	zone = dns.Fqdn(zone)

	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	_, err := kdb.DB.Exec(`
INSERT OR REPLACE INTO ZoneRefreshState (zone, last_confirmed, serial)
VALUES (?, ?, ?)`,
		zone, when.UTC().Format(time.RFC3339Nano), serial)
	if err != nil {
		return fmt.Errorf("SetZoneRefreshState: zone %s: %v", zone, err)
	}
	return nil
}

// GetZoneRefreshState returns the zone's last recorded confirmation, and
// whether there is one at all.
//
// "No record" is not an error: it is what every zone looks like against a
// database written by an older tdns, and what a zone looks like that has never
// completed a refresh. The caller starts the expire clock at load time instead
// (Option 3 in the brief) rather than treating the absence as expiry.
func (kdb *KeyDB) GetZoneRefreshState(zone string) (*ZoneRefreshState, bool, error) {
	if kdb == nil || kdb.DB == nil {
		return nil, false, fmt.Errorf("GetZoneRefreshState: no database")
	}
	zone = dns.Fqdn(zone)

	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	var stamp string
	st := ZoneRefreshState{Zone: zone}
	err := kdb.DB.QueryRow(
		`SELECT last_confirmed, serial FROM ZoneRefreshState WHERE zone=?`,
		zone).Scan(&stamp, &st.Serial)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("GetZoneRefreshState: zone %s: %v", zone, err)
	}
	when, perr := time.Parse(time.RFC3339Nano, stamp)
	if perr != nil {
		// A stamp we cannot read is no stamp. Same handling as no row: the
		// caller falls back to load time rather than inventing an instant.
		return nil, false, fmt.Errorf("GetZoneRefreshState: zone %s: unparseable timestamp %q: %v", zone, stamp, perr)
	}
	st.LastConfirmed = when
	return &st, true, nil
}

// DeleteZoneRefreshState drops the recorded confirmation, used when a zone is
// removed.
//
// Not housekeeping. A stamp that outlives its zone is inherited by the next
// zone created under the same name, and if it is already past expire that zone
// is dark from its first bind -- strictly worse than having no stamp at all,
// which is the safe Option 3 path. The serial cross-check at restore time
// catches this too; deleting the row means not depending on it.
func (kdb *KeyDB) DeleteZoneRefreshState(zone string) error {
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("DeleteZoneRefreshState: no database")
	}
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	if _, err := kdb.DB.Exec(`DELETE FROM ZoneRefreshState WHERE zone=?`, dns.Fqdn(zone)); err != nil {
		return fmt.Errorf("DeleteZoneRefreshState: %v", err)
	}
	return nil
}

// noteSuccessfulRefresh records that a primary answered with a usable SOA.
//
// "Usable SOA", not "Refresh returned a nil error". DoTransfer returns
// (false, 0, nil) when at least one primary answered but none gave a usable
// SOA -- all REFUSED, NOERROR with an empty answer, NOERROR whose first RR is
// not an SOA -- and Refresh collapses that to (false, nil), the same pair as
// "serial unchanged". Stamping on a nil error would let a secondary whose
// primaries have revoked its ACL refresh its own expire clock every cycle and
// never expire, which is the exact failure expire exists to prevent.
//
// So this is called from DoTransfer's two usable-SOA returns and nowhere else:
// not from quiet backoff, not from all-unreachable (which returns an error
// anyway), and not from the file adoption at first bind, which is evidence
// about our disk and not about the primary.
//
// An unchanged serial is a confirmation. That is the whole point: it is the
// RFC's proof the primary is alive, and it writes no zone file and no journal,
// so this write stands alone rather than joining a transaction.
func (zd *ZoneData) noteSuccessfulRefresh(serial uint32) {
	if zd == nil {
		return
	}
	now := time.Now()

	zd.mu.Lock()
	zd.LatestRefresh = now
	zd.mu.Unlock()

	if zd.KeyDB == nil {
		// In-memory only. The zone still serves; it just starts a fresh
		// expire budget on the next restart (Option 3).
		return
	}
	if err := zd.KeyDB.SetZoneRefreshState(zd.ZoneName, serial, now); err != nil {
		// Logged, never fatal. A confirmation we could not persist does not
		// make the copy we hold any less valid, and failing the refresh over
		// it would take a zone dark to protect a timestamp.
		lg.Warn("could not persist refresh confirmation", "zone", zd.ZoneName, "serial", serial, "err", err)
	}
}

// restoreRefreshStateAtFirstBind gives a freshly loaded copy its expire budget
// back, and is called only after that copy is in memory.
//
// The stamp is trusted only when it describes the copy that actually loaded.
// A serial that does not match means the stamp is about something else -- a
// hand-placed zone file, a restored backup, a zone re-created under a name
// that was used before -- and an expire budget measured against the wrong copy
// is worse than none, because it can be arbitrarily far in the past.
//
// Anything short of a match falls back to Option 3: start the clock now, and
// say so. That can serve past the true expire by up to one expire interval,
// which is a real deviation from RFC 1034 §4.3.5 and the reason it is logged
// rather than done quietly. The alternative -- treating an unknown stamp as
// expired -- would take every zone dark on every upgrade.
func (zd *ZoneData) restoreRefreshStateAtFirstBind() {
	if zd == nil {
		return
	}
	fallback := func(why string) {
		zd.mu.Lock()
		zd.LatestRefresh = time.Now()
		zd.mu.Unlock()
		lg.Info("no usable refresh confirmation on record; expire budget restarts from now",
			"zone", zd.ZoneName, "reason", why, "serial", zd.IncomingSerial)
	}

	if zd.KeyDB == nil {
		fallback("no database")
		return
	}
	zd.mu.Lock()
	verdict := zd.lastFileVerdict
	zd.mu.Unlock()

	st, ok, err := zd.KeyDB.GetZoneRefreshState(zd.ZoneName)
	switch {
	case err != nil:
		fallback(fmt.Sprintf("unreadable: %v", err))
		return
	case !ok:
		fallback("no record")
		return
	case verdict == ZoneFileChanged:
		// The file is not the one whose identity was recorded, so the
		// confirmation is about content we no longer hold. The serial cannot
		// see this on its own: a zone file can be regenerated, or restored
		// from a backup, reusing the serial it had. That is precisely what
		// the recorded digest exists to catch.
		fallback("the zone file changed since its identity was recorded")
		return
	case st.Serial != zd.IncomingSerial:
		fallback(fmt.Sprintf("recorded for serial %d, loaded copy is serial %d", st.Serial, zd.IncomingSerial))
		return
	}

	zd.mu.Lock()
	zd.LatestRefresh = st.LastConfirmed
	zd.mu.Unlock()
	lg.Info("restored refresh confirmation for the loaded copy",
		"zone", zd.ZoneName, "serial", st.Serial, "lastConfirmed", st.LastConfirmed.UTC().Format(time.RFC3339))
}

// effectiveExpire is the SOA EXPIRE this zone is actually held to, which is not
// always the one the primary published.
//
// Nothing in the protocol stops a primary publishing an EXPIRE of 0, or one
// below its own REFRESH. Taken literally, either expires the secondary before
// it can ever refresh: the zone goes dark on a schedule, driven by data
// somebody else controls. BIND warns about exactly this shape. So an EXPIRE
// below refresh+retry is clamped up to that sum, which is the smallest value
// that leaves room for one refresh and one retry.
//
// Not a ConfigError. The value belongs to the primary, and a zone that is
// otherwise fine should not stop answering over it.
func (zd *ZoneData) effectiveExpire(soa *dns.SOA) time.Duration {
	published := time.Duration(soa.Expire) * time.Second
	floor := time.Duration(soa.Refresh+soa.Retry) * time.Second
	if published >= floor && published > 0 {
		return published
	}

	// Once per zone per load: keyed on the serial of the copy being served, so
	// a zone whose primary keeps publishing a bad EXPIRE says so on each new
	// copy and not on every query.
	zd.mu.Lock()
	first := zd.expireClampLoggedSerial != soa.Serial
	zd.expireClampLoggedSerial = soa.Serial
	zd.mu.Unlock()
	if first {
		lg.Warn("SOA EXPIRE is below refresh+retry; clamping",
			"zone", zd.ZoneName, "serial", soa.Serial,
			"published", published, "refresh+retry", floor, "using", floor)
	}
	return floor
}

// HasExpired reports whether this zone has gone past its SOA EXPIRE and must
// stop answering. RFC 1034 §4.3.5: a secondary serves the copy it holds until
// EXPIRE has elapsed since the last *successful* refresh, and then stops.
//
// False for everything that cannot expire, so callers need no role test of
// their own:
//
//   - primaries, which originate their data and have nothing to expire against
//   - every app type other than tdns-auth, matching the scoping
//     2026-07-25-secondary-zones-immutable.md §1.1 treats as load-bearing:
//     expire is a statement about authoritative service
//   - a zone holding nothing, which HasPublishedData already refuses, and
//   - a zone with no confirmation on record at all, which is the permissive
//     direction and the one Stage 1 shipped
//
// Expire is deliberately NOT a service-impacting error. That list is consulted
// by the refresh ticker, which skips the zones on it -- an expired zone would
// then have no way back. Instead the zone keeps being refreshed, and the next
// usable SOA moves LatestRefresh forward and un-expires it with no further
// machinery.
func (zd *ZoneData) HasExpired() bool {
	if zd == nil || zd.ZoneType != Secondary || Globals.App.Type != AppTypeAuth {
		return false
	}
	snap := zd.publishedSnapshot()
	if snap == nil || snap.SOA == nil {
		return false
	}

	zd.mu.Lock()
	last := zd.LatestRefresh
	zd.mu.Unlock()
	if last.IsZero() {
		return false
	}

	return time.Now().After(last.Add(zd.effectiveExpire(snap.SOA)))
}
