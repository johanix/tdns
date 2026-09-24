/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The journal as an overlay on every full transfer, for a zone that transfers
// its content and signs it itself. See
// docs/2026-09-24-journal-overlay-on-transfer.md.
//
// Transfers are never journalled, so such a zone's journal holds exactly what
// this server has added to its upstream's zone. Its own records there -- the
// DS engine's CDS, delegation sync's CSYNC -- have no second source: a full
// transfer replaces the zone, and CollectDynamicRRs puts back only the keys
// and the transport signals. So every full replacement applies them again,
// and then compacts the journal to what it applied.

// overlayZonePredicate says whether a zone is an overlay zone: tdns-auth or
// tdns-signer (both run as AppTypeAuth), a secondary, inline-signing, and not
// multi-provider. On a multi-provider zone the combiner's zone and the key
// lifecycle owner decide the CDS (ownedZoneCDS), and the journal could hold an
// older one.
//
// Not zoneMayOriginateContent: that is true for every app other than
// tdns-auth, and a derived app's secondary must not get an overlay.
func overlayZonePredicate(app AppType, zoneType ZoneType, opts map[ZoneOption]bool) bool {
	return app == AppTypeAuth && zoneType == Secondary && opts[OptInlineSigning] && !opts[OptMultiProvider]
}

// isOverlayZoneLocked asks the predicate for zd. The caller holds zd.mu: a
// config reload replaces zd.Options wholesale under that lock.
func (zd *ZoneData) isOverlayZoneLocked() bool {
	return overlayZonePredicate(Globals.App.Type, zd.ZoneType, zd.Options)
}

// isOverlayZone is isOverlayZoneLocked for a caller that does not hold zd.mu.
func (zd *ZoneData) isOverlayZone() bool {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return zd.isOverlayZoneLocked()
}

// overlayTypes are the records this server originates for its parent, and the
// only ones overlaid. An allowlist, not a filter: DNSKEY and KEY come from the
// keystore, and the journal's copy could bring back a key it has retired;
// local edits to the upstream's data stay lost at a full transfer, as they
// always were. CDNSKEY is not generated today. It is listed so that a DS-engine
// change that journals one is covered.
var overlayTypes = map[uint16]bool{
	dns.TypeCDS:     true,
	dns.TypeCDNSKEY: true,
	dns.TypeCSYNC:   true,
}

// overlayRecord is one record's net instruction.
type overlayRecord struct {
	add bool
	rr  dns.RR
	// inTransfer: the transferred zone held the record before the overlay was
	// applied. It decides what compaction keeps of a delete.
	inTransfer bool
}

// journalOverlay is what one replacement read from the journal and applied.
type journalOverlay struct {
	records []overlayRecord
	// throughID is the highest row read. Compaction replaces those rows and no
	// others.
	throughID int64
	// unreadable: a row did not parse. Compacting would drop it, so the
	// journal is left as it is.
	unreadable bool
}

// netOverlay reduces the journal to the net effect of the zone's own records
// at its apex: one instruction per record, the last one winning, records
// compared as rrKey compares them (owner, type, RDATA; the TTL aside). Three
// CDS publishes are one CDS, not three adds and two deletes.
func netOverlay(zone string, insns []ZoneDeltaRR) (recs []overlayRecord, unreadable bool) {
	at := map[string]int{}
	for _, insn := range insns {
		rr, err := dns.NewRR(insn.RR)
		if err != nil || rr == nil || (insn.Action != ZoneDeltaAdd && insn.Action != ZoneDeltaDel) {
			lg.Error("journal overlay: a journal row cannot be read; it is not applied, and the journal"+
				" is not compacted", "zone", zone, "action", insn.Action, "row", insn.RR, "error", err)
			unreadable = true
			continue
		}
		if !overlayTypes[rr.Header().Rrtype] || !core.EqualNames(rr.Header().Name, zone) {
			continue
		}
		rr.Header().Class = dns.ClassINET
		rec := overlayRecord{add: insn.Action == ZoneDeltaAdd, rr: rr}
		k := rrKey(rr)
		if i, seen := at[k]; seen {
			recs[i] = rec
			continue
		}
		at[k] = len(recs)
		recs = append(recs, rec)
	}
	return recs, unreadable
}

// applyJournalOverlayLocked applies the net effect of the zone's own records
// in the journal to new_zd, the content a full replacement is about to
// publish. The caller holds zd.mu, and keeps holding it through the publish
// and the compaction, so no local change can land between this read and the
// compaction.
//
// The server's copy wins for these types: a journalled delete removes the
// transferred record, and a journalled add is applied. The IXFR applier's
// primitives refuse an add already present and a delete of an absent record,
// so both are skipped here first.
//
// nil when there is nothing to apply or compact.
func (zd *ZoneData) applyJournalOverlayLocked(new_zd *ZoneData) *journalOverlay {
	insns, throughID, err := zd.JournalInstructions()
	if err != nil {
		lg.Error("journal overlay: the journal could not be read; this server's own records are"+
			" not applied to this transfer", "zone", zd.ZoneName, "error", err)
		return nil
	}
	if throughID <= 0 {
		return nil
	}
	recs, unreadable := netOverlay(zd.ZoneName, insns)
	ov := &journalOverlay{records: recs, throughID: throughID, unreadable: unreadable}

	var replaced []string
	for i := range ov.records {
		rec := &ov.records[i]
		rec.inTransfer = dataHasRR(new_zd.Data, rec.rr)
		var aerr error
		switch {
		case rec.add && !rec.inTransfer:
			aerr = applyIxfrAdd(new_zd.Data, rec.rr)
		case !rec.add && rec.inTransfer:
			if aerr = applyIxfrRemove(new_zd.Data, rec.rr); aerr == nil {
				replaced = append(replaced, rec.rr.String())
			}
		}
		if aerr != nil {
			lg.Error("journal overlay: a journalled record could not be applied to the transfer",
				"zone", zd.ZoneName, "record", rec.rr.String(), "error", aerr)
		}
	}
	// One line per transfer, not a ConfigWarning: there is no artefact for an
	// operator to act on, and the same conflict would warn at every transfer.
	if len(replaced) > 0 {
		lg.Warn("journal overlay: the upstream serves records of this server's own types that its"+
			" journal removed; serving the journal's instead",
			"zone", zd.ZoneName, "removed", replaced)
	}
	return ov
}

// dataHasRR reports whether data holds rr, TTL aside.
func dataHasRR(data *core.NameMap[OwnerData], rr dns.RR) bool {
	if data == nil {
		return false
	}
	nod, ok := data.Get(rr.Header().Name)
	if !ok {
		return false
	}
	rs, ok := nod.RRtypes.Get(rr.Header().Rrtype)
	return ok && containsRR(rs.RRs, rr)
}

// compactOverlayJournalLocked replaces the rows the overlay read with one
// delta, from CurrentSerial-1 to CurrentSerial, holding what the overlay still
// has to do. The caller holds zd.mu, as it did for the read.
//
// Kept: every add, including one the transfer already has. That is local
// intent; if the upstream withdraws the record later, the next full transfer
// must put it back. And deletes of records the transfer has.
//
// Dropped: deletes of records the transfer lacks. They do nothing now, and
// must not delete the record if the upstream adds it again later. And rows of
// every other type, which the transfer has superseded.
//
// A failure is logged, not returned. The zone already serves the overlay, the
// rows left in place still carry it, and the next full replacement tries
// again.
func (zd *ZoneData) compactOverlayJournalLocked(ov *journalOverlay) {
	if ov.unreadable {
		return
	}
	var removed, added []dns.RR
	for _, rec := range ov.records {
		switch {
		case rec.add:
			added = append(added, rec.rr)
		case rec.inTransfer:
			removed = append(removed, rec.rr)
		}
	}
	if len(removed) == 0 && len(added) == 0 {
		// ReplaceZoneJournal refuses an empty replacement.
		if _, err := zd.KeyDB.DeleteZoneDeltasThroughID(zd.ZoneName, ov.throughID); err != nil {
			lg.Error("journal overlay: the journal could not be cleared after a full transfer;"+
				" the next one tries again", "zone", zd.ZoneName, "error", err)
		}
		return
	}
	serial := zd.CurrentSerial
	if err := zd.KeyDB.ReplaceZoneJournal(zd.ZoneName, serial-1, serial,
		[]core.RRset{{RRs: removed}}, []core.RRset{{RRs: added}}, ov.throughID); err != nil {
		lg.Error("journal overlay: the journal could not be compacted after a full transfer;"+
			" the next one tries again", "zone", zd.ZoneName, "error", err)
	}
}
