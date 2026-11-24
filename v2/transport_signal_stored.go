/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// What the transport-signal start-up pass stored, per owner, so that a later
// run tells its own signal from records provisioned in the zone (design
// 2026-11-14 section 5; the maintainer's ruling on plan step S2,
// 2026-11-15). The pass leaves provisioned records alone, replaces its own
// signal with what the configuration gives now, and withdraws it from a name
// that is no longer an identity at home in the zone. Its own signal is zone
// content, and a journal replay or a persisted copy brings it back after a
// restart, so the record is kept in the KeyDB as well as in memory. Without
// a KeyDB the record lasts as long as the process. Matching what the
// configuration gives is never taken as the pass's own: an operator may
// write exactly that.
//
// The record keeps the digests of the signals the pass stored before the
// last one, too. The pass stores a signal into the working set; it reaches
// the zone file only when the zone is next written (WriteZoneToFile writes
// every RRset), which may be much later or never. A restart in between
// loads whatever signal the file holds, which is then an earlier one of the
// pass's, not the last. Known by the last digest alone, it would be taken
// for the operator's and kept for good. Up to signalStoredKeep digests are
// kept, newest first.

// signalStoredKeep is how many digests the record keeps per owner.
const signalStoredKeep = 8

// signalDigest is a digest of an RRset's records, TTL and order aside, and
// names compared without case, as dns.IsDuplicate compares them.
func signalDigest(rrs []dns.RR) string {
	lines := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		c := dns.Copy(rr)
		c.Header().Ttl = 0
		lines = append(lines, strings.ToLower(c.String()))
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// signalRecordDB is the KeyDB the record is kept in, or nil when there is
// none behind the zone: the record then lasts as long as the process.
func (zd *ZoneData) signalRecordDB() *KeyDB {
	if zd.KeyDB == nil || zd.KeyDB.DB == nil {
		return nil
	}
	return zd.KeyDB
}

// noteSignalStored records that the signal pass stored rrs at owner, in
// memory and in the KeyDB, ahead of the digests of what it stored there
// before. The earlier digests are read first (signalStoredDigests), and the
// write is SetTransportSignalStored after a read and
// PrependTransportSignalStored after a failed one. With D the new digest and
// E the digests read (or, unread, those the record holds), the four outcomes:
//
//   - Read ok, write ok: memory [D E], the record [D E], signalUnrecorded
//     cleared. The next run reads memory: the signal is the pass's.
//   - Read ok, write fails: memory [D E], the record unchanged,
//     signalUnrecorded cleared (its digests are in E). The next run reads
//     memory: the signal is the pass's. After a restart the record lacks D,
//     so a zone that holds this signal reads as the operator's, which the
//     warning says.
//   - Read fails, prepend ok: memory unset, the record [D E]. The next run
//     reads the record: the signal is the pass's once the record reads, and
//     is left as it is while it does not. Memory holding [D] alone would be
//     what the next store reads, without the KeyDB, and writes back whole,
//     dropping E.
//   - Read fails, prepend fails, as with the earlier column missing: memory
//     unset, the record unchanged, D kept in signalUnrecorded. The next run
//     knows the signal for the pass's without a read (signalStoredByPass),
//     and its next store that reads the record writes [D E], clearing
//     signalUnrecorded. A restart forgets D, as in the second case.
//
// In every case the next store that reads the record writes the new digest
// ahead of every digest kept, never a shorter list.
func (zd *ZoneData) noteSignalStored(owner string, rrs []dns.RR) {
	zd.noteSignalStoredOver(owner, rrs, nil)
}

// noteSignalStoredOver is noteSignalStored for a store that replaced
// replaced, a signal of the pass's that was staged at the owner. Right
// behind the new digest it keeps those of the signals of the pass's the zone
// can still serve or load at the owner, so the history never evicts them:
// the replaced one, the one the zone serves (signalServedDigest), and the
// one the zone file holds (signalOnDiskDigest) or may still hold after a
// crash (signalOnDiskPrevDigests), the ones a write of the zone file in
// progress is putting in it (signalWritingDigests), and the ones a replay of
// the journal can yield (signalJournaledDigests). Each would
// otherwise be held only by its place in the signalStoredKeep places, and a
// run of stores would push it out: stores the publish cadence holds back
// push out the signal still served, stores with no zone write in between,
// one per restart with a configuration that changed each time or several in
// one process, push out the zone file's, which a restart loads until the
// zone is next written, stores published while a write runs push out the
// signal it writes, and stores published with no journal entry push out the
// signal an earlier journaled publish carried, which a restart replays. The
// pass would then take a signal of its own for the operator's for good, in
// this process or after the next restart (CodeRabbit on #1118 and on
// #1145). None of them takes one of those places from another: the record
// holds them all, past signalStoredKeep if need be (mergeSignalDigests).
func (zd *ZoneData) noteSignalStoredOver(owner string, rrs, replaced []dns.RR) {
	owner = core.CanonicalizeName(owner)
	digest := signalDigest(rrs)
	earlier, readErr := zd.signalStoredDigests(owner)
	if readErr != nil {
		lgDns.Warn("noteSignalStored: could not read the earlier digests; the new one is put ahead of what the KeyDB holds",
			"zone", zd.ZoneName, "owner", owner, "error", readErr)
	}
	digests := []string{digest}
	if len(replaced) > 0 {
		digests = append(digests, signalDigest(replaced))
	}
	if served := zd.signalServedDigest(owner, append(slices.Clone(digests), earlier...)); served != "" {
		digests = append(digests, served)
	}
	if onDisk := zd.signalOnDiskDigest(owner, replaced); onDisk != "" {
		digests = append(digests, onDisk)
	}
	digests = append(digests, zd.signalOnDiskPrevDigests(owner)...)
	digests = append(digests, zd.signalWritingDigests(owner)...)
	digests = append(digests, zd.signalJournaledDigests(owner, earlier, readErr == nil)...)
	digests = mergeSignalDigests(digests, earlier)
	if readErr == nil {
		// The digests read include those the KeyDB had not taken
		// (signalStoredDigests); the record in memory holds them now.
		zd.signalStoredMu.Lock()
		if zd.signalStored == nil {
			zd.signalStored = map[string][]string{}
		}
		zd.signalStored[owner] = digests
		delete(zd.signalUnrecorded, owner)
		zd.signalStoredMu.Unlock()
	}
	kdb := zd.signalRecordDB()
	if kdb == nil {
		return
	}
	write := func() error { return kdb.SetTransportSignalStored(zd.ZoneName, owner, digests) }
	if readErr != nil {
		write = func() error { return kdb.PrependTransportSignalStored(zd.ZoneName, owner, digest) }
	}
	if err := write(); err != nil {
		lgDns.Warn("noteSignalStored: could not record the stored signal; after a restart it may be taken for the operator's",
			"zone", zd.ZoneName, "owner", owner, "error", err)
		if readErr != nil {
			zd.noteSignalUnrecorded(owner, digest)
		}
	}
}

// noteSignalUnrecorded keeps digest, a signal the pass stored at owner that
// neither the in-memory record nor the KeyDB holds, ahead of the others it
// keeps there (signalUnrecorded).
func (zd *ZoneData) noteSignalUnrecorded(owner, digest string) {
	zd.signalStoredMu.Lock()
	defer zd.signalStoredMu.Unlock()
	if zd.signalUnrecorded == nil {
		zd.signalUnrecorded = map[string][]string{}
	}
	zd.signalUnrecorded[owner] = mergeSignalDigests([]string{digest}, zd.signalUnrecorded[owner])
}

// signalServedDigest returns the digest of the SVCB RRset the zone serves
// at owner (the published snapshot) when known, the digests the record
// holds for the pass's, has it: the pass's signal served there. "" when the
// zone serves none there, or serves an RRset the record does not know for
// the pass's. Caller holds zd.mu, as the pass does.
func (zd *ZoneData) signalServedDigest(owner string, known []string) string {
	rrset := getRRsetFrom(zd.publishedSnapshot(), owner, dns.TypeSVCB)
	if rrset == nil || len(rrset.RRs) == 0 {
		return ""
	}
	if d := signalDigest(rrset.RRs); slices.Contains(known, d) {
		return d
	}
	return ""
}

// signalOnDiskDigest returns the digest of the pass's signal the zone file
// holds at owner, "" when it holds none. A load or a refresh that adopts
// the zone file sets it (noteZoneFileAdopted), and a zone write moves it
// (noteZoneFileWritten). Failing both, the first store at the owner in this
// process sets it from what that store replaced: the zone has not been
// written since it loaded, so the working set holds what the file gave, or
// nothing of the pass's.
func (zd *ZoneData) signalOnDiskDigest(owner string, replaced []dns.RR) string {
	zd.signalStoredMu.Lock()
	defer zd.signalStoredMu.Unlock()
	if d, ok := zd.signalOnDisk[owner]; ok {
		return d
	}
	d := ""
	if len(replaced) > 0 {
		d = signalDigest(replaced)
	}
	if zd.signalOnDisk == nil {
		zd.signalOnDisk = map[string]string{}
	}
	zd.signalOnDisk[owner] = d
	return d
}

// noteZoneFileWritten moves what signalOnDiskDigest returns, for each owner
// the pass stored at in this process or a replay of the journal yields a
// signal of the pass's at, to what the zone file now holds there (snap, the
// snapshot written): the pass's signal, or nothing. An SVCB RRset there
// that the record does not know for the pass's leaves it as it was:
// keeping that digest would take the operator's records for the pass's.
// durable says the rename that put the file in place is on disk. When it
// is not, a crash can bring back the file it replaced, so the signal that
// file held is kept beside the new one (signalOnDiskPrevDigests) until a
// durable write (CodeRabbit on #1145).
func (zd *ZoneData) noteZoneFileWritten(snap *zoneSnapshot, durable bool) {
	if snap == nil {
		return
	}
	zd.signalStoredMu.Lock()
	defer zd.signalStoredMu.Unlock()
	if durable {
		zd.signalOnDiskPrev = nil
	}
	for _, owner := range zd.signalFileOwnersLocked() {
		was, had := zd.signalOnDisk[owner]
		now := was
		if rrset := getRRsetFrom(snap, owner, dns.TypeSVCB); rrset == nil || len(rrset.RRs) == 0 {
			now = ""
		} else if d := signalDigest(rrset.RRs); zd.signalKnownLocked(owner, d) {
			now = d
		} else if !had {
			continue
		}
		if zd.signalOnDisk == nil {
			zd.signalOnDisk = map[string]string{}
		}
		zd.signalOnDisk[owner] = now
		if !durable && had && was != "" && was != now {
			zd.keepOnDiskPrevLocked(owner, was)
		}
	}
	zd.fileJournalPinsLocked(snap, durable)
}

// keepOnDiskPrevLocked keeps d, the signal of the pass's a zone file whose
// replacement is not yet on disk held at owner (signalOnDiskPrevDigests).
// Caller holds signalStoredMu.
func (zd *ZoneData) keepOnDiskPrevLocked(owner, d string) {
	if slices.Contains(zd.signalOnDiskPrev[owner], d) {
		return
	}
	if zd.signalOnDiskPrev == nil {
		zd.signalOnDiskPrev = map[string][]string{}
	}
	zd.signalOnDiskPrev[owner] = append(zd.signalOnDiskPrev[owner], d)
}

// fileJournalPinsLocked marks each signal a replay of the journal can yield
// (signalJournaled) that the zone file now holds, snap being the snapshot
// written: filed. A verified one this write has already followed into the
// zone file's (noteZoneFileWritten). An unverified one the file holds stays
// past the drop of the journal (noteJournalDropped), until the next store
// that reads the record settles it (signalJournaledDigests): once the
// journal is gone the file is what holds the signal, and a write that
// dropped the pin with the journal kept nothing for the file it went into.
// A filed one that this write replaced stays filed while the rename is not
// on disk, since a crash can bring its file back; a verified one goes to
// signalOnDiskPrev then, as the zone file's own signal would (CodeRabbit on
// #1145). Caller holds signalStoredMu.
func (zd *ZoneData) fileJournalPinsLocked(snap *zoneSnapshot, durable bool) {
	for owner, pins := range zd.signalJournaled {
		holds := ""
		if rrset := getRRsetFrom(snap, owner, dns.TypeSVCB); rrset != nil && len(rrset.RRs) > 0 {
			holds = signalDigest(rrset.RRs)
		}
		for i := range pins {
			switch {
			case pins[i].digest == holds:
				pins[i].filed = true
			case !pins[i].filed || durable:
				pins[i].filed = false
			case pins[i].verified:
				zd.keepOnDiskPrevLocked(owner, pins[i].digest)
				pins[i].filed = false
			}
		}
	}
}

// signalFileOwnersLocked returns the owners a write of the zone file
// follows: those of signalOnDisk and those a replay of the journal yields a
// signal of the pass's at (signalJournaled). Caller holds signalStoredMu.
func (zd *ZoneData) signalFileOwnersLocked() []string {
	owners := make([]string, 0, len(zd.signalOnDisk)+len(zd.signalJournaled))
	for owner := range zd.signalOnDisk {
		owners = append(owners, owner)
	}
	for owner, pins := range zd.signalJournaled {
		if _, ok := zd.signalOnDisk[owner]; !ok && slices.ContainsFunc(pins, func(p signalJournalPin) bool { return p.verified }) {
			owners = append(owners, owner)
		}
	}
	return owners
}

// signalKnownLocked reports whether the record in memory knows digest d at
// owner for the pass's: one of the digests read or stored in this process
// (signalStored, signalUnrecorded), or a signal a replay of the journal
// yields there that the KeyDB's record knew (signalJournaled). A process
// that only replayed the journal has stored nothing at the owner yet, and
// without the last its zone write would leave the zone file's digest at
// the file it replaced while the journal that held the signal is dropped
// (CodeRabbit on #1145). Caller holds signalStoredMu.
func (zd *ZoneData) signalKnownLocked(owner, d string) bool {
	return slices.Contains(zd.signalStored[owner], d) || slices.Contains(zd.signalUnrecorded[owner], d) ||
		slices.ContainsFunc(zd.signalJournaled[owner], func(p signalJournalPin) bool { return p.verified && p.digest == d })
}

// signalOnDiskPrevDigests returns the digests of the pass's signals at
// owner that zone files replaced by writes whose rename is not yet on disk
// held: a crash can bring one back (noteZoneFileWritten).
func (zd *ZoneData) signalOnDiskPrevDigests(owner string) []string {
	zd.signalStoredMu.Lock()
	defer zd.signalStoredMu.Unlock()
	return slices.Clone(zd.signalOnDiskPrev[owner])
}

// holdSignalsWritten takes the published snapshot for a write of the
// zone's own file, and until release keeps the digest of the pass's signal
// it holds at each owner noteZoneFileWritten follows
// (signalFileOwnersLocked), by noteZoneFileWritten's rule: the record knows
// it for the pass's (signalKnownLocked). Stores
// that run while the file is written can publish newer signals, and each
// keeps the served one and the zone file's, not the one being written: a
// run of them would push it out of the record, and noteZoneFileWritten,
// not finding it there, would leave the zone file's digest at the earlier
// signal, which a restart then loads while the record does not know it
// (CodeRabbit on #1145). The snapshot is taken under signalStoredMu, so
// that no store records between taking it and holding what it holds.
// Release once the write has failed or noteZoneFileWritten has followed it.
func (zd *ZoneData) holdSignalsWritten() (*zoneSnapshot, func()) {
	zd.signalStoredMu.Lock()
	defer zd.signalStoredMu.Unlock()
	snap := zd.publishedSnapshot()
	held := map[string]string{}
	for _, owner := range zd.signalFileOwnersLocked() {
		rrset := getRRsetFrom(snap, owner, dns.TypeSVCB)
		if rrset == nil || len(rrset.RRs) == 0 {
			continue
		}
		if d := signalDigest(rrset.RRs); zd.signalKnownLocked(owner, d) {
			held[owner] = d
		}
	}
	if len(held) == 0 {
		return snap, func() {}
	}
	if zd.signalWriting == nil {
		zd.signalWriting = map[uint64]map[string]string{}
	}
	zd.signalWritingSeq++
	id := zd.signalWritingSeq
	zd.signalWriting[id] = held
	return snap, func() {
		zd.signalStoredMu.Lock()
		delete(zd.signalWriting, id)
		zd.signalStoredMu.Unlock()
	}
}

// signalWritingDigests returns the digests holdSignalsWritten holds at
// owner for the writes of the zone file in progress.
func (zd *ZoneData) signalWritingDigests(owner string) []string {
	zd.signalStoredMu.Lock()
	defer zd.signalStoredMu.Unlock()
	var out []string
	for _, held := range zd.signalWriting {
		if d, ok := held[owner]; ok && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}

// signalJournalPin is a signal that a replay of the zone's journal can
// yield at an owner, and the serial of the newest journal delta that set it
// there (signalJournaled). verified says the KeyDB's record knew it for the
// pass's. An unverified one was set when the record could not be read, and
// the next store that reads it settles which it is (signalJournaledDigests).
// filed says the zone file holds it, or may hold it again after a crash
// (fileJournalPinsLocked).
type signalJournalPin struct {
	digest   string
	serial   uint32
	verified bool
	filed    bool
}

// signalOwnersInDelta returns the _dns. owners whose SVCB RRset a journal
// delta changes: the owner of each SVCB RRset among removed and added.
func signalOwnersInDelta(removed, added []core.RRset) []string {
	var owners []string
	for _, rs := range append(append([]core.RRset(nil), removed...), added...) {
		owner := core.CanonicalizeName(rs.Name)
		if rs.RRtype == dns.TypeSVCB && strings.HasPrefix(owner, "_dns.") && !slices.Contains(owners, owner) {
			owners = append(owners, owner)
		}
	}
	return owners
}

// signalOwnersInActions returns the _dns. owners whose SVCB RRset replayed
// update actions can change: an SVCB action, or one deleting every RRset at
// the owner.
func signalOwnersInActions(actions []dns.RR) []string {
	var owners []string
	for _, rr := range actions {
		h := rr.Header()
		owner := core.CanonicalizeName(h.Name)
		if (h.Rrtype == dns.TypeSVCB || h.Rrtype == dns.TypeANY) && strings.HasPrefix(owner, "_dns.") && !slices.Contains(owners, owner) {
			owners = append(owners, owner)
		}
	}
	return owners
}

// noteSignalsJournaled records, for each of owners, _dns. owners whose SVCB
// RRset journal deltas up to serial changed, a signal a replay of the
// journal can yield there: the SVCB RRset snap holds at the owner, snap
// being the zone those deltas were published or replayed into. A signal the
// record knows for the pass's is kept in every store until a zone write
// drops those deltas (noteJournalDropped). One the record does not know is
// not kept. When the record cannot be read, the signal is kept unverified,
// and the next store that reads the record keeps it if the record knows it
// and drops it if not (signalJournaledDigests): a process that has just
// replayed the journal has nothing else to keep it by (CodeRabbit on
// #1145).
//
// What was kept for earlier deltas stays, whatever snap holds now. The
// stores of the pass are published with no journal entry, so the journal
// does not replay to the zone served: a delta removes only the records the
// zone held before its publish, and a signal an earlier delta added, which
// a store has replaced since, comes back on a replay though snap holds no
// SVCB RRset at the owner (CodeRabbit on #1145). A stored signal that rode
// in a journaled publish of another writer's change, and was then replaced
// by such stores, was held only by its place in the record, and a run of
// them pushed it out while the journal still held it: a restart replayed it
// and took it for the operator's (CodeRabbit on #1145). Caller holds zd.mu.
func (zd *ZoneData) noteSignalsJournaled(owners []string, snap *zoneSnapshot, serial uint32) {
	for _, owner := range owners {
		rrset := getRRsetFrom(snap, owner, dns.TypeSVCB)
		if rrset == nil || len(rrset.RRs) == 0 {
			continue
		}
		pin := signalJournalPin{digest: signalDigest(rrset.RRs), serial: serial, verified: true}
		known, err := zd.signalStoredDigests(owner)
		if err != nil {
			lgDns.Warn("noteSignalsJournaled: could not read the record of what the pass stored at the owner; the signal the journal replays there is kept until a store can read it",
				"zone", zd.ZoneName, "owner", owner, "error", err)
			pin.verified = false
		} else if !slices.Contains(known, pin.digest) {
			continue
		}
		zd.signalStoredMu.Lock()
		if zd.signalJournaled == nil {
			zd.signalJournaled = map[string][]signalJournalPin{}
		}
		pins := zd.signalJournaled[owner]
		if i := slices.IndexFunc(pins, func(p signalJournalPin) bool { return p.digest == pin.digest }); i >= 0 {
			if serialNewer(pin.serial, pins[i].serial) {
				pins[i].serial = pin.serial
			}
			pins[i].verified = pins[i].verified || pin.verified
		} else {
			zd.signalJournaled[owner] = append(pins, pin)
		}
		zd.signalStoredMu.Unlock()
	}
}

// signalJournaledDigests returns the digests of the pass's signals a replay
// of the journal can yield at owner (noteSignalsJournaled), for a store to
// keep. known is the record the store read, and readOK says it could read
// it: an unverified signal the record knows becomes verified and is kept,
// and one it does not know is dropped, so that the operator's records
// never become the pass's. With no record read, an unverified one is left
// as it is.
func (zd *ZoneData) signalJournaledDigests(owner string, known []string, readOK bool) []string {
	zd.signalStoredMu.Lock()
	defer zd.signalStoredMu.Unlock()
	var out []string
	pins := zd.signalJournaled[owner][:0]
	for _, p := range zd.signalJournaled[owner] {
		if !p.verified && readOK {
			if !slices.Contains(known, p.digest) {
				continue
			}
			p.verified = true
		}
		if p.verified {
			out = append(out, p.digest)
		}
		pins = append(pins, p)
	}
	if len(pins) == 0 {
		delete(zd.signalJournaled, owner)
	} else if zd.signalJournaled != nil {
		zd.signalJournaled[owner] = pins
	}
	return out
}

// noteJournalDropped ends what noteSignalsJournaled keeps for the journal
// deltas a zone write has dropped: those whose serial is not newer than
// serial, the one the zone file was written at, which holds what they did.
// An unverified one the zone file holds stays until a read of the record
// settles it (fileJournalPinsLocked).
func (zd *ZoneData) noteJournalDropped(serial uint32) {
	zd.signalStoredMu.Lock()
	defer zd.signalStoredMu.Unlock()
	for owner, pins := range zd.signalJournaled {
		pins = slices.DeleteFunc(pins, func(p signalJournalPin) bool {
			return !serialNewer(p.serial, serial) && (p.verified || !p.filed)
		})
		if len(pins) == 0 {
			delete(zd.signalJournaled, owner)
		} else {
			zd.signalJournaled[owner] = pins
		}
	}
}

// noteZoneFileAdopted sets what signalOnDiskDigest returns, for each owner
// the record holds, to what the zone file a load or a refresh has just
// adopted holds there (file, the zone data parsed from it, before the
// refresh adds anything), by noteZoneFileWritten's rule: "" when the file
// holds no SVCB RRset there, its digest when the record knows that for the
// pass's, and as it was when the record does not, or cannot be read. When
// the KeyDB's list of owners cannot be read, only the owners known in this
// process follow the file. A reload that adopts a file holding a signal of
// the pass's other than the one last written left that signal held only by
// its place in the record, and a run of stores pushed it out while the file
// still held it (CodeRabbit on #1145). Caller holds zd.mu, so that no store
// runs in between.
//
// read is the stat of the zone file taken before it was read. The note is
// made only while that file is still the one in place, checked under
// zoneFileMu, so that no write renames another over it in between: a write
// that put a newer file in place while the refresh ran has noted that file,
// and the older file read must not take its place. With no stat, the note
// is made. The signals kept for files a crash can bring back
// (signalOnDiskPrevDigests) stay: a reload does not put a rename on disk
// (CodeRabbit on #1145).
func (zd *ZoneData) noteZoneFileAdopted(file *core.NameMap[OwnerData], read os.FileInfo) {
	if file == nil {
		return
	}
	owners, err := zd.signalStoredOwners()
	if err != nil {
		lgDns.Warn("noteZoneFileAdopted: could not list the owners the KeyDB's record holds; only those known in this process follow the zone file",
			"zone", zd.ZoneName, "error", err)
	}
	onDisk := map[string]string{}
	for _, owner := range owners {
		d := ""
		if od, ok := file.Get(owner); ok {
			if rrset, ok := od.RRtypes.Get(dns.TypeSVCB); ok && len(rrset.RRs) > 0 {
				d = signalDigest(rrset.RRs)
			}
		}
		if d != "" {
			known, err := zd.signalStoredDigests(owner)
			if err != nil || !slices.Contains(known, d) {
				continue
			}
		}
		onDisk[owner] = d
	}
	zd.zoneFileMu.Lock()
	defer zd.zoneFileMu.Unlock()
	if !zoneFileStillRead(zd.Zonefile, read) {
		lgDns.Debug("noteZoneFileAdopted: the zone file was replaced after it was read; the record follows the file in place",
			"zone", zd.ZoneName, "file", zd.Zonefile)
		return
	}
	zd.signalStoredMu.Lock()
	defer zd.signalStoredMu.Unlock()
	if zd.signalOnDisk == nil {
		zd.signalOnDisk = map[string]string{}
	}
	for owner, d := range onDisk {
		zd.signalOnDisk[owner] = d
	}
}

// zoneFileStillRead reports whether the file at path is still the one read
// describes, the stat taken before it was read: the same file, unchanged
// since. True when there is no stat to compare.
func zoneFileStillRead(path string, read os.FileInfo) bool {
	if read == nil {
		return true
	}
	now, err := os.Stat(path)
	return err == nil && os.SameFile(read, now) && now.Size() == read.Size() && now.ModTime().Equal(read.ModTime())
}

// mergeSignalDigests is first followed by the digests of then that are not
// in it, at most signalStoredKeep in all. Every digest of first is kept,
// past signalStoredKeep if need be: the caller holds each one, and the cap
// only ends the history behind them. A cap that cut first dropped held
// signals, the newest a replay of the journal can yield among them, while
// they were still held (CodeRabbit on #1145).
func mergeSignalDigests(first, then []string) []string {
	out := make([]string, 0, len(first)+len(then))
	for _, d := range first {
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	for _, d := range then {
		if !slices.Contains(out, d) && len(out) < signalStoredKeep {
			out = append(out, d)
		}
	}
	return out
}

// forgetSignalStored ends the pass's claim on owner: the RRset there is the
// operator's now. The in-memory record becomes an explicit revocation first,
// an entry with no digest, so that nothing falls back to the KeyDB's record
// while it is being dropped. The entry goes once the KeyDB has dropped its
// record. A failed KeyDB delete is returned and the revocation stays: in
// this process the owner is not the pass's, signalStoredOwners still lists
// it, and the next forget tries the delete again. After a restart the
// KeyDB's record would count again, which is why the callers warn.
func (zd *ZoneData) forgetSignalStored(owner string) error {
	owner = core.CanonicalizeName(owner)
	zd.signalStoredMu.Lock()
	if zd.signalStored == nil {
		zd.signalStored = map[string][]string{}
	}
	zd.signalStored[owner] = nil
	delete(zd.signalUnrecorded, owner)
	delete(zd.signalOnDisk, owner)
	delete(zd.signalOnDiskPrev, owner)
	delete(zd.signalJournaled, owner)
	zd.signalStoredMu.Unlock()
	if kdb := zd.signalRecordDB(); kdb != nil {
		if err := kdb.DeleteTransportSignalStoredOwner(zd.ZoneName, owner); err != nil {
			return fmt.Errorf("forgetSignalStored: zone %s owner %s: %w", zd.ZoneName, owner, err)
		}
	}
	zd.signalStoredMu.Lock()
	if d, ok := zd.signalStored[owner]; ok && d == nil {
		delete(zd.signalStored, owner)
	}
	zd.signalStoredMu.Unlock()
	return nil
}

// signalRevocationPending reports whether forgetSignalStored revoked owner
// in this process and the KeyDB has not yet dropped its record.
func (zd *ZoneData) signalRevocationPending(owner string) bool {
	zd.signalStoredMu.Lock()
	defer zd.signalStoredMu.Unlock()
	d, ok := zd.signalStored[core.CanonicalizeName(owner)]
	return ok && d == nil
}

// warnSignalForgetFailed is how the pass handles a failed forget: the
// revocation holds in this process, and the pass tries the delete again on
// its next run, but a restart before the KeyDB drops the record would make
// the pass take the records at the owner for its own again.
func (zd *ZoneData) warnSignalForgetFailed(owner string, err error) {
	lgDns.Warn("the KeyDB could not drop the stored-signal record: the records at the owner are not the pass's in this process and the pass tries again on its next run, but after a restart the KeyDB's record would count again",
		"zone", zd.ZoneName, "owner", owner, "error", err)
}

// signalStoredReadHook, when set, is asked before the KeyDB's record is read
// in signalStoredDigests, and an error it returns is the read's: tests set
// it to make the read fail while the writes still work.
var signalStoredReadHook func(zone, owner string) error

// signalStoredDigests returns the digests the pass recorded for owner, the
// last first: the in-memory record, or else the KeyDB's, which holds what
// an earlier process stored, behind the digests the KeyDB did not take
// (signalUnrecorded). nil when there is none, and nil for an owner revoked
// in this process (forgetSignalStored), whose KeyDB record is then not
// consulted.
//
// An error when the KeyDB's record cannot be read. "No record" and "a
// record that cannot be read" are not the same answer: the first makes the
// RRset at the owner the operator's, while the second leaves it unknown,
// and a caller that took it for the first would forget the pass's own
// signal for good (CodeRabbit on #1118).
func (zd *ZoneData) signalStoredDigests(owner string) ([]string, error) {
	zd.signalStoredMu.Lock()
	digests, ok := zd.signalStored[owner]
	unrecorded := append([]string(nil), zd.signalUnrecorded[owner]...)
	zd.signalStoredMu.Unlock()
	if ok {
		return digests, nil
	}
	kdb := zd.signalRecordDB()
	if kdb == nil {
		return unrecorded, nil
	}
	if signalStoredReadHook != nil {
		if err := signalStoredReadHook(zd.ZoneName, owner); err != nil {
			return nil, err
		}
	}
	digests, _, err := kdb.GetTransportSignalStored(zd.ZoneName, owner)
	if err != nil {
		return nil, err
	}
	if len(unrecorded) > 0 {
		return mergeSignalDigests(unrecorded, digests), nil
	}
	return digests, nil
}

// signalStoredByPass reports whether rrs at owner are exactly a signal the
// pass stored there: the last one, or one before it that a zone written in
// between may hold. An RRset the operator has since replaced, by an update
// or in the zone file, is not. An error when the record cannot be read
// (signalStoredDigests); the answer is then neither yes nor no.
//
// A digest the KeyDB did not take (signalUnrecorded) answers yes without a
// read: the pass stored that signal in this process.
func (zd *ZoneData) signalStoredByPass(owner string, rrs []dns.RR) (bool, error) {
	owner = core.CanonicalizeName(owner)
	digest := signalDigest(rrs)
	zd.signalStoredMu.Lock()
	unrecorded := slices.Contains(zd.signalUnrecorded[owner], digest)
	zd.signalStoredMu.Unlock()
	if unrecorded {
		return true, nil
	}
	digests, err := zd.signalStoredDigests(owner)
	if err != nil {
		return false, err
	}
	return slices.Contains(digests, digest), nil
}

// warnSignalRecordUnreadable is how the pass handles an owner whose record
// cannot be read: it does not know whether the RRset there is its own or the
// operator's, so it neither replaces nor withdraws it, and does not forget
// the record. The owner stays as it is until the pass next runs.
func (zd *ZoneData) warnSignalRecordUnreadable(owner string, err error) {
	lgDns.Warn("transport signal pass: could not read the record of what the pass stored at the owner; leaving the owner as it is until the pass next runs",
		"zone", zd.ZoneName, "owner", owner, "error", err)
}

// signalStoredRecorded reports whether the pass has a record of storing a
// signal at owner: in this process (a revocation still pending included, so
// that a release tries the KeyDB delete again), among the digests the KeyDB
// did not take, or in the KeyDB from an earlier process. An error when the
// KeyDB cannot be asked: "no record" would make a release report that there
// was nothing to release, while the KeyDB's record stays and counts again
// (CodeRabbit on #1118).
func (zd *ZoneData) signalStoredRecorded(owner string) (bool, error) {
	owner = core.CanonicalizeName(owner)
	zd.signalStoredMu.Lock()
	_, inMemory := zd.signalStored[owner]
	unrecorded := len(zd.signalUnrecorded[owner]) > 0
	zd.signalStoredMu.Unlock()
	if inMemory || unrecorded {
		return true, nil
	}
	kdb := zd.signalRecordDB()
	if kdb == nil {
		return false, nil
	}
	return kdb.HasTransportSignalStored(zd.ZoneName, owner)
}

// signalStoredOwners lists the owners the pass has a record of storing a
// signal at in this zone: in this process, and in the KeyDB from an earlier
// one. An owner whose revocation is pending is listed too, so that the pass
// tries the KeyDB delete again. An error when the KeyDB's list cannot be
// read; the owners known in this process are listed all the same.
func (zd *ZoneData) signalStoredOwners() ([]string, error) {
	seen := map[string]bool{}
	var out []string
	zd.signalStoredMu.Lock()
	for owner := range zd.signalStored {
		seen[owner] = true
		out = append(out, owner)
	}
	for owner := range zd.signalUnrecorded {
		if !seen[owner] {
			seen[owner] = true
			out = append(out, owner)
		}
	}
	zd.signalStoredMu.Unlock()
	var listErr error
	if kdb := zd.signalRecordDB(); kdb != nil {
		owners, err := kdb.ListTransportSignalStored(zd.ZoneName)
		listErr = err
		for _, owner := range owners {
			if !seen[owner] {
				seen[owner] = true
				out = append(out, owner)
			}
		}
	}
	sort.Strings(out)
	return out, listErr
}

// SetTransportSignalStored records the digests of the signals stored at
// owner, the last first: the last in digest, the earlier ones in earlier,
// separated by spaces.
func (kdb *KeyDB) SetTransportSignalStored(zone, owner string, digests []string) error {
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("SetTransportSignalStored: no database")
	}
	if len(digests) == 0 {
		return fmt.Errorf("SetTransportSignalStored: zone %s owner %s: no digest", zone, owner)
	}
	kdb.mu.Lock()
	defer kdb.mu.Unlock()
	_, err := kdb.DB.Exec(`
INSERT OR REPLACE INTO TransportSignalStored (zone, owner, digest, earlier, updated_at)
VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		dns.Fqdn(zone), core.CanonicalizeName(owner), digests[0], strings.Join(digests[1:], " "))
	if err != nil {
		return fmt.Errorf("SetTransportSignalStored: zone %s owner %s: %v", zone, owner, err)
	}
	return nil
}

// PrependTransportSignalStored records digest as the last one for owner,
// ahead of the digests the record holds, in one statement: for a writer that
// could not read the record first (noteSignalStored). A digest that is the
// last one already changes nothing; one among the earlier digests moves to
// the front rather than appearing twice, where it would take one of the
// signalStoredKeep places from a distinct digest. The list is not trimmed
// here; the next SetTransportSignalStored trims it.
func (kdb *KeyDB) PrependTransportSignalStored(zone, owner, digest string) error {
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("PrependTransportSignalStored: no database")
	}
	if digest == "" {
		return fmt.Errorf("PrependTransportSignalStored: zone %s owner %s: no digest", zone, owner)
	}
	kdb.mu.Lock()
	defer kdb.mu.Unlock()
	_, err := kdb.DB.Exec(`
INSERT INTO TransportSignalStored (zone, owner, digest, earlier, updated_at)
VALUES (?, ?, ?, '', CURRENT_TIMESTAMP)
ON CONFLICT(zone, owner) DO UPDATE SET
	earlier = CASE WHEN digest = excluded.digest THEN earlier
		ELSE TRIM(REPLACE(' ' || digest || ' ' || earlier || ' ', ' ' || excluded.digest || ' ', ' ')) END,
	digest = excluded.digest,
	updated_at = CURRENT_TIMESTAMP`,
		dns.Fqdn(zone), core.CanonicalizeName(owner), digest)
	if err != nil {
		return fmt.Errorf("PrependTransportSignalStored: zone %s owner %s: %v", zone, owner, err)
	}
	return nil
}

// GetTransportSignalStored returns the recorded digests for owner, the last
// first, and whether there is a record. No record is not an error.
func (kdb *KeyDB) GetTransportSignalStored(zone, owner string) ([]string, bool, error) {
	if kdb == nil || kdb.DB == nil {
		return nil, false, fmt.Errorf("GetTransportSignalStored: no database")
	}
	kdb.mu.Lock()
	defer kdb.mu.Unlock()
	var digest, earlier string
	err := kdb.DB.QueryRow(`SELECT digest, earlier FROM TransportSignalStored WHERE zone=? AND owner=?`,
		dns.Fqdn(zone), core.CanonicalizeName(owner)).Scan(&digest, &earlier)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("GetTransportSignalStored: zone %s owner %s: %v", zone, owner, err)
	}
	return append([]string{digest}, strings.Fields(earlier)...), true, nil
}

// HasTransportSignalStored reports whether owner has a record in zone. It
// reads no digest, so it answers where GetTransportSignalStored cannot read
// the digests.
func (kdb *KeyDB) HasTransportSignalStored(zone, owner string) (bool, error) {
	if kdb == nil || kdb.DB == nil {
		return false, fmt.Errorf("HasTransportSignalStored: no database")
	}
	kdb.mu.Lock()
	defer kdb.mu.Unlock()
	var one int
	err := kdb.DB.QueryRow(`SELECT 1 FROM TransportSignalStored WHERE zone=? AND owner=?`,
		dns.Fqdn(zone), core.CanonicalizeName(owner)).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("HasTransportSignalStored: zone %s owner %s: %v", zone, owner, err)
	}
	return true, nil
}

// ListTransportSignalStored returns the owners with a record in zone.
func (kdb *KeyDB) ListTransportSignalStored(zone string) ([]string, error) {
	if kdb == nil || kdb.DB == nil {
		return nil, fmt.Errorf("ListTransportSignalStored: no database")
	}
	kdb.mu.Lock()
	defer kdb.mu.Unlock()
	rows, err := kdb.DB.Query(`SELECT owner FROM TransportSignalStored WHERE zone=?`, dns.Fqdn(zone))
	if err != nil {
		return nil, fmt.Errorf("ListTransportSignalStored: zone %s: %v", zone, err)
	}
	defer rows.Close()
	var owners []string
	for rows.Next() {
		var owner string
		if err := rows.Scan(&owner); err != nil {
			return owners, fmt.Errorf("ListTransportSignalStored: zone %s: %v", zone, err)
		}
		owners = append(owners, owner)
	}
	if err := rows.Err(); err != nil {
		return owners, fmt.Errorf("ListTransportSignalStored: zone %s: %v", zone, err)
	}
	return owners, nil
}

// DeleteTransportSignalStoredOwner drops the record for one owner.
func (kdb *KeyDB) DeleteTransportSignalStoredOwner(zone, owner string) error {
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("DeleteTransportSignalStoredOwner: no database")
	}
	kdb.mu.Lock()
	defer kdb.mu.Unlock()
	if _, err := kdb.DB.Exec(`DELETE FROM TransportSignalStored WHERE zone=? AND owner=?`,
		dns.Fqdn(zone), core.CanonicalizeName(owner)); err != nil {
		return fmt.Errorf("DeleteTransportSignalStoredOwner: %v", err)
	}
	return nil
}

// TransportSignalStoredRow is one owner's record as the table keeps it:
// what TakeTransportSignalStored drops and RestoreTransportSignalStored puts
// back.
type TransportSignalStoredRow struct {
	Owner   string
	Digest  string
	Earlier string
}

// TakeTransportSignalStored drops a zone's records, used when the zone is
// removed, and returns them, so that a removal that fails later can put
// them back as they were (RestoreTransportSignalStored). They are read and
// dropped under the one lock every writer of the table takes, so no record
// written in between is dropped without being returned.
func (kdb *KeyDB) TakeTransportSignalStored(zone string) ([]TransportSignalStoredRow, error) {
	if kdb == nil || kdb.DB == nil {
		return nil, fmt.Errorf("TakeTransportSignalStored: no database")
	}
	zone = core.CanonicalizeName(dns.Fqdn(zone))
	kdb.mu.Lock()
	defer kdb.mu.Unlock()
	rows, err := kdb.DB.Query(`SELECT owner, digest, earlier FROM TransportSignalStored WHERE zone=?`, zone)
	if err != nil {
		return nil, fmt.Errorf("TakeTransportSignalStored: zone %s: %v", zone, err)
	}
	defer rows.Close()
	var taken []TransportSignalStoredRow
	for rows.Next() {
		var r TransportSignalStoredRow
		if err := rows.Scan(&r.Owner, &r.Digest, &r.Earlier); err != nil {
			return nil, fmt.Errorf("TakeTransportSignalStored: zone %s: %v", zone, err)
		}
		taken = append(taken, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("TakeTransportSignalStored: zone %s: %v", zone, err)
	}
	rows.Close()
	if _, err := kdb.DB.Exec(`DELETE FROM TransportSignalStored WHERE zone=?`, zone); err != nil {
		return nil, fmt.Errorf("TakeTransportSignalStored: zone %s: %v", zone, err)
	}
	return taken, nil
}

// RestoreTransportSignalStored puts back the records TakeTransportSignalStored
// dropped, in one statement, so either all of them are back or none is.
func (kdb *KeyDB) RestoreTransportSignalStored(zone string, taken []TransportSignalStoredRow) error {
	if len(taken) == 0 {
		return nil
	}
	if kdb == nil || kdb.DB == nil {
		return fmt.Errorf("RestoreTransportSignalStored: no database")
	}
	zone = core.CanonicalizeName(dns.Fqdn(zone))
	args := make([]any, 0, 4*len(taken))
	for _, r := range taken {
		args = append(args, zone, r.Owner, r.Digest, r.Earlier)
	}
	q := `INSERT OR REPLACE INTO TransportSignalStored (zone, owner, digest, earlier, updated_at) VALUES ` +
		strings.TrimSuffix(strings.Repeat("(?, ?, ?, ?, CURRENT_TIMESTAMP), ", len(taken)), ", ")
	kdb.mu.Lock()
	defer kdb.mu.Unlock()
	if _, err := kdb.DB.Exec(q, args...); err != nil {
		return fmt.Errorf("RestoreTransportSignalStored: zone %s: %v", zone, err)
	}
	return nil
}

// refreshCarriesSignal reports whether a refresh carries the SVCB RRset rrs
// at owner over from the published zone (CollectDynamicRRs): when it is the
// pass's own, and when that cannot be told because the record cannot be
// read. A signal the pass synthesized is in no zone file or transfer, so
// not carrying it would take it out of the served zone for as long as the
// record stays unreadable. An operator's RRset is not carried because the
// fresh data holds their edit, and a carried copy never overrides that:
// records the fresh data holds at the owner win (repopulateWorkingSetLocked
// drops the carried copy). Only an RRset the operator removed from the file
// comes back, until a refresh after the record reads again.
func (zd *ZoneData) refreshCarriesSignal(owner string, rrs []dns.RR) bool {
	own, err := zd.signalStoredByPass(owner, rrs)
	if err != nil {
		lgDns.Warn("CollectDynamicRRs: could not read the record of what the pass stored at the owner; its SVCB RRset is carried over the refresh, as the pass's own would be",
			"zone", zd.ZoneName, "owner", owner, "error", err)
		return true
	}
	return own
}
