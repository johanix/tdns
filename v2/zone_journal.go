/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Operator surface for the delta journal.
//
// The journal is durable state that decides what a zone serves, and until now
// it had none: no way to see whether it held anything, what was in it, or
// whether it would replay. That gap is what `rm zone.jnl` fills in the BIND
// world, badly -- it is the only tool, it is unconditional, and it destroys
// the only copy of changes that never reached the zone file.
//
// The four operations here are status, list, truncate and purge. What makes
// purge different from `rm` is that it writes what it discards, in a format
// that can be fed straight back in (see zone_update_instructions.go), before
// deleting anything.

// ZoneJournalInfo is what `zone journal status` reports.
type ZoneJournalInfo struct {
	Zone     string
	Zonefile string

	Deltas  int // number of deltas in the chain
	Records int // total ADD/DEL instructions across them

	// AnchorSerial is the serial the chain claims to start from, HeadSerial
	// where it ends. Both are zero when the journal is empty.
	AnchorSerial uint32
	HeadSerial   uint32

	// FileSerial is the serial of the zone file as last read or written,
	// ServedSerial what the zone is publishing right now. They differ on any
	// signed zone -- load-time signing republishes -- which is exactly why the
	// journal anchors to the first and not the second.
	FileSerial   uint32
	ServedSerial uint32

	// Replayable answers the question an operator actually has: will this
	// journal survive a restart? Diagnosis says why not when it will not.
	Replayable bool
	Diagnosis  string

	// Replayed records whether the deltas were applied over the file currently
	// loaded. False with a non-empty journal means the changes are in the
	// database but NOT in what the zone is serving.
	Replayed bool

	// PersistenceActive is false when the deployment-wide kill-switch
	// (journal: active: false) is set. A server quietly not persisting is the
	// thing this whole subsystem exists to prevent, so it is reported rather
	// than left to be inferred from a journal that never grows.
	PersistenceActive bool

	Deltalist []ZoneJournalDelta `json:",omitempty"`
}

// ZoneJournalDelta is one delta, as reported by `zone journal list`.
type ZoneJournalDelta struct {
	FromSerial uint32
	ToSerial   uint32
	Adds       int
	Dels       int
	RRs        []ZoneDeltaRR `json:",omitempty"`
}

// JournalInfo describes the zone's journal.
//
// detail controls whether the individual records travel with it: a summary is
// cheap and a full listing of a busy zone's journal is not, and `status` has
// no use for the records.
func (zd *ZoneData) JournalInfo(detail bool) (*ZoneJournalInfo, error) {
	if zd == nil {
		return nil, fmt.Errorf("no such zone")
	}
	if zd.KeyDB == nil || zd.KeyDB.DB == nil {
		return nil, fmt.Errorf("zone %s: no database, so no journal", zd.ZoneName)
	}

	deltas, err := zd.KeyDB.LoadZoneDeltas(zd.ZoneName)
	if err != nil {
		return nil, err
	}

	zd.mu.Lock()
	fileSerial := zd.fileSerial
	served := zd.CurrentSerial
	replayed := zd.deltasReplayed
	zd.mu.Unlock()

	info := &ZoneJournalInfo{
		Zone:              zd.ZoneName,
		Zonefile:          zd.Zonefile,
		Deltas:            len(deltas),
		FileSerial:        fileSerial,
		ServedSerial:      served,
		Replayed:          replayed,
		Replayable:        true,
		PersistenceActive: JournalActive(),
	}

	for _, d := range deltas {
		info.Records += len(d.RRs)
		entry := ZoneJournalDelta{FromSerial: d.FromSerial, ToSerial: d.ToSerial}
		for _, rr := range d.RRs {
			if rr.Action == ZoneDeltaDel {
				entry.Dels++
			} else {
				entry.Adds++
			}
		}
		if detail {
			entry.RRs = d.RRs
		}
		info.Deltalist = append(info.Deltalist, entry)
	}

	if len(deltas) > 0 {
		info.AnchorSerial = deltas[0].FromSerial
		info.HeadSerial = deltas[len(deltas)-1].ToSerial

		// The same check the load path runs, from the same function, so the
		// answer here cannot drift away from what actually happens at startup.
		if err := validateDeltaChain(zd.ZoneName, deltas, fileSerial); err != nil {
			info.Replayable = false
			info.Diagnosis = err.Error()
		}
	}

	return info, nil
}

// JournalInstructions flattens the journal into one instruction list, in
// replay order. This is what `journal list --instructions` prints and what
// purge preserves.
//
// The second return is the highest row id the list covers. Callers that then
// DELETE what they have just read must bound the delete by it -- see
// JournalPurge.
func (zd *ZoneData) JournalInstructions() ([]ZoneDeltaRR, int64, error) {
	deltas, err := zd.KeyDB.LoadZoneDeltas(zd.ZoneName)
	if err != nil {
		return nil, 0, err
	}
	var out []ZoneDeltaRR
	var maxID int64
	for _, d := range deltas {
		out = append(out, d.RRs...)
		if d.MaxID > maxID {
			maxID = d.MaxID
		}
	}
	return out, maxID, nil
}

// ZoneJournalPurgeResult reports what a purge did.
type ZoneJournalPurgeResult struct {
	Rows         int64
	Deltas       int
	Artefact     string        // where the discarded content was written ("" if nowhere)
	Instructions []ZoneDeltaRR // and the content itself, always
	// Remaining counts deltas that were still in the journal afterwards, which
	// happens only when an update published DURING the purge. Those are not in
	// the artefact and were deliberately not deleted.
	Remaining int
}

// JournalPurge discards the whole journal, having first written what it holds
// somewhere the operator can get it back from.
//
// Two things distinguish this from deleting the rows by hand:
//
// It is not silent. Everything discarded is written to
// {zonefile}.{serial}.purged as ADD/DEL instructions, and returned to the
// caller besides, so a purge issued in error is recoverable by feeding the
// artefact back through `zone update from-file`.
//
// It refuses a HEALTHY journal without force. A journal that will replay holds
// changes that exist nowhere else; discarding those is a real decision and
// `zone sync` is almost always the better one -- it folds the same changes
// into the zone file and loses nothing. A journal that will NOT replay is a
// different matter: its changes are already absent from what the zone serves,
// so purging costs nothing that was not already lost, and requiring a flag
// there would just be an obstacle in front of the one remedy.
func (zd *ZoneData) JournalPurge(force bool) (*ZoneJournalPurgeResult, error) {
	info, err := zd.JournalInfo(false)
	if err != nil {
		return nil, err
	}
	if info.Deltas == 0 {
		return &ZoneJournalPurgeResult{}, nil
	}

	if info.Replayable && !force {
		return nil, fmt.Errorf("zone %s: the journal holds %d change(s) in %d delta(s) that are"+
			" NOT in the zone file, and it would replay cleanly on restart. Purging discards them."+
			" Use `zone sync` to fold them into the zone file instead (nothing is lost), or"+
			" repeat with --force if you really mean to throw them away",
			zd.ZoneName, info.Records, info.Deltas)
	}

	insns, maxID, err := zd.JournalInstructions()
	if err != nil {
		return nil, err
	}

	res := &ZoneJournalPurgeResult{Deltas: info.Deltas, Instructions: insns}

	// Preserve before destroying, and fail the purge if preserving fails. A
	// purge whose artefact could not be written is exactly the `rm zone.jnl`
	// this command exists to be better than.
	if zd.Zonefile != "" {
		path := fmt.Sprintf("%s.%d.purged", zd.Zonefile, info.HeadSerial)
		if err := writeInstructionFile(path, []string{
			"tdns: journal content discarded by `zone journal purge`",
			fmt.Sprintf("zone:     %s", zd.ZoneName),
			fmt.Sprintf("serials:  %d -> %d (%d deltas, %d records)",
				info.AnchorSerial, info.HeadSerial, info.Deltas, info.Records),
			fmt.Sprintf("file:     %s (serial %d)", zd.Zonefile, info.FileSerial),
			fmt.Sprintf("purged:   %s", time.Now().Format(time.RFC3339)),
			"",
			"Replay what you want back with:",
			fmt.Sprintf("  tdns-cli auth zone update from-file --file %s --zone %s --via api",
				path, zd.ZoneName),
		}, insns); err != nil {
			return nil, fmt.Errorf("zone %s: refusing to purge the journal, because the discarded"+
				" content could not be saved to %s: %v", zd.ZoneName, path, err)
		}
		res.Artefact = path
	} else {
		// A zone with no file on disk has nowhere to put the artefact. The
		// content still travels back in the response, so it is not lost -- but
		// say so rather than let the operator assume a file was written.
		lg.Warn("purging a journal for a zone with no zone file;"+
			" the discarded content is in the response only, not saved to disk",
			"zone", zd.ZoneName, "records", info.Records)
	}

	// Delete exactly what the artefact records, and not a row more.
	//
	// An update can publish between the read above and this delete. Its delta
	// is not in the artefact -- it did not exist when the artefact was written
	// -- so an unbounded delete would destroy content that was never saved
	// anywhere, which is the one thing purge must not do. Bounding by the row
	// id the snapshot covered leaves such a delta in place.
	n, err := zd.KeyDB.DeleteZoneDeltasThroughID(zd.ZoneName, maxID)
	if err != nil {
		return nil, err
	}
	res.Rows = n

	// Did anything arrive during the purge? Then the journal is not empty, and
	// what remains no longer chains from the zone file -- its predecessors are
	// gone. Say so: silence here would leave the operator believing the purge
	// finished the job, and the next restart reporting a journal that refuses
	// to replay with no obvious cause.
	after, aerr := zd.JournalInfo(false)
	switch {
	case aerr != nil:
		// Do not report a clean purge we cannot vouch for. The rows are gone
		// either way, but whether an update landed mid-purge is now unknown,
		// and unknown is not the same as none.
		res.Remaining = -1
		lg.Error("journal purged, but the post-purge state could not be read;"+
			" whether an update landed during the purge is unknown",
			"zone", zd.ZoneName, "error", aerr)
	case after.Deltas > 0:
		res.Remaining = after.Deltas
		lg.Warn("an update published while the journal was being purged;"+
			" its delta was kept (it is not in the purge artefact) but no longer chains"+
			" from the zone file",
			"zone", zd.ZoneName, "remaining_deltas", after.Deltas)
	}

	// Nothing remains to replay for this load -- unless something arrived
	// mid-purge, in which case it has NOT been applied and the flag must not
	// claim otherwise either way.
	zd.mu.Lock()
	zd.deltasReplayed = false
	zd.mu.Unlock()

	lg.Info("zone journal purged", "zone", zd.ZoneName, "deltas", info.Deltas,
		"records", info.Records, "rows", n, "artefact", res.Artefact,
		"remaining", res.Remaining)

	return res, nil
}

// JournalTruncate drops the journal's tail, keeping the chain through serial.
func (zd *ZoneData) JournalTruncate(serial uint32) (int64, error) {
	if zd == nil || zd.KeyDB == nil {
		return 0, fmt.Errorf("no such zone")
	}
	n, err := zd.KeyDB.TruncateZoneDeltasAfterSerial(zd.ZoneName, serial)
	if err != nil {
		return 0, err
	}
	lg.Info("zone journal truncated", "zone", zd.ZoneName, "through_serial", serial, "rows", n)
	return n, nil
}

// writeInstructionFile renders instructions to path DURABLY: staged in a
// temporary file beside the target, synced, closed, renamed into place, and the
// directory synced afterwards.
//
// os.WriteFile was not enough, and the reason is specific to what this file is
// for. JournalPurge deletes the journal rows once this returns, so the artefact
// is the only surviving copy of those changes -- and os.WriteFile neither syncs
// the data nor publishes it atomically. A host crash could therefore take the
// journal and leave a truncated or absent artefact, which is exactly the
// failure `purge` exists not to have.
//
// Building the whole thing in memory first is kept for the same reason as
// before: a formatting failure must leave nothing behind claiming to be a
// complete record.
func writeInstructionFile(path string, comments []string, insns []ZoneDeltaRR) error {
	var buf bytes.Buffer
	if err := WriteUpdateInstructions(&buf, comments, insns); err != nil {
		return err
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp")
	if err != nil {
		return fmt.Errorf("creating a temporary file beside %s: %v", path, err)
	}
	tmpname := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmpname)
		}
	}()

	if _, err := tmp.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("writing %s: %v", tmpname, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("syncing %s: %v", tmpname, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing %s: %v", tmpname, err)
	}
	if err := os.Chmod(tmpname, 0644); err != nil {
		return fmt.Errorf("setting mode on %s: %v", tmpname, err)
	}
	if err := os.Rename(tmpname, path); err != nil {
		return fmt.Errorf("renaming %s to %s: %v", tmpname, path, err)
	}
	committed = true

	d, derr := os.Open(dir)
	if derr != nil {
		return fmt.Errorf("opening %s to sync the rename: %v", dir, derr)
	}
	if serr := d.Sync(); serr != nil {
		d.Close()
		return fmt.Errorf("syncing %s after writing %s: %v", dir, path, serr)
	}
	return d.Close()
}

// ApiZoneJournal dispatches the journal subcommands arriving over the
// management API.
//
// Read-only subcommands are available on any zone that has a journal. truncate
// and purge are not gated on allow-api-updates: they do not change zone
// content, they change what is stored ABOUT it -- and a zone whose updates
// have been turned off is precisely one whose leftover journal an operator may
// need to clear.
func (zd *ZoneData) ApiZoneJournal(zp ZonePost) (*ZoneResponse, error) {
	resp := &ZoneResponse{Zone: zd.ZoneName}

	switch zp.SubCommand {
	case "status", "":
		info, err := zd.JournalInfo(false)
		if err != nil {
			return nil, err
		}
		resp.Journal = info

	case "list":
		info, err := zd.JournalInfo(true)
		if err != nil {
			return nil, err
		}
		resp.Journal = info
		if zp.Instructions {
			insns, _, err := zd.JournalInstructions()
			if err != nil {
				return nil, err
			}
			resp.Instructions = insns
		}

	case "truncate":
		n, err := zd.JournalTruncate(zp.Serial)
		if err != nil {
			return nil, err
		}
		resp.Msg = fmt.Sprintf("Zone %s: journal truncated through serial %d, %d record(s) dropped",
			zd.ZoneName, zp.Serial, n)

	case "purge":
		res, err := zd.JournalPurge(zp.Force)
		if err != nil {
			return nil, err
		}
		resp.Instructions = res.Instructions
		resp.Artefact = res.Artefact
		switch {
		case res.Deltas == 0:
			resp.Msg = fmt.Sprintf("Zone %s: the journal is empty, nothing to purge", zd.ZoneName)
		case res.Artefact != "":
			resp.Msg = fmt.Sprintf("Zone %s: journal purged (%d delta(s), %d record(s));"+
				" discarded content saved to %s",
				zd.ZoneName, res.Deltas, len(res.Instructions), res.Artefact)
		default:
			resp.Msg = fmt.Sprintf("Zone %s: journal purged (%d delta(s), %d record(s));"+
				" NOT saved to disk (the zone has no zone file) -- the content is in this"+
				" response only", zd.ZoneName, res.Deltas, len(res.Instructions))
		}
		if res.Remaining > 0 {
			resp.Msg += fmt.Sprintf("\nNOTE: %d delta(s) were published while the purge ran."+
				" They are NOT in the artefact and were not deleted, but they no longer chain"+
				" from the zone file. Run `zone sync` to fold them in, or purge again to"+
				" discard them.", res.Remaining)
		}

	default:
		return nil, fmt.Errorf("unknown journal subcommand %q (want status, list, truncate or purge)",
			zp.SubCommand)
	}

	return resp, nil
}
