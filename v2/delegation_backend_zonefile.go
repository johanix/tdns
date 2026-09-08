/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * zonefileWriter is the zonefile writer: after the store has recorded a child
 * update, it regenerates that child's delegation data as a DNS zone file
 * fragment that can be $INCLUDEd into the parent zone file, and optionally
 * runs a command to tell whatever generates the zone. Files are written
 * atomically (write-to-temp + rename). Before the split this and the sqlite
 * store together were the "zonefile" backend.
 */
package tdns

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type zonefileWriter struct {
	directory     string
	notifyCommand string
	store         DelegationStore
}

func (w *zonefileWriter) Name() string { return DelegationWriterZonefile }

// Write regenerates the fragment of every child the actions touch, from what
// the store now holds, and then runs the notify command if there is one.
func (w *zonefileWriter) Write(ctx context.Context, parentZone string, actions []dns.RR, desc string) error {
	affected := map[string]bool{}
	for _, rr := range actions {
		affected[childZoneFromOwner(rr.Header().Name, parentZone)] = true
	}
	if err := w.refreshFragments(parentZone, affected); err != nil {
		return err
	}
	if w.notifyCommand != "" {
		w.runNotifyCommand(parentZone)
	}
	return nil
}

// refreshFragments regenerates the fragment of every child in affected from
// what the store holds: written when the child has data, removed when it has
// none.
//
// A store that cannot be READ is neither. It used to be: GetDelegationData
// returned an error for an empty child, this loop took any error as "no data
// left" and removed the fragment, and so a transient database failure would
// have deleted a child's delegation from the generated parent zone. The store
// now answers empty with an empty map, and an error here is returned as one.
func (w *zonefileWriter) refreshFragments(parentZone string, affected map[string]bool) error {
	for childZone := range affected {
		data, err := w.store.GetDelegationData(parentZone, childZone)
		if err != nil {
			return fmt.Errorf("reading delegation data for %s: %w", childZone, err)
		}
		if len(data) == 0 {
			path := w.filePath(childZone)
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("removing delegation file for %s: %w", childZone, err)
			}
			lg.Info("zonefile writer: removed delegation file (no data left)", "child", childZone)
			continue
		}
		if err := w.writeZoneFile(childZone, data); err != nil {
			return fmt.Errorf("write zone file for %s failed: %w", childZone, err)
		}
	}
	return nil
}

func (w *zonefileWriter) filePath(childZone string) string {
	// Use child zone name as filename, strip trailing dot for filesystem
	name := strings.TrimSuffix(childZone, ".")
	return filepath.Join(w.directory, name+".zone")
}

func (w *zonefileWriter) writeZoneFile(childZone string, data map[string]map[uint16][]dns.RR) error {
	path := w.filePath(childZone)

	// Ensure directory exists
	if err := os.MkdirAll(w.directory, 0755); err != nil {
		return fmt.Errorf("create directory %s: %w", w.directory, err)
	}

	// Collect all RRs, sorted by owner then type
	type ownerType struct {
		owner  string
		rrtype uint16
	}
	var keys []ownerType
	for owner, rrtypes := range data {
		for rrtype := range rrtypes {
			keys = append(keys, ownerType{owner, rrtype})
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].owner != keys[j].owner {
			return keys[i].owner < keys[j].owner
		}
		return keys[i].rrtype < keys[j].rrtype
	})

	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("; Delegation data for %s\n", childZone))
	buf.WriteString(fmt.Sprintf("; Last updated: %s\n", time.Now().UTC().Format(time.RFC3339)))
	buf.WriteString(";\n")

	for _, k := range keys {
		for _, rr := range data[k.owner][k.rrtype] {
			buf.WriteString(rr.String())
			buf.WriteString("\n")
		}
	}

	// Atomic write: temp file + rename
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(buf.String()), 0644); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename temp file: %w", err)
	}

	lg.Info("zonefile writer: wrote delegation file", "child", childZone, "path", path)
	return nil
}

func (w *zonefileWriter) runNotifyCommand(parentZone string) {
	cmd := strings.ReplaceAll(w.notifyCommand, "{ZONENAME}", parentZone)
	lg.Info("zonefile writer: running notify command", "cmd", cmd)
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		lg.Error("zonefile writer: notify command failed", "cmd", cmd, "error", err, "output", string(out))
	}
}
