/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * ZonefileDelegationBackend writes per-child delegation data as DNS zone file
 * fragments. Each child zone gets its own file that can be $INCLUDEd into the
 * parent zone file. Files are written atomically (write-to-temp + rename).
 */
package tdns

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type ZonefileDelegationBackend struct {
	backendName   string
	directory     string
	notifyCommand string
	kdb           *KeyDB
}

func (b *ZonefileDelegationBackend) Name() string { return b.backendName }

// ApplyChildUpdate persists the update to the DB (as source of truth) and
// then regenerates the child's zone file fragment from the DB state.
func (b *ZonefileDelegationBackend) ApplyChildUpdate(parentZone string, ur UpdateRequest) error {
	// Use the DB backend as persistent storage
	dbBackend := &DBDelegationBackend{kdb: b.kdb}
	if err := dbBackend.ApplyChildUpdate(parentZone, ur); err != nil {
		return fmt.Errorf("db persist failed: %w", err)
	}

	// Determine which child zone(s) were affected
	affected := map[string]bool{}
	for _, rr := range ur.Actions {
		child := childZoneFromOwner(rr.Header().Name, parentZone)
		affected[child] = true
	}

	// Regenerate zone file fragment for each affected child
	for childZone := range affected {
		data, err := dbBackend.GetDelegationData(parentZone, childZone)
		if err != nil {
			// No data left (all deleted) — remove the file
			path := b.filePath(childZone)
			os.Remove(path)
			lg.Info("ZonefileDelegationBackend: removed delegation file (no data left)", "child", childZone)
			continue
		}
		if err := b.writeZoneFile(childZone, data); err != nil {
			return fmt.Errorf("write zone file for %s failed: %w", childZone, err)
		}
	}

	// Run notify command if configured
	if b.notifyCommand != "" {
		b.runNotifyCommand(parentZone)
	}

	return nil
}

func (b *ZonefileDelegationBackend) GetDelegationData(parentZone, childZone string) (map[string]map[uint16][]dns.RR, error) {
	dbBackend := &DBDelegationBackend{kdb: b.kdb}
	return dbBackend.GetDelegationData(parentZone, childZone)
}

func (b *ZonefileDelegationBackend) ListChildren(parentZone string) ([]string, error) {
	dbBackend := &DBDelegationBackend{kdb: b.kdb}
	return dbBackend.ListChildren(parentZone)
}

func (b *ZonefileDelegationBackend) filePath(childZone string) string {
	// Use child zone name as filename, strip trailing dot for filesystem
	name := strings.TrimSuffix(childZone, ".")
	return filepath.Join(b.directory, name+".zone")
}

func (b *ZonefileDelegationBackend) writeZoneFile(childZone string, data map[string]map[uint16][]dns.RR) error {
	path := b.filePath(childZone)

	// Ensure directory exists
	if err := os.MkdirAll(b.directory, 0755); err != nil {
		return fmt.Errorf("create directory %s: %w", b.directory, err)
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

	lg.Info("ZonefileDelegationBackend: wrote delegation file", "child", childZone, "path", path)
	return nil
}

func (b *ZonefileDelegationBackend) runNotifyCommand(parentZone string) {
	cmd := strings.ReplaceAll(b.notifyCommand, "{ZONENAME}", parentZone)
	lg.Info("ZonefileDelegationBackend: running notify command", "cmd", cmd)
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		lg.Error("ZonefileDelegationBackend: notify command failed", "cmd", cmd, "error", err, "output", string(out))
	}
}
