/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// DelegationBackend is the interface for storing delegation data received
// from child zones via DNS UPDATE. Implementations persist the data in
// different ways (in-memory zone, database, zone files, etc.).
type DelegationBackend interface {
	// ApplyChildUpdate processes an approved child UPDATE.
	// Actions are ClassINET (add), ClassNONE (delete-RR), ClassANY (delete-RRset).
	ApplyChildUpdate(parentZone string, ur UpdateRequest) error

	// GetDelegationData returns current delegation RRs for a child zone,
	// grouped by owner name and RR type.
	GetDelegationData(parentZone, childZone string) (map[string]map[uint16][]dns.RR, error)

	// ListChildren returns all child zones with stored delegation data.
	ListChildren(parentZone string) ([]string, error)

	// Name returns the backend name for logging.
	Name() string
}

// DelegationBackendConf is a named backend definition from the config file.
// Predefined backends ("db", "direct") need no config entry. Named backends
// are only needed for types that require parameters (e.g. "zonefile").
type DelegationBackendConf struct {
	Name          string `yaml:"name"`
	Type          string `yaml:"type"`
	Directory     string `yaml:"directory"`      // zonefile backend
	NotifyCommand string `yaml:"notify-command"` // zonefile backend
}

// LookupDelegationBackend resolves a backend name to a DelegationBackend.
//
// Predefined names:
//   - "db"     → DBDelegationBackend (uses the zone's existing KeyDB)
//   - "direct" → DirectDelegationBackend (modifies in-memory zone data)
//
// Any other name is looked up in the "delegation-backends" config list.
func LookupDelegationBackend(name string, kdb *KeyDB, zd *ZoneData) (DelegationBackend, error) {
	switch name {
	case "db":
		return &DBDelegationBackend{kdb: kdb}, nil
	case "direct":
		return &DirectDelegationBackend{zd: zd, kdb: kdb}, nil
	}

	// Look up named backend in config
	var backends []DelegationBackendConf
	if err := viper.UnmarshalKey("delegation-backends", &backends); err != nil {
		return nil, fmt.Errorf("failed to parse delegation-backends config: %w", err)
	}

	for _, bc := range backends {
		if bc.Name != name {
			continue
		}
		switch bc.Type {
		case "db":
			return &DBDelegationBackend{kdb: kdb}, nil
		case "direct":
			return &DirectDelegationBackend{zd: zd, kdb: kdb}, nil
		case "zonefile":
			if bc.Directory == "" {
				return nil, fmt.Errorf("delegation backend %q (type zonefile): directory is required", name)
			}
			return &ZonefileDelegationBackend{
				backendName:   name,
				directory:     bc.Directory,
				notifyCommand: bc.NotifyCommand,
				kdb:           kdb,
			}, nil
		default:
			return nil, fmt.Errorf("delegation backend %q: unknown type %q", name, bc.Type)
		}
	}

	return nil, fmt.Errorf("delegation backend %q not found in delegation-backends config", name)
}

// ExportDelegationData writes all delegation data for a parent zone to a file
// in DNS zone file format. Called from the /delegation API handler.
func ExportDelegationData(backend DelegationBackend, parentZone, outfile string) error {
	children, err := backend.ListChildren(parentZone)
	if err != nil {
		return fmt.Errorf("ListChildren: %w", err)
	}

	sort.Strings(children)

	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("; Delegation data for parent zone %s\n", parentZone))
	buf.WriteString(fmt.Sprintf("; Exported: %s\n", time.Now().UTC().Format(time.RFC3339)))
	buf.WriteString(fmt.Sprintf("; Backend: %s\n", backend.Name()))
	buf.WriteString(fmt.Sprintf("; Children: %d\n", len(children)))
	buf.WriteString(";\n")

	for _, child := range children {
		data, err := backend.GetDelegationData(parentZone, child)
		if err != nil {
			buf.WriteString(fmt.Sprintf("; ERROR: %s: %v\n", child, err))
			continue
		}

		buf.WriteString(fmt.Sprintf("; --- %s ---\n", child))

		// Collect and sort by owner then rrtype
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

		for _, k := range keys {
			for _, rr := range data[k.owner][k.rrtype] {
				buf.WriteString(rr.String())
				buf.WriteString("\n")
			}
		}
	}

	// Atomic write
	tmpfile := outfile + ".tmp"
	if err := os.WriteFile(tmpfile, []byte(buf.String()), 0644); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmpfile, outfile); err != nil {
		os.Remove(tmpfile)
		return fmt.Errorf("rename: %w", err)
	}

	lg.Info("ExportDelegationData: wrote file", "zone", parentZone, "file", outfile, "children", len(children))
	return nil
}
