/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Data access layer for the CombinerContributions snapshot table.
 * Provides persistence for AgentContributions (per-agent record tracking).
 */

package tdns

import (
	"fmt"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// SaveContributions replaces all rows for (zone, senderID) with the current
// contributions. Runs in a transaction: DELETE old rows, INSERT new rows.
func SaveContributions(kdb *KeyDB, zone, senderID string, contributions map[string]map[uint16]core.RRset) error {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	tx, err := kdb.DB.Begin()
	if err != nil {
		return fmt.Errorf("SaveContributions: begin tx: %w", err)
	}
	defer tx.Rollback()

	// Delete existing rows for this agent/zone pair
	_, err = tx.Exec(`DELETE FROM CombinerContributions WHERE zone = ? AND sender_id = ?`, zone, senderID)
	if err != nil {
		return fmt.Errorf("SaveContributions: delete old rows: %w", err)
	}

	now := time.Now().Unix()

	// Insert one row per RR
	stmt, err := tx.Prepare(`INSERT INTO CombinerContributions (zone, sender_id, owner, rrtype, rr, updated_at) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("SaveContributions: prepare: %w", err)
	}
	defer stmt.Close()

	for owner, rrtypeMap := range contributions {
		for rrtype, rrset := range rrtypeMap {
			for _, rr := range rrset.RRs {
				_, err = stmt.Exec(zone, senderID, owner, rrtype, rr.String(), now)
				if err != nil {
					return fmt.Errorf("SaveContributions: insert RR: %w", err)
				}
			}
		}
	}

	return tx.Commit()
}

// LoadAllContributions loads the entire CombinerContributions table and returns
// it structured as zone → senderID → owner → rrtype → RRset.
// Used at startup to hydrate AgentContributions for all combiner zones.
func LoadAllContributions(kdb *KeyDB) (map[string]map[string]map[string]map[uint16]core.RRset, error) {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	rows, err := kdb.DB.Query(`SELECT zone, sender_id, owner, rrtype, rr FROM CombinerContributions`)
	if err != nil {
		return nil, fmt.Errorf("LoadAllContributions: query: %w", err)
	}
	defer rows.Close()

	// zone → senderID → owner → rrtype → RRset
	result := make(map[string]map[string]map[string]map[uint16]core.RRset)

	for rows.Next() {
		var zone, senderID, owner, rrStr string
		var rrtype uint16
		if err := rows.Scan(&zone, &senderID, &owner, &rrtype, &rrStr); err != nil {
			return nil, fmt.Errorf("LoadAllContributions: scan: %w", err)
		}

		rr, err := dns.NewRR(rrStr)
		if err != nil {
			lgCombiner.Warn("LoadAllContributions: skipping unparseable RR", "zone", zone, "sender", senderID, "rr", rrStr, "err", err)
			continue
		}

		if result[zone] == nil {
			result[zone] = make(map[string]map[string]map[uint16]core.RRset)
		}
		if result[zone][senderID] == nil {
			result[zone][senderID] = make(map[string]map[uint16]core.RRset)
		}
		if result[zone][senderID][owner] == nil {
			result[zone][senderID][owner] = make(map[uint16]core.RRset)
		}

		existing := result[zone][senderID][owner][rrtype]
		existing.Name = owner
		existing.RRtype = rrtype
		existing.RRs = append(existing.RRs, rr)
		result[zone][senderID][owner][rrtype] = existing
	}

	return result, rows.Err()
}

// DeleteContributions removes all rows for a specific agent/zone pair.
func DeleteContributions(kdb *KeyDB, zone, senderID string) error {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	_, err := kdb.DB.Exec(`DELETE FROM CombinerContributions WHERE zone = ? AND sender_id = ?`, zone, senderID)
	if err != nil {
		return fmt.Errorf("DeleteContributions: %w", err)
	}
	return nil
}
