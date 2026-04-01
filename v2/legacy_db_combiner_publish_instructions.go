/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Data access layer for the CombinerPublishInstructions table.
 * Persists per-agent KEY/CDS publication instructions so the combiner
 * can maintain _signal names across restarts and NS changes.
 */

package tdns

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	core "github.com/johanix/tdns/v2/core"
)

// StoredPublishInstruction is the persisted form of a PublishInstruction,
// augmented with the set of NS targets that currently have active _signal KEYs.
type StoredPublishInstruction struct {
	Zone        string
	SenderID    string
	KEYRRs      []string
	CDSRRs      []string
	Locations   []string
	PublishedNS []string // NS targets with currently active _signal KEYs
	UpdatedAt   time.Time
}

// ToPublishInstruction converts back to the wire-format struct.
func (s *StoredPublishInstruction) ToPublishInstruction() *core.PublishInstruction {
	return &core.PublishInstruction{
		KEYRRs:    s.KEYRRs,
		CDSRRs:    s.CDSRRs,
		Locations: s.Locations,
	}
}

// SavePublishInstruction upserts a publish instruction for (zone, senderID).
func SavePublishInstruction(kdb *KeyDB, zone, senderID string, instr *core.PublishInstruction, publishedNS []string) error {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	keyJSON, err := json.Marshal(instr.KEYRRs)
	if err != nil {
		return fmt.Errorf("SavePublishInstruction: marshal KEYRRs: %w", err)
	}
	cdsJSON, err := json.Marshal(instr.CDSRRs)
	if err != nil {
		return fmt.Errorf("SavePublishInstruction: marshal CDSRRs: %w", err)
	}
	locJSON, err := json.Marshal(instr.Locations)
	if err != nil {
		return fmt.Errorf("SavePublishInstruction: marshal Locations: %w", err)
	}
	nsJSON, err := json.Marshal(publishedNS)
	if err != nil {
		return fmt.Errorf("SavePublishInstruction: marshal publishedNS: %w", err)
	}

	_, err = kdb.DB.Exec(`
		INSERT INTO CombinerPublishInstructions (zone, sender_id, key_rrs_json, cds_rrs_json, locations_json, published_ns_json, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(zone, sender_id) DO UPDATE SET
			key_rrs_json = excluded.key_rrs_json,
			cds_rrs_json = excluded.cds_rrs_json,
			locations_json = excluded.locations_json,
			published_ns_json = excluded.published_ns_json,
			updated_at = excluded.updated_at`,
		zone, senderID, string(keyJSON), string(cdsJSON), string(locJSON), string(nsJSON), time.Now().Unix())
	if err != nil {
		return fmt.Errorf("SavePublishInstruction: upsert: %w", err)
	}
	return nil
}

// GetPublishInstruction returns the stored instruction for (zone, senderID), or nil.
func GetPublishInstruction(kdb *KeyDB, zone, senderID string) (*StoredPublishInstruction, error) {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	var keyJSON, cdsJSON, locJSON, nsJSON string
	var updatedAt int64
	err := kdb.DB.QueryRow(`
		SELECT key_rrs_json, cds_rrs_json, locations_json, published_ns_json, updated_at
		FROM CombinerPublishInstructions WHERE zone = ? AND sender_id = ?`,
		zone, senderID).Scan(&keyJSON, &cdsJSON, &locJSON, &nsJSON, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("GetPublishInstruction: query: %w", err)
	}

	s := &StoredPublishInstruction{
		Zone:      zone,
		SenderID:  senderID,
		UpdatedAt: time.Unix(updatedAt, 0),
	}
	if err := json.Unmarshal([]byte(keyJSON), &s.KEYRRs); err != nil {
		return nil, fmt.Errorf("GetPublishInstruction: unmarshal KEYRRs: %w", err)
	}
	if err := json.Unmarshal([]byte(cdsJSON), &s.CDSRRs); err != nil {
		return nil, fmt.Errorf("GetPublishInstruction: unmarshal CDSRRs: %w", err)
	}
	if err := json.Unmarshal([]byte(locJSON), &s.Locations); err != nil {
		return nil, fmt.Errorf("GetPublishInstruction: unmarshal Locations: %w", err)
	}
	if err := json.Unmarshal([]byte(nsJSON), &s.PublishedNS); err != nil {
		return nil, fmt.Errorf("GetPublishInstruction: unmarshal PublishedNS: %w", err)
	}
	return s, nil
}

// DeletePublishInstruction removes the stored instruction for (zone, senderID).
func DeletePublishInstruction(kdb *KeyDB, zone, senderID string) error {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	_, err := kdb.DB.Exec(`DELETE FROM CombinerPublishInstructions WHERE zone = ? AND sender_id = ?`, zone, senderID)
	if err != nil {
		return fmt.Errorf("DeletePublishInstruction: %w", err)
	}
	return nil
}

// LoadAllPublishInstructions loads all stored instructions, keyed by zone then senderID.
func LoadAllPublishInstructions(kdb *KeyDB) (map[string]map[string]*StoredPublishInstruction, error) {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	rows, err := kdb.DB.Query(`SELECT zone, sender_id, key_rrs_json, cds_rrs_json, locations_json, published_ns_json, updated_at FROM CombinerPublishInstructions`)
	if err != nil {
		return nil, fmt.Errorf("LoadAllPublishInstructions: query: %w", err)
	}
	defer rows.Close()

	result := make(map[string]map[string]*StoredPublishInstruction)
	for rows.Next() {
		var zone, senderID, keyJSON, cdsJSON, locJSON, nsJSON string
		var updatedAt int64
		if err := rows.Scan(&zone, &senderID, &keyJSON, &cdsJSON, &locJSON, &nsJSON, &updatedAt); err != nil {
			return nil, fmt.Errorf("LoadAllPublishInstructions: scan: %w", err)
		}

		s := &StoredPublishInstruction{
			Zone:      zone,
			SenderID:  senderID,
			UpdatedAt: time.Unix(updatedAt, 0),
		}
		if err := json.Unmarshal([]byte(keyJSON), &s.KEYRRs); err != nil {
			return nil, fmt.Errorf("LoadAllPublishInstructions: zone=%s senderID=%s decode KEYRRs: %w", zone, senderID, err)
		}
		if err := json.Unmarshal([]byte(cdsJSON), &s.CDSRRs); err != nil {
			return nil, fmt.Errorf("LoadAllPublishInstructions: zone=%s senderID=%s decode CDSRRs: %w", zone, senderID, err)
		}
		if err := json.Unmarshal([]byte(locJSON), &s.Locations); err != nil {
			return nil, fmt.Errorf("LoadAllPublishInstructions: zone=%s senderID=%s decode Locations: %w", zone, senderID, err)
		}
		if err := json.Unmarshal([]byte(nsJSON), &s.PublishedNS); err != nil {
			return nil, fmt.Errorf("LoadAllPublishInstructions: zone=%s senderID=%s decode PublishedNS: %w", zone, senderID, err)
		}

		if result[zone] == nil {
			result[zone] = make(map[string]*StoredPublishInstruction)
		}
		result[zone][senderID] = s
	}

	return result, rows.Err()
}
