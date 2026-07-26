package tdns

import "fmt"

func (kdb *KeyDB) SaveOutgoingSerial(zone string, serial uint32) error {
	_, err := kdb.DB.Exec(`INSERT OR REPLACE INTO OutgoingSerials (zone, serial, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`, zone, serial)
	if err != nil {
		return fmt.Errorf("SaveOutgoingSerial: %w", err)
	}
	return nil
}

func (kdb *KeyDB) LoadOutgoingSerial(zone string) (uint32, error) {
	var serial uint32
	err := kdb.DB.QueryRow(`SELECT serial FROM OutgoingSerials WHERE zone = ?`, zone).Scan(&serial)
	if err != nil {
		return 0, fmt.Errorf("LoadOutgoingSerial: %w", err)
	}
	return serial, nil
}

// DeleteOutgoingSerial drops any persisted outbound serial for a zone. Used
// when a zone is a tdns-auth secondary that may not originate content: its
// serial is upstream's property, so a value persisted earlier (before the zone
// became a mirror, or by a pre-fix build that bumped secondaries) must not
// linger — otherwise it sits in the DB waiting for some future change to the
// restore path to resurrect an inflated serial. Deleting a row that does not
// exist is not an error.
func (kdb *KeyDB) DeleteOutgoingSerial(zone string) error {
	_, err := kdb.DB.Exec(`DELETE FROM OutgoingSerials WHERE zone = ?`, zone)
	if err != nil {
		return fmt.Errorf("DeleteOutgoingSerial: %w", err)
	}
	return nil
}
