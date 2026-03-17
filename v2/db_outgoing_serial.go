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
