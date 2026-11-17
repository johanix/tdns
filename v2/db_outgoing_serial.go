package tdns

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

func (kdb *KeyDB) SaveOutgoingSerial(zone string, serial uint32) error {
	_, err := kdb.DB.Exec(`INSERT OR REPLACE INTO OutgoingSerials (zone, serial, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`, zone, serial)
	if err != nil {
		return fmt.Errorf("SaveOutgoingSerial: %w", err)
	}
	return nil
}

// RaiseOutgoingSerial records serial for zone unless the record already holds
// one newer than it, in RFC 1982 order. The record is the highest serial the
// zone has published, and the floor its next start lands past (#655), so a
// write never lowers it: a zone recreated under the same name, or parsed
// straight into a live ZoneData, can publish below it, and the secondaries
// that hold the higher serial still need the floor.
//
// One statement, so the comparison and the write cannot interleave with
// another writer. The WHERE clause is serialNewer: (new - old) mod 2^32 in
// [1, 2^31).
//
// A raise clears the content digest: it described the content at the old
// serial. SetPublishedContentDigest puts one back for the new serial when the
// publish computed one.
//
// The floor must be recorded even when the schema migration that adds the
// digest column failed (db.go logs that and carries on). Without the column
// no digest was ever stored, so there is none to clear, and the raise is
// retried without clearing one.
func (kdb *KeyDB) RaiseOutgoingSerial(zone string, serial uint32) error {
	_, err := kdb.DB.Exec(raiseOutgoingSerialSQL("content_digest = NULL, "), zone, serial)
	if err != nil && strings.Contains(err.Error(), "no such column: content_digest") {
		_, err = kdb.DB.Exec(raiseOutgoingSerialSQL(""), zone, serial)
	}
	if err != nil {
		return fmt.Errorf("RaiseOutgoingSerial: %w", err)
	}
	return nil
}

func raiseOutgoingSerialSQL(clearDigest string) string {
	return `
INSERT INTO OutgoingSerials (zone, serial, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
ON CONFLICT(zone) DO UPDATE SET serial = excluded.serial, ` + clearDigest + `updated_at = CURRENT_TIMESTAMP
WHERE ((excluded.serial - OutgoingSerials.serial) % 4294967296 + 4294967296) % 4294967296
      BETWEEN 1 AND 2147483647`
}

// SetPublishedContentDigest records digest as the content published at
// serial, provided serial is still the zone's recorded one. A digest that
// arrives after a newer serial was recorded describes nothing current and is
// dropped by the WHERE clause.
func (kdb *KeyDB) SetPublishedContentDigest(zone string, serial uint32, digest string) error {
	_, err := kdb.DB.Exec(`UPDATE OutgoingSerials SET content_digest = ? WHERE zone = ? AND serial = ?`,
		digest, zone, serial)
	if err != nil {
		return fmt.Errorf("SetPublishedContentDigest: %w", err)
	}
	return nil
}

// PublishedContentDigest returns the recorded serial and the digest of the
// content published at it, and whether there is a digest at all. No row, or a
// row without a digest, is not an error.
func (kdb *KeyDB) PublishedContentDigest(zone string) (uint32, string, bool, error) {
	var serial uint32
	var digest sql.NullString
	err := kdb.DB.QueryRow(`SELECT serial, content_digest FROM OutgoingSerials WHERE zone = ?`, zone).Scan(&serial, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", false, nil
	}
	if err != nil {
		return 0, "", false, fmt.Errorf("PublishedContentDigest: %w", err)
	}
	if !digest.Valid || digest.String == "" {
		return serial, "", false, nil
	}
	return serial, digest.String, true, nil
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
