package tdns

import (
	"fmt"

	"github.com/miekg/dns"
)

// GenerateKskRolloverCreated inserts a new KSK in state created with RolloverKeyState (multi-ds / double-signature pipeline).
func GenerateKskRolloverCreated(kdb *KeyDB, zone, creator string, alg uint8, method RolloverMethod) (keyid uint16, rolloverIndex int, err error) {
	zone = dns.Fqdn(zone)
	tx, err := kdb.Begin("GenerateKskRolloverCreated")
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			err = tx.Commit()
		}
	}()

	ri, err := nextRolloverIndexTx(tx, zone)
	if err != nil {
		return 0, 0, err
	}

	pkc, _, err := kdb.GenerateKeypair(zone, creator, DnskeyStateCreated, dns.TypeDNSKEY, alg, "KSK", tx)
	if err != nil {
		return 0, 0, fmt.Errorf("GenerateKskRolloverCreated: %w", err)
	}

	if err := insertRolloverKeyStateTx(tx, zone, pkc.KeyId, ri, method); err != nil {
		return 0, 0, fmt.Errorf("GenerateKskRolloverCreated: rollover state: %w", err)
	}

	delete(kdb.KeystoreDnskeyCache, zone+"+"+DnskeyStateCreated)

	return pkc.KeyId, ri, nil
}

// CountKskInRolloverPipeline counts SEP keys in pre-terminal rollover pipeline states.
func CountKskInRolloverPipeline(kdb *KeyDB, zone string) (int, error) {
	zone = dns.Fqdn(zone)
	const q = `
SELECT COUNT(*) FROM DnssecKeyStore
WHERE zonename = ? AND (CAST(flags AS INTEGER) & ?) != 0
  AND state IN ('created','ds-published','standby','published','active','retired')`
	var n int
	err := kdb.DB.QueryRow(q, zone, int(dns.SEP)).Scan(&n)
	return n, err
}
