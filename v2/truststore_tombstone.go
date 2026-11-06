/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

// SIG(0) truststore tombstones.
//
// In a multi-provider zone the zone's SIG(0) key is rolled when a provider
// leaves, because the leaver holds the private half. The roll ends with a
// trusted UPDATE that deletes the old key here. Deleting the row is not
// enough: the parent bootstraps a key from a self-signed upload, or from a KEY
// it finds in the child's DNS, so whoever still holds the old private half --
// the leaver included -- could bring it straight back while any copy of the
// KEY is still published. No rule on the child side can stop that, since the
// leaver needs nothing from the child to send its own bootstrap. Only the
// parent can refuse.
//
// So a key that a child's trusted UPDATE deletes leaves a tombstone, and no
// later add of the same key for that child is accepted, whatever its source:
// a self-signed upload, the bootstrap ceremony, a key found in DNS, a trusted
// UPDATE, an operator's add. The match is on the public key (algorithm and key
// bytes), not the key tag: a new key that happens to share a tag with a
// retired one is a different key and bootstraps as usual.
//
// The tombstone is a table of its own rather than a flag on the Sig0TrustStore
// row. The row is deleted exactly as before, so no reader of Sig0TrustStore
// can take a retired key for a trusted one, and the row's UNIQUE (zonename,
// keyid) cannot make a new key with a colliding tag either overwrite the
// tombstone or be refused by it.
//
// Only a child's trusted UPDATE leaves one. An operator's "truststore sig0
// delete", the keystore's own delete and the bootstrap ceremony's deferred
// DEL-ANY-KEY cleanup remove the row as they always did. Keys in the
// validator.sig0.trusted.file config are the operator's own authority and are
// loaded without this check.
//
// Tombstones do not expire. The parent cannot know when the private half is
// gone, or when the last copy of the KEY has left caches, secondaries and
// signal names, and a tombstone blocks only that one key. An operator clears
// one deliberately with "truststore sig0 tombstone clear" (the truststore
// API's "tombstone-clear" subcommand); the key can then be added again like
// any new key.

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	// OR IGNORE: a second delete of a key already tombstoned keeps the time
	// of the first.
	addSig0TombstoneSql = `
INSERT OR IGNORE INTO Sig0TrustStoreTombstone (zonename, keyid, algorithm, publickey, keyrr, deleted_at, source) VALUES (?, ?, ?, ?, ?, ?, ?)`
	findSig0TombstoneSql = `
SELECT deleted_at FROM Sig0TrustStoreTombstone WHERE zonename=? AND algorithm=? AND publickey=?`
	listSig0TombstonesSql = `
SELECT zonename, keyid, algorithm, keyrr, deleted_at, source FROM Sig0TrustStoreTombstone ORDER BY zonename, keyid`
	// By name and tag, which is what an operator has in hand. Two retired
	// keys of one child that share a tag are both cleared.
	clearSig0TombstoneSql = `
DELETE FROM Sig0TrustStoreTombstone WHERE zonename=? AND keyid=?`
)

// ErrSig0KeyTombstoned is the refusal of an add of a key its child retired.
var ErrSig0KeyTombstoned = errors.New("SIG(0) key was deleted by the child's trusted UPDATE and will not be trusted again")

// Sig0Tombstone is a child SIG(0) key that the child's own trusted UPDATE
// deleted from the truststore.
type Sig0Tombstone struct {
	Name      string
	Keyid     uint16
	Algorithm uint8
	KeyRR     string
	DeletedAt string
	Source    string
}

// sig0Querier is what a tombstone lookup needs: a *Tx inside a transaction,
// the KeyDB outside one.
type sig0Querier interface {
	QueryRow(query string, args ...interface{}) *sql.Row
}

// sig0TombstoneKey is what a tombstone matches on: the child, the algorithm and
// the public key bytes, re-encoded so that two spellings of one key compare
// equal.
func sig0TombstoneKey(zone string, key *dns.KEY) (string, uint8, string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(key.PublicKey), ""))
	if err != nil {
		return "", 0, "", fmt.Errorf("SIG(0) key %s keyid %d: public key is not base64: %v", zone, key.KeyTag(), err)
	}
	return dns.CanonicalName(zone), key.Algorithm, base64.StdEncoding.EncodeToString(raw), nil
}

// sameSig0Key reports whether a and b are the same key: the comparison a
// tombstone matches on, without the owner name.
func sameSig0Key(a, b *dns.KEY) bool {
	_, aalg, apub, aerr := sig0TombstoneKey(a.Hdr.Name, a)
	_, balg, bpub, berr := sig0TombstoneKey(b.Hdr.Name, b)
	return aerr == nil && berr == nil && aalg == balg && apub == bpub
}

func parseSig0KeyRR(s string) (*dns.KEY, error) {
	rr, err := parseKeyRR(s)
	if err != nil {
		return nil, err
	}
	key, isKey := rr.(*dns.KEY)
	if !isKey {
		return nil, fmt.Errorf("expected a KEY record, got %s", dns.TypeToString[rr.Header().Rrtype])
	}
	return key, nil
}

// tombstoneSig0Key records that zone's own trusted UPDATE deleted key, in the
// caller's transaction, so that the tombstone and the delete land together.
func tombstoneSig0Key(tx *Tx, zone string, key *dns.KEY, source string) error {
	z, alg, pub, err := sig0TombstoneKey(zone, key)
	if err != nil {
		return err
	}
	// Stored as an ordinary record: the one in a delete UPDATE is class NONE.
	k := dns.Copy(key).(*dns.KEY)
	k.Hdr.Class = dns.ClassINET
	_, err = tx.Exec(addSig0TombstoneSql, z, k.KeyTag(), alg, pub, k.String(),
		time.Now().UTC().Format(time.RFC3339), source)
	return err
}

// sig0KeyTombstoned reports whether key is tombstoned for zone, and when its
// child deleted it.
func sig0KeyTombstoned(q sig0Querier, zone string, key *dns.KEY) (bool, string, error) {
	z, alg, pub, err := sig0TombstoneKey(zone, key)
	if err != nil {
		return false, "", err
	}
	var deletedAt string
	err = q.QueryRow(findSig0TombstoneSql, z, alg, pub).Scan(&deletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	return true, deletedAt, nil
}

// Sig0KeyTombstoned is sig0KeyTombstoned outside a transaction, for the UPDATE
// approval path.
func (kdb *KeyDB) Sig0KeyTombstoned(zone string, key *dns.KEY) (bool, string, error) {
	return sig0KeyTombstoned(kdb, zone, key)
}

// refuseTombstonedSig0Key is the check every truststore add makes: nil if
// keyrr may be stored for zone, an ErrSig0KeyTombstoned if its child retired
// it.
func refuseTombstonedSig0Key(tx *Tx, zone, keyrr string) error {
	key, err := parseSig0KeyRR(keyrr)
	if err != nil {
		return err
	}
	dead, deletedAt, err := sig0KeyTombstoned(tx, zone, key)
	if err != nil {
		return fmt.Errorf("SIG(0) key %s keyid %d: looking for a tombstone: %v", zone, key.KeyTag(), err)
	}
	if dead {
		return fmt.Errorf("%w: %s keyid %d, deleted %s; an operator can clear the tombstone with \"truststore sig0 tombstone clear\"",
			ErrSig0KeyTombstoned, zone, key.KeyTag(), deletedAt)
	}
	return nil
}

func listSig0Tombstones(tx *Tx) ([]Sig0Tombstone, error) {
	rows, err := tx.Query(listSig0TombstonesSql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sig0Tombstone
	for rows.Next() {
		var ts Sig0Tombstone
		var keyid, alg int
		if err := rows.Scan(&ts.Name, &keyid, &alg, &ts.KeyRR, &ts.DeletedAt, &ts.Source); err != nil {
			return nil, err
		}
		ts.Keyid, ts.Algorithm = uint16(keyid), uint8(alg)
		out = append(out, ts)
	}
	return out, rows.Err()
}
