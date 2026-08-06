/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Bulk export and import of keystore material.
 *
 * The keystore is a SQLite file, which makes it a poor place for key material
 * that has to outlive the machine: it cannot be reviewed, diffed or committed,
 * and losing it loses every key for every zone the server signs. Bulk
 * export/import is the durable-format escape hatch — BIND-convention key files
 * plus a manifest (see keystore_manifest.go), which together round-trip a
 * subset of the keystore losslessly.
 *
 * Import is create-if-absent by default. The keystore is authoritative for a
 * RUNNING server: an on-disk copy is a snapshot that may be arbitrarily stale,
 * and letting it overwrite live rows would mean a stale export directory
 * silently un-rolls a rolled key on every restart, with the symptom (a
 * suddenly-stale parent DS) surfacing nowhere near the cause. So a key that is
 * already present and differs is reported as a conflict and skipped. Force
 * flips that to overwrite, for the case the safety is in the way of: restoring
 * a keystore that is known to be wrong.
 */

package tdns

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Bulk import dispositions, one per key offered.
const (
	BulkStatusImported  = "imported"  // not present, inserted
	BulkStatusUnchanged = "unchanged" // present and identical, left alone
	BulkStatusConflict  = "conflict"  // present and different, SKIPPED (needs force)
	BulkStatusReplaced  = "replaced"  // present and different, overwritten under force
)

// BulkKeyDisposition reports the outcome for one offered key.
type BulkKeyDisposition struct {
	Name   string `json:"name"`
	Keyid  uint16 `json:"keyid,omitempty"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"` // for conflict/replaced: what differed
}

// BulkDnssecKey is one DNSSEC key on the wire, key material included. Distinct
// from DnssecKey (which the list/export commands use and which redacts) so that
// adding a keystore column here does not perturb the display types.
type BulkDnssecKey struct {
	Zone        string `json:"zone"`
	Keyid       uint16 `json:"keyid"`
	Flags       uint16 `json:"flags"`
	Algorithm   string `json:"algorithm"`
	State       string `json:"state"`
	Creator     string `json:"creator,omitempty"`
	Comment     string `json:"comment,omitempty"`
	PublishedAt string `json:"published_at,omitempty"`
	ActiveAt    string `json:"active_at,omitempty"`
	RetiredAt   string `json:"retired_at,omitempty"`
	ActiveSeq   *int64 `json:"active_seq,omitempty"`
	PrivateKey  string `json:"privatekey"` // PKCS#8 PEM, exactly as stored
	KeyRR       string `json:"keyrr"`      // zone-file DNSKEY RR text
}

// BulkSig0Key is one SIG(0) key on the wire, key material included.
type BulkSig0Key struct {
	Zone        string `json:"zone"`
	Keyid       uint16 `json:"keyid"`
	Algorithm   string `json:"algorithm"`
	State       string `json:"state"`
	Creator     string `json:"creator,omitempty"`
	Comment     string `json:"comment,omitempty"`
	ParentState uint8  `json:"parent_state,omitempty"`
	PrivateKey  string `json:"privatekey"` // PKCS#8 PEM, exactly as stored
	KeyRR       string `json:"keyrr"`      // zone-file KEY RR text
}

// BulkTsigKey is one TSIG key on the wire. The secret is the whole key.
type BulkTsigKey struct {
	Keyname   string `json:"keyname"`
	Algorithm string `json:"algorithm"`
	Secret    string `json:"secret"`
	Origin    string `json:"origin,omitempty"`
	Owner     string `json:"owner,omitempty"`
	Creator   string `json:"creator,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	Comment   string `json:"comment,omitempty"`
}

// --- selection ---------------------------------------------------------

// KeySelector picks which keys a bulk export covers. Exact names match one
// owner; Subtree names match that owner AND everything below it. An empty
// selector selects everything — that is the whole-keystore backup case, and it
// is deliberate rather than accidental (the CLI says so in its output).
type KeySelector struct {
	Exact   []string `json:"exact,omitempty"`
	Subtree []string `json:"subtree,omitempty"`
}

// NewKeySelector normalizes caller-supplied names to lowercase FQDNs so that
// "PQ.DNSLAB" and "pq.dnslab." select the same thing.
//
// A blank entry is an ERROR, not something to drop. Dropping it would leave the
// selector Empty(), and an empty selector means "everything" — so `--zones
// "$SUBTREE"` with an unset variable would silently export every private key in
// the keystore instead of failing. "No selector at all" must stay a deliberate
// act, never something a caller can arrive at by accident.
func NewKeySelector(exact, subtree []string) (KeySelector, error) {
	norm := func(in []string, what string) ([]string, error) {
		out := make([]string, 0, len(in))
		for _, n := range in {
			trimmed := strings.TrimSpace(n)
			if trimmed == "" {
				return nil, fmt.Errorf("empty %s selector: to select everything, pass no selector at all", what)
			}
			out = append(out, dns.Fqdn(strings.ToLower(trimmed)))
		}
		return out, nil
	}
	e, err := norm(exact, "exact")
	if err != nil {
		return KeySelector{}, err
	}
	s, err := norm(subtree, "subtree")
	if err != nil {
		return KeySelector{}, err
	}
	return KeySelector{Exact: e, Subtree: s}, nil
}

// Empty reports whether the selector constrains anything.
func (s KeySelector) Empty() bool { return len(s.Exact) == 0 && len(s.Subtree) == 0 }

// Matches reports whether name is selected.
//
// Subtree matching is on LABEL boundaries, not string suffixes: --zones
// pq.dnslab must not also scoop up notpq.dnslab.
func (s KeySelector) Matches(name string) bool {
	if s.Empty() {
		return true
	}
	name = dns.Fqdn(strings.ToLower(name))
	for _, e := range s.Exact {
		if name == e {
			return true
		}
	}
	for _, r := range s.Subtree {
		if r == "." { // the root's subtree is everything
			return true
		}
		if name == r || strings.HasSuffix(name, "."+r) {
			return true
		}
	}
	return false
}

// --- export ------------------------------------------------------------

const (
	bulkGetDnssecSql = `
SELECT zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr, comment,
       published_at, active_at, retired_at, active_seq
FROM DnssecKeyStore`

	bulkGetSig0Sql = `
SELECT zonename, state, keyid, algorithm, creator, privatekey, keyrr, comment, parent_state
FROM Sig0KeyStore`

	bulkGetTsigSql = `
SELECT keyname, algorithm, secret, origin, owner, creator, created_at, comment
FROM TsigKeystore`
)

// BulkExportDnssec returns every DNSSEC key matching sel, key material
// included and unredacted — that is the point of an export.
//
// Worth being deliberate about: this adds no new authorization (the same API
// key already permits per-key `keystore dnssec export`), but it does change the
// SHAPE of the exposure. Reading the whole keystore went from N calls, each
// needing a zone and a keyid the caller had to know, to one call that needs
// neither — and it leaves one line in the audit log instead of N. Anyone
// weighing where to expose the management API should price that in.
func (kdb *KeyDB) BulkExportDnssec(tx *Tx, sel KeySelector) ([]BulkDnssecKey, error) {
	rows, err := bulkQuery(kdb, tx, bulkGetDnssecSql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BulkDnssecKey
	for rows.Next() {
		var (
			zone, state, algorithm                    string
			creator, privkey, keyrr                   sql.NullString
			comment, publishedAt, activeAt, retiredAt sql.NullString
			keyid, flags                              int
			activeSeq                                 sql.NullInt64
		)
		if err := rows.Scan(&zone, &state, &keyid, &flags, &algorithm, &creator, &privkey,
			&keyrr, &comment, &publishedAt, &activeAt, &retiredAt, &activeSeq); err != nil {
			return nil, fmt.Errorf("BulkExportDnssec: scan: %v", err)
		}
		if !sel.Matches(zone) {
			continue
		}
		k := BulkDnssecKey{
			Zone:        zone,
			Keyid:       uint16(keyid),
			Flags:       uint16(flags),
			Algorithm:   algorithm,
			State:       state,
			Creator:     creator.String,
			Comment:     comment.String,
			PublishedAt: publishedAt.String,
			ActiveAt:    activeAt.String,
			RetiredAt:   retiredAt.String,
			PrivateKey:  privkey.String,
			KeyRR:       keyrr.String,
		}
		if activeSeq.Valid {
			v := activeSeq.Int64
			k.ActiveSeq = &v
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// BulkExportSig0 returns every SIG(0) key matching sel.
func (kdb *KeyDB) BulkExportSig0(tx *Tx, sel KeySelector) ([]BulkSig0Key, error) {
	rows, err := bulkQuery(kdb, tx, bulkGetSig0Sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BulkSig0Key
	for rows.Next() {
		var (
			zone, state, algorithm           string
			creator, privkey, keyrr, comment sql.NullString
			keyid, parentState               int
		)
		if err := rows.Scan(&zone, &state, &keyid, &algorithm, &creator, &privkey,
			&keyrr, &comment, &parentState); err != nil {
			return nil, fmt.Errorf("BulkExportSig0: scan: %v", err)
		}
		if !sel.Matches(zone) {
			continue
		}
		out = append(out, BulkSig0Key{
			Zone:        zone,
			Keyid:       uint16(keyid),
			Algorithm:   algorithm,
			State:       state,
			Creator:     creator.String,
			Comment:     comment.String,
			ParentState: uint8(parentState),
			PrivateKey:  privkey.String,
			KeyRR:       keyrr.String,
		})
	}
	return out, rows.Err()
}

// BulkExportTsig returns every TSIG key matching sel. TSIG key names are DNS
// names, so the same exact/subtree selection applies.
func (kdb *KeyDB) BulkExportTsig(tx *Tx, sel KeySelector) ([]BulkTsigKey, error) {
	rows, err := bulkQuery(kdb, tx, bulkGetTsigSql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BulkTsigKey
	for rows.Next() {
		var (
			keyname, algorithm, secret, origin string
			owner, creator, createdAt, comment sql.NullString
		)
		if err := rows.Scan(&keyname, &algorithm, &secret, &origin, &owner,
			&creator, &createdAt, &comment); err != nil {
			return nil, fmt.Errorf("BulkExportTsig: scan: %v", err)
		}
		if !sel.Matches(keyname) {
			continue
		}
		out = append(out, BulkTsigKey{
			Keyname:   keyname,
			Algorithm: algorithm,
			Secret:    secret,
			Origin:    origin,
			Owner:     owner.String,
			Creator:   creator.String,
			CreatedAt: createdAt.String,
			Comment:   comment.String,
		})
	}
	return out, rows.Err()
}

// bulkQuery runs a read against the transaction when there is one, else
// against the DB directly. Export is read-only, so it does not need a
// transaction of its own.
func bulkQuery(kdb *KeyDB, tx *Tx, q string) (*sql.Rows, error) {
	if tx != nil {
		rows, err := tx.Query(q)
		if err != nil {
			return nil, fmt.Errorf("query: %v", err)
		}
		return rows, nil
	}
	rows, err := kdb.Query(q)
	if err != nil {
		return nil, fmt.Errorf("query: %v", err)
	}
	return rows, nil
}

// --- import ------------------------------------------------------------

const (
	bulkSelectDnssecSql = `
SELECT state, flags, algorithm, creator, privatekey, keyrr, comment,
       published_at, active_at, retired_at, active_seq
FROM DnssecKeyStore WHERE zonename=? AND keyid=?`

	bulkInsertDnssecSql = `
INSERT INTO DnssecKeyStore (zonename, state, keyid, flags, algorithm, creator, privatekey,
       keyrr, comment, published_at, active_at, retired_at, active_seq)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	bulkUpdateDnssecSql = `
UPDATE DnssecKeyStore SET state=?, flags=?, algorithm=?, creator=?, privatekey=?, keyrr=?,
       comment=?, published_at=?, active_at=?, retired_at=?, active_seq=?
WHERE zonename=? AND keyid=?`

	bulkSelectSig0Sql = `
SELECT state, algorithm, creator, privatekey, keyrr, comment, parent_state
FROM Sig0KeyStore WHERE zonename=? AND keyid=?`

	bulkInsertSig0Sql = `
INSERT INTO Sig0KeyStore (zonename, state, keyid, algorithm, creator, privatekey, keyrr,
       comment, parent_state)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	bulkUpdateSig0Sql = `
UPDATE Sig0KeyStore SET state=?, algorithm=?, creator=?, privatekey=?, keyrr=?, comment=?,
       parent_state=? WHERE zonename=? AND keyid=?`

	bulkSelectTsigSql = `
SELECT algorithm, secret, origin, owner, creator, created_at, comment
FROM TsigKeystore WHERE keyname=?`

	bulkInsertTsigSql = `
INSERT INTO TsigKeystore (keyname, algorithm, secret, origin, owner, creator, created_at, comment)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	bulkUpdateTsigSql = `
UPDATE TsigKeystore SET algorithm=?, secret=?, origin=?, owner=?, creator=?, created_at=?,
       comment=? WHERE keyname=?`
)

// BulkImportDnssec inserts keys that are absent, leaves identical ones alone,
// and skips differing ones unless force is set. It returns one disposition per
// offered key, in the order offered.
//
// Note what this does NOT do: it never parses the private key. The PEM column
// is stored verbatim, so a key whose algorithm this binary does not link still
// restores correctly (it will fail later, loudly, if the zone actually tries to
// sign with it) — which is what makes pre-load safe to run before any zone is
// bound. It is still checked for PEM armour, since storing a non-PEM blob in
// the PEM column would otherwise surface only at signing time. The public half
// IS parsed, because that is a cheap, crypto-free way to catch a manifest that
// disagrees with its own files.
func (kdb *KeyDB) BulkImportDnssec(tx *Tx, keys []BulkDnssecKey, force bool) ([]BulkKeyDisposition, error) {
	tx, done, err := kdb.bulkTx(tx, "BulkImportDnssec")
	if err != nil {
		return nil, err
	}
	var ok bool
	defer func() { done(ok) }()

	out := make([]BulkKeyDisposition, 0, len(keys))
	for _, k := range keys {
		zone := dns.Fqdn(k.Zone)
		if err := validateDnssecKeyRR(k); err != nil {
			return nil, fmt.Errorf("%s keyid %d: %v", zone, k.Keyid, err)
		}

		var (
			curState, curAlg                          string
			curCreator, curPriv, curKeyRR, curComment sql.NullString
			curPub, curAct, curRet                    sql.NullString
			curFlags                                  int
			curSeq                                    sql.NullInt64
		)
		row := tx.QueryRow(bulkSelectDnssecSql, zone, int(k.Keyid))
		scanErr := row.Scan(&curState, &curFlags, &curAlg, &curCreator, &curPriv, &curKeyRR,
			&curComment, &curPub, &curAct, &curRet, &curSeq)

		switch {
		case scanErr == sql.ErrNoRows:
			if _, err := tx.Exec(bulkInsertDnssecSql, zone, k.State, int(k.Keyid), int(k.Flags),
				k.Algorithm, k.Creator, k.PrivateKey, k.KeyRR, k.Comment,
				k.PublishedAt, k.ActiveAt, k.RetiredAt, nullableInt64(k.ActiveSeq)); err != nil {
				return nil, fmt.Errorf("inserting DNSSEC key %s keyid %d: %v", zone, k.Keyid, err)
			}
			out = append(out, BulkKeyDisposition{Name: zone, Keyid: k.Keyid, Status: BulkStatusImported})

		case scanErr != nil:
			return nil, fmt.Errorf("reading DNSSEC key %s keyid %d: %v", zone, k.Keyid, scanErr)

		default:
			diffs := diffFields(
				field{"state", curState, k.State},
				field{"flags", fmt.Sprint(curFlags), fmt.Sprint(k.Flags)},
				field{"algorithm", curAlg, k.Algorithm},
				field{"creator", curCreator.String, k.Creator},
				field{"privatekey", curPriv.String, k.PrivateKey},
				field{"keyrr", curKeyRR.String, k.KeyRR},
				field{"comment", curComment.String, k.Comment},
				field{"published_at", curPub.String, k.PublishedAt},
				field{"active_at", curAct.String, k.ActiveAt},
				field{"retired_at", curRet.String, k.RetiredAt},
				field{"active_seq", nullInt64String(curSeq), ptrInt64String(k.ActiveSeq)},
			)
			switch {
			case len(diffs) == 0:
				out = append(out, BulkKeyDisposition{Name: zone, Keyid: k.Keyid, Status: BulkStatusUnchanged})
			case !force:
				out = append(out, BulkKeyDisposition{Name: zone, Keyid: k.Keyid,
					Status: BulkStatusConflict, Detail: strings.Join(diffs, ", ")})
			default:
				if _, err := tx.Exec(bulkUpdateDnssecSql, k.State, int(k.Flags), k.Algorithm,
					k.Creator, k.PrivateKey, k.KeyRR, k.Comment, k.PublishedAt, k.ActiveAt,
					k.RetiredAt, nullableInt64(k.ActiveSeq), zone, int(k.Keyid)); err != nil {
					return nil, fmt.Errorf("replacing DNSSEC key %s keyid %d: %v", zone, k.Keyid, err)
				}
				out = append(out, BulkKeyDisposition{Name: zone, Keyid: k.Keyid,
					Status: BulkStatusReplaced, Detail: strings.Join(diffs, ", ")})
			}
		}
	}
	ok = true
	return out, nil
}

// BulkImportSig0 is the SIG(0) counterpart of BulkImportDnssec.
//
// It also invalidates the in-memory KeystoreSig0Cache for every key it actually
// changes. GetSig0Keys is read-through against that cache, and every other
// SIG(0) write path drops the affected entries — without this a bulk import on
// a RUNNING daemon would leave it signing UPDATEs with the superseded key until
// the next restart. (Pre-load runs before anything populates the cache, so this
// matters only on the live API path.) The plain map delete matches what the
// other write paths do; the cache has never been mutex-guarded.
func (kdb *KeyDB) BulkImportSig0(tx *Tx, keys []BulkSig0Key, force bool) ([]BulkKeyDisposition, error) {
	tx, done, err := kdb.bulkTx(tx, "BulkImportSig0")
	if err != nil {
		return nil, err
	}
	var ok bool
	defer func() { done(ok) }()

	out := make([]BulkKeyDisposition, 0, len(keys))
	for _, k := range keys {
		zone := dns.Fqdn(k.Zone)
		if err := validateSig0KeyRR(k); err != nil {
			return nil, fmt.Errorf("%s keyid %d: %v", zone, k.Keyid, err)
		}

		var (
			curState, curAlg                          string
			curCreator, curPriv, curKeyRR, curComment sql.NullString
			curParentState                            int
		)
		row := tx.QueryRow(bulkSelectSig0Sql, zone, int(k.Keyid))
		scanErr := row.Scan(&curState, &curAlg, &curCreator, &curPriv, &curKeyRR,
			&curComment, &curParentState)

		switch {
		case scanErr == sql.ErrNoRows:
			if _, err := tx.Exec(bulkInsertSig0Sql, zone, k.State, int(k.Keyid), k.Algorithm,
				k.Creator, k.PrivateKey, k.KeyRR, k.Comment, int(k.ParentState)); err != nil {
				return nil, fmt.Errorf("inserting SIG(0) key %s keyid %d: %v", zone, k.Keyid, err)
			}
			out = append(out, BulkKeyDisposition{Name: zone, Keyid: k.Keyid, Status: BulkStatusImported})

		case scanErr != nil:
			return nil, fmt.Errorf("reading SIG(0) key %s keyid %d: %v", zone, k.Keyid, scanErr)

		default:
			diffs := diffFields(
				field{"state", curState, k.State},
				field{"algorithm", curAlg, k.Algorithm},
				field{"creator", curCreator.String, k.Creator},
				field{"privatekey", curPriv.String, k.PrivateKey},
				field{"keyrr", curKeyRR.String, k.KeyRR},
				field{"comment", curComment.String, k.Comment},
				field{"parent_state", fmt.Sprint(curParentState), fmt.Sprint(k.ParentState)},
			)
			switch {
			case len(diffs) == 0:
				out = append(out, BulkKeyDisposition{Name: zone, Keyid: k.Keyid, Status: BulkStatusUnchanged})
			case !force:
				out = append(out, BulkKeyDisposition{Name: zone, Keyid: k.Keyid,
					Status: BulkStatusConflict, Detail: strings.Join(diffs, ", ")})
			default:
				if _, err := tx.Exec(bulkUpdateSig0Sql, k.State, k.Algorithm, k.Creator,
					k.PrivateKey, k.KeyRR, k.Comment, int(k.ParentState), zone, int(k.Keyid)); err != nil {
					return nil, fmt.Errorf("replacing SIG(0) key %s keyid %d: %v", zone, k.Keyid, err)
				}
				out = append(out, BulkKeyDisposition{Name: zone, Keyid: k.Keyid,
					Status: BulkStatusReplaced, Detail: strings.Join(diffs, ", ")})
			}
		}
	}
	for _, d := range out {
		if d.Status == BulkStatusImported || d.Status == BulkStatusReplaced {
			kdb.invalidateSig0Cache(d.Name)
		}
	}
	ok = true
	return out, nil
}

// invalidateSig0Cache drops every cached state entry for one zone, mirroring
// what Sig0KeyMgmt does after add/generate/delete/setstate.
func (kdb *KeyDB) invalidateSig0Cache(zone string) {
	if kdb.KeystoreSig0Cache == nil {
		return
	}
	for _, state := range []string{Sig0StateCreated, Sig0StatePublished, Sig0StateActive, Sig0StateRetired} {
		delete(kdb.KeystoreSig0Cache, zone+"+"+state)
	}
}

// BulkImportTsig is the TSIG counterpart. Callers that hold the live TSIG cache
// (the API handler) must refresh it afterwards; pre-load runs before the cache
// is built, so it has nothing to invalidate.
func (kdb *KeyDB) BulkImportTsig(tx *Tx, keys []BulkTsigKey, force bool) ([]BulkKeyDisposition, error) {
	tx, done, err := kdb.bulkTx(tx, "BulkImportTsig")
	if err != nil {
		return nil, err
	}
	var ok bool
	defer func() { done(ok) }()

	out := make([]BulkKeyDisposition, 0, len(keys))
	for _, k := range keys {
		name := dns.Fqdn(k.Keyname)
		if k.Algorithm == "" || k.Secret == "" {
			return nil, fmt.Errorf("TSIG key %s: algorithm and secret are both required", name)
		}
		origin := k.Origin
		if origin == "" {
			origin = "import"
		}

		var (
			curAlg, curSecret, curOrigin           string
			curOwner, curCreator, curCreated, curC sql.NullString
		)
		row := tx.QueryRow(bulkSelectTsigSql, name)
		scanErr := row.Scan(&curAlg, &curSecret, &curOrigin, &curOwner, &curCreator, &curCreated, &curC)

		switch {
		case scanErr == sql.ErrNoRows:
			if _, err := tx.Exec(bulkInsertTsigSql, name, k.Algorithm, k.Secret, origin,
				k.Owner, k.Creator, k.CreatedAt, k.Comment); err != nil {
				return nil, fmt.Errorf("inserting TSIG key %s: %v", name, err)
			}
			out = append(out, BulkKeyDisposition{Name: name, Status: BulkStatusImported})

		case scanErr != nil:
			return nil, fmt.Errorf("reading TSIG key %s: %v", name, scanErr)

		default:
			diffs := diffFields(
				field{"algorithm", curAlg, k.Algorithm},
				field{"secret", curSecret, k.Secret},
				field{"origin", curOrigin, origin},
				field{"owner", curOwner.String, k.Owner},
				field{"creator", curCreator.String, k.Creator},
				field{"created_at", curCreated.String, k.CreatedAt},
				field{"comment", curC.String, k.Comment},
			)
			switch {
			case len(diffs) == 0:
				out = append(out, BulkKeyDisposition{Name: name, Status: BulkStatusUnchanged})
			case !force:
				out = append(out, BulkKeyDisposition{Name: name, Status: BulkStatusConflict,
					Detail: strings.Join(diffs, ", ")})
			default:
				if _, err := tx.Exec(bulkUpdateTsigSql, k.Algorithm, k.Secret, origin, k.Owner,
					k.Creator, k.CreatedAt, k.Comment, name); err != nil {
					return nil, fmt.Errorf("replacing TSIG key %s: %v", name, err)
				}
				out = append(out, BulkKeyDisposition{Name: name, Status: BulkStatusReplaced,
					Detail: strings.Join(diffs, ", ")})
			}
		}
	}
	ok = true
	return out, nil
}

// --- helpers -----------------------------------------------------------

// bulkTx returns the transaction to use plus a finisher. When the caller
// supplied a transaction the finisher is a no-op (the caller owns commit);
// otherwise it commits on success and rolls back on failure. An import is
// all-or-nothing: a partially-restored keystore is the state nobody can reason
// about.
func (kdb *KeyDB) bulkTx(tx *Tx, who string) (*Tx, func(bool), error) {
	if tx != nil {
		return tx, func(bool) {}, nil
	}
	newTx, err := kdb.Begin(who)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: begin: %v", who, err)
	}
	return newTx, func(ok bool) {
		if ok {
			if err := newTx.Commit(); err != nil {
				lgSigner.Error("bulk keystore import commit failed", "who", who, "err", err)
			}
			return
		}
		newTx.Rollback()
	}, nil
}

// summarizeDispositions renders the one-line result an operator reads first.
// Conflicts are named explicitly rather than folded into a count, because a
// conflict means "your file is not what is running" — the one outcome that is
// easy to skim past and expensive to miss.
func summarizeDispositions(ds []BulkKeyDisposition, force bool) string {
	var imported, unchanged, conflicts, replaced int
	for _, d := range ds {
		switch d.Status {
		case BulkStatusImported:
			imported++
		case BulkStatusUnchanged:
			unchanged++
		case BulkStatusConflict:
			conflicts++
		case BulkStatusReplaced:
			replaced++
		}
	}
	msg := fmt.Sprintf("%d key(s) offered: %d imported, %d unchanged", len(ds), imported, unchanged)
	if force {
		msg += fmt.Sprintf(", %d replaced", replaced)
	}
	if conflicts > 0 {
		msg += fmt.Sprintf(", %d SKIPPED as conflicting (already in the keystore with different content; --force to overwrite)", conflicts)
	}
	return msg
}

// changedZones lists the distinct zones a bulk import actually altered, so the
// caller can republish their signing-key sets after commit. Unchanged and
// conflicting keys are excluded: nothing about those zones moved.
func changedZones(ds []BulkKeyDisposition) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range ds {
		if d.Status != BulkStatusImported && d.Status != BulkStatusReplaced {
			continue
		}
		if seen[d.Name] {
			continue
		}
		seen[d.Name] = true
		out = append(out, d.Name)
	}
	return out
}

type field struct {
	name string
	have string
	want string
}

// diffFields names the fields where the stored value and the offered value
// disagree. The names, not the values, are reported: a diff on "privatekey"
// must not print key material into a log.
func diffFields(fs ...field) []string {
	var out []string
	for _, f := range fs {
		if f.have != f.want {
			out = append(out, f.name)
		}
	}
	return out
}

func nullableInt64(v *int64) interface{} {
	if v == nil {
		return nil
	}
	return *v
}

func nullInt64String(v sql.NullInt64) string {
	if !v.Valid {
		return ""
	}
	return fmt.Sprint(v.Int64)
}

func ptrInt64String(v *int64) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(*v)
}

// validateBulkPrivateKey checks that the private half is what the keystore
// column expects: PKCS#8 PEM. It does NOT parse the key — IsPEMFormat only looks
// at the armour — so the "never parse a private key" property that lets an
// unknown algorithm restore correctly is preserved.
//
// The check earns its place because bulk import writes the blob through
// verbatim. The single-key `keystore <class> import` accepts BIND-format
// private keys too and converts them (PrepareKeyCache), so a BIND blob in an
// export directory is a plausible mistake — and without this it would be stored
// happily and only fail much later, at signing time.
func validateBulkPrivateKey(privkey string) error {
	if strings.TrimSpace(privkey) == "" {
		return fmt.Errorf("no private key material")
	}
	if !IsPEMFormat(privkey) {
		return fmt.Errorf("private key is not PKCS#8 PEM; for a BIND-format key use 'keystore <class> import', which converts it")
	}
	return nil
}

// validateDnssecKeyRR checks the public half against the metadata that travels
// with it. This is deliberately crypto-free — it parses the RR and compares
// flags/algorithm/owner/keytag — so it works for algorithms this binary has no
// implementation for, and still catches a manifest that has drifted from its
// key files (the failure that would otherwise surface as an unsignable zone).
func validateDnssecKeyRR(k BulkDnssecKey) error {
	if err := validateBulkPrivateKey(k.PrivateKey); err != nil {
		return err
	}
	rr, err := dns.NewRR(k.KeyRR)
	if err != nil {
		return fmt.Errorf("unparsable DNSKEY RR: %v", err)
	}
	dnskey, isDnskey := rr.(*dns.DNSKEY)
	if !isDnskey {
		return fmt.Errorf("expected a DNSKEY RR, got %s", dns.TypeToString[rr.Header().Rrtype])
	}
	if !strings.EqualFold(dnskey.Header().Name, dns.Fqdn(k.Zone)) {
		return fmt.Errorf("DNSKEY owner %q does not match zone %q", dnskey.Header().Name, dns.Fqdn(k.Zone))
	}
	if dnskey.Flags != k.Flags {
		return fmt.Errorf("DNSKEY flags %d do not match the recorded flags %d", dnskey.Flags, k.Flags)
	}
	if tag := dnskey.KeyTag(); tag != k.Keyid {
		return fmt.Errorf("DNSKEY keytag %d does not match the recorded keyid %d", tag, k.Keyid)
	}
	if name, ok := dns.AlgorithmToString[dnskey.Algorithm]; ok && !strings.EqualFold(name, k.Algorithm) {
		return fmt.Errorf("DNSKEY algorithm %s does not match the recorded algorithm %s", name, k.Algorithm)
	}
	return nil
}

// validateSig0KeyRR is the KEY-RR counterpart of validateDnssecKeyRR.
func validateSig0KeyRR(k BulkSig0Key) error {
	if err := validateBulkPrivateKey(k.PrivateKey); err != nil {
		return err
	}
	rr, err := dns.NewRR(k.KeyRR)
	if err != nil {
		return fmt.Errorf("unparsable KEY RR: %v", err)
	}
	key, isKey := rr.(*dns.KEY)
	if !isKey {
		return fmt.Errorf("expected a KEY RR, got %s", dns.TypeToString[rr.Header().Rrtype])
	}
	if !strings.EqualFold(key.Header().Name, dns.Fqdn(k.Zone)) {
		return fmt.Errorf("KEY owner %q does not match zone %q", key.Header().Name, dns.Fqdn(k.Zone))
	}
	if tag := key.KeyTag(); tag != k.Keyid {
		return fmt.Errorf("KEY keytag %d does not match the recorded keyid %d", tag, k.Keyid)
	}
	if name, ok := dns.AlgorithmToString[key.Algorithm]; ok && !strings.EqualFold(name, k.Algorithm) {
		return fmt.Errorf("KEY algorithm %s does not match the recorded algorithm %s", name, k.Algorithm)
	}
	return nil
}
