/*
 * Copyright (c) Johan Stenstam, <johani@johani.org>
 */
package tdns

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

// Named returns so the deferred commit can report its own failure, matching
// DnssecKeyMgmt below. Without them a localtx commit error was logged and
// dropped: the function had already returned a fully-populated response and a
// nil error, so every caller was told the write succeeded when nothing had been
// written.
func (kdb *KeyDB) Sig0KeyMgmt(tx *Tx, kp KeystorePost) (out *KeystoreResponse, err error) {

	const (
		addSig0KeySql = `
INSERT OR REPLACE INTO Sig0KeyStore (zonename, state, keyid, algorithm, creator, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, ?, ?)`
		setStateSig0KeySql = "UPDATE Sig0KeyStore SET state=? WHERE zonename=? AND keyid=?"
		deleteSig0KeySql   = `DELETE FROM Sig0KeyStore WHERE zonename=? AND keyid=?`
		getAllSig0KeysSql  = `SELECT zonename, state, keyid, algorithm, creator, privatekey, keyrr FROM Sig0KeyStore`
		getSig0KeySql      = `
SELECT zonename, state, keyid, algorithm, creator, privatekey, keyrr FROM Sig0KeyStore WHERE zonename=? AND keyid=?`
	)

	var resp = KeystoreResponse{Time: time.Now()}
	var res sql.Result

	var localtx = false
	var txSuccess bool
	// Zones whose SIG(0) cache entries a bulk-import invalidated. Applied below
	// only on the localtx path; when the caller owns the transaction they travel
	// out on resp.BulkSig0InvalidateZones instead, because the commit that makes
	// the new rows visible has not happened yet at that point.
	var sig0InvalidateZones []string

	if tx == nil {
		tx, err = kdb.Begin("Sig0KeyMgmt")
		if err != nil {
			return nil, err
		}
		localtx = true
	}
	defer func() {
		if localtx {
			if txSuccess {
				if cerr := tx.Commit(); cerr != nil {
					lgSigner.Error("Sig0KeyMgmt commit failed", "err", cerr)
					err = cerr
					// The response was built on the assumption that the write
					// would land. Handing back "imported"/"added" for rows that
					// were just rolled back is worse than handing back nothing,
					// because that is the answer an operator acts on -- the same
					// reasoning as the bulkTx commit-error fix.
					if out != nil {
						out.Error = true
						out.ErrorMsg = cerr.Error()
						out.BulkDispositions = nil
						out.BulkSig0InvalidateZones = nil
						out.GeneratedSig0Key = nil
					}
					// Nothing was written, so nothing is stale: skipping the
					// invalidation keeps the cache consistent with the DB.
					return
				}
				// AFTER the commit, never before -- see BulkSig0InvalidateZones.
				for _, zone := range sig0InvalidateZones {
					kdb.invalidateSig0Cache(zone)
				}
			} else {
				tx.Rollback()
			}
		}
	}()

	lgSigner.Debug("Sig0KeyMgmt request", "subcommand", kp.SubCommand)

	// An application client's own keys only (design 4.6): the keys of its
	// own zones, checked on the name each subcommand acts on.
	app := kp.appClient

	switch kp.SubCommand {
	case "list":
		q, args := getAllSig0KeysSql, []any(nil)
		if app != "" {
			where, arg := appOwnZonesFilter(app)
			q, args = q+" WHERE "+where, []any{arg}
		}
		rows, err := tx.Query(q, args...)
		if err != nil {
			return &resp, fmt.Errorf("error from tx.Query(%s): %v", q, err)
		}
		defer rows.Close()

		var keyname, state, algorithm, creator, privatekey, keyrrstr string
		var keyid int

		tmp2 := map[string]Sig0Key{}
		for rows.Next() {
			err := rows.Scan(&keyname, &state, &keyid, &algorithm, &creator, &privatekey, &keyrrstr)
			if err != nil {
				return &resp, fmt.Errorf("error from rows.Scan(): %v", err)
			}
			if len(privatekey) < 10 {
				privatekey = "ULTRA SECRET KEY"
			}
			mapkey := fmt.Sprintf("%s::%d", keyname, keyid)
			tmp2[mapkey] = Sig0Key{
				Name:       keyname,
				State:      state,
				Algorithm:  algorithm,
				Creator:    creator,
				PrivateKey: "-***-",
				Keystr:     keyrrstr,
				ApiOwner:   keystoreApiOwner(keyname),
			}
		}
		resp.Sig0keys = tmp2
		resp.Msg = "Here are all the SIG(0) keys that we know"

	// XXX: FIXME: "add" should also add the public key to the TrustStore.
	case "add": // AKA "import"
		pkc := kp.PrivateKeyCache
		if app != "" {
			if pkc == nil {
				return &resp, fmt.Errorf("add: no key in the request")
			}
			// The key's own name is the zone it goes in, and the name
			// the TrustStore copy gets.
			if err := appKeyZoneRefusal(app, pkc.KeyRR.Header().Name); err != nil {
				return &resp, err
			}
		}
		if pkc == nil || pkc.KeyRR.Header().Name == "" {
			return &resp, fmt.Errorf("add: no key in the request")
		}
		lgSigner.Info("importing private key", "type", fmt.Sprintf("%T", pkc.K))

		privkey, err := reconstructSigningKey(pkc, pkc.KeyRR.String(), dns.TypeKEY)
		if err != nil {
			return &resp, err
		}
		// Stored, and mirrored to the TrustStore, under the canonical name
		// (lower case), which the readers of a zone's keys use.
		keyRR := pkc.KeyRR
		keyRR.Hdr.Name = canonicalKeyName(keyRR.Hdr.Name)

		privkeyPEM, err := PrivateKeyToPEM(privkey)
		if err != nil {
			lgSigner.Error("PrivateKeyToPEM failed", "err", err)
			return &resp, fmt.Errorf("failed to convert private key to PEM: %v", err)
		}

		res, err = tx.Exec(addSig0KeySql, keyRR.Hdr.Name, kp.State, keyRR.KeyTag(),
			dns.AlgorithmToString[pkc.Algorithm], "tdns-cli", privkeyPEM, keyRR.String())
		if err != nil {
			lgSigner.Error("failed to add SIG(0) key", "err", err)
			return &resp, err
		} else {
			rows, _ := res.RowsAffected()
			resp.Msg = fmt.Sprintf("Updated %d rows.\nAdded private+public key to KeyStore.", rows)
		}

		// Now also add the public key to the TrustStore.
		tspost := TruststorePost{
			Command:    "truststore",
			SubCommand: "add",
			Keyname:    keyRR.Hdr.Name,
			Keyid:      int(keyRR.KeyTag()),
			Validated:  true,
			Trusted:    true, // we implicitly trust keys that we have added ourselves
			Src:        "keystore",
			KeyRR:      keyRR.String(),
		}
		tsresp, err := kdb.Sig0TrustMgmt(tx, tspost)
		if err != nil {
			return nil, err
		}
		// After commit only — see sig0InvalidateZones / BulkSig0InvalidateZones.
		// The row's owner, not kp.Keyname: the CLI's add does not set Keyname.
		sig0InvalidateZones = appendSig0InvalidateZone(sig0InvalidateZones, keyRR.Hdr.Name)
		resp.Msg += fmt.Sprintf("\nAdded public key to TrustStore: %s", tsresp.Msg)

	case "bulk-export":
		sel, err := NewKeySelector(kp.SelectExact, kp.SelectSubtree)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		keys, err := kdb.bulkExportSig0(tx, sel, app)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		// SIG(0) keys carry no timestamps, so a bind rendering of one gets
		// the key material and no timing tags.
		for i := range keys {
			priv, err := PrivateKeyForExport(kp.KeyFormat, keys[i].KeyRR, keys[i].PrivateKey, "", "", "")
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("%s keyid %d: %v", keys[i].Zone, keys[i].Keyid, err)
				return &resp, nil
			}
			keys[i].PrivateKey = priv
		}
		resp.BulkSig0Keys = keys
		resp.Msg = fmt.Sprintf("Exported %d SIG(0) key(s)", len(keys))
		txSuccess = true
		return &resp, nil

	case "bulk-import":
		dispositions, err := kdb.bulkImportSig0(tx, kp.BulkSig0Keys, kp.Force, app)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}

		// Mirror every changed key into the TrustStore, in THIS transaction.
		//
		// Both single-key paths that put a private SIG(0) key into the keystore
		// -- "add" above and "generate" below -- also write the public half to
		// the TrustStore, because a key tdns holds the private half of is one it
		// must also be willing to verify. bulk-import wrote Sig0KeyStore only,
		// so a restored key was present for signing and absent for verification;
		// after a forced replace it was worse than absent, since the TrustStore
		// kept the superseded public key.
		//
		// Same tx as the rows themselves: the two stores must not be able to
		// diverge across a rollback. Driven off the dispositions, not the
		// offered keys, so unchanged and conflicted keys leave the TrustStore
		// alone exactly as they left the keystore alone. The underlying SQL is
		// INSERT OR REPLACE, which is what makes "replaced" work.
		//
		// Each disposition carries the record that its own write stored, not
		// a lookup of the offered keys by name and key ID: two offers of one
		// key in a batch would find the last, so a first offer imported and
		// a second refused as a conflict would mirror the conflicting
		// record. Mirrored in order, a forced replacement later in the batch
		// overwrites the TrustStore as it overwrote the keystore.
		for _, d := range dispositions {
			if d.Status != BulkStatusImported && d.Status != BulkStatusReplaced {
				continue
			}
			if d.keyRR == "" {
				// Unreachable: bulkImportSig0 sets it on every key it writes.
				// Fail rather than log-and-continue -- silently skipping
				// would leave a key that can sign but not verify, which is the
				// precise state this block exists to prevent.
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("internal: no stored record for SIG(0) key %s keyid %d", d.Name, d.Keyid)
				return &resp, fmt.Errorf("%s", resp.ErrorMsg)
			}
			tspost := TruststorePost{
				Command:    "truststore",
				SubCommand: "add",
				Keyname:    d.Name,
				Keyid:      int(d.Keyid),
				Validated:  true,
				Trusted:    true, // we hold the private half; same reasoning as "add"
				Src:        "keystore",
				KeyRR:      d.keyRR,
			}
			if _, err := kdb.Sig0TrustMgmt(tx, tspost); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return &resp, fmt.Errorf("bulk-import: TrustStore update for %s keyid %d: %v", d.Name, d.Keyid, err)
			}
		}

		resp.BulkDispositions = dispositions
		// Who drops the stale cache entries depends on who commits: the localtx
		// defer above, or the external-tx caller via this field. Set on both
		// paths -- on the localtx path the field is simply unread.
		resp.BulkSig0InvalidateZones = changedZones(dispositions)
		sig0InvalidateZones = resp.BulkSig0InvalidateZones
		resp.Msg = summarizeDispositions(dispositions, kp.Force)
		txSuccess = true
		return &resp, nil

	case "generate":
		lgSigner.Info("generating new SIG(0) keypair", "name", kp.Keyname)
		if kp.Keyname == "" {
			kp.Keyname = kp.Zone
		}
		if err := appKeyZoneRefusal(app, kp.Keyname); err != nil {
			return &resp, err
		}
		pkc, msg, err := kdb.GenerateKeypair(kp.Keyname, kp.Creator, kp.State, dns.TypeKEY, kp.Algorithm, "", tx)
		if err != nil {
			lgSigner.Error("GenerateKeypair failed", "err", err)
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		resp.Msg = msg
		tspost := TruststorePost{
			Command:    "truststore",
			SubCommand: "add",
			Keyname:    pkc.KeyRR.Header().Name,
			Keyid:      int(pkc.KeyRR.KeyTag()),
			Validated:  true,
			Trusted:    true, // we implicitly trust keys that we have generated ourselves
			Src:        "keystore",
			KeyRR:      pkc.KeyRR.String(),
		}
		tsresp, err := kdb.Sig0TrustMgmt(tx, tspost)
		if err != nil {
			return nil, err
		}
		// After commit only — see sig0InvalidateZones / BulkSig0InvalidateZones.
		sig0InvalidateZones = appendSig0InvalidateZone(sig0InvalidateZones, kp.Keyname)
		resp.BulkSig0InvalidateZones = sig0InvalidateZones
		resp.Msg += fmt.Sprintf("\nAdded public key of newly generated keypair to TrustStore: %s", tsresp.Msg)
		resp.GeneratedSig0Key = pkc
		txSuccess = true
		return &resp, err

	case "export":
		// Before the lookup: a key of someone else's zone, of a zone not
		// served here, and no key at all get the same answer.
		notFound := func() *KeystoreResponse {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("SIG(0) key for zone %q keyid %d not found", kp.Zone, kp.Keyid)
			return &resp
		}
		if out, err := appKeyExportRefusal(app, kp.Zone, notFound); out != nil {
			return out, err
		}
		stored, err := storedKeyName(tx, "Sig0KeyStore", kp.Zone, kp.Keyid)
		if err != nil {
			return &resp, err
		}
		row := tx.QueryRow(getSig0KeySql, stored, kp.Keyid)
		var zonename, state, algorithm, creator, privatekey, keyrrstr string
		var keyid int
		err = row.Scan(&zonename, &state, &keyid, &algorithm, &creator, &privatekey, &keyrrstr)
		if err != nil {
			if err == sql.ErrNoRows {
				return notFound(), nil
			}
			return &resp, fmt.Errorf("error from row.Scan(): %v", err)
		}
		privkeyOut, err := PrivateKeyForExport(kp.KeyFormat, keyrrstr, privatekey, "", "", "")
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("%s keyid %d: %v", zonename, keyid, err)
			return &resp, nil
		}
		mapkey := fmt.Sprintf("%s::%d", zonename, keyid)
		resp.Sig0keys = map[string]Sig0Key{
			mapkey: {
				Name:       zonename,
				State:      state,
				Keyid:      uint16(keyid),
				Algorithm:  algorithm,
				Creator:    creator,
				PrivateKey: privkeyOut, // unredacted: export intentionally surfaces it
				Keystr:     keyrrstr,
			},
		}
		resp.Msg = fmt.Sprintf("Exported SIG(0) key %s keyid %d", zonename, keyid)

	case "setstate":
		if err := appKeyZoneRefusal(app, kp.Keyname); err != nil {
			return &resp, err
		}
		if kp.Keyname, err = storedKeyName(tx, "Sig0KeyStore", kp.Keyname, kp.Keyid); err != nil {
			return &resp, err
		}
		res, err = tx.Exec(setStateSig0KeySql, kp.State, kp.Keyname, kp.Keyid)
		if err != nil {
			lgSigner.Error("failed to set SIG(0) key state", "err", err)
			return &resp, err
		}
		rows, _ := res.RowsAffected()

		// An error, not only a message: a caller changing several states in
		// one transaction (a rollover) must not commit the rest without this.
		if rows == 0 {
			return &resp, fmt.Errorf("SIG(0) key with name %q and keyid %d not found", kp.Keyname, kp.Keyid)
		}
		// We don't know the old state, so invalidate every cached state for this
		// name — but only after commit (sig0InvalidateZones / BulkSig0InvalidateZones).
		sig0InvalidateZones = appendSig0InvalidateZone(sig0InvalidateZones, kp.Keyname)
		resp.Msg = fmt.Sprintf("Updated %d rows", rows)

	case "setparentstate":
		const setParentStateSql = "UPDATE Sig0KeyStore SET parent_state=? WHERE zonename=? AND keyid=?"
		if err := appKeyZoneRefusal(app, kp.Keyname); err != nil {
			return &resp, err
		}
		if kp.Keyname, err = storedKeyName(tx, "Sig0KeyStore", kp.Keyname, kp.Keyid); err != nil {
			return &resp, err
		}
		res, err = tx.Exec(setParentStateSql, kp.ParentState, kp.Keyname, kp.Keyid)
		if err != nil {
			lgSigner.Error("failed to set SIG(0) key parent_state", "err", err)
			return &resp, err
		}
		rows, _ := res.RowsAffected()
		if rows > 0 {
			resp.Msg = fmt.Sprintf("Updated parent_state to %d for key %s (keyid %d)", kp.ParentState, kp.Keyname, kp.Keyid)
		} else {
			resp.Msg = fmt.Sprintf("Key with name %q and keyid %d not found", kp.Keyname, kp.Keyid)
		}

	case "delete":
		const getSig0KeySql = `
SELECT zonename, keyid, algorithm, privatekey, keyrr FROM Sig0KeyStore WHERE zonename=? AND keyid=?`

		// The key is looked up and deleted, from the keystore and the
		// TrustStore, by one name: Keyname, or Zone when Keyname is empty.
		// A request that names two zones would check one key and delete
		// another (keyWriteZone refuses it). The application's check is on
		// that one name, and the row is the one stored under it in any case.
		name, err := keyWriteZone("delete", "Keyname is", kp.Keyname, kp.Zone)
		if err != nil {
			return &resp, err
		}
		if err := appKeyZoneRefusal(app, name); err != nil {
			return &resp, err
		}
		canon := name
		if name != "" {
			if name, err = storedKeyName(tx, "Sig0KeyStore", name, kp.Keyid); err != nil {
				return &resp, err
			}
		}
		kp.Zone, kp.Keyname = name, name

		// 1. Find key, if not --> error
		row := tx.QueryRow(getSig0KeySql, kp.Zone, kp.Keyid)

		var zone, algorithm, privatekey, keyrr string
		var keyid int
		err = row.Scan(&zone, &keyid, &algorithm, &privatekey, &keyrr)
		if err != nil {
			lgSigner.Error("failed to scan SIG(0) key for delete", "err", err)
			if err == sql.ErrNoRows {
				return &resp, fmt.Errorf("key %s (keyid %d) not found", kp.Keyname, kp.Keyid)
			}
			return &resp, err
		}
		if uint16(keyid) != kp.Keyid || zone != kp.Zone {
			lgSigner.Warn("SIG(0) key not found for delete", "keyname", kp.Keyname, "keyid", kp.Keyid)
			resp.Msg = fmt.Sprintf("key %s %d not found", kp.Keyname, kp.Keyid)
			return &resp, nil
		}

		// 3. Return all good, now untrusted
		res, err = tx.Exec(deleteSig0KeySql, kp.Keyname, kp.Keyid)
		if err != nil {
			lgSigner.Error("failed to delete SIG(0) key", "err", err)
			return &resp, err
		}
		rows, _ := res.RowsAffected()
		resp.Msg = fmt.Sprintf("SIG(0) key %s (keyid %d) deleted from KeyStore (%d rows)", kp.Keyname, kp.Keyid, rows)

		// Now also delete it from the TrustStore.
		tspost := TruststorePost{
			Command:    "truststore",
			SubCommand: "delete",
			Keyname:    kp.Keyname,
			Keyid:      int(kp.Keyid),
		}
		tsresp, err := kdb.Sig0TrustMgmt(tx, tspost)
		if err != nil {
			return &resp, err
		}
		resp.Msg += fmt.Sprintf("\nAlso deleted the public key from TrustStore:\n%s", tsresp.Msg)
		// After commit only — see sig0InvalidateZones / BulkSig0InvalidateZones.
		sig0InvalidateZones = appendSig0InvalidateZone(sig0InvalidateZones, kp.Keyname)
		sig0InvalidateZones = appendSig0InvalidateZone(sig0InvalidateZones, canon)

	default:
		lgSigner.Warn("unknown Sig0KeyMgmt subcommand", "subcommand", kp.SubCommand)
	}

	txSuccess = true
	if len(sig0InvalidateZones) > 0 {
		resp.BulkSig0InvalidateZones = sig0InvalidateZones
	}
	return &resp, nil
}

// keyWriteZone is the zone a keystore write goes to, by its canonical name
// (canonicalKeyName): written, the name the key is written under (or
// deleted from), which the post-commit republish, re-sign and cache drop
// follow, or zone when written is empty. A request whose Zone names another zone is refused before
// anything is written ("<sub>: <what> <written>, but the request names
// zone <zone>"): it would otherwise change one zone's key and act on the
// other zone. An empty Zone, or one that is written in another case or
// without the final dot, is no conflict.
func keyWriteZone(sub, what, written, zone string) (string, error) {
	if written == "" {
		return canonicalKeyName(zone), nil
	}
	if zone != "" && !core.EqualNames(dns.Fqdn(written), dns.Fqdn(zone)) {
		return "", fmt.Errorf("%s: %s %s, but the request names zone %s; nothing was changed",
			sub, what, written, zone)
	}
	return canonicalKeyName(written), nil
}

// purgeAllZones says whether zone is dnssec purge's selector "all" (any
// case), every zone, rather than a zone name; "all." is the zone.
func purgeAllZones(zone string) bool {
	return strings.EqualFold(strings.TrimSpace(zone), "all")
}

// canonicalKeystoreNames makes the zone names of a SIG(0) or DNSSEC keystore
// request canonical (canonicalKeyName), as the key rows are stored, and
// leaves a keyword alone: dnssec purge's Zone "all" is every zone, not the
// zone "all.". These are the only keywords the two commands take in Zone or
// Keyname; an empty name stays empty.
func canonicalKeystoreNames(kp *KeystorePost) {
	switch kp.Command {
	case "sig0-mgmt", "dnssec-mgmt":
	default:
		return
	}
	if !(kp.Command == "dnssec-mgmt" && kp.SubCommand == "purge" && purgeAllZones(kp.Zone)) {
		kp.Zone = canonicalKeyName(kp.Zone)
	}
	kp.Keyname = canonicalKeyName(kp.Keyname)
}

// canonicalKeyName is name as a key row stores it: lower case and fully
// qualified, as ZoneData.ZoneName, by which the signing and the other
// readers of a zone's keys look them up. "" stays "" (no name given).
func canonicalKeyName(name string) string {
	if name == "" {
		return ""
	}
	return core.CanonicalizeName(dns.Fqdn(name))
}

// storedKeyName is the zone name that the key row of table (DnssecKeyStore,
// Sig0KeyStore) with key ID keyid is stored under, for a command that names
// the zone in any case: the canonical name when a row has it, else a row
// stored in another case before writes were canonical, so that such a row
// can still be managed. Without a row it is the canonical name, and the
// command finds no key.
func storedKeyName(tx *Tx, table, name string, keyid uint16) (string, error) {
	canon := canonicalKeyName(name)
	var stored string
	err := tx.QueryRow(`SELECT zonename FROM `+table+` WHERE zonename = ? COLLATE NOCASE AND keyid = ?
ORDER BY zonename = ? DESC LIMIT 1`, canon, int(keyid), canon).Scan(&stored)
	switch {
	case err == sql.ErrNoRows:
		return canon, nil
	case err != nil:
		return "", fmt.Errorf("looking up %s keyid %d: %v", name, keyid, err)
	}
	return stored, nil
}

// appendSig0InvalidateZone adds zone to the post-commit SIG(0) cache drop list
// once. Zones are compared as stored (callers pass the keystore name/keyname).
func appendSig0InvalidateZone(zones []string, zone string) []string {
	if zone == "" {
		return zones
	}
	for _, z := range zones {
		if z == zone {
			return zones
		}
	}
	return append(zones, zone)
}

func (kdb *KeyDB) DnssecKeyMgmt(ctx context.Context, tx *Tx, kp KeystorePost) (out *KeystoreResponse, err error) {
	// dump.P(kp)

	const (
		deleteDnskeySql  = `DELETE FROM DnssecKeyStore WHERE zonename=? AND keyid=?`
		getAllDnskeysSql = `SELECT zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr, pub, sign, ds FROM DnssecKeyStore`
		getDnskeySql     = `
SELECT zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr FROM DnssecKeyStore WHERE zonename=? AND keyid=?`
	)

	var localtx = false
	var txSuccess bool
	var needsRepublish bool // R2: one post-commit republish for the zone
	// bulkRepublishZones is the plural counterpart of needsRepublish, for the
	// one subcommand that spans zones. Kept separate because needsRepublish is
	// hardwired to kp.Zone, which a bulk import does not have.
	var bulkRepublishZones []string
	// strip: clear's and policy-cleanup's strip of the served RRSIGs, staged
	// under the transaction and published after it commits (#985).
	var strip *stagedStrip

	if tx == nil {
		tx, err = kdb.Begin("DnssecKeyMgmt")
		if err != nil {
			return nil, err
		}
		localtx = true
	}
	defer func() {
		if out != nil && needsRepublish && err == nil {
			out.NeedsSigningKeysRepublish = true
		}
		if out != nil {
			out.keyZone = kp.Zone // add and setstate set it to the zone written
		}
		if localtx {
			if txSuccess {
				if cerr := tx.Commit(); cerr != nil {
					lgSigner.Error("DnssecKeyMgmt commit failed", "err", cerr)
					strip.finish(false)
					err = cerr
					return
				}
				if needsRepublish {
					if rerr := republishSigningKeysForZone(kdb, kp.Zone); rerr != nil {
						lgSigner.Error("DnssecKeyMgmt: post-commit signing-keys republish failed",
							"zone", kp.Zone, "err", rerr)
					}
				}
				// After the republish: the publish re-signs the SOA, with the
				// signing keys it finds published.
				strip.finish(true)
				// A bulk import on the local-tx path used to commit the rows and
				// republish nothing, leaving every affected zone serving the
				// pre-import signing-key set with no indication anything was
				// pending. resp.BulkRepublishZones carried the information out,
				// but only APIkeystore ever read it.
				for _, z := range bulkRepublishZones {
					if rerr := republishSigningKeysForZone(kdb, z); rerr != nil {
						lgSigner.Error("DnssecKeyMgmt: post-commit signing-keys republish failed after bulk import",
							"zone", z, "err", rerr)
					}
				}
			} else {
				lgSigner.Debug("DnssecKeyMgmt rollback")
				tx.Rollback()
				strip.finish(false)
			}
		} else {
			if txSuccess && needsRepublish {
				// External tx (APIkeystore): caller must republish after Commit (R1).
				lgSigner.Debug("DnssecKeyMgmt: external tx; APIkeystore must republishSigningKeysForZone post-commit",
					"zone", kp.Zone)
			}
			// External tx: the caller finishes the strip after its commit and
			// republish, or after its rollback on a failure here (APIkeystore).
			if out != nil {
				out.stagedStrip = strip
			} else {
				strip.finish(false)
			}
		}
	}()

	var resp = KeystoreResponse{Time: time.Now()}

	// An application client's own keys only (design 4.6): the keys of its
	// own zones, checked on the name each subcommand acts on.
	app := kp.appClient

	switch kp.SubCommand {
	case "list":
		q, args := getAllDnskeysSql, []any(nil)
		if app != "" {
			where, arg := appOwnZonesFilter(app)
			q, args = q+" WHERE "+where, []any{arg}
		}
		rows, err := tx.Query(q, args...)
		if err != nil {
			return nil, fmt.Errorf("error from tx.Query(%s): %v", q, err)
		}
		defer rows.Close()

		var keyname, state, algorithm, creator, privatekey, keyrrstr string
		var keyid, flags int
		var pub, sign, ds sql.NullInt64

		tmp2 := map[string]DnssecKey{}
		for rows.Next() {
			err := rows.Scan(&keyname, &state, &keyid, &flags, &algorithm, &creator, &privatekey, &keyrrstr, &pub, &sign, &ds)
			if err != nil {
				return nil, fmt.Errorf("error from rows.Scan(): %v", err)
			}
			if len(privatekey) < 10 {
				privatekey = "ULTRA SECRET KEY"
			}
			mapkey := fmt.Sprintf("%s::%d", keyname, keyid)
			dk := DnssecKey{
				Name:       keyname,
				State:      state,
				Flags:      uint16(flags),
				Algorithm:  algorithm,
				Creator:    creator,
				PrivateKey: "-***-",
				Keystr:     keyrrstr,
				Pub:        pub.Valid && pub.Int64 != 0,
				Sign:       sign.Valid && sign.Int64 != 0,
				DS:         nullBoolPtr(ds),
				ApiOwner:   keystoreApiOwner(keyname),
			}
			tmp2[mapkey] = dk
		}
		resp.Dnskeys = tmp2
		resp.Msg = "Here are all the DNSSEC keys that we know"

	case "add": // AKA "import"
		pkc := kp.PrivateKeyCache
		if pkc == nil || pkc.DnskeyRR.Header().Name == "" {
			return &resp, fmt.Errorf("add: no key in the request")
		}
		// The DNSKEY's owner name is the zone the row goes in, and the
		// zone republished after the commit.
		if err := appKeyZoneRefusal(app, pkc.DnskeyRR.Header().Name); err != nil {
			return &resp, err
		}
		zone, err := keyWriteZone("add", "the DNSKEY's owner name is", pkc.DnskeyRR.Header().Name, kp.Zone)
		if err != nil {
			return &resp, err
		}
		kp.Zone = zone
		// Stored under the canonical name, which the signing reads use.
		dnskey := pkc.DnskeyRR
		dnskey.Hdr.Name = zone

		// Convert private key to PEM format for storage
		// If pkc.K is nil (e.g., when received via JSON API), reconstruct it from pkc.PrivateKey
		privkey, err := reconstructSigningKey(pkc, pkc.DnskeyRR.String(), dns.TypeDNSKEY)
		if err != nil {
			return &resp, err
		}

		privkeyPEM, err := PrivateKeyToPEM(privkey)
		if err != nil {
			lgSigner.Error("PrivateKeyToPEM failed", "err", err)
			return &resp, fmt.Errorf("failed to convert private key to PEM: %v", err)
		}

		if err := insertKeyRowTx(tx, KeyRow{
			Zone: zone, State: kp.State, Keyid: dnskey.KeyTag(), Flags: dnskey.Flags,
			Algorithm: dns.AlgorithmToString[pkc.Algorithm], Creator: "tdns-cli", PrivateKey: privkeyPEM,
			KeyRR: dnskey.String(), Replace: true,
		}); err != nil {
			lgSigner.Error("failed to add DNSKEY", "err", err)
			return &resp, err
		}
		lgSigner.Debug("DNSKEY added successfully")
		resp.Msg = "Updated 1 rows"
		needsRepublish = true

	case "bulk-export":
		sel, err := NewKeySelector(kp.SelectExact, kp.SelectSubtree)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		keys, err := kdb.bulkExportDnssec(tx, sel, app)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		for i := range keys {
			priv, err := PrivateKeyForExport(kp.KeyFormat, keys[i].KeyRR, keys[i].PrivateKey,
				keys[i].PublishedAt, keys[i].ActiveAt, keys[i].RetiredAt)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("%s keyid %d: %v", keys[i].Zone, keys[i].Keyid, err)
				return &resp, nil
			}
			keys[i].PrivateKey = priv
		}
		resp.BulkDnssecKeys = keys
		resp.Msg = fmt.Sprintf("Exported %d DNSSEC key(s)", len(keys))
		txSuccess = true
		return &resp, nil

	case "bulk-import":
		// needsRepublish is deliberately NOT set: it is single-zone (kp.Zone),
		// and a bulk import spans zones. bulkRepublishZones is its plural twin,
		// consumed by the local-tx defer above; resp.BulkRepublishZones carries
		// the same names out for the external-tx caller (APIkeystore).
		//
		// NOTE for a future in-process caller: the local-tx path re-signs a
		// zone whose served keys the import changed (the republish asks,
		// #918), but not one whose signing keys alone changed. That needs
		// triggerResign, which takes the
		// *Config this function does not take — and threading conf
		// through DnssecKeyMgmt for one subcommand with no in-process caller
		// today is not worth the churn. The consequence is bounded and not a
		// correctness hole: the signing-key set is republished immediately, so
		// the zone stops using the superseded key, and the RRSIGs are refreshed
		// on the resigner's next scheduled pass rather than at once. A caller
		// that needs it sooner should go through the API, which does both.
		dispositions, err := kdb.bulkImportDnssec(tx, kp.BulkDnssecKeys, kp.Force, app)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		resp.BulkDispositions = dispositions
		resp.BulkRepublishZones = changedZones(dispositions)
		bulkRepublishZones = resp.BulkRepublishZones
		resp.Msg = summarizeDispositions(dispositions, kp.Force)
		txSuccess = true
		return &resp, nil

	case "generate":
		if err := appKeyZoneRefusal(app, kp.Zone); err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		// On a zone whose key lifecycle is owned, generate names the key
		// columns like setstate (design Q4): a state alone would have the
		// store fill them from tdns's table, minting a key the owner did
		// not ask for in a shape it did not name.
		var genFlags *KeyRowFlags
		genState := kp.State
		if genState == "" {
			genState = DnskeyStateActive // GenerateKeypair's default, named once for both writes
		}
		if zd, owned := zoneOwnedByName(kp.Zone); owned {
			if kp.Pub == nil || kp.Sign == nil || kp.DS == nil {
				err := fmt.Errorf("%w; generate on it names pub, sign and ds", ownedRefusal(zd, "generate"))
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return &resp, err
			}
			genFlags = &KeyRowFlags{Pub: *kp.Pub, Sign: *kp.Sign, DS: sql.NullBool{Bool: *kp.DS, Valid: true}}
		}
		var msg string
		var err error
		if genFlags != nil {
			_, msg, err = kdb.GenerateKeypairWithColumns(kp.Zone, "api-request", genState, kp.Algorithm, kp.KeyType, *genFlags, tx)
		} else {
			_, msg, err = kdb.GenerateKeypair(kp.Zone, "api-request", genState, dns.TypeDNSKEY, kp.Algorithm, kp.KeyType, tx)
		}
		if err != nil {
			lgSigner.Error("GenerateKeypair failed", "err", err)
			resp.Error = true
			resp.ErrorMsg = err.Error()
		}
		resp.Msg = msg
		if err == nil {
			needsRepublish = true
			txSuccess = true
		}
		return &resp, err

	case "setstate":
		// On a zone whose key lifecycle is owned, setstate names the key
		// columns (design §3.2): the owner's states are its own, and a bare
		// state write would bypass it. With the columns the write goes
		// through setKeyRowTx like every other, and any state is the owner's
		// to name.
		//
		// The key is named by Keyname (Zone when Keyname is empty), and
		// its zone is the one republished and re-signed after the commit.
		if kp.Keyname == "" {
			kp.Keyname = kp.Zone
		}
		if err := appKeyZoneRefusal(app, kp.Keyname); err != nil {
			return &resp, err
		}
		zone, err := keyWriteZone("setstate", "the key is in zone", kp.Keyname, kp.Zone)
		if err != nil {
			return &resp, err
		}
		kp.Zone, kp.Keyname = zone, zone
		// The row as stored: one written in another case before writes
		// were canonical is still found.
		stored, err := storedKeyName(tx, "DnssecKeyStore", zone, kp.Keyid)
		if err != nil {
			return &resp, err
		}
		var stateFlags KeyRowFlags
		zd, owned := zoneOwnedByName(kp.Keyname)
		if owned && kp.Pub != nil && kp.Sign != nil && kp.DS != nil {
			stateFlags = KeyRowFlags{Pub: *kp.Pub, Sign: *kp.Sign, DS: sql.NullBool{Bool: *kp.DS, Valid: true}}
		} else {
			if owned {
				err := fmt.Errorf("%w; setstate on it names pub, sign and ds", ownedRefusal(zd, "setstate"))
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return &resp, err
			}
			// On a zone tdns runs, the columns follow the state and the
			// state is one of tdns's own; the request's columns are ignored.
			allowed := map[string]bool{
				DnskeyStateCreated: true, DnskeyStatePublished: true, DnskeyStateDsPublished: true,
				DnskeyStateStandby: true, DnskeyStateActive: true, DnskeyStateRetired: true, DnskeyStateRemoved: true,
			}
			if !allowed[kp.State] {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("invalid dnssec state %q", kp.State)
				return &resp, fmt.Errorf("invalid dnssec state %q", kp.State)
			}
			stateFlags, _ = keyFlagsForState(kp.State)
		}
		if _, err := setKeyRowTx(tx, stored, kp.Keyid, kp.State, stateFlags, ""); err != nil {
			if errors.Is(err, errKeyRowNotFound) {
				resp.Msg = fmt.Sprintf("Key with name \"%s\" and keyid %d not found.", kp.Keyname, kp.Keyid)
			} else {
				lgSigner.Error("failed to set DNSKEY state", "err", err)
				return &resp, err
			}
		} else {
			resp.Msg = "Updated 1 rows"
		}
		needsRepublish = true

	case "rollover":
		if err := appKeyZoneRefusal(app, kp.Zone); err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		keytype := kp.KeyType
		if keytype == "" {
			keytype = "ZSK"
		}
		oldKeyid, newKeyid, err := kdb.RolloverKey(kp.Zone, keytype, tx)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		resp.Msg = fmt.Sprintf("%s rollover for zone %s: active key %d retired, standby key %d now active", keytype, kp.Zone, oldKeyid, newKeyid)
		needsRepublish = true

	case "export":
		const getDnskeySql = `
SELECT zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr FROM DnssecKeyStore WHERE zonename=? AND keyid=?`
		// Before the lookup: a key of someone else's zone, of a zone not
		// served here, and no key at all get the same answer.
		notFound := func() *KeystoreResponse {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("DNSSEC key for zone %q keyid %d not found", kp.Zone, kp.Keyid)
			return &resp
		}
		if out, err := appKeyExportRefusal(app, kp.Zone, notFound); out != nil {
			return out, err
		}
		stored, err := storedKeyName(tx, "DnssecKeyStore", kp.Zone, kp.Keyid)
		if err != nil {
			return &resp, err
		}
		row := tx.QueryRow(getDnskeySql, stored, kp.Keyid)
		var zonename, state, algorithm, creator, privatekey, keyrrstr string
		var keyid, flags int
		err = row.Scan(&zonename, &state, &keyid, &flags, &algorithm, &creator, &privatekey, &keyrrstr)
		if err != nil {
			if err == sql.ErrNoRows {
				return notFound(), nil
			}
			return &resp, fmt.Errorf("error from row.Scan(): %v", err)
		}
		// The single-key row carries no timestamps, so a bind rendering here
		// gets the key material and no timing tags; bulk-export has them.
		privkeyOut, err := PrivateKeyForExport(kp.KeyFormat, keyrrstr, privatekey, "", "", "")
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("%s keyid %d: %v", zonename, keyid, err)
			return &resp, nil
		}
		mapkey := fmt.Sprintf("%s::%d", zonename, keyid)
		resp.Dnskeys = map[string]DnssecKey{
			mapkey: {
				Name:       zonename,
				State:      state,
				Keyid:      uint16(keyid),
				Flags:      uint16(flags),
				Algorithm:  algorithm,
				Creator:    creator,
				PrivateKey: privkeyOut, // unredacted: export intentionally surfaces it
				Keystr:     keyrrstr,
			},
		}
		resp.Msg = fmt.Sprintf("Exported DNSSEC key %s keyid %d", zonename, keyid)

	case "delete":
		const getDnskeySql = `
SELECT zonename, state, keyid, flags, algorithm, privatekey, keyrr FROM DnssecKeyStore WHERE zonename=? AND keyid=?`

		if err := appKeyZoneRefusal(app, kp.Zone); err != nil {
			return &resp, err
		}
		// The row as stored: one written in another case before writes
		// were canonical is still found. kp.Zone stays the canonical name,
		// the zone republished and re-signed.
		stored, err := storedKeyName(tx, "DnssecKeyStore", kp.Zone, kp.Keyid)
		if err != nil {
			return &resp, err
		}

		// 1. Find key, if not --> error
		row := tx.QueryRow(getDnskeySql, stored, kp.Keyid)

		var zone, state, algorithm, privatekey, keyrr string
		var keyid, flags int
		err = row.Scan(&zone, &state, &keyid, &flags, &algorithm, &privatekey, &keyrr)
		if err != nil {
			lgSigner.Error("failed to scan DNSKEY for delete", "err", err)
			if err == sql.ErrNoRows {
				return &resp, fmt.Errorf("key %s (keyid %d) not found", kp.Keyname, kp.Keyid)
			}
			return &resp, err
		}
		if uint16(keyid) != kp.Keyid || zone != stored {
			lgSigner.Warn("DNSKEY not found for delete", "keyname", kp.Keyname, "keyid", kp.Keyid)
			resp.Msg = fmt.Sprintf("key %s %d not found", kp.Keyname, kp.Keyid)
			return &resp, nil
		}

		targetState := DnskeyStateRemoved

		// On the existing tx (UpdateDnssecKeyState would Begin a second one).
		removedFlags, _ := keyFlagsForState(targetState)
		if _, err := setKeyRowTx(tx, stored, kp.Keyid, targetState, removedFlags, ""); err != nil {
			lgSigner.Error("failed to transition DNSKEY for delete", "err", err)
			return &resp, err
		}
		resp.Msg = fmt.Sprintf("Key %s (keyid %d) transitioned to %s", kp.Keyname, kp.Keyid, targetState)
		needsRepublish = true

	case "clear":
		if kp.Zone == "" {
			resp.Error = true
			resp.ErrorMsg = "zone is required for clear"
			return &resp, fmt.Errorf("zone is required for clear")
		}
		if zd, owned := zoneOwnedByName(kp.Zone); owned {
			err := ownedRefusal(zd, "clear")
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		result, err := tx.Exec(`DELETE FROM DnssecKeyStore WHERE zonename=?`, kp.Zone)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		count, _ := result.RowsAffected()
		needsRepublish = true // post-commit via defer (R2); never mid-tx
		lgSigner.Info("all DNSSEC keys cleared", "zone", kp.Zone, "count", count)

		// Immediately generate 1 active ZSK + 1 active KSK so the zone can be signed.
		// Standby keys will be generated by KeyStateWorker on its next tick.
		zd, zoneExists := Zones.Get(kp.Zone)
		if !zoneExists || zd.DnssecPolicy == nil {
			resp.Msg = fmt.Sprintf("Deleted all %d DNSSEC keys for zone %s. Zone not found or has no DNSSEC policy; no new keys generated.", count, kp.Zone)
			return &resp, nil
		}

		var generated []string

		// Generate 1 active ZSK. The old keys were just deleted (line above);
		// if generation fails we MUST abort and roll back the tx, otherwise
		// the zone is committed with no keys at all and DNSSEC breaks.
		zskPkc, _, err := kdb.GenerateKeypair(kp.Zone, "clear-regen", DnskeyStateActive, dns.TypeDNSKEY, zd.DnssecPolicy.ZSKAlgorithm, "ZSK", tx)
		if err != nil {
			lgSigner.Error("clear: failed to generate active ZSK", "zone", kp.Zone, "err", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("clear: failed to generate active ZSK for zone %s: %v", kp.Zone, err)
			return &resp, err
		}
		generated = append(generated, fmt.Sprintf("ZSK %d (active)", zskPkc.KeyId))

		// Generate 1 active KSK (same abort-and-rollback on failure).
		kskPkc, _, err := kdb.GenerateKeypair(kp.Zone, "clear-regen", DnskeyStateActive, dns.TypeDNSKEY, zd.DnssecPolicy.KSKAlgorithm, "KSK", tx)
		if err != nil {
			lgSigner.Error("clear: failed to generate active KSK", "zone", kp.Zone, "err", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("clear: failed to generate active KSK for zone %s: %v", kp.Zone, err)
			return &resp, err
		}
		generated = append(generated, fmt.Sprintf("KSK %d (active)", kskPkc.KeyId))

		// Strip the served RRSIGs left behind by the just-deleted keys: any
		// RRSIG whose keytag is not one of the regenerated keys is an orphan
		// (its DNSKEY is gone) and can no longer validate. The post-commit
		// re-sign (triggerResign) is additive and would not remove them. The
		// strip is staged under the transaction and published after its commit
		// (stagedStrip).
		keep := map[uint16]bool{}
		if zskPkc != nil {
			keep[zskPkc.KeyId] = true
		}
		if kskPkc != nil {
			keep[kskPkc.KeyId] = true
		}
		strip, err = zd.stageStripUnderKeystoreTx(ctx, func(rrsig *dns.RRSIG) bool {
			return !keep[rrsig.KeyTag]
		})
		if err != nil {
			// Fail the whole operation: returning rolls back the keystore tx
			// (key delete+regenerate), and the strip was put back, so the
			// operator can re-run cleanly rather than be left with un-stripped
			// orphan RRSIGs and a "success" message.
			lgSigner.Error("clear: failed to strip orphan RRSIGs", "zone", kp.Zone, "err", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("clear: failed to strip orphan RRSIGs for zone %s: %v", kp.Zone, err)
			return &resp, err
		}

		resp.Msg = fmt.Sprintf("Deleted %d keys for zone %s. Generated: %s. Standby keys will follow via KeyStateWorker.",
			count, kp.Zone, strings.Join(generated, ", "))

	case "policy-cleanup":
		// Collapse the double-signed window left by a policy change: remove the
		// zone's RETIRED keys (and their RRSIGs) NOW, keeping the active keys,
		// instead of waiting for the KeyStateWorker to age them out after
		// propagation-delay. Operator-chosen: it accelerates removal, so a
		// resolver still caching ONLY an old (now-removed) DNSKEY briefly can't
		// validate until it re-queries; the active new-alg keys already serve.
		// Distinct from `clear`, which deletes ALL keys and regenerates.
		if kp.Zone == "" {
			resp.Error = true
			resp.ErrorMsg = "zone is required for policy-cleanup"
			return &resp, fmt.Errorf("zone is required for policy-cleanup")
		}
		if zd, owned := zoneOwnedByName(kp.Zone); owned {
			err := ownedRefusal(zd, "policy-cleanup")
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		retired, err := GetDnssecKeysByStateTx(tx, kp.Zone, DnskeyStateRetired)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		zd, zoneExists := Zones.Get(kp.Zone)
		var removedTags []uint16
		for _, k := range retired {
			if err := UpdateDnssecKeyStateTx(tx, kdb, kp.Zone, k.KeyTag, DnskeyStateRemoved); err != nil {
				lgSigner.Error("policy-cleanup: retired→removed failed", "zone", kp.Zone, "keyid", k.KeyTag, "err", err)
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("policy-cleanup: retired→removed failed for key %d in zone %s: %v", k.KeyTag, kp.Zone, err)
				return &resp, err
			}
			removedTags = append(removedTags, k.KeyTag)
		}
		// Strip the removed keys' RRSIGs from the served zone, in one strip
		// staged under the transaction and published after its commit
		// (stagedStrip). A failed strip fails the whole operation, rolling the
		// state changes back, so we never report success while orphan RRSIGs
		// remain.
		if zoneExists && len(removedTags) > 0 {
			gone := make(map[uint16]bool, len(removedTags))
			for _, tag := range removedTags {
				gone[tag] = true
			}
			strip, err = zd.stageStripUnderKeystoreTx(ctx, func(rrsig *dns.RRSIG) bool {
				return gone[rrsig.KeyTag]
			})
			if err != nil {
				lgSigner.Error("policy-cleanup: failed to strip the removed keys' RRSIGs", "zone", kp.Zone, "keyids", removedTags, "err", err)
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("policy-cleanup: failed to strip RRSIGs for keys %v in zone %s: %v", removedTags, kp.Zone, err)
				return &resp, err
			}
		}
		if len(removedTags) == 0 {
			resp.Msg = fmt.Sprintf("Zone %s: no retired keys to clean up.", kp.Zone)
		} else {
			resp.Msg = fmt.Sprintf("Zone %s: removed %d retired key(s) %v and stripped their RRSIGs; active keys retained.",
				kp.Zone, len(removedTags), removedTags)
			needsRepublish = true
		}

	case "purge":
		purgeResp, err := kdb.dnssecKeyPurge(tx, kp)
		if err != nil {
			return purgeResp, err
		}
		resp = *purgeResp
		needsRepublish = true

	case "check":
		// The key invariants (keyrow_check.go) for one zone, or for every
		// zone in the keystore. Read-only.
		violations, n, err := checkKeystoreZones(ctx, tx, kp.Zone)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		resp.KeyViolations = violations
		resp.Msg = fmt.Sprintf("Checked the key invariants of %d zone(s): %d violation(s)", n, len(violations))

	default:
		resp.Msg = fmt.Sprintf("Unknown keystore dnssec sub-command: %s", kp.SubCommand)
		lgSigner.Warn("unknown DnssecKeyMgmt subcommand", "subcommand", kp.SubCommand)
		resp.Error = true
		resp.ErrorMsg = resp.Msg
	}

	txSuccess = true
	return &resp, nil
}

// forceZoneKeysToPolicyRoles is the surgical per-role counterpart to the keystore
// `clear` operation, used by policy-reset. For each role flagged changed it drops
// ALL of that role's keys (every state) and generates one fresh active key of the
// config algorithm; the unchanged role's keys are left untouched. It runs the key
// mutation in one transaction that rolls back on any failure, and on success
// republishes the zone's signing-keys snapshot post-commit (the DELETE+regen
// changed the active set; this method owns its transaction, so the republish is
// complete — unlike a mid-tx wipe that a read in the uncommitted window can undo).
//
// It returns the SURVIVING keytags (the kept role's keys + the regenerated ones);
// the caller strips the now-stale served RRSIGs via stripStaleRRSIGsForKeySet
// AFTER this returns — never before commit — so a keystore commit failure can
// never leave the served zone published without its signatures.
//
// For a CSK policy a single SEP "CSK" key covers both roles: dropKSK true drops
// every key and regenerates one CSK (dropZSK is ignored). For a split policy the
// SEP bit selects the role (KSK = flags&1==1, ZSK = flags&1==0).
func (kdb *KeyDB) forceZoneKeysToPolicyRoles(zd *ZoneData, pol *DnssecPolicy, dropKSK, dropZSK bool) (map[uint16]bool, error) {
	if zoneOwned(zd) {
		return nil, ownedRefusal(zd, "policy-reset")
	}
	if pol == nil {
		return nil, fmt.Errorf("forceZoneKeysToPolicyRoles: nil policy for zone %s", zd.ZoneName)
	}
	if !dropKSK && !dropZSK {
		return nil, nil // nothing to roll
	}
	zone := zd.ZoneName

	// Under the zone keys lock, before the transaction (lockZoneKeys): a zone
	// delete takes the zone's keys under it, and no keys are made for a zone
	// deleted meanwhile.
	unlockKeys, err := zd.lockZoneKeys("forceZoneKeysToPolicyRoles")
	if err != nil {
		return nil, err
	}
	defer unlockKeys()

	tx, err := kdb.Begin("forceZoneKeysToPolicyRoles")
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()

	if pol.Mode == DnssecPolicyModeCSK {
		// Collapse to a single CSK: drop every key, regenerate one active CSK.
		if _, err := tx.Exec(`DELETE FROM DnssecKeyStore WHERE zonename=?`, zone); err != nil {
			return nil, fmt.Errorf("forceZoneKeysToPolicyRoles: delete keys for %s: %w", zone, err)
		}
		if _, _, err := kdb.GenerateKeypair(zone, "policy-reset-regen", DnskeyStateActive, dns.TypeDNSKEY, pol.Algorithm, "CSK", tx); err != nil {
			return nil, fmt.Errorf("forceZoneKeysToPolicyRoles: regenerate CSK for %s: %w", zone, err)
		}
	} else {
		if dropKSK {
			if _, err := tx.Exec(`DELETE FROM DnssecKeyStore WHERE zonename=? AND (CAST(flags AS INTEGER) & 1) = 1`, zone); err != nil {
				return nil, fmt.Errorf("forceZoneKeysToPolicyRoles: delete KSK keys for %s: %w", zone, err)
			}
			if _, _, err := kdb.GenerateKeypair(zone, "policy-reset-regen", DnskeyStateActive, dns.TypeDNSKEY, pol.KSKAlgorithm, "KSK", tx); err != nil {
				return nil, fmt.Errorf("forceZoneKeysToPolicyRoles: regenerate KSK for %s: %w", zone, err)
			}
		}
		if dropZSK {
			if _, err := tx.Exec(`DELETE FROM DnssecKeyStore WHERE zonename=? AND (CAST(flags AS INTEGER) & 1) = 0`, zone); err != nil {
				return nil, fmt.Errorf("forceZoneKeysToPolicyRoles: delete ZSK keys for %s: %w", zone, err)
			}
			if _, _, err := kdb.GenerateKeypair(zone, "policy-reset-regen", DnskeyStateActive, dns.TypeDNSKEY, pol.ZSKAlgorithm, "ZSK", tx); err != nil {
				return nil, fmt.Errorf("forceZoneKeysToPolicyRoles: regenerate ZSK for %s: %w", zone, err)
			}
		}
	}

	// Surviving keytags = the kept role's keys (all states) + the just-generated
	// active key(s), visible within this tx.
	surviving, err := txZoneKeytags(tx, zone)
	if err != nil {
		return nil, fmt.Errorf("forceZoneKeysToPolicyRoles: list surviving keys for %s: %w", zone, err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("forceZoneKeysToPolicyRoles: commit for %s: %w", zone, err)
	}
	committed = true

	// Post-commit signing-keys snapshot republish (G3).
	if err := zd.republishSigningKeys(kdb); err != nil {
		return surviving, fmt.Errorf("forceZoneKeysToPolicyRoles: republish signing keys for %s: %w", zone, err)
	}
	return surviving, nil
}

// stripStaleRRSIGsForKeySet removes served RRSIGs that a key-set change made
// stale: (a) orphans — those made by a dropped key (keytag no longer in
// `surviving`) — AND (b) EVERY DNSKEY-covering RRSIG. The DNSKEY RRset content
// always changes when the key set changes (a DNSKEY comes or goes), so even a
// KEPT KSK's DNSKEY RRSIG now covers a stale key set; it is not an orphan and the
// additive re-sign would leave it in place as bogus cruft. The re-sign that
// follows regenerates exactly one fresh RRSIG per active KSK.
//
// Call this AFTER the keystore mutation has committed (see
// forceZoneKeysToPolicyRoles): running it before commit would publish the
// stripped zone, and a subsequent commit failure would then leave the served
// zone without its signatures.
func stripStaleRRSIGsForKeySet(ctx context.Context, zd *ZoneData, surviving map[uint16]bool) (int, error) {
	return zd.StripZoneRRSIGs(ctx, func(rrsig *dns.RRSIG) bool {
		return !surviving[rrsig.KeyTag] || rrsig.TypeCovered == dns.TypeDNSKEY
	})
}

// txZoneKeytags returns the set of keytags currently present in the keystore for
// a zone, read within tx (so it sees this transaction's own deletes and inserts).
func txZoneKeytags(tx *Tx, zone string) (map[uint16]bool, error) {
	rows, err := tx.Query(`SELECT keyid FROM DnssecKeyStore WHERE zonename=?`, zone)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uint16]bool{}
	for rows.Next() {
		var keyid int
		if err := rows.Scan(&keyid); err != nil {
			return nil, err
		}
		out[uint16(keyid)] = true
	}
	return out, rows.Err()
}

// dnssecKeyPurge deletes DNSKEY keystore rows in state 'removed', keeping
// the 3 most recent per zone (highest auto-increment id). When kp.Zone is
// "all" (case-insensitive), every zone with removed keys is processed.
// kp.Force=false means dry-run: the rows that would be deleted are
// returned in resp.Dnskeys but no DELETE runs.
//
// Ordering by id (rather than a transition timestamp) is pragmatic — the
// DnssecKeyStore schema has no removed_at column, but in a normal
// KSK-rollover lifecycle keys are removed in creation order, so the
// highest 3 ids among removed keys are exactly the most recent.
func (kdb *KeyDB) dnssecKeyPurge(tx *Tx, kp KeystorePost) (*KeystoreResponse, error) {
	const keepN = 3

	resp := &KeystoreResponse{Time: time.Now()}

	// Resolve target zone list.
	var zones []string
	if purgeAllZones(kp.Zone) {
		rows, err := tx.Query(
			`SELECT DISTINCT zonename FROM DnssecKeyStore WHERE state=? ORDER BY zonename`,
			DnskeyStateRemoved)
		if err != nil {
			return resp, fmt.Errorf("dnssecKeyPurge: list zones: %w", err)
		}
		for rows.Next() {
			var z string
			if err := rows.Scan(&z); err != nil {
				rows.Close()
				return resp, fmt.Errorf("dnssecKeyPurge: scan zone: %w", err)
			}
			zones = append(zones, z)
		}
		rows.Close()
	} else {
		if kp.Zone == "" {
			resp.Error = true
			resp.ErrorMsg = "zone is required for purge (use 'all' to purge every zone)"
			return resp, fmt.Errorf("%s", resp.ErrorMsg)
		}
		zones = []string{kp.Zone}
	}

	purged := map[string]DnssecKey{}
	deletedCount := 0
	zonesAffected := 0

	for _, zone := range zones {
		// Find the ids to keep: 3 most recent removed keys for this zone.
		rows, err := tx.Query(
			`SELECT id FROM DnssecKeyStore WHERE zonename=? AND state=? ORDER BY id DESC LIMIT ?`,
			zone, DnskeyStateRemoved, keepN)
		if err != nil {
			return resp, fmt.Errorf("dnssecKeyPurge: keep query for %s: %w", zone, err)
		}
		var keepIDs []int
		for rows.Next() {
			var id int
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return resp, fmt.Errorf("dnssecKeyPurge: scan keep id for %s: %w", zone, err)
			}
			keepIDs = append(keepIDs, id)
		}
		rows.Close()

		// Build the "NOT IN (?,?,?)" clause and arg list. With fewer than
		// keepN removed keys for this zone, the clause collapses to a no-op
		// and there's nothing to purge for that zone.
		args := []interface{}{zone, DnskeyStateRemoved}
		notInClause := ""
		if len(keepIDs) > 0 {
			placeholders := make([]string, len(keepIDs))
			for i, id := range keepIDs {
				placeholders[i] = "?"
				args = append(args, id)
			}
			notInClause = " AND id NOT IN (" + strings.Join(placeholders, ",") + ")"
		}

		// Collect the to-be-purged keys for the response (for both dry-run
		// and commit — operators want to see what was/will be deleted).
		listSQL := `SELECT keyid, flags, algorithm, keyrr FROM DnssecKeyStore WHERE zonename=? AND state=?` + notInClause
		listRows, err := tx.Query(listSQL, args...)
		if err != nil {
			return resp, fmt.Errorf("dnssecKeyPurge: list query for %s: %w", zone, err)
		}
		zonePurgedCount := 0
		for listRows.Next() {
			var keyid, flags int
			var algorithm, keyrr string
			if err := listRows.Scan(&keyid, &flags, &algorithm, &keyrr); err != nil {
				listRows.Close()
				return resp, fmt.Errorf("dnssecKeyPurge: scan key for %s: %w", zone, err)
			}
			mapkey := fmt.Sprintf("%s::%d", zone, keyid)
			purged[mapkey] = DnssecKey{
				Name:      zone,
				State:     DnskeyStateRemoved,
				Flags:     uint16(flags),
				Algorithm: algorithm,
				Keystr:    keyrr,
			}
			zonePurgedCount++
		}
		listRows.Close()
		if zonePurgedCount > 0 {
			zonesAffected++
		}

		if !kp.Force {
			continue // dry-run: don't actually delete
		}

		// Commit path: delete the rows. Active signing-keys snapshot is unchanged
		// (only 'removed' rows are purged); DnssecKeyMgmt may still republish.
		delSQL := `DELETE FROM DnssecKeyStore WHERE zonename=? AND state=?` + notInClause
		res, err := tx.Exec(delSQL, args...)
		if err != nil {
			return resp, fmt.Errorf("dnssecKeyPurge: delete for %s: %w", zone, err)
		}
		n, _ := res.RowsAffected()
		deletedCount += int(n)
	}

	resp.Dnskeys = purged
	if kp.Force {
		resp.Msg = fmt.Sprintf("Purged %d removed key(s) across %d zone(s) (kept %d most recent per zone).",
			deletedCount, zonesAffected, keepN)
		lgSigner.Info("dnssec keystore purge", "deleted", deletedCount, "zones", zonesAffected)
	} else {
		resp.Msg = fmt.Sprintf("DRY RUN: would purge %d removed key(s) across %d zone(s) (keeping %d most recent per zone). Pass --force to actually delete.",
			len(purged), zonesAffected, keepN)
	}
	return resp, nil
}

func (kdb *KeyDB) GetSig0Keys(zonename, state string) (*Sig0ActiveKeys, error) {
	const (
		fetchSig0PrivKeySql = `
SELECT keyid, algorithm, privatekey, keyrr FROM Sig0KeyStore WHERE zonename=? AND state=?`
	)

	cacheKey := zonename + "+" + state
	kdb.sig0CacheMu.RLock()
	if sak, ok := kdb.KeystoreSig0Cache[cacheKey]; ok {
		kdb.sig0CacheMu.RUnlock()
		return sak, nil
	}
	gen := kdb.sig0CacheGen
	kdb.sig0CacheMu.RUnlock()

	rows, err := kdb.Query(fetchSig0PrivKeySql, zonename, state)
	if err != nil {
		lgSigner.Error("failed to query SIG(0) keys", "sql", fetchSig0PrivKeySql, "zone", zonename, "err", err)
		return nil, err
	}
	defer rows.Close()

	var algorithm, privatekey, keyrrstr string
	var keyid int

	var keyfound bool
	var sak Sig0ActiveKeys

	for rows.Next() {
		err := rows.Scan(&keyid, &algorithm, &privatekey, &keyrrstr)
		if err != nil {
			if err == sql.ErrNoRows {
				// This is not an error, so lets just return an empty Sig0ActiveKeys
				lgSigner.Debug("no SIG(0) key found", "state", state, "zone", zonename)
				return &sak, nil
			}
			lgSigner.Error("rows.Scan failed", "err", err)
			return nil, err
		}

		if keyfound {
			lgSigner.Warn("multiple SIG(0) keys found", "state", state, "zone", zonename)
			// XXX: Should we return an error here?
			continue
		}

		// Parse private key, detecting old BIND format or new PEM format
		// PrivateKeyCacheFromDB, NOT ParsePrivateKeyFromDB + PrepareKeyCache: the
		// latter pair re-derives a BIND blob from an already-parsed PEM and
		// re-parses it via NewPrivateKey, which dispatches on the algorithm
		// codepoint and fails ("dns: bad private key") for any key stored under
		// a codepoint that has since been renumbered.
		pkc, alg, err := PrivateKeyCacheFromDB(privatekey, algorithm, keyrrstr)
		if err != nil {
			lgSigner.Error("PrivateKeyCacheFromDB failed", "err", err)
			return nil, err
		}

		// Ensure the parsed algorithm matches
		if pkc.Algorithm != alg {
			lgSigner.Warn("algorithm mismatch", "stored", alg, "parsed", pkc.Algorithm)
			return nil, fmt.Errorf("error: algorithm mismatch for key %s: stored=%d, parsed=%d", keyrrstr, alg, pkc.Algorithm)
		}

		sak.Keys = append(sak.Keys, pkc)
		keyfound = true
	}

	if !keyfound {
		// This is not an error, so lets just return an empty Sig0ActiveKeys
		lgSigner.Debug("no SIG(0) key found", "state", state, "zone", zonename)
		return &sak, nil
	}

	lgSigner.Debug("GetSig0Keys returned keys", "zone", zonename, "state", state, "keys", sak)

	if getSig0KeysBeforeStore != nil {
		getSig0KeysBeforeStore()
	}
	kdb.sig0CacheMu.Lock()
	// An invalidation since the read means a commit may have changed these
	// rows; caching them would undo it. The caller still gets what was read.
	if kdb.sig0CacheGen == gen {
		kdb.KeystoreSig0Cache[cacheKey] = &sak
	}
	kdb.sig0CacheMu.Unlock()

	return &sak, err
}

// getSig0KeysBeforeStore runs in GetSig0Keys between the read and the cache
// store; a test commits a key change there. Nil in production.
var getSig0KeysBeforeStore func()

// GetSig0KeyRaw returns the raw database column values for a SIG(0) key.
// Used for transferring key material between agents via RFI CONFIG.
func (kdb *KeyDB) GetSig0KeyRaw(zonename, state string) (algorithm, privatekey, keyrr string, found bool, err error) {
	const sql = `SELECT algorithm, privatekey, keyrr FROM Sig0KeyStore WHERE zonename=? AND state=?`

	rows, err := kdb.Query(sql, zonename, state)
	if err != nil {
		return "", "", "", false, err
	}
	defer rows.Close()

	if rows.Next() {
		err = rows.Scan(&algorithm, &privatekey, &keyrr)
		if err != nil {
			return "", "", "", false, err
		}
		return algorithm, privatekey, keyrr, true, nil
	}
	if err := rows.Err(); err != nil {
		return "", "", "", false, err
	}
	return "", "", "", false, nil
}

// GetDnssecKeys returns DNSSEC keys for zonename in the given state. Asked for
// DnskeyStateActive it returns the keys that sign, which is the sign column
// rather than the state: for a loaded zone from the per-zone signing-keys
// snapshot (CAS-if-unbuilt on first access), otherwise DB-direct. The other
// states are lifecycle questions and are always DB-direct by state.
func (kdb *KeyDB) GetDnssecKeys(zonename, state string) (*DnssecKeys, error) {
	zonename = dns.Fqdn(strings.TrimSpace(zonename))
	if state != DnskeyStateActive {
		return loadDnssecKeysFromDB(kdb, zonename, state)
	}
	if zd, ok := Zones.Get(zonename); ok && zd != nil {
		return zd.activeKeysCAS(kdb)
	}
	return loadSigningKeysFromDB(kdb, zonename)
}

func (kdb *KeyDB) PromoteDnssecKey(zonename string, keyid uint16, oldstate, newstate string) (err error) {
	f, ok := keyFlagsForState(newstate)
	if !ok {
		return fmt.Errorf("key state %q has no flags in the flag table", newstate)
	}

	tx, err := kdb.Begin("PromoteDnssecKey")
	if err != nil {
		return fmt.Errorf("error beginning transaction: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()

	// A compare-and-set on the old state: the row must still be in it.
	if _, err := setKeyRowTx(tx, zonename, keyid, newstate, f, oldstate); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit failed: %w", err)
	}
	committed = true

	// Post-commit signing-keys republish (own-tx; R1).
	if rerr := republishSigningKeysForZone(kdb, zonename); rerr != nil {
		return fmt.Errorf("PromoteDnssecKey: republish signing keys: %w", rerr)
	}
	return nil
}

// GenerateAndStageKey generates a new DNSSEC key and stages it: created →
// published.
func GenerateAndStageKey(kdb *KeyDB, zone, creator string, alg uint8, keytype string) (uint16, error) {
	if zd, owned := zoneOwnedByName(zone); owned {
		return 0, ownedRefusal(zd, "generate")
	}
	pkc, _, err := kdb.GenerateKeypair(zone, creator, DnskeyStateCreated, dns.TypeDNSKEY, alg, keytype, nil)
	if err != nil {
		return 0, fmt.Errorf("GenerateAndStageKey: key generation failed: %w", err)
	}

	keyid := pkc.KeyId
	if err := UpdateDnssecKeyState(kdb, zone, keyid, DnskeyStatePublished); err != nil {
		return 0, fmt.Errorf("GenerateAndStageKey: state transition to %s failed: %w", DnskeyStatePublished, err)
	}

	lgSigner.Info("generated and staged DNSSEC key", "zone", zone, "keyid", keyid, "keytype", keytype, "state", DnskeyStatePublished)
	return keyid, nil
}

// DefaultDnskeyTTL is the assumed DNSKEY RRset TTL when the actual TTL is not readily available.
const DefaultDnskeyTTL = 3600 * time.Second

// KeyInventoryItem is a lightweight DNSKEY entry for inventory responses.
// Does not include private key material — only the metadata needed for key classification.
type KeyInventoryItem struct {
	KeyTag    uint16
	Algorithm uint8
	Flags     uint16
	State     string // "created","published","standby","active","retired","removed"
	KeyRR     string // Full DNSKEY RR string (public key data, no private key)
	// The mechanism columns beside the state (KeyRowFlags). DS nil is unknown.
	Pub  bool
	Sign bool
	DS   *bool
}

// GetKeyInventory returns the complete DNSKEY inventory for a zone — all keys
// across all states. Used by the signer to respond to RFI KEYSTATE requests.
// Returns lightweight entries (keytag, algorithm, flags, state, keyrr) without private keys.
func GetKeyInventory(kdb *KeyDB, zonename string) ([]KeyInventoryItem, error) {
	const inventorySql = `SELECT keyid, flags, algorithm, state, COALESCE(keyrr, ''), pub, sign, ds FROM DnssecKeyStore WHERE zonename=?`

	rows, err := kdb.Query(inventorySql, zonename)
	if err != nil {
		return nil, fmt.Errorf("GetKeyInventory: query failed for zone %s: %w", zonename, err)
	}
	defer rows.Close()

	var entries []KeyInventoryItem
	for rows.Next() {
		var keyid, flags int
		var algorithm string
		var state, keyrr string
		var pub, sign, ds sql.NullInt64
		if err := rows.Scan(&keyid, &flags, &algorithm, &state, &keyrr, &pub, &sign, &ds); err != nil {
			return nil, fmt.Errorf("GetKeyInventory: scan failed: %w", err)
		}
		alg, ok := dns.StringToAlgorithm[algorithm]
		if !ok {
			lgSigner.Warn("GetKeyInventory: unknown algorithm, skipping key", "zone", zonename, "keyid", keyid, "algorithm", algorithm)
			continue
		}
		entries = append(entries, KeyInventoryItem{
			KeyTag:    uint16(keyid),
			Algorithm: alg,
			Flags:     uint16(flags),
			State:     state,
			KeyRR:     keyrr,
			Pub:       pub.Valid && pub.Int64 != 0,
			Sign:      sign.Valid && sign.Int64 != 0,
			DS:        nullBoolPtr(ds),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetKeyInventory: rows iteration failed: %w", err)
	}

	return entries, nil
}

// DnssecKeyWithTimestamps extends KeyInventoryItem with lifecycle timestamps.
// Used by the KeyStateWorker for time-based state transitions.
type DnssecKeyWithTimestamps struct {
	ZoneName    string
	KeyTag      uint16
	Algorithm   uint8
	Flags       uint16
	State       string
	KeyRR       string
	PublishedAt *time.Time
	ActiveAt    *time.Time
	RetiredAt   *time.Time
	// ActiveSeq is the per-key "n-th active in this zone's history" counter
	// (DnssecKeyStore.active_seq), nil when never stamped. For ZSK this is
	// the operator-facing roll counter; KSK uses RolloverKeyState instead.
	ActiveSeq *int
}

// GetDnssecKeysByState returns all DNSSEC keys in a given state, with lifecycle timestamps.
// If zone is empty, returns keys across all zones.
func GetDnssecKeysByState(kdb *KeyDB, zone string, state string) ([]DnssecKeyWithTimestamps, error) {
	return dnssecKeysByState(kdb, zone, state)
}

// GetDnssecKeysByStateTx is GetDnssecKeysByState read through tx, for code
// that holds a keystore transaction: it reads what the transaction has
// written, and does not wait for the transaction's lock (#986).
func GetDnssecKeysByStateTx(tx *Tx, zone string, state string) ([]DnssecKeyWithTimestamps, error) {
	return dnssecKeysByState(tx, zone, state)
}

func dnssecKeysByState(q rowsQuerier, zone string, state string) ([]DnssecKeyWithTimestamps, error) {
	if zone == "" {
		return queryKeyRows(q, `state=?`, state)
	}
	return queryKeyRows(q, `zonename=? AND state=?`, zone, state)
}

// GetSigningKeyRows returns the zone's rows with sign set: the keys that
// sign, whatever their state (design D3). This is what a policy compares its
// algorithms against; a lifecycle question is GetDnssecKeysByState.
func GetSigningKeyRows(kdb *KeyDB, zone string) ([]DnssecKeyWithTimestamps, error) {
	return queryKeyRows(kdb, `zonename=? AND sign=1`, zone)
}

// queryKeyRows reads DnssecKeyStore rows matching where, with their lifecycle
// timestamps.
func queryKeyRows(q rowsQuerier, where string, args ...interface{}) ([]DnssecKeyWithTimestamps, error) {
	// ORDER BY published_at ASC, keyid ASC makes the result deterministic and
	// FIFO by propagation age (oldest-published first). This is REQUIRED for
	// correct ZSK rollover: RolloverKey promotes the first standby returned
	// here, so without an explicit order promotion is arbitrary (SQLite row
	// order is unspecified) — fatal to an algorithm roll, where an old-alg
	// standby must promote before a younger new-alg one. NULL published_at
	// sorts first (an unpublished key precedes published ones); standby keys
	// always have published_at, so the promotion pick is unaffected.
	query := `SELECT zonename, keyid, flags, algorithm, state, COALESCE(keyrr, ''), COALESCE(published_at, ''), COALESCE(active_at, ''), COALESCE(retired_at, ''), active_seq FROM DnssecKeyStore WHERE ` + where + ` ORDER BY published_at ASC, keyid ASC`

	rows, err := q.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("key rows: query failed: %w", err)
	}
	defer rows.Close()

	var entries []DnssecKeyWithTimestamps
	for rows.Next() {
		var zonename, algorithm, st, keyrr, publishedAtStr, activeAtStr, retiredAtStr string
		var keyid, flags int
		var activeSeq sql.NullInt64
		if err := rows.Scan(&zonename, &keyid, &flags, &algorithm, &st, &keyrr, &publishedAtStr, &activeAtStr, &retiredAtStr, &activeSeq); err != nil {
			return nil, fmt.Errorf("key rows: scan failed: %w", err)
		}

		alg, ok := dns.StringToAlgorithm[algorithm]
		if !ok {
			lgSigner.Warn("key rows: unknown algorithm, skipping key", "zone", zonename, "keyid", keyid, "algorithm", algorithm)
			continue
		}
		entry := DnssecKeyWithTimestamps{
			ZoneName:  zonename,
			KeyTag:    uint16(keyid),
			Algorithm: alg,
			Flags:     uint16(flags),
			State:     st,
			KeyRR:     keyrr,
		}

		if publishedAtStr != "" {
			if t, err := time.Parse(time.RFC3339, publishedAtStr); err == nil {
				entry.PublishedAt = &t
			}
		}
		if activeAtStr != "" {
			if t, err := time.Parse(time.RFC3339, activeAtStr); err == nil {
				entry.ActiveAt = &t
			}
		}
		if retiredAtStr != "" {
			if t, err := time.Parse(time.RFC3339, retiredAtStr); err == nil {
				entry.RetiredAt = &t
			}
		}
		if activeSeq.Valid {
			v := int(activeSeq.Int64)
			entry.ActiveSeq = &v
		}

		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("key rows: rows iteration failed: %w", err)
	}

	return entries, nil
}

// UpdateDnssecKeyState transitions a DNSSEC key to a new state and sets the
// appropriate lifecycle timestamp. When transitioning to "published", sets
// published_at. When transitioning to "retired", sets retired_at.
// Owns its transaction and republishes the zone's signing-keys snapshot
// post-commit (R1).
func UpdateDnssecKeyState(kdb *KeyDB, zonename string, keyid uint16, newstate string) (err error) {
	tx, err := kdb.Begin("UpdateDnssecKeyState")
	if err != nil {
		return fmt.Errorf("error beginning transaction: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()

	if err := UpdateDnssecKeyStateTx(tx, kdb, zonename, keyid, newstate); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit failed: %w", err)
	}
	committed = true
	if rerr := republishSigningKeysForZone(kdb, zonename); rerr != nil {
		return fmt.Errorf("UpdateDnssecKeyState: republish signing keys: %w", rerr)
	}
	return nil
}

// UpdateDnssecKeyStateTx updates a DNSKEY's state on an existing transaction.
// Used by callers that need to wrap the state change together with other
// rollover bookkeeping in a single TX (§9.4 two-store consistency).
//
// Does NOT republish the signing-keys snapshot — the caller must call
// republishSigningKeysForZone after their Commit (R1). Callers today:
// DnssecKeyMgmt (policy-cleanup; R2 defer), AtomicRollover, KSK observe-advance.
func UpdateDnssecKeyStateTx(tx *Tx, kdb *KeyDB, zonename string, keyid uint16, newstate string) error {
	f, ok := keyFlagsForState(newstate)
	if !ok {
		return fmt.Errorf("key state %q has no flags in the flag table (zone %s, keyid %d); register it with RegisterKeyStateFlags", newstate, zonename, keyid)
	}
	oldstate, err := setKeyRowTx(tx, zonename, keyid, newstate, f, "")
	if err != nil {
		return err
	}
	lgSigner.Info("DNSKEY state updated", "zone", zonename, "keyid", keyid, "oldstate", oldstate, "newstate", newstate)
	return nil
}

// RolloverKey performs a manual key rollover for the specified zone and key type.
// It swaps the oldest standby key to active and the current active key to retired.
// Returns the old active keyid and the new active keyid.
// If tx is non-nil, uses the existing transaction; otherwise begins its own.
func (kdb *KeyDB) RolloverKey(zonename string, keytype string, tx *Tx) (uint16, uint16, error) {
	// No zone is no rollover: the keys are picked by zone, and with none
	// they would be picked from every zone (dnssecKeysByState).
	if strings.TrimSpace(zonename) == "" {
		return 0, 0, fmt.Errorf("rollover: no zone named")
	}
	if zd, owned := zoneOwnedByName(zonename); owned {
		return 0, 0, ownedRefusal(zd, "rollover")
	}
	var expectedFlags uint16
	switch keytype {
	case "ZSK":
		expectedFlags = 256
	case "KSK", "CSK":
		expectedFlags = 257
	default:
		return 0, 0, fmt.Errorf("invalid keytype %q, must be ZSK or KSK", keytype)
	}

	// Use existing transaction or begin a new one. The keys are read through
	// it, so that the roll acts on what the transaction holds (#986).
	// When tx != nil (external), the caller must republishSigningKeysForZone
	// after their Commit (R1). When tx == nil we own the commit and republish.
	var err error
	localtx := false
	if tx == nil {
		tx, err = kdb.Begin("RolloverKey")
		if err != nil {
			return 0, 0, fmt.Errorf("error beginning transaction: %w", err)
		}
		localtx = true
	}

	var txErr error
	committed := false
	defer func() {
		if localtx && !committed {
			tx.Rollback()
		}
	}()

	// Get active keys of this type
	activeKeys, err := GetDnssecKeysByStateTx(tx, zonename, DnskeyStateActive)
	if err != nil {
		return 0, 0, fmt.Errorf("error getting active keys: %w", err)
	}

	// One active key per (role, algorithm). Collect every role-matching
	// active instead of taking the first: two actives of one algorithm is a
	// broken invariant we must not silently "fix" by retiring one of them,
	// and for the KSK two actives of DIFFERENT algorithms is the legitimate
	// overlap of an algorithm rollover -- which this manual path must not
	// drive, since the engine owns both keys and the parent DS set.
	var activeKey *DnssecKeyWithTimestamps
	algsSeen := map[uint8]int{}
	for i, k := range activeKeys {
		if k.Flags != expectedFlags {
			continue
		}
		algsSeen[k.Algorithm]++
		if activeKey == nil {
			activeKey = &activeKeys[i]
		}
	}
	if activeKey == nil {
		return 0, 0, fmt.Errorf("no active %s found for zone %s", keytype, zonename)
	}
	for alg, n := range algsSeen {
		if n > 1 {
			return 0, 0, fmt.Errorf("zone %s has %d active %s keys of algorithm %s; refusing to pick one to retire (one active key per role and algorithm)",
				zonename, n, keytype, dns.AlgorithmToString[alg])
		}
	}
	if len(algsSeen) > 1 {
		return 0, 0, fmt.Errorf("manual %s rollover refused for zone %s: active %s keys of %d algorithms means a KSK algorithm rollover is in progress and the auto-rollover engine owns them; let it finish or cancel it",
			keytype, zonename, keytype, len(algsSeen))
	}

	// Get standby keys of this type
	standbyKeys, err := GetDnssecKeysByStateTx(tx, zonename, DnskeyStateStandby)
	if err != nil {
		return 0, 0, fmt.Errorf("error getting standby keys: %w", err)
	}

	var standbyKey *DnssecKeyWithTimestamps
	for i, k := range standbyKeys {
		if k.Flags == expectedFlags {
			standbyKey = &standbyKeys[i]
			break
		}
	}
	if standbyKey == nil {
		return 0, 0, fmt.Errorf("no standby %s available for rollover in zone %s", keytype, zonename)
	}

	// standby → active
	activeFlags, _ := keyFlagsForState(DnskeyStateActive)
	if _, txErr = setKeyRowTx(tx, zonename, standbyKey.KeyTag, DnskeyStateActive, activeFlags, DnskeyStateStandby); txErr != nil {
		return 0, 0, fmt.Errorf("standby→active transition failed: %w", txErr)
	}

	// Stamp the ZSK active_seq counter (operator-facing "n-th active ZSK")
	// in the same transaction as active_at, so a roll visibly increments it.
	// KSK active_seq lives in RolloverKeyState (stamped by AtomicRollover),
	// not here — RolloverKey is the ZSK roll path.
	if keytype == "ZSK" {
		seq, serr := nextZskActiveSeqTx(tx, zonename)
		if serr != nil {
			txErr = serr
			return 0, 0, fmt.Errorf("zsk active_seq: %w", serr)
		}
		if serr := setZskActiveSeqTx(tx, zonename, standbyKey.KeyTag, seq); serr != nil {
			txErr = serr
			return 0, 0, fmt.Errorf("stamp zsk active_seq: %w", serr)
		}
	}

	// active → retired (setKeyRowTx stamps retired_at)
	retiredFlags, _ := keyFlagsForState(DnskeyStateRetired)
	if _, txErr = setKeyRowTx(tx, zonename, activeKey.KeyTag, DnskeyStateRetired, retiredFlags, DnskeyStateActive); txErr != nil {
		return 0, 0, fmt.Errorf("active→retired transition failed: %w", txErr)
	}

	if localtx {
		if err := tx.Commit(); err != nil {
			txErr = err
			return 0, 0, fmt.Errorf("commit failed: %w", err)
		}
		committed = true
		if rerr := republishSigningKeysForZone(kdb, zonename); rerr != nil {
			return 0, 0, fmt.Errorf("RolloverKey: republish signing keys: %w", rerr)
		}
	}

	lgSigner.Info("key rollover completed", "zone", zonename, "keytype", keytype,
		"old_active", activeKey.KeyTag, "new_active", standbyKey.KeyTag)

	return activeKey.KeyTag, standbyKey.KeyTag, nil
}
