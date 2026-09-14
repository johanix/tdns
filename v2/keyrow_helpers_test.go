package tdns

import (
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// The two queries S1a replaces, kept here as the reference for T1a.2: what the
// code before the key columns meant by "the keys that sign" and "the DNSKEYs
// that are served" (loadDnssecKeysFromDB with state active, and
// FetchZoneDnskeysSql plus the active set). They are not edited when the code
// changes; S4 removes them with the code they describe (test plan T4.3).
const (
	refSigningKeysSql = `SELECT keyid FROM DnssecKeyStore WHERE zonename=? AND state='active'`
	refServedKeysSql  = `SELECT keyid FROM DnssecKeyStore WHERE zonename=? AND state IN ('active','published','standby','retired','mpdist','foreign')`
	colSigningKeysSql = `SELECT keyid FROM DnssecKeyStore WHERE zonename=? AND sign=1`
	colServedKeysSql  = `SELECT keyid FROM DnssecKeyStore WHERE zonename=? AND pub=1`
)

// keyStatesForRowTests is every state a DnssecKeyStore row can carry today:
// tdns's own seven and the three a multi-provider owner stages.
var keyStatesForRowTests = []string{
	DnskeyStateCreated, DnskeyStateDsPublished, DnskeyStatePublished, DnskeyStateStandby,
	DnskeyStateActive, DnskeyStateRetired, DnskeyStateRemoved,
	DnskeyStateMpdist, DnskeyStateForeign, DnskeyStateMpremove,
}

var keyRolesForRowTests = []string{"KSK", "ZSK", "CSK"}

func keyidSet(t *testing.T, kdb *KeyDB, q, zone string) map[uint16]bool {
	t.Helper()
	rows, err := kdb.Query(q, zone)
	if err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	defer rows.Close()
	out := map[uint16]bool{}
	for rows.Next() {
		var k int
		if err := rows.Scan(&k); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[uint16(k)] = true
	}
	return out
}

func keyidSetString(m map[uint16]bool) string {
	var ks []int
	for k := range m {
		ks = append(ks, int(k))
	}
	sort.Ints(ks)
	return fmt.Sprint(ks)
}

// assertKeySetsAgree is T1a.2's assertion: the reference sets and the column
// sets are equal for zone.
func assertKeySetsAgree(t *testing.T, kdb *KeyDB, zone string) {
	t.Helper()
	for _, c := range []struct{ what, ref, col string }{
		{"signing set", refSigningKeysSql, colSigningKeysSql},
		{"served DNSKEY set", refServedKeysSql, colServedKeysSql},
	} {
		ref, col := keyidSet(t, kdb, c.ref, zone), keyidSet(t, kdb, c.col, zone)
		if keyidSetString(ref) != keyidSetString(col) {
			t.Errorf("%s: %s differs: from state %v, from the columns %v", zone, c.what, keyidSetString(ref), keyidSetString(col))
		}
	}
}

// testDNSKEY is a DNSKEY whose public key is rng-derived bytes: it has a key
// tag and a wire form, and is never used for crypto. Row-level tests need the
// shape of a key, not signatures.
func testDNSKEY(zone, role string, rng *rand.Rand) *dns.DNSKEY {
	flags := uint16(257)
	if role == "ZSK" {
		flags = 256
	}
	pk := make([]byte, 32)
	for i := range pk {
		pk[i] = byte(rng.IntN(256))
	}
	return &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: base64.StdEncoding.EncodeToString(pk),
	}
}

// testKeyRow is a synthetic keystore row for zone in state with the given role.
// Foreign rows have no private key, as tdns-mp writes them; every other row
// carries a placeholder that is not a key either.
func testKeyRow(zone, state, role string, rng *rand.Rand) KeyRow {
	dk := testDNSKEY(zone, role, rng)
	priv := "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n"
	creator := "test"
	if state == DnskeyStateForeign {
		priv, creator = "", "foreign"
	}
	return KeyRow{
		Zone: zone, State: state, Keyid: dk.KeyTag(), Flags: dk.Flags,
		Algorithm: dns.AlgorithmToString[dk.Algorithm], Creator: creator,
		PrivateKey: priv, KeyRR: dk.String(),
	}
}

// insertTestKeyRow writes one synthetic row through insertKeyRowTx and returns
// its keyid. The flags come from the state, as they do for tdns's own writers.
func insertTestKeyRow(t *testing.T, kdb *KeyDB, zone, state, role string, rng *rand.Rand) uint16 {
	t.Helper()
	row := testKeyRow(zone, state, role, rng)
	tx, err := kdb.Begin("insertTestKeyRow")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := insertKeyRowTx(tx, row); err != nil {
		tx.Rollback()
		t.Fatalf("insert %s %s row: %v", state, role, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return row.Keyid
}

// insertRawTestKeyRow writes a row the way the code before the key columns
// did: state only, no flags. This is how an older binary, or a test that
// predates the columns, leaves a row.
func insertRawTestKeyRow(t *testing.T, kdb *KeyDB, zone, state, role string, rng *rand.Rand) uint16 {
	t.Helper()
	row := testKeyRow(zone, state, role, rng)
	if _, err := kdb.DB.Exec(`INSERT INTO DnssecKeyStore (zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		row.Zone, row.State, row.Keyid, row.Flags, row.Algorithm, row.Creator, row.PrivateKey, row.KeyRR); err != nil {
		t.Fatalf("raw insert %s %s row: %v", state, role, err)
	}
	return row.Keyid
}

// readKeyRowFlags returns a row's pub, sign and ds columns; nil for NULL.
func readKeyRowFlags(t *testing.T, kdb *KeyDB, zone string, keyid uint16) (pub, sign, ds *int64) {
	t.Helper()
	var p, s, d *int64
	if err := kdb.DB.QueryRow(`SELECT pub, sign, ds FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, zone, keyid).Scan(&p, &s, &d); err != nil {
		t.Fatalf("read flags of %s/%d: %v", zone, keyid, err)
	}
	return p, s, d
}

func flagString(v *int64) string {
	if v == nil {
		return "NULL"
	}
	return fmt.Sprint(*v)
}

func newTestRand(seed uint64) *rand.Rand { return rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)) }

// installTestKeystoreGuards adds to a test keystore what the test plan asks of
// one (§4.1 T1a.5 and §5):
//
//   - a trigger that aborts any update of state that leaves pub or sign
//     unset, once the columns exist;
//   - a write recorder: every insert, update and delete on DnssecKeyStore is
//     logged in KeystoreWriteLog, so a test can assert that a code path wrote
//     nothing (T2.1).
func installTestKeystoreGuards(t *testing.T, kdb *KeyDB) {
	t.Helper()
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS KeystoreWriteLog (id INTEGER PRIMARY KEY, op TEXT, zonename TEXT, keyid INTEGER)`,
		`CREATE TRIGGER IF NOT EXISTS KeystoreWriteLog_insert AFTER INSERT ON DnssecKeyStore
BEGIN INSERT INTO KeystoreWriteLog (op, zonename, keyid) VALUES ('insert', NEW.zonename, NEW.keyid); END`,
		`CREATE TRIGGER IF NOT EXISTS KeystoreWriteLog_update AFTER UPDATE ON DnssecKeyStore
BEGIN INSERT INTO KeystoreWriteLog (op, zonename, keyid) VALUES ('update', NEW.zonename, NEW.keyid); END`,
		`CREATE TRIGGER IF NOT EXISTS KeystoreWriteLog_delete AFTER DELETE ON DnssecKeyStore
BEGIN INSERT INTO KeystoreWriteLog (op, zonename, keyid) VALUES ('delete', OLD.zonename, OLD.keyid); END`,
	}
	if dbColumnExists(kdb.DB, "DnssecKeyStore", "pub") {
		stmts = append(stmts, `CREATE TRIGGER IF NOT EXISTS DnssecKeyStore_flags_guard
BEFORE UPDATE OF state ON DnssecKeyStore FOR EACH ROW
WHEN NEW.pub IS NULL OR NEW.sign IS NULL
BEGIN SELECT RAISE(ABORT, 'DnssecKeyStore: a state update left pub or sign unset'); END`)
	}
	for _, s := range stmts {
		if _, err := kdb.DB.Exec(s); err != nil {
			t.Fatalf("install keystore guard: %v\n%s", err, s)
		}
	}
}

// keystoreWrites returns the recorded writes since the last reset, as
// "op zone keyid" lines.
func keystoreWrites(t *testing.T, kdb *KeyDB) []string {
	t.Helper()
	rows, err := kdb.DB.Query(`SELECT op, zonename, keyid FROM KeystoreWriteLog ORDER BY id`)
	if err != nil {
		t.Fatalf("read the write log: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var op, zone string
		var keyid int
		if err := rows.Scan(&op, &zone, &keyid); err != nil {
			t.Fatalf("scan the write log: %v", err)
		}
		out = append(out, fmt.Sprintf("%s %s %d", op, zone, keyid))
	}
	return out
}

func resetKeystoreWrites(t *testing.T, kdb *KeyDB) {
	t.Helper()
	if _, err := kdb.DB.Exec(`DELETE FROM KeystoreWriteLog`); err != nil {
		t.Fatalf("reset the write log: %v", err)
	}
}

// violationsByInvariant indexes what the checker found.
func violationsByInvariant(vs []KeyInvariantViolation) map[string][]KeyInvariantViolation {
	out := map[string][]KeyInvariantViolation{}
	for _, v := range vs {
		out[v.Invariant] = append(out[v.Invariant], v)
	}
	return out
}

func violationList(vs []KeyInvariantViolation) string {
	var ss []string
	for _, v := range vs {
		ss = append(ss, v.String())
	}
	return strings.Join(ss, "; ")
}
