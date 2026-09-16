package tdns

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/miekg/dns"
)

// An owner's state write names the columns (design §3.2): UpdateKeyRow writes
// state, pub, sign and ds in one statement through the write function, on a
// zone tdns's writer would leave ds unset (a multi-provider zone), and
// republishes like every state write.
func TestOwnerKeyRowWriteNamesTheColumns(t *testing.T) {
	kdb := newTestKeyDB(t)
	const zone = "ownerwrite.example."
	zd := dsTestZone(t, kdb, zone, RolloverMethodNone)
	zd.Options[OptMultiProvider] = true
	RegisterKeyStateFlags(map[string]KeyRowFlags{"mpdist": {Pub: true}})
	k := ktGenKSK(t, kdb, zone, DnskeyStateStandby, dns.ED25519)
	if got := dsOf(t, kdb, zone, k); got != "NULL" {
		t.Fatalf("fixture: a multi-provider zone's KSK has ds=%s, want NULL", got)
	}
	// tdns's own state write cannot give it a ds
	if err := UpdateDnssecKeyState(kdb, zone, k, DnskeyStateStandby); err != nil {
		t.Fatal(err)
	}
	if got := dsOf(t, kdb, zone, k); got != "NULL" {
		t.Fatalf("UpdateDnssecKeyState wrote ds=%s on a multi-provider zone", got)
	}
	resetKeystoreWrites(t, kdb)
	yes := sql.NullBool{Bool: true, Valid: true}
	if err := UpdateKeyRow(kdb, zone, k, DnskeyStateStandby, KeyRowFlags{Pub: true, DS: yes}); err != nil {
		t.Fatalf("UpdateKeyRow: %v", err)
	}
	pub, sign, ds := readKeyRowFlags(t, kdb, zone, k)
	if flagString(pub) != "1" || flagString(sign) != "0" || flagString(ds) != "1" {
		t.Errorf("after the owner's write: pub=%s sign=%s ds=%s, want 1 0 1", flagString(pub), flagString(sign), flagString(ds))
	}
	if w := keystoreWrites(t, kdb); len(w) != 1 {
		t.Errorf("the owner's write made %d keystore writes, want 1: %v", len(w), w)
	}
	// an owner's own state, with its columns
	if err := UpdateKeyRow(kdb, zone, k, "mpdist", KeyRowFlags{Pub: true, DS: sql.NullBool{Valid: true}}); err != nil {
		t.Fatalf("UpdateKeyRow to an owner state: %v", err)
	}
	if st := ktKeyState(t, kdb, zone, k); st != "mpdist" {
		t.Errorf("state %s, want mpdist", st)
	}
	if _, _, ds := readKeyRowFlags(t, kdb, zone, k); flagString(ds) != "0" {
		t.Errorf("ds=%s after the owner wrote 0, want 0", flagString(ds))
	}
	// the invariants the writer checks still hold: sign implies pub
	err := UpdateKeyRow(kdb, zone, k, DnskeyStateActive, KeyRowFlags{Sign: true, DS: yes})
	if err == nil {
		t.Error("a write with sign and no pub was accepted")
	}
	// and a compare-and-set on the state the caller expects
	err = UpdateKeyRowFrom(kdb, zone, k, DnskeyStateActive, DnskeyStateStandby, KeyRowFlags{Pub: true, Sign: true, DS: yes})
	if err == nil || !errors.Is(err, ErrKeyRowStateChanged) {
		t.Errorf("a write expecting standby on an mpdist key: err=%v, want ErrKeyRowStateChanged", err)
	}
	if err := UpdateKeyRowFrom(kdb, zone, k, DnskeyStateActive, "mpdist", KeyRowFlags{Pub: true, Sign: true, DS: yes}); err != nil {
		t.Fatalf("UpdateKeyRowFrom mpdist -> active: %v", err)
	}
	if st := ktKeyState(t, kdb, zone, k); st != DnskeyStateActive {
		t.Errorf("state %s, want active", st)
	}
}
