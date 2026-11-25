package tdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A zone delete takes the zone's DNSSEC and SIG(0) keys along, unless told
// to keep them (design 2026-11-23 API ownership, 4.10).

const (
	keysZone  = "keys.example."
	otherZone = "other.example."
	xfrKey    = "xfr-key."
)

// keysFixture is an API-managed secondary, keysZone, whose primary uses the
// TSIG key xfrKey, and a zone that is not deleted, otherZone. Both have two
// DNSSEC keys, a SIG(0) key with its TrustStore copy, and a row in every
// table of zoneKeyStateTables. keysZone's name also has a child's key in
// the truststore, which is not this zone's.
func keysFixture(t *testing.T) (*Config, *KeyDB) {
	t.Helper()
	resetZonesForTest()
	t.Cleanup(resetZonesForTest)
	kdb := newTestKeyDB(t)
	conf := &Config{}
	conf.Internal.KeyDB = kdb

	for _, zone := range []string{keysZone, otherZone} {
		fixtureActivePair(t, kdb, zone)
		keyid := generateSig0Key(t, kdb, zone, Sig0StateActive)
		addZoneKeyState(t, kdb, zone)
		if zone == keysZone {
			// Another tag than the zone's own key: the store is unique on
			// (zonename, keyid).
			if _, err := kdb.DB.Exec(`INSERT INTO Sig0TrustStore (zonename, keyid, validated, trusted, source, keyrr) VALUES (?, ?, 1, 1, 'child-update', 'child key')`,
				zone, int(keyid^1)); err != nil {
				t.Fatal(err)
			}
		}
	}

	tx, err := kdb.Begin("keysFixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertTsigKeystore(tx, TsigKeystoreRow{Keyname: xfrKey, Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "api", Creator: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	Zones.Set(keysZone, &ZoneData{ZoneName: keysZone, ZoneType: Secondary,
		Options:       map[ZoneOption]bool{OptApiManagedZone: true},
		PrimariesConf: []PeerConf{{Addr: "192.0.2.1:53", Key: xfrKey}}})
	return conf, kdb
}

func addZoneKeyState(t *testing.T, kdb *KeyDB, zone string) {
	t.Helper()
	for _, q := range []string{
		`INSERT INTO RolloverKeyState (zone, keyid, rollover_index, active_at) VALUES (?, 1, 0, '2026-01-01T00:00:00Z')`,
		`INSERT INTO RolloverZoneState (zone, rollover_phase, rollover_in_progress, next_rollover_index) VALUES (?, 'pending-parent-observe', 1, 1)`,
		`INSERT INTO ZskRolloverState (zone, manual_rollover_requested_at) VALUES (?, '2026-01-01T00:00:00Z')`,
		`INSERT INTO RolloverCdsPublication (zone, keyids, published_at) VALUES (?, '1', '2026-01-01T00:00:00Z')`,
		`INSERT INTO ZonePolicyOverride (zone, policy) VALUES (?, 'old-policy')`,
	} {
		if _, err := kdb.DB.Exec(q, zone); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func countRows(t *testing.T, kdb *KeyDB, table, col, zone string) int {
	t.Helper()
	var n int
	if err := kdb.DB.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE %s=?`, table, col), zone).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// zoneKeyRows is every row this change deletes for zone, by table.
func zoneKeyRows(t *testing.T, kdb *KeyDB, zone string) map[string]int {
	t.Helper()
	got := map[string]int{
		"DnssecKeyStore": countRows(t, kdb, "DnssecKeyStore", "zonename", zone),
		"Sig0KeyStore":   countRows(t, kdb, "Sig0KeyStore", "zonename", zone),
	}
	var n int
	if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM Sig0TrustStore WHERE zonename=? AND source='keystore'`, zone).Scan(&n); err != nil {
		t.Fatal(err)
	}
	got["Sig0TrustStore (keystore copies)"] = n
	for _, table := range zoneKeyStateTables {
		got[table] = countRows(t, kdb, table, "zone", zone)
	}
	return got
}

func wantAllRows(t *testing.T, kdb *KeyDB, zone, what string) {
	t.Helper()
	for table, n := range zoneKeyRows(t, kdb, zone) {
		want := 1
		if table == "DnssecKeyStore" {
			want = 2
		}
		if n != want {
			t.Errorf("%s: %s has %d rows for %s, want %d", what, table, n, zone, want)
		}
	}
}

func sig0Cached(kdb *KeyDB, zone string) bool {
	kdb.sig0CacheMu.RLock()
	defer kdb.sig0CacheMu.RUnlock()
	_, ok := kdb.KeystoreSig0Cache[zone+"+"+Sig0StateActive]
	return ok
}

// By default the keys go with the zone, and the state that describes them;
// the other zone keeps everything, the TSIG key stays (its reference went
// with the zone), and so does the child's key in the truststore.
func TestZoneDeleteDeletesItsKeys(t *testing.T) {
	conf, kdb := keysFixture(t)
	for _, z := range []string{keysZone, otherZone} {
		if _, err := kdb.GetSig0Keys(z, Sig0StateActive); err != nil || !sig0Cached(kdb, z) {
			t.Fatalf("the SIG(0) key of %s is not cached (error %v)", z, err)
		}
	}
	if n := conf.tsigKeyZoneRefCount(xfrKey); n != 1 {
		t.Fatalf("the TSIG key has %d references before the delete, want 1", n)
	}

	removal, err := conf.RemoveDynamicZone(keysZone, false)
	if err != nil {
		t.Fatalf("RemoveDynamicZone: %v", err)
	}
	if removal.KeysError != "" || removal.KeepKeys || removal.DnssecKeys != 2 || removal.Sig0Keys != 1 {
		t.Errorf("removal = %+v, want 2 DNSSEC and 1 SIG(0) key deleted", removal)
	}
	if _, ok := Zones.Get(keysZone); ok {
		t.Error("the zone is still served")
	}
	for table, n := range zoneKeyRows(t, kdb, keysZone) {
		if n != 0 {
			t.Errorf("%s has %d rows for the deleted zone", table, n)
		}
	}
	if sig0Cached(kdb, keysZone) {
		t.Error("the deleted zone's SIG(0) key is still cached")
	}
	if n := countRows(t, kdb, "Sig0TrustStore", "zonename", keysZone); n != 1 {
		t.Errorf("the truststore has %d rows under the zone's name, want the child's key only", n)
	}

	wantAllRows(t, kdb, otherZone, "the other zone")
	if !sig0Cached(kdb, otherZone) {
		t.Error("the other zone's SIG(0) cache entry was dropped")
	}

	if _, err := getTsigKeystoreByName(kdb, xfrKey); err != nil {
		t.Errorf("the TSIG key was deleted with the zone: %v", err)
	}
	if n := conf.tsigKeyZoneRefCount(xfrKey); n != 0 {
		t.Errorf("the TSIG key has %d references after the delete, want 0", n)
	}
}

// --keep-keys leaves the keys and their state, and counts them.
func TestZoneDeleteKeepKeys(t *testing.T) {
	conf, kdb := keysFixture(t)
	removal, err := conf.RemoveDynamicZone(keysZone, true)
	if err != nil {
		t.Fatalf("RemoveDynamicZone: %v", err)
	}
	if _, ok := Zones.Get(keysZone); ok {
		t.Error("the zone is still served")
	}
	if !removal.KeepKeys || removal.KeysError != "" || removal.DnssecKeys != 2 || removal.Sig0Keys != 1 {
		t.Errorf("removal = %+v, want 2 DNSSEC and 1 SIG(0) key kept", removal)
	}
	wantAllRows(t, kdb, keysZone, "--keep-keys")
	wantAllRows(t, kdb, otherZone, "the other zone")
	msg := removal.Msg()
	for _, want := range []string{
		"zone keys.example. deleted; its keys were kept: 2 DNSSEC, 1 SIG(0)",
		"\nthe kept keys belong to no zone now; a re-add takes them back",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("Msg = %q, want it to say %q", msg, want)
		}
	}
	if w := removal.Warnings(); len(w) != 0 {
		t.Errorf("warnings with the keys kept: %q", w)
	}
}

// The keys are kept under the zone's canonical name, which a delete given
// the name in another case finds.
func TestZoneDeleteInAnotherCaseDeletesTheKeys(t *testing.T) {
	conf, kdb := keysFixture(t)
	removal, err := conf.RemoveDynamicZone("KEYS.Example", false)
	if err != nil {
		t.Fatalf("RemoveDynamicZone: %v", err)
	}
	if removal.Zone != keysZone || removal.DnssecKeys != 2 || removal.Sig0Keys != 1 {
		t.Errorf("removal = %+v, want 2 DNSSEC and 1 SIG(0) key of %s", removal, keysZone)
	}
	for table, n := range zoneKeyRows(t, kdb, keysZone) {
		if n != 0 {
			t.Errorf("%s has %d rows for the deleted zone", table, n)
		}
	}
	wantAllRows(t, kdb, otherZone, "the other zone")
}

// A KeyDB that cannot delete the keys leaves them all, in both tables, and
// the zone deleted: the response says so, how to clear them by hand, and is
// an error.
func TestZoneDeleteWhoseKeysCannotBeDeleted(t *testing.T) {
	conf, kdb := keysFixture(t)
	if _, err := kdb.DB.Exec(`CREATE TRIGGER refuse_delete BEFORE DELETE ON DnssecKeyStore
BEGIN SELECT RAISE(ABORT, 'delete refused by the test'); END`); err != nil {
		t.Fatal(err)
	}
	removal, err := conf.RemoveDynamicZone(keysZone, false)
	if err != nil {
		t.Fatalf("RemoveDynamicZone: %v (the zone was deleted; the keys are not an error of the removal)", err)
	}
	if _, ok := Zones.Get(keysZone); ok {
		t.Error("the zone came back")
	}
	if removal.KeysError == "" || removal.DnssecKeys != 0 || removal.Sig0Keys != 0 {
		t.Errorf("removal = %+v, want the key error and no keys counted", removal)
	}
	wantAllRows(t, kdb, keysZone, "a failed key delete")
	msg := removal.Msg()
	for _, want := range []string{
		"zone keys.example. deleted, but its keys were not: ",
		"keystore dnssec clear --zone keys.example. --force",
		"keystore sig0 delete --zone keys.example. --keyid <keyid>",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("Msg = %q, want it to say %q", msg, want)
		}
	}
	if w := removal.Warnings(); len(w) != 0 {
		t.Errorf("a DS warning with no keys deleted: %q", w)
	}
}

// The output counts the keys deleted, and warns of a DS at the parent only
// when DNSSEC keys went: as a fact when the rollover engine saw one, not at
// all when it saw none (and never confirmed one), and conditionally when it
// does not know.
func TestZoneDeleteOutput(t *testing.T) {
	at := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	const atStr = "2026-11-24T10:00:00Z"
	conditional := "if the parent has a DS for keys.example., it matches no key here now: validating resolvers treat the zone as bogus until the DS is removed or replaced"
	seen := "the parent had a DS for keys.example. at the last poll (" + atStr + "); it matches no key here now: validating resolvers treat the zone as bogus until the DS is removed or replaced"

	cases := []struct {
		name     string
		setup    func(t *testing.T, kdb *KeyDB)
		msg      string
		warnings []string
	}{
		{
			name:     "no DS observation",
			msg:      "zone keys.example. deleted, with its keys: 2 DNSSEC, 1 SIG(0)",
			warnings: []string{conditional},
		},
		{
			name: "DS seen at the parent",
			setup: func(t *testing.T, kdb *KeyDB) {
				if err := setLastDsObserved(kdb, keysZone, []uint16{12345}, at); err != nil {
					t.Fatal(err)
				}
			},
			msg:      "zone keys.example. deleted, with its keys: 2 DNSSEC, 1 SIG(0)",
			warnings: []string{seen},
		},
		{
			name: "no DS at the parent",
			setup: func(t *testing.T, kdb *KeyDB) {
				if err := setLastDsObserved(kdb, keysZone, nil, at); err != nil {
					t.Fatal(err)
				}
			},
			msg: "zone keys.example. deleted, with its keys: 2 DNSSEC, 1 SIG(0)\n" +
				"the parent had no DS for keys.example. at the last poll (" + atStr + ")",
		},
		{
			name: "no DS at the parent, but one confirmed before",
			setup: func(t *testing.T, kdb *KeyDB) {
				if err := setLastDsObserved(kdb, keysZone, nil, at); err != nil {
					t.Fatal(err)
				}
				if err := saveLastDSConfirmedRange(kdb, keysZone, 0, 0); err != nil {
					t.Fatal(err)
				}
			},
			msg:      "zone keys.example. deleted, with its keys: 2 DNSSEC, 1 SIG(0)",
			warnings: []string{conditional},
		},
		{
			name: "SIG(0) keys only",
			setup: func(t *testing.T, kdb *KeyDB) {
				if _, err := kdb.DB.Exec(`DELETE FROM DnssecKeyStore WHERE zonename=?`, keysZone); err != nil {
					t.Fatal(err)
				}
				if err := setLastDsObserved(kdb, keysZone, []uint16{12345}, at); err != nil {
					t.Fatal(err)
				}
			},
			msg: "zone keys.example. deleted, with its keys: 0 DNSSEC, 1 SIG(0)",
		},
		{
			name: "no keys",
			setup: func(t *testing.T, kdb *KeyDB) {
				for _, table := range []string{"DnssecKeyStore", "Sig0KeyStore"} {
					if _, err := kdb.DB.Exec(`DELETE FROM `+table+` WHERE zonename=?`, keysZone); err != nil {
						t.Fatal(err)
					}
				}
			},
			msg: "zone keys.example. deleted; it had no DNSSEC or SIG(0) keys",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conf, kdb := keysFixture(t)
			if tc.setup != nil {
				tc.setup(t, kdb)
			}
			removal, err := conf.RemoveDynamicZone(keysZone, false)
			if err != nil {
				t.Fatalf("RemoveDynamicZone: %v", err)
			}
			if got := removal.Msg(); got != tc.msg {
				t.Errorf("Msg:\n got %q\nwant %q", got, tc.msg)
			}
			if got := removal.Warnings(); strings.Join(got, "|") != strings.Join(tc.warnings, "|") {
				t.Errorf("Warnings:\n got %q\nwant %q", got, tc.warnings)
			}
		})
	}
}

// The /zone API handler carries the removal, its words, and --keep-keys
// (keepkeys in the request); a delete whose keys stay behind is an error.
func TestZoneDeleteThroughTheAPI(t *testing.T) {
	prevKDB, prevFile := Conf.Internal.KeyDB, Conf.DynamicZones.ConfigFile
	t.Cleanup(func() { Conf.Internal.KeyDB, Conf.DynamicZones.ConfigFile = prevKDB, prevFile })
	Conf.DynamicZones.ConfigFile = ""

	handler := APIzone(&AppDetails{Name: "tdns-auth"}, nil, nil)
	post := func(t *testing.T, body string) ZoneResponse {
		t.Helper()
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodPost, "/api/v1/zone", bytes.NewReader([]byte(body))))
		var resp ZoneResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decoding response: %v\n%s", err, rec.Body.String())
		}
		return resp
	}

	t.Run("default", func(t *testing.T) {
		_, kdb := keysFixture(t)
		Conf.Internal.KeyDB = kdb
		resp := post(t, `{"Command":"delete","Zone":"keys.example."}`)
		if resp.Error || resp.Removal == nil {
			t.Fatalf("delete: error %v (%s), removal %+v", resp.Error, resp.ErrorMsg, resp.Removal)
		}
		if resp.Removal.DnssecKeys != 2 || resp.Removal.Sig0Keys != 1 || resp.Msg != resp.Removal.Msg() || len(resp.Warnings) != 1 {
			t.Errorf("delete: msg %q, warnings %q, removal %+v", resp.Msg, resp.Warnings, resp.Removal)
		}
		if n := countRows(t, kdb, "DnssecKeyStore", "zonename", keysZone); n != 0 {
			t.Errorf("%d DNSSEC keys left", n)
		}
	})

	t.Run("keepkeys", func(t *testing.T) {
		_, kdb := keysFixture(t)
		Conf.Internal.KeyDB = kdb
		resp := post(t, `{"Command":"delete","Zone":"keys.example.","keepkeys":true}`)
		if resp.Error || resp.Removal == nil || !resp.Removal.KeepKeys {
			t.Fatalf("delete --keep-keys: error %v (%s), removal %+v", resp.Error, resp.ErrorMsg, resp.Removal)
		}
		wantAllRows(t, kdb, keysZone, "keepkeys")
		if len(resp.Warnings) != 0 {
			t.Errorf("delete --keep-keys: warnings %q", resp.Warnings)
		}
	})

	t.Run("keys not deleted", func(t *testing.T) {
		_, kdb := keysFixture(t)
		Conf.Internal.KeyDB = kdb
		if _, err := kdb.DB.Exec(`CREATE TRIGGER refuse_delete BEFORE DELETE ON Sig0KeyStore
BEGIN SELECT RAISE(ABORT, 'delete refused by the test'); END`); err != nil {
			t.Fatal(err)
		}
		resp := post(t, `{"Command":"delete","Zone":"keys.example."}`)
		if !resp.Error || resp.Removal == nil || resp.Removal.KeysError == "" {
			t.Fatalf("delete with the keys left: error %v, removal %+v", resp.Error, resp.Removal)
		}
		if !strings.HasPrefix(resp.ErrorMsg, "zone keys.example. deleted, but its keys were not") {
			t.Errorf("ErrorMsg = %q", resp.ErrorMsg)
		}
		if _, ok := Zones.Get(keysZone); ok {
			t.Error("the zone came back")
		}
	})
}

// A KSK rollover tick that got the zone before a delete and takes the
// rollover lock after it writes nothing: the delete has just taken the
// zone's rollover state, and the tick would put it back.
func TestRolloverTickSkipsARemovedZone(t *testing.T) {
	kdb := newTestKeyDB(t)
	const zone = "removed.ds.example."
	zd := dsTestZone(t, kdb, zone, RolloverMethodMultiDS)
	if row, err := LoadRolloverZoneRow(kdb, zone); err != nil || row != nil {
		t.Fatalf("rollover state before the tick: %+v %v", row, err)
	}
	zd.removed.Store(true)
	if err := RolloverAutomatedTick(context.Background(), ktDeps(zd, kdb, time.Now())); err != nil {
		t.Fatalf("tick on a removed zone: %v", err)
	}
	if row, err := LoadRolloverZoneRow(kdb, zone); err != nil || row != nil {
		t.Fatalf("the tick wrote rollover state for a removed zone: %+v %v", row, err)
	}
	// The same tick on the zone still served does write it.
	zd.removed.Store(false)
	if err := RolloverAutomatedTick(context.Background(), ktDeps(zd, kdb, time.Now())); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if row, err := LoadRolloverZoneRow(kdb, zone); err != nil || row == nil {
		t.Fatalf("no rollover state after a tick on a served zone: %+v %v", row, err)
	}
}

// A refresh of a zone deleted while it ran sets or clears an error when it
// ends. That must not put the zone back in Zones (it came back without its
// keys, and the next rewrite persisted it). A zone not registered yet is
// still registered by SetError, as before.
func TestAnErrorChangeDoesNotResurrectADeletedZone(t *testing.T) {
	conf, _ := keysFixture(t)
	zd, ok := Zones.Get(keysZone)
	if !ok {
		t.Fatal("fixture zone not registered")
	}
	if _, err := conf.RemoveDynamicZone(keysZone, false); err != nil {
		t.Fatal(err)
	}
	zd.SetError(RefreshError, "the refresh that ran across the delete failed")
	zd.ClearError(RefreshError)
	if _, back := Zones.Get(keysZone); back {
		t.Fatal("an error change on the deleted zone put it back in Zones")
	}

	const fresh = "fresh.example."
	t.Cleanup(func() { Zones.Remove(fresh) })
	fz := &ZoneData{ZoneName: fresh}
	fz.SetError(ConfigError, "built in error state")
	if cur, ok := Zones.Get(fresh); !ok || cur != fz {
		t.Error("SetError no longer registers a zone that is not in Zones yet")
	}
}

// A SIG(0) rollover makes no key for a zone deleted while it ran. Here the
// delete runs during the lookup of the parent's DSYNC target. With
// --keep-keys the zone's active key is still there afterwards, and the
// zone's removal alone stops the rollover before it makes a key or asks
// the parent; without, the delete has taken every key of the zone, and
// none comes back. The fake parent fails the test on any UPDATE.
func TestASig0RolloverMakesNoKeyForADeletedZone(t *testing.T) {
	for _, keepKeys := range []bool{true, false} {
		t.Run(fmt.Sprintf("keep-keys=%v", keepKeys), func(t *testing.T) {
			zd, kdb, fp := newRolloverZone(t)
			conf := &Config{}
			conf.Internal.KeyDB = kdb
			before := rolloverKeyStates(t, kdb, zd.ZoneName)
			rolloverLookupDSYNCTarget = func(ctx context.Context, zone string) (*DsyncTarget, error) {
				// RemoveDynamicZone's steps, from taking the zone out of Zones
				// to the keys.
				zd.leaveZones(zd.ZoneName)
				conf.removeZoneKeys(zone, keepKeys)
				return &DsyncTarget{Name: "updates.example.", Addresses: []string{"192.0.2.53:53"}}, nil
			}

			_, _, _, _, err := zd.RolloverSig0KeyWithParent(context.Background(), dns.ED25519, "complete")
			if err == nil {
				t.Fatal("the rollover of a deleted zone succeeded")
			}
			if keepKeys && !errors.Is(err, errRolloverZoneGone) {
				t.Errorf("the rollover of a zone deleted with its keys kept returned %v, want %v", err, errRolloverZoneGone)
			}
			want := map[uint16]string{}
			if keepKeys {
				want = before
			}
			if got := rolloverKeyStates(t, kdb, zd.ZoneName); !maps.Equal(got, want) {
				t.Errorf("keys after the rollover = %v, want %v", got, want)
			}
			if len(fp.sent) != 0 {
				t.Errorf("the rollover of a deleted zone sent %d UPDATEs", len(fp.sent))
			}
			assertKeystoreFree(t, kdb)
		})
	}
}

// A SIG(0) rollover makes its new key under the zone's rollover lock, the
// lock a zone delete deletes the zone's keys under, so the key is either
// there for the delete to take or not made. It does not hold the lock
// across the exchanges with the parent.
func TestASig0RolloverMakesItsKeyUnderTheRolloverLock(t *testing.T) {
	ok := rolloverAnswer{rcode: dns.RcodeSuccess}
	zd, _, fp := newRolloverZone(t, ok, ok)
	lock := AcquireRolloverLock(zd.ZoneName)
	heldAtGenerate := false
	testHookSig0RolloverGenerating = func() {
		if lock.TryLock() {
			lock.Unlock()
			return
		}
		heldAtGenerate = true
	}
	t.Cleanup(func() { testHookSig0RolloverGenerating = nil })
	heldAtUpdate := false
	fp.during = func(*dns.Msg) {
		if lock.TryLock() {
			lock.Unlock()
			return
		}
		heldAtUpdate = true
	}

	if _, _, _, _, err := zd.RolloverSig0KeyWithParent(context.Background(), dns.ED25519, "complete"); err != nil {
		t.Fatalf("RolloverSig0KeyWithParent: %v", err)
	}
	if !heldAtGenerate {
		t.Error("the new key was made without the zone's rollover lock")
	}
	if heldAtUpdate {
		t.Error("the rollover lock was held across an UPDATE to the parent")
	}
}

// A modify replaces the zone's ZoneData, and the refresh that still holds
// the old one sets or clears an error when it ends. That must not put the
// old ZoneData back over its replacement: a delete of the replacement then
// left the old one in Zones, and the deleted name came back. A modify
// whose config rewrite fails puts the old ZoneData back, live again.
func TestAnErrorChangeOnAReplacedZoneDoesNotOutliveTheDelete(t *testing.T) {
	resetZonesForTest()
	t.Cleanup(resetZonesForTest)
	conf, ch := newTestConfigForCores(t)
	const name = "replaced.example."
	upstream := func(addr string) []PeerConf { return []PeerConf{{Addr: addr, Key: NOKEY}} }
	live := func() *ZoneData {
		zd, _ := Zones.Get(name)
		return zd
	}

	if _, err := conf.ProvisionDynamicZone(context.Background(),
		DynamicZoneInput{Name: name, Type: Secondary, Primaries: upstream("192.0.2.1:53")}, true); err != nil {
		t.Fatalf("add: %v", err)
	}
	<-ch
	first := live()
	if _, err := conf.ModifyDynamicZone(context.Background(),
		DynamicZoneInput{Name: name, Type: Secondary, Primaries: upstream("192.0.2.9:53")}); err != nil {
		t.Fatalf("modify: %v", err)
	}
	<-ch
	second := live()
	if second == first {
		t.Fatal("the modify did not replace the ZoneData")
	}
	first.SetError(RefreshError, "the refresh of the replaced ZoneData failed")
	first.ClearError(RefreshError)
	if live() != second {
		t.Fatal("an error change on the replaced ZoneData put it back over its replacement")
	}

	// A modify whose config rewrite fails (its directory does not exist)
	// puts second back, and its error changes republish it again.
	dir := t.TempDir()
	conf.DynamicZones.ConfigFile = filepath.Join(dir, "missing", "dynamic.yaml")
	conf.DynamicZones.ZoneDirectory = dir
	conf.DynamicZones.Dynamic.Storage = "persistent"
	if _, err := conf.ModifyDynamicZone(context.Background(),
		DynamicZoneInput{Name: name, Type: Secondary, Primaries: upstream("192.0.2.10:53")}); err == nil {
		t.Fatal("a modify whose config rewrite fails succeeded")
	}
	if live() != second {
		t.Fatal("the failed modify did not put the previous ZoneData back")
	}
	second.SetError(RefreshError, "an error on the zone put back")
	if live() != second || !second.HasError(RefreshError) {
		t.Error("an error change on the ZoneData put back did not republish it")
	}
	second.ClearError(RefreshError)
	conf.DynamicZones.ConfigFile = ""

	if _, err := conf.RemoveDynamicZone(name, false); err != nil {
		t.Fatalf("delete: %v", err)
	}
	first.SetError(RefreshError, "the refresh of the replaced ZoneData failed, after the delete")
	second.SetError(RefreshError, "the refresh of the deleted ZoneData failed")
	if zd, back := Zones.Get(name); back {
		t.Fatalf("the deleted name came back (ZoneData %p; first %p, second %p)", zd, first, second)
	}
}

// A --keep-keys delete that comes while a SIG(0) rollover is past its
// check of zd.removed, with the rollover lock held, waits for the new key:
// the key is one of the kept ones, and counted. The rollover then finds
// the zone removed and does not send the key to the parent; a rollover
// started after the delete makes no key at all. The fake parent fails the
// test on any UPDATE.
func TestAKeepKeysDeleteWaitsForARolloverPastItsCheck(t *testing.T) {
	zd, kdb, fp := newRolloverZone(t)
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	if zd.Options == nil {
		zd.Options = map[ZoneOption]bool{}
	}
	zd.Options[OptApiManagedZone] = true
	Zones.Set(zd.ZoneName, zd)
	t.Cleanup(func() { Zones.Remove(zd.ZoneName) })
	before := len(rolloverKeyStates(t, kdb, zd.ZoneName))

	type outcome struct {
		r   *ZoneRemoval
		err error
	}
	deleted := make(chan outcome, 1)
	testHookSig0RolloverGenerating = func() {
		go func() {
			r, err := conf.RemoveDynamicZone(zd.ZoneName, true)
			deleted <- outcome{r, err}
		}()
		for deadline := time.Now().Add(5 * time.Second); !zd.removed.Load(); time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("the delete did not mark the zone removed")
			}
		}
		// The rest of the delete, up to the count of the kept keys, is
		// local and quick; given time, it must still be waiting.
		select {
		case o := <-deleted:
			t.Errorf("the --keep-keys delete returned while a rollover past its check held the lock (%+v)", o.r)
			deleted <- o
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Cleanup(func() { testHookSig0RolloverGenerating = nil })

	_, _, _, _, err := zd.RolloverSig0KeyWithParent(context.Background(), dns.ED25519, "complete")
	testHookSig0RolloverGenerating = nil
	if !errors.Is(err, errRolloverZoneGone) {
		t.Errorf("the rollover the delete came during returned %v, want %v", err, errRolloverZoneGone)
	}
	var o outcome
	select {
	case o = <-deleted:
	case <-time.After(5 * time.Second):
		t.Fatal("the --keep-keys delete did not return")
	}
	if o.err != nil {
		t.Fatalf("the --keep-keys delete: %v", o.err)
	}
	kept := rolloverKeyStates(t, kdb, zd.ZoneName)
	if len(kept) != before+1 {
		t.Errorf("SIG(0) keys after the delete = %v, want the %d there before and the rollover's new one", kept, before)
	}
	if o.r.Sig0Keys != len(kept) {
		t.Errorf("the delete counted %d SIG(0) keys kept, the keystore holds %d", o.r.Sig0Keys, len(kept))
	}

	_, _, _, _, err = zd.RolloverSig0KeyWithParent(context.Background(), dns.ED25519, "complete")
	if !errors.Is(err, errRolloverZoneGone) {
		t.Errorf("a rollover after the delete returned %v, want %v", err, errRolloverZoneGone)
	}
	if got := rolloverKeyStates(t, kdb, zd.ZoneName); !maps.Equal(got, kept) {
		t.Errorf("a rollover after the delete changed the kept keys: %v, want %v", got, kept)
	}
	if len(fp.sent) != 0 {
		t.Errorf("%d UPDATEs sent to the parent for a deleted zone", len(fp.sent))
	}
	assertKeystoreFree(t, kdb)
}
