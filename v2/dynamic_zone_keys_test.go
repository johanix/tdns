package tdns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
