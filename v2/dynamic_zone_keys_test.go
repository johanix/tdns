package tdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
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

	// A removal a crash could still undo is not a success either: the
	// report, with its keys kept and the commands to finish, as the error.
	t.Run("removal not on disk", func(t *testing.T) {
		_, kdb := keysFixture(t)
		Conf.Internal.KeyDB = kdb
		Conf.DynamicZones.ConfigFile = filepath.Join(t.TempDir(), "dynamic.yaml")
		t.Cleanup(func() { Conf.DynamicZones.ConfigFile = "" })
		prev := syncDynamicConfigDir
		syncDynamicConfigDir = func(string) error { return errors.New("sync refused by the test") }
		t.Cleanup(func() { syncDynamicConfigDir = prev })
		resp := post(t, `{"Command":"delete","Zone":"keys.example."}`)
		if !resp.Error || resp.Removal == nil || resp.Removal.NotSynced == "" || resp.ErrorMsg != resp.Msg {
			t.Fatalf("delete not on disk: error %v (%s), removal %+v", resp.Error, resp.ErrorMsg, resp.Removal)
		}
		if !strings.Contains(resp.ErrorMsg, "must stay until the removal is on disk") || strings.Contains(resp.ErrorMsg, "keystore ") {
			t.Errorf("ErrorMsg = %q", resp.ErrorMsg)
		}
		wantAllRows(t, kdb, keysZone, "removal not on disk")
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

// The defence behind the claim that keeps a delete from starting during a
// SIG(0) rollover (beginZoneDelete): a --keep-keys removal of the keys that
// comes while a rollover is past its check of zd.removed, with the rollover
// lock held, waits for the new key, and the key is one of the kept ones,
// and counted. The rollover then finds the zone removed and does not send
// the key to the parent; a rollover started after the delete makes no key
// at all. The fake parent fails the test on any UPDATE.
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
			// RemoveDynamicZone's steps from taking the zone out of Zones
			// to the keys; its claim would refuse the delete outright.
			zd.leaveZones(zd.ZoneName)
			deleted <- outcome{conf.removeZoneKeys(zd.ZoneName, true), nil}
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

// rolloverZoneToDelete is newRolloverZone's zone registered as an
// API-managed zone that RemoveDynamicZone can delete, with conf over the
// same keystore.
func rolloverZoneToDelete(t *testing.T, answers ...rolloverAnswer) (*Config, *ZoneData, *KeyDB, *rolloverParent) {
	t.Helper()
	zd, kdb, fp := newRolloverZone(t, answers...)
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	if zd.Options == nil {
		zd.Options = map[ZoneOption]bool{}
	}
	zd.Options[OptApiManagedZone] = true
	Zones.Set(zd.ZoneName, zd)
	t.Cleanup(func() { Zones.Remove(zd.ZoneName) })
	return conf, zd, kdb, fp
}

const sig0RollingRefusal = "a SIG(0) key rollover is in progress; try again when it finishes"

// A zone delete, with --keep-keys or without, is refused while a SIG(0)
// rollover of the zone runs, here while its ADD waits for the parent, past
// both checks of zd.removed: taking the keys then could leave the parent
// trusting a key whose private half is gone. The zone and its keys are left
// as they are, and once the rollover is done the delete succeeds.
func TestAZoneDeleteIsRefusedDuringASig0Rollover(t *testing.T) {
	ok := rolloverAnswer{rcode: dns.RcodeSuccess}
	conf, zd, kdb, fp := rolloverZoneToDelete(t, ok, ok)
	refused := 0
	fp.during = func(*dns.Msg) {
		if len(fp.sent) > 0 {
			return // the REMOVE: once is enough
		}
		keys := rolloverKeyStates(t, kdb, zd.ZoneName)
		for _, keepKeys := range []bool{false, true} {
			r, err := conf.RemoveDynamicZone(zd.ZoneName, keepKeys)
			if err == nil || !strings.Contains(err.Error(), sig0RollingRefusal) {
				t.Errorf("delete (keep-keys %v) during a rollover returned %+v, %v", keepKeys, r, err)
				continue
			}
			refused++
		}
		if cur, live := Zones.Get(zd.ZoneName); !live || cur != zd || zd.removed.Load() {
			t.Error("a refused delete took the zone out of Zones")
		}
		if got := rolloverKeyStates(t, kdb, zd.ZoneName); !maps.Equal(got, keys) {
			t.Errorf("a refused delete changed the keys: %v, want %v", got, keys)
		}
	}

	if _, _, _, _, err := zd.RolloverSig0KeyWithParent(context.Background(), dns.ED25519, "complete"); err != nil {
		t.Fatalf("the rollover the deletes were refused during: %v", err)
	}
	if refused != 2 {
		t.Fatalf("%d of 2 deletes refused during the rollover", refused)
	}
	if len(fp.sent) != 2 {
		t.Errorf("UPDATEs sent = %d, want the ADD and the REMOVE", len(fp.sent))
	}

	if _, err := conf.RemoveDynamicZone(zd.ZoneName, false); err != nil {
		t.Fatalf("the delete after the rollover: %v", err)
	}
	if got := rolloverKeyStates(t, kdb, zd.ZoneName); len(got) != 0 {
		t.Errorf("SIG(0) keys after the delete: %v", got)
	}
}

// A SIG(0) rollover is refused while the zone is being deleted, and says
// so: it sends nothing and makes no key, and the delete takes the keys.
func TestASig0RolloverIsRefusedDuringAZoneDelete(t *testing.T) {
	conf, zd, kdb, fp := rolloverZoneToDelete(t)
	var rollErr error
	testHookSignalRecordTaken = func() {
		_, _, _, _, rollErr = zd.RolloverSig0KeyWithParent(context.Background(), dns.ED25519, "complete")
	}
	t.Cleanup(func() { testHookSignalRecordTaken = nil })

	if _, err := conf.RemoveDynamicZone(zd.ZoneName, false); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if rollErr == nil || !strings.Contains(rollErr.Error(), "zone "+zd.ZoneName+" is being deleted; no rollover started") {
		t.Errorf("a rollover during the delete returned %v", rollErr)
	}
	if len(fp.sent) != 0 {
		t.Errorf("a rollover during the delete sent %d UPDATEs", len(fp.sent))
	}
	if got := rolloverKeyStates(t, kdb, zd.ZoneName); len(got) != 0 {
		t.Errorf("SIG(0) keys after the delete: %v", got)
	}
}

// signingZoneToDelete is an API-managed, online-signed zone with a bound
// DNSSEC policy and no keys, registered for RemoveDynamicZone to delete.
func signingZoneToDelete(t *testing.T, name string) (*Config, *ZoneData, *KeyDB) {
	t.Helper()
	kdb := newTestKeyDB(t)
	zd := testZone(t, name, name+"\t3600\tIN\tSOA\tns."+name+" hostmaster."+name+" 1 7200 1800 604800 7200\n"+
		name+"\t3600\tIN\tNS\tns."+name+"\n")
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptOnlineSigning: true, OptApiManagedZone: true}
	zd.DnssecPolicy = &DnssecPolicy{Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.ED25519, ZSKAlgorithm: dns.ED25519}
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	Zones.Set(name, zd)
	t.Cleanup(func() { Zones.Remove(name) })
	return conf, zd, kdb
}

func dnssecKeyCount(t *testing.T, kdb *KeyDB, zone string) int {
	t.Helper()
	var n int
	if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM DnssecKeyStore WHERE zonename=?`, zone).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A zone deleted after EnsureActiveDnssecKeys found it without keys, and
// before it made them -- the policy binds after Ready, so a delete right
// after an add meets the first sign there -- gets none: the delete found no
// keys to take, and keys made after it would outlive the zone.
func TestAZoneDeletedBeforeItsFirstKeysGetsNone(t *testing.T) {
	const name = "firstkeys.example."
	conf, zd, kdb := signingZoneToDelete(t, name)
	testHookEnsureKeys = func(stage string) {
		if stage != "make" {
			return
		}
		testHookEnsureKeys = nil
		if _, err := conf.RemoveDynamicZone(name, false); err != nil {
			t.Errorf("delete: %v", err)
		}
	}
	t.Cleanup(func() { testHookEnsureKeys = nil })

	if _, err := zd.EnsureActiveDnssecKeys(kdb, false); !errors.Is(err, errNoKeysForRemovedZone) {
		t.Errorf("EnsureActiveDnssecKeys on a zone deleted under it returned %v, want %v", err, errNoKeysForRemovedZone)
	}
	if n := dnssecKeyCount(t, kdb, name); n != 0 {
		t.Errorf("%d DNSSEC keys made for the deleted zone", n)
	}
	// And a signing pass that starts after the delete makes none either.
	if _, err := zd.SignZone(context.Background(), kdb, false); !errors.Is(err, errNoKeysForRemovedZone) {
		t.Errorf("SignZone on the deleted zone returned %v, want %v", err, errNoKeysForRemovedZone)
	}
	if n := dnssecKeyCount(t, kdb, name); n != 0 {
		t.Errorf("%d DNSSEC keys made for the deleted zone by a signing pass", n)
	}
}

// A policy change holds the zone's rollover lock across the re-sign that
// makes a keyless zone's first keys, and the publish path makes them with
// zd.mu held. Neither may block: the first keys are made under the zone
// keys lock, not the rollover lock.
func TestFirstKeysAreMadeWhileTheRolloverLockIsHeld(t *testing.T) {
	const name = "lockheld.example."
	_, zd, kdb := signingZoneToDelete(t, name)
	lock := AcquireRolloverLock(name)
	lock.Lock()
	defer lock.Unlock()

	done := make(chan error, 1)
	go func() {
		zd.mu.Lock()
		defer zd.mu.Unlock()
		_, err := zd.EnsureActiveDnssecKeys(kdb, true)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("EnsureActiveDnssecKeys: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("EnsureActiveDnssecKeys blocked on the rollover lock")
	}
	if n := dnssecKeyCount(t, kdb, name); n != 2 {
		t.Errorf("%d DNSSEC keys made, want a KSK and a ZSK", n)
	}
}

func dnssecKeyState(t *testing.T, kdb *KeyDB, zone string, keyid uint16) string {
	t.Helper()
	var state string
	if err := kdb.DB.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, zone, int(keyid)).Scan(&state); err != nil {
		t.Fatalf("state of key %d: %v", keyid, err)
	}
	return state
}

// sameNameZones is a zone served under name with a bound policy and an old
// ZoneData of the same name, deleted or replaced since, that a signing pass
// still holds. The keys under name are the served zone's; the old one has
// a policy of its own.
func sameNameZones(t *testing.T, name string, oldPol *DnssecPolicy) (old *ZoneData, kdb *KeyDB) {
	t.Helper()
	kdb = newTestKeyDB(t)
	soa := name + "\t3600\tIN\tSOA\tns." + name + " hostmaster." + name + " 1 7200 1800 604800 7200\n" +
		name + "\t3600\tIN\tNS\tns." + name + "\n"
	served := testZone(t, name, soa)
	served.KeyDB = kdb
	served.Options = map[ZoneOption]bool{OptOnlineSigning: true}
	served.DnssecPolicy = &DnssecPolicy{Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.ED25519, ZSKAlgorithm: dns.ED25519}
	Zones.Set(name, served)
	t.Cleanup(func() { Zones.Remove(name) })
	old = testZone(t, name, soa)
	old.KeyDB = kdb
	old.Options = map[ZoneOption]bool{OptOnlineSigning: true}
	old.DnssecPolicy = oldPol
	return old, kdb
}

// A signing pass on an old ZoneData, removed after it looked up the keys
// by the zone's name -- a delete and a re-add of the name came in between
// -- makes no algorithm-reconcile write to the keys it found, which are
// the new zone's: its old policy would remove the new zone's standby KSK.
// The check is the one made under the zone keys lock, not the earlier one.
func TestAnOldZoneDataDoesNotReconcileANewZonesKeys(t *testing.T) {
	const name = "samename.example."
	oldPol := &DnssecPolicy{Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.ECDSAP256SHA256, ZSKAlgorithm: dns.ED25519}
	oldPol.Rollover.Method = RolloverMethodMultiDS
	old, kdb := sameNameZones(t, name, oldPol)
	fixtureActivePair(t, kdb, name)
	standby := fixtureStaged(t, kdb, name, "KSK", DnskeyStateStandby)

	testHookEnsureKeys = func(stage string) {
		if stage == "reconcile" {
			old.removed.Store(true)
		}
	}
	t.Cleanup(func() { testHookEnsureKeys = nil })
	if _, err := old.EnsureActiveDnssecKeys(kdb, false); !errors.Is(err, errNoKeysForRemovedZone) {
		t.Errorf("EnsureActiveDnssecKeys on the old ZoneData returned %v, want %v", err, errNoKeysForRemovedZone)
	}
	if st := dnssecKeyState(t, kdb, name, standby); st != DnskeyStateStandby {
		t.Errorf("the new zone's standby KSK is %s after a pass on the old ZoneData", st)
	}

	// The premise: the same pass on a ZoneData still in Zones removes it.
	testHookEnsureKeys = nil
	old.removed.Store(false)
	if _, err := old.EnsureActiveDnssecKeys(kdb, false); err != nil {
		t.Fatalf("EnsureActiveDnssecKeys: %v", err)
	}
	if st := dnssecKeyState(t, kdb, name, standby); st != DnskeyStateRemoved {
		t.Errorf("test premise: the old policy's reconcile left the standby KSK %s", st)
	}
}

// Nor does it promote the new zone's published keys, when it found no
// active ones: removed after it found them missing, it writes nothing.
func TestAnOldZoneDataDoesNotPromoteANewZonesKeys(t *testing.T) {
	const name = "samename2.example."
	old, kdb := sameNameZones(t, name, &DnssecPolicy{Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.ED25519, ZSKAlgorithm: dns.ED25519})
	ksk := fixtureStaged(t, kdb, name, "KSK")
	zsk := fixtureStaged(t, kdb, name, "ZSK")

	testHookEnsureKeys = func(stage string) {
		if stage == "make" {
			old.removed.Store(true)
		}
	}
	t.Cleanup(func() { testHookEnsureKeys = nil })
	if _, err := old.EnsureActiveDnssecKeys(kdb, false); !errors.Is(err, errNoKeysForRemovedZone) {
		t.Errorf("EnsureActiveDnssecKeys on the old ZoneData returned %v, want %v", err, errNoKeysForRemovedZone)
	}
	for _, k := range []uint16{ksk, zsk} {
		if st := dnssecKeyState(t, kdb, name, k); st != DnskeyStatePublished {
			t.Errorf("the new zone's published key %d is %s after a pass on the old ZoneData", k, st)
		}
	}
	if n := dnssecKeyCount(t, kdb, name); n != 2 {
		t.Errorf("%d DNSSEC keys under the name, want the new zone's 2", n)
	}

	// The premise: the same pass on a ZoneData still in Zones promotes them.
	testHookEnsureKeys = nil
	old.removed.Store(false)
	if _, err := old.EnsureActiveDnssecKeys(kdb, false); err != nil {
		t.Fatalf("EnsureActiveDnssecKeys: %v", err)
	}
	if st := dnssecKeyState(t, kdb, name, ksk); st != DnskeyStateActive {
		t.Errorf("test premise: the published KSK is %s after a pass, not active", st)
	}
}

// A SIG(0) bootstrap of a zone deleted after it found no key, or after it
// looked up the parent, makes no key and sends nothing. The fake parent's
// UPDATE path is not even set up: an UPDATE would go nowhere.
func TestASig0BootstrapOfADeletedZoneMakesAndSendsNothing(t *testing.T) {
	const name = "bootstrap.example."
	kdb := newTestKeyDB(t)
	zd := testZone(t, name, name+"\t3600\tIN\tSOA\tns."+name+" hostmaster."+name+" 1 7200 1800 604800 7200\n"+
		name+"\t3600\tIN\tNS\tns."+name+"\n")
	zd.KeyDB = kdb
	zd.SetParent("example.")

	// Removed before the key is made: the check under the zone keys lock.
	zd.removed.Store(true)
	resp, err := zd.generateBootstrapSig0Key(dns.ED25519)
	if resp != nil || !errors.Is(err, errNoKeysForRemovedZone) {
		t.Errorf("a bootstrap key for a deleted zone: %+v, %v", resp, err)
	}
	if n := countRows(t, kdb, "Sig0KeyStore", "zonename", name); n != 0 {
		t.Errorf("%d SIG(0) keys made for a deleted zone", n)
	}
	if _, _, err := zd.bootstrapSig0KeyWithParent(context.Background(), dns.ED25519, nil, true); !errors.Is(err, errNoKeysForRemovedZone) {
		t.Errorf("the bootstrap of a deleted zone returned %v, want %v", err, errNoKeysForRemovedZone)
	}

	// For a zone still in Zones the key is made, once, and a second call
	// leaves it as the one to bootstrap.
	zd.removed.Store(false)
	if resp, err := zd.generateBootstrapSig0Key(dns.ED25519); err != nil || resp == nil {
		t.Fatalf("a bootstrap key for a live zone: %+v, %v", resp, err)
	}
	if resp, err := zd.generateBootstrapSig0Key(dns.ED25519); err != nil || resp != nil {
		t.Errorf("a second bootstrap key: %+v, %v", resp, err)
	}
	if n := countRows(t, kdb, "Sig0KeyStore", "zonename", name); n != 1 {
		t.Errorf("%d SIG(0) keys, want 1", n)
	}
}

// countingUpdateResponder is a parent that answers every query with rcode
// and counts the UPDATEs it is sent; during, if set, runs while the
// answer to one waits, in the responder's goroutine.
func countingUpdateResponder(t *testing.T, rcode int, during func()) (addr string, updates *atomic.Int32) {
	t.Helper()
	updates = &atomic.Int32{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	srv := &dns.Server{Listener: ln, Net: "tcp", MsgAcceptFunc: MsgAcceptFunc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			if r.Opcode == dns.OpcodeUpdate {
				updates.Add(1)
				if during != nil {
					during()
				}
			}
			m := new(dns.Msg)
			m.SetReply(r)
			m.SetEdns0(4096, false)
			m.Rcode = rcode
			_ = w.WriteMsg(m)
		})}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	<-started
	return ln.Addr().String(), updates
}

// bootstrapFixture is an API-managed child zone with an active SIG(0) key,
// registered for RemoveDynamicZone to delete, whose parent advertises an
// UPDATE target with at-apex bootstrap at a countingUpdateResponder.
func bootstrapFixture(t *testing.T, during func()) (*Config, *ZoneData, *KeyDB, *atomic.Int32) {
	t.Helper()
	const child, parent = "ceremony.parent.example.", "parent.example."
	kdb := newTestKeyDB(t)
	zd := testZone(t, child, child+"\t3600\tIN\tSOA\tns."+child+" hostmaster."+child+" 1 7200 1800 604800 7200\n"+
		child+"\t3600\tIN\tNS\tns."+child+"\n")
	zd.KeyDB = kdb
	zd.SetParent(parent)
	zd.Options = map[ZoneOption]bool{OptApiManagedZone: true}
	generateSig0Key(t, kdb, child, Sig0StateActive)
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	Zones.Set(child, zd)
	t.Cleanup(func() { Zones.Remove(child) })

	addr, updates := countingUpdateResponder(t, dns.RcodeRefused, during)
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	imr := cacheOnlyImr(t, map[string][]string{"ceremony._dsync." + parent: {"ANY UPDATE " + port + " upd." + parent}},
		map[string]string{"upd." + parent: "127.0.0.1"})
	// The parent advertises at-apex, so the bootstrap gets to its ceremony.
	target := "upd." + parent
	imr.Cache.Set(target, dns.TypeSVCB, &cache.CachedRRset{
		Name: target, RRtype: dns.TypeSVCB,
		RRset:   &core.RRset{Name: target, RRtype: dns.TypeSVCB, RRs: []dns.RR{newBootstrapSVCB(target, "at-apex", 300)}},
		Context: cache.ContextAnswer,
		State:   cache.ValidationStateSecure,
	})
	prev := Globals.ImrEngine
	Globals.ImrEngine = imr
	t.Cleanup(func() { Globals.ImrEngine = prev })
	return conf, zd, kdb, updates
}

// A bootstrap that has its key, and finds the parent's UPDATE target, sends
// no KEY UPDATE for a zone deleted meanwhile: the check made before the
// ceremony goes out. For a zone still in Zones the ceremony does go out:
// one UPDATE reaches the parent, which refuses it.
func TestASig0BootstrapSendsNothingForAZoneDeletedBeforeTheCeremony(t *testing.T) {
	_, zd, _, updates := bootstrapFixture(t, nil)

	zd.removed.Store(true)
	if _, _, err := zd.bootstrapSig0KeyWithParent(context.Background(), dns.ED25519, []string{"at-apex"}, false); !errors.Is(err, errNoKeysForRemovedZone) {
		t.Errorf("the bootstrap of a zone deleted before its ceremony returned %v, want %v", err, errNoKeysForRemovedZone)
	}
	if n := updates.Load(); n != 0 {
		t.Errorf("%d UPDATEs reached the parent for a deleted zone", n)
	}

	zd.removed.Store(false)
	if _, _, err := zd.bootstrapSig0KeyWithParent(context.Background(), dns.ED25519, []string{"at-apex"}, false); err == nil || errors.Is(err, errNoKeysForRemovedZone) {
		t.Errorf("test premise: the bootstrap of a live zone returned %v, want the parent's refusal", err)
	}
	if n := updates.Load(); n != 1 {
		t.Errorf("test premise: %d UPDATEs reached the parent for a live zone, want the ceremony", n)
	}
}

// A zone delete that comes while a bootstrap's ceremony is with the parent,
// after its last check of the zone, is refused: the bootstrap holds the
// zone's SIG(0) claim until the parent answers, as a rollover does, and the
// key the ceremony carries stays. Once the bootstrap is done the delete
// goes through. And a bootstrap that starts during a delete is refused.
func TestAZoneDeleteIsRefusedDuringASig0Bootstrap(t *testing.T) {
	var conf *Config
	var zd *ZoneData
	var kdb *KeyDB
	var delErr error
	var keysDuring int
	conf, zd, kdb, updates := bootstrapFixture(t, func() {
		_, delErr = conf.RemoveDynamicZone(zd.ZoneName, false)
		keysDuring = countRows(t, kdb, "Sig0KeyStore", "zonename", zd.ZoneName)
	})

	if _, _, err := zd.bootstrapSig0KeyWithParent(context.Background(), dns.ED25519, []string{"at-apex"}, false); err == nil {
		t.Error("test premise: the parent refuses the ceremony")
	}
	if n := updates.Load(); n != 1 {
		t.Fatalf("test premise: %d UPDATEs reached the parent, want the ceremony", n)
	}
	if delErr == nil || !strings.Contains(delErr.Error(), "a SIG(0) key bootstrap is in progress; try again when it finishes") {
		t.Errorf("a delete during the ceremony returned %v", delErr)
	}
	if keysDuring != 1 {
		t.Errorf("%d SIG(0) keys while the ceremony was with the parent, want its 1", keysDuring)
	}
	if cur, live := Zones.Get(zd.ZoneName); !live || cur != zd {
		t.Error("a refused delete took the zone out of Zones")
	}

	var bootErr error
	testHookSignalRecordTaken = func() {
		_, _, bootErr = zd.bootstrapSig0KeyWithParent(context.Background(), dns.ED25519, []string{"at-apex"}, false)
	}
	t.Cleanup(func() { testHookSignalRecordTaken = nil })
	if _, err := conf.RemoveDynamicZone(zd.ZoneName, false); err != nil {
		t.Fatalf("the delete after the bootstrap: %v", err)
	}
	if !errors.Is(bootErr, errSig0ZoneBusy) || !strings.Contains(bootErr.Error(), "is being deleted; no bootstrap started") {
		t.Errorf("a bootstrap during the delete returned %v", bootErr)
	}
	if n := updates.Load(); n != 1 {
		t.Errorf("%d UPDATEs reached the parent, want only the first ceremony", n)
	}
	if n := countRows(t, kdb, "Sig0KeyStore", "zonename", zd.ZoneName); n != 0 {
		t.Errorf("%d SIG(0) keys after the delete", n)
	}
}

// A zone whose key lifecycle an owner runs only reads its keys here. An
// old ZoneData of such a zone, deleted and the name re-added after its
// first check, gets none of the new zone's keys, which the lookup by name
// finds: the check after the lookup sees the mark the delete made first.
func TestAnOldOwnedZoneDataGetsNoneOfANewZonesKeys(t *testing.T) {
	const name = "owned.samename.example."
	old, kdb := sameNameZones(t, name, &DnssecPolicy{Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.ED25519, ZSKAlgorithm: dns.ED25519})
	installOwner(t, &testOwner{owns: map[string]bool{name: true}})
	old.Options[OptMultiProvider] = true
	fixtureActivePair(t, kdb, name)

	testHookEnsureKeys = func(stage string) {
		if stage == "lookup" {
			old.removed.Store(true)
		}
	}
	t.Cleanup(func() { testHookEnsureKeys = nil })
	if dak, err := old.EnsureActiveDnssecKeys(kdb, false); !errors.Is(err, errNoKeysForRemovedZone) {
		t.Errorf("an old owned ZoneData got %+v, %v; want %v", dak, err, errNoKeysForRemovedZone)
	}

	// The premise: a ZoneData still in Zones gets the owner's keys.
	testHookEnsureKeys = nil
	old.removed.Store(false)
	if dak, err := old.EnsureActiveDnssecKeys(kdb, false); err != nil || len(dak.KSKs) == 0 || len(dak.ZSKs) == 0 {
		t.Errorf("test premise: an owned zone's keys: %+v, %v", dak, err)
	}
}
