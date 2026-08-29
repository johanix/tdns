/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Stage 2 of docs/2026-08-28-secondary-serve-until-expire.md: hold the copy
 * across a restart, record when a primary was last seen alive, and stop
 * answering once SOA EXPIRE has elapsed since then.
 */
package tdns

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

const s2Zone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 7 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.3
`

// persistentConf is a config that persists API-managed secondaries into a
// temp directory, which is what ShouldPersistZone (and therefore the path
// derivation) requires.
func persistentConf(t *testing.T, kdb *KeyDB) (*Config, string) {
	t.Helper()
	// tdns-auth, because that is the only app type the expire guard applies to
	// -- and because the app type also decides whether publishing bumps the
	// serial. zoneMayOriginateContent is true for every app type other than
	// tdns-auth, so a fixture left on the zero value would publish its
	// secondary with a bumped outbound serial, which a mirroring secondary
	// must never do. The stamp is matched against the serial in the file, so
	// getting that wrong makes every restore look like a mismatch.
	authApp(t)
	dir := t.TempDir()
	conf := &Config{}
	conf.DynamicZones.ZoneDirectory = dir
	conf.DynamicZones.Dynamic.Storage = "persistent"
	conf.DynamicZones.Dynamic.Allowed = []string{"secondary"}
	conf.Internal.KeyDB = kdb
	return conf, dir
}

// persistedSecondary is an API-managed secondary as it looks at first bind
// after a restart: a copy on disk, nothing published yet, and -- the detail
// that matters -- an empty Zonefile field, because WriteDynamicZoneFile
// derives the path and never writes it back.
func persistedSecondary(t *testing.T, kdb *KeyDB, dir string, upstream string) *ZoneData {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "example.zone"), []byte(s2Zone), 0644); err != nil {
		t.Fatalf("write zone file: %v", err)
	}
	zd := &ZoneData{
		ZoneName:  "example.",
		ZoneStore: MapZone,
		ZoneType:  Secondary,
		Logger:    discardLogger(),
		KeyDB:     kdb,
		Options:   map[ZoneOption]bool{OptApiManagedZone: true},
		Upstreams: []PeerConf{{Addr: upstream}},
	}
	registerZones(t, zd)
	t.Cleanup(zd.stopPublisher)
	return zd
}

// ---------------------------------------------------------------- the stamp

// TestStampAdvancesOnUsableSOA is the core of §3(b): both usable-SOA outcomes
// are confirmations, including the one that transfers nothing. An unchanged
// serial IS the proof the primary is alive.
func TestStampAdvancesOnUsableSOA(t *testing.T) {
	for _, tc := range []struct {
		what         string
		ourSerial    uint32
		theirSerial  uint32
		wantTransfer bool
	}{
		{"serial unchanged", 7, 7, false},
		{"serial increased", 7, 8, true},
	} {
		t.Run(tc.what, func(t *testing.T) {
			kdb := newTestKeyDB(t)
			addr, stop := startTestSOAServer(t, "example.", tc.theirSerial, dns.RcodeSuccess)
			defer stop()

			zd := &ZoneData{
				ZoneName: "example.", Logger: discardLogger(), KeyDB: kdb,
				IncomingSerial: tc.ourSerial,
				Upstreams:      []PeerConf{{Addr: addr}},
			}
			xfr, _, err := zd.DoTransfer(context.Background(), &Config{})
			if err != nil {
				t.Fatalf("DoTransfer: %v", err)
			}
			if xfr != tc.wantTransfer {
				t.Errorf("transfer=%v, want %v", xfr, tc.wantTransfer)
			}
			if zd.LatestRefresh.IsZero() {
				t.Error("LatestRefresh not set by a usable SOA")
			}
			st, ok, err := kdb.GetZoneRefreshState("example.")
			if err != nil || !ok {
				t.Fatalf("no confirmation persisted: ok=%v err=%v", ok, err)
			}
			if st.Serial != tc.ourSerial {
				t.Errorf("stamp serial %d, want %d (the copy we hold, not the primary's)",
					st.Serial, tc.ourSerial)
			}
		})
	}
}

// TestStampDoesNotAdvanceWithoutAUsableSOA is the failure the whole design
// turns on. DoTransfer returns (false, 0, nil) for quiet backoff -- every
// primary answered, none usably -- which Refresh collapses to (false, nil),
// the same pair as "serial unchanged". A secondary whose primaries revoked its
// ACL must expire, not refresh its own clock forever.
func TestStampDoesNotAdvanceWithoutAUsableSOA(t *testing.T) {
	for _, tc := range []struct {
		what    string
		addr    func(t *testing.T) string
		wantErr bool
	}{
		{
			what: "all primaries REFUSED (quiet backoff, err == nil)",
			addr: func(t *testing.T) string {
				a, stop := startTestSOAServer(t, "example.", 7, dns.RcodeRefused)
				t.Cleanup(stop)
				return a
			},
		},
		{
			what:    "no primary reachable",
			addr:    func(t *testing.T) string { return "127.0.0.1:1" },
			wantErr: true,
		},
	} {
		t.Run(tc.what, func(t *testing.T) {
			kdb := newTestKeyDB(t)
			zd := &ZoneData{
				ZoneName: "example.", Logger: discardLogger(), KeyDB: kdb,
				IncomingSerial: 7,
				Upstreams:      []PeerConf{{Addr: tc.addr(t)}},
			}
			_, _, err := zd.DoTransfer(context.Background(), &Config{})
			if tc.wantErr != (err != nil) {
				t.Fatalf("err=%v, wantErr=%v", err, tc.wantErr)
			}
			if !zd.LatestRefresh.IsZero() {
				t.Error("LatestRefresh advanced without a usable SOA")
			}
			if _, ok, _ := kdb.GetZoneRefreshState("example."); ok {
				t.Error("a confirmation was persisted without a usable SOA; " +
					"a secondary whose primaries all REFUSE would never expire")
			}
		})
	}
}

// TestSetZoneFileStateDoesNotClobberTheStamp is the trap that put this in its
// own table: SetZoneFileState writes INSERT OR REPLACE naming every column, so
// a stamp parked on ZoneFileState would be reset by the next file-identity
// record -- an expire clock that keeps forgetting.
func TestSetZoneFileStateDoesNotClobberTheStamp(t *testing.T) {
	kdb := newTestKeyDB(t)
	when := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	if err := kdb.SetZoneRefreshState("example.", 7, when); err != nil {
		t.Fatalf("SetZoneRefreshState: %v", err)
	}
	if err := kdb.SetZoneFileState("example.", 7, "deadbeef"); err != nil {
		t.Fatalf("SetZoneFileState: %v", err)
	}
	st, ok, err := kdb.GetZoneRefreshState("example.")
	if err != nil || !ok {
		t.Fatalf("stamp gone after recording file state: ok=%v err=%v", ok, err)
	}
	if !st.LastConfirmed.Equal(when) {
		t.Errorf("LastConfirmed = %v, want %v", st.LastConfirmed, when)
	}
}

// TestZoneRefreshStateSurvivesReopen covers the migration claim in §4: a new
// table needs no dbMigrateSchema entry, because dbSetupTables runs
// CREATE TABLE IF NOT EXISTS over DefaultTables at every open. Dropping the
// table and reopening stands in for a database written by an older tdns.
func TestZoneRefreshStateSurvivesReopen(t *testing.T) {
	f := filepath.Join(t.TempDir(), "test.db")
	if err := os.WriteFile(f, nil, 0664); err != nil {
		t.Fatalf("create db file: %v", err)
	}
	kdb, err := NewKeyDB(f, false, nil)
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	if _, err := kdb.DB.Exec(`DROP TABLE ZoneRefreshState`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if err := kdb.SetZoneRefreshState("example.", 7, time.Now()); err == nil {
		t.Fatal("precondition: writing to the dropped table should fail")
	}

	reopened, err := NewKeyDB(f, false, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := reopened.SetZoneRefreshState("example.", 7, time.Now()); err != nil {
		t.Errorf("table not recreated on reopen: %v", err)
	}
}

// TestDeletingAZoneDropsItsStamp: a stamp that outlives its zone is inherited
// by the next zone created under the same name, and an already-past-expire one
// would take that zone dark from first bind.
func TestDeletingAZoneDropsItsStamp(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf, dir := persistentConf(t, kdb)
	conf.DynamicZones.ConfigFile = filepath.Join(dir, "dynamic.yaml")
	if err := os.WriteFile(conf.DynamicZones.ConfigFile, []byte("zones:\n"), 0644); err != nil {
		t.Fatalf("write dynamic config: %v", err)
	}

	zd := &ZoneData{
		ZoneName: "example.", ZoneStore: MapZone, ZoneType: Secondary,
		Logger: discardLogger(), KeyDB: kdb,
		Options: map[ZoneOption]bool{OptApiManagedZone: true},
	}
	Zones.Set("example.", zd)
	t.Cleanup(func() { Zones.Remove("example.") })

	if err := kdb.SetZoneRefreshState("example.", 7, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("SetZoneRefreshState: %v", err)
	}
	if _, err := conf.RemoveDynamicZone("example."); err != nil {
		t.Fatalf("RemoveDynamicZone: %v", err)
	}
	if _, ok, _ := kdb.GetZoneRefreshState("example."); ok {
		t.Error("the deleted zone's confirmation stamp is still on record; " +
			"a zone re-created under this name would inherit it")
	}
}

// ------------------------------------------------------- first-bind adoption

// TestFirstBindServesThePersistedCopyWhenThePrimaryIsDown is the headline case
// for the whole project: restart with an unreachable primary must serve the
// copy already on disk, not nothing.
func TestFirstBindServesThePersistedCopyWhenThePrimaryIsDown(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf, dir := persistentConf(t, kdb)
	zd := persistedSecondary(t, kdb, dir, "127.0.0.1:1") // nothing listening

	if zd.publishedSnapshot() != nil {
		t.Fatal("precondition: nothing published yet")
	}

	// The transfer fails, and that is reported. The point is what the zone
	// holds afterwards.
	if _, err := zd.Refresh(context.Background(), false, false, false, conf); err == nil {
		t.Fatal("expected the transfer against a dead primary to fail")
	}

	if zd.publishedSnapshot() == nil {
		t.Fatal("no published snapshot: the persisted copy was not adopted, " +
			"so a restart with the primary down still serves nothing")
	}
	if zd.Zonefile == "" {
		t.Error("Zonefile still empty: the derived path was not assigned, so " +
			"FetchFromFile would have stat'd \"\"")
	}
	if zd.IncomingSerial != 7 {
		t.Errorf("IncomingSerial = %d, want 7 from the adopted copy (this is the "+
			"base serial an inbound IXFR would ask from)", zd.IncomingSerial)
	}
	owner, err := zd.GetOwner("www.example.")
	if err != nil || owner == nil {
		t.Fatalf("adopted copy does not contain www.example.: %v", err)
	}
}

// TestFirstBindWithNoPersistedCopyIsNotAnError: a zone added through the API in
// this process has not written a file yet. Nothing to adopt, and no complaint.
func TestFirstBindWithNoPersistedCopyIsNotAnError(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf, _ := persistentConf(t, kdb)
	zd := &ZoneData{
		ZoneName: "example.", ZoneStore: MapZone, ZoneType: Secondary,
		Logger: discardLogger(), KeyDB: kdb,
		Options:   map[ZoneOption]bool{OptApiManagedZone: true},
		Upstreams: []PeerConf{{Addr: "127.0.0.1:1"}},
	}
	registerZones(t, zd)

	if _, err := zd.Refresh(context.Background(), false, false, false, conf); err == nil {
		t.Fatal("expected the transfer to fail")
	}
	if zd.publishedSnapshot() != nil {
		t.Error("published something with no copy on disk and no transfer")
	}
}

// TestLaterFailedRefreshDoesNotReloadFromFile: the file may be older than
// memory, so adoption is first-bind only.
func TestLaterFailedRefreshDoesNotReloadFromFile(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf, dir := persistentConf(t, kdb)
	zd := persistedSecondary(t, kdb, dir, "127.0.0.1:1")

	if _, err := zd.Refresh(context.Background(), false, false, false, conf); err == nil {
		t.Fatal("expected the transfer to fail")
	}
	first := zd.publishedSnapshot()
	if first == nil {
		t.Fatal("precondition: the copy should have been adopted")
	}

	// Replace the file with different content. A second failed refresh must
	// not pick it up.
	newer := s2Zone + "later.example.\t3600\tIN\tA\t10.0.0.9\n"
	if err := os.WriteFile(filepath.Join(dir, "example.zone"), []byte(newer), 0644); err != nil {
		t.Fatalf("rewrite zone file: %v", err)
	}
	if _, err := zd.Refresh(context.Background(), false, false, false, conf); err == nil {
		t.Fatal("expected the second transfer to fail too")
	}
	if owner, _ := zd.GetOwner("later.example."); owner != nil {
		t.Error("a later failed refresh reloaded the zone from disk; the file " +
			"can be older than what is in memory")
	}
}

// ------------------------------------------------------------ stamp restore

func TestRestoreAtFirstBind(t *testing.T) {
	hourAgo := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)

	t.Run("a stamp for the loaded copy is restored", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		conf, dir := persistentConf(t, kdb)
		if err := kdb.SetZoneRefreshState("example.", 7, hourAgo); err != nil {
			t.Fatalf("seed: %v", err)
		}
		zd := persistedSecondary(t, kdb, dir, "127.0.0.1:1")
		_, _ = zd.Refresh(context.Background(), false, false, false, conf)

		if !zd.LatestRefresh.Equal(hourAgo) {
			t.Errorf("LatestRefresh = %v, want the recorded %v: the zone lost the "+
				"expire budget it had already used", zd.LatestRefresh, hourAgo)
		}
	})

	t.Run("a stamp for a different serial is discarded", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		conf, dir := persistentConf(t, kdb)
		if err := kdb.SetZoneRefreshState("example.", 999, hourAgo); err != nil {
			t.Fatalf("seed: %v", err)
		}
		zd := persistedSecondary(t, kdb, dir, "127.0.0.1:1")
		_, _ = zd.Refresh(context.Background(), false, false, false, conf)

		if zd.LatestRefresh.Equal(hourAgo) {
			t.Error("a stamp recorded for another serial was applied to this copy")
		}
		if zd.LatestRefresh.IsZero() {
			t.Error("no fallback clock started; the zone would never expire")
		}
	})

	t.Run("no record starts the clock at load", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		conf, dir := persistentConf(t, kdb)
		zd := persistedSecondary(t, kdb, dir, "127.0.0.1:1")
		before := time.Now()
		_, _ = zd.Refresh(context.Background(), false, false, false, conf)

		if zd.LatestRefresh.Before(before) {
			t.Errorf("LatestRefresh = %v, want >= %v: with no record the budget "+
				"restarts from load time", zd.LatestRefresh, before)
		}
	})
}

// ------------------------------------------------------------ expire guard

// expiredZone is a served secondary whose last confirmation is older than its
// SOA EXPIRE (604800 in s2Zone).
func expiredZone(t *testing.T) *ZoneData {
	t.Helper()
	zd := testSnapshotZone(t, "example.", s2Zone)
	zd.ZoneType = Secondary
	zd.LatestRefresh = time.Now().Add(-8 * 24 * time.Hour)
	return zd
}

func TestExpiredSecondaryStopsAnswering(t *testing.T) {
	authApp(t)
	zd := expiredZone(t)
	registerZones(t, zd)

	if !zd.HasExpired() {
		t.Fatal("precondition: the zone should be past SOA EXPIRE")
	}
	for _, tc := range []struct{ what, qname string }{
		{"apex through Zones.Get", "example."},
		{"sub-apex through FindZone", "www.example."},
	} {
		if got := ask(t, tc.qname, dns.TypeA); got.Rcode != dns.RcodeServerFailure {
			t.Errorf("%s: rcode %s, want SERVFAIL", tc.what, dns.RcodeToString[got.Rcode])
		}
	}

	r := new(dns.Msg)
	r.SetUpdate("example.")
	msgo, _ := edns0.ExtractFlagsAndEDNS0Options(r)
	rw := &fakeRW{remote: udpAddr("127.0.0.1")}
	if err := UpdateResponder(&DnsUpdateRequest{
		ResponseWriter: rw, Msg: r, Qname: "example.", Options: msgo, Status: &UpdateStatus{},
	}, nil); err != nil {
		t.Fatalf("UpdateResponder: %v", err)
	}
	if rw.written.Rcode != dns.RcodeServerFailure {
		t.Errorf("UPDATE: rcode %s, want SERVFAIL for an expired zone",
			dns.RcodeToString[rw.written.Rcode])
	}
}

// TestAUsableSOAUnexpires: expire is not a service-impacting error precisely so
// the ticker keeps trying, and the next confirmation brings the zone back with
// no further machinery.
func TestAUsableSOAUnexpires(t *testing.T) {
	authApp(t)
	kdb := newTestKeyDB(t)
	zd := expiredZone(t)
	zd.KeyDB = kdb
	zd.IncomingSerial = 7
	registerZones(t, zd)

	if zd.HasServiceImpactingError() {
		t.Fatal("expire must not be a service-impacting error: the refresh " +
			"ticker skips those zones, so the zone could never come back")
	}
	if got := ask(t, "www.example.", dns.TypeA); got.Rcode != dns.RcodeServerFailure {
		t.Fatalf("precondition: expired zone should SERVFAIL, got %s",
			dns.RcodeToString[got.Rcode])
	}

	addr, stop := startTestSOAServer(t, "example.", 7, dns.RcodeSuccess)
	defer stop()
	zd.Upstreams = []PeerConf{{Addr: addr}}
	if _, _, err := zd.DoTransfer(context.Background(), &Config{}); err != nil {
		t.Fatalf("DoTransfer: %v", err)
	}

	if zd.HasExpired() {
		t.Error("still expired after a usable SOA")
	}
	if got := ask(t, "www.example.", dns.TypeA); got.Rcode != dns.RcodeSuccess {
		t.Errorf("after re-confirmation: rcode %s, want NOERROR",
			dns.RcodeToString[got.Rcode])
	}
}

func TestExpireGuardScope(t *testing.T) {
	t.Run("primaries never expire", func(t *testing.T) {
		authApp(t)
		zd := expiredZone(t)
		zd.ZoneType = Primary
		if zd.HasExpired() {
			t.Error("a primary expired; it originates its data and has nothing " +
				"to expire against")
		}
	})

	t.Run("non-auth apps never expire", func(t *testing.T) {
		authApp(t)
		Globals.App.Type = AppTypeAgent
		zd := expiredZone(t)
		if zd.HasExpired() {
			t.Error("expire applied outside tdns-auth")
		}
	})

	t.Run("a zone with no confirmation on record does not expire", func(t *testing.T) {
		authApp(t)
		zd := expiredZone(t)
		zd.LatestRefresh = time.Time{}
		if zd.HasExpired() {
			t.Error("expired on a zero timestamp; the permissive direction is " +
				"the safe one here")
		}
	})
}

// TestExpireIsClampedToRefreshPlusRetry: nothing stops a primary publishing an
// EXPIRE of 0, or one below its own REFRESH. Taken literally either takes the
// zone dark on a schedule set by someone else's data.
func TestExpireIsClampedToRefreshPlusRetry(t *testing.T) {
	authApp(t)
	for _, tc := range []struct {
		what   string
		expire uint32
	}{
		{"zero", 0},
		{"below refresh+retry", 60},
	} {
		t.Run(tc.what, func(t *testing.T) {
			zone := fmt.Sprintf(`example.	3600	IN	SOA	ns.example. hostmaster.example. 7 7200 1800 %d 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	10.0.0.3
`, tc.expire)
			zd := testSnapshotZone(t, "example.", zone)
			zd.ZoneType = Secondary

			// Inside the clamp (refresh 7200 + retry 1800 = 9000s): still serving.
			zd.LatestRefresh = time.Now().Add(-time.Hour)
			if zd.HasExpired() {
				t.Errorf("expired after 1h with a published EXPIRE of %d; the "+
					"clamp should hold it to refresh+retry", tc.expire)
			}
			// Past the clamp: expired, so clamping is not "never expire".
			zd.LatestRefresh = time.Now().Add(-4 * time.Hour)
			if !zd.HasExpired() {
				t.Errorf("not expired after 4h, past the refresh+retry clamp")
			}
		})
	}
}

// TestRestoreIgnoresTheRecordedFileIdentity documents a deliberate gap rather
// than a behaviour worth having.
//
// The brief wants the confirmation checked against the recorded ZONEMD identity
// as well as the serial, to catch a file regenerated or restored reusing its
// serial. That check is not made, because the identity is not maintained on
// this path: WriteDynamicZoneFile, which is what the refresh engine calls for a
// persistable dynamic zone, does not record what it writes. Consulting a stale
// record would reject a good confirmation on every restart after a
// content-changing transfer.
//
// So: a stale, mismatched file identity does NOT stop the stamp being restored,
// and this test exists to fail loudly if WriteDynamicZoneFile ever starts
// recording -- at which point the digest check should come back.
func TestRestoreIgnoresTheRecordedFileIdentity(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf, dir := persistentConf(t, kdb)
	hourAgo := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)

	if err := kdb.SetZoneRefreshState("example.", 7, hourAgo); err != nil {
		t.Fatalf("seed stamp: %v", err)
	}
	// A recorded identity that does not describe the file on disk.
	if err := kdb.SetZoneFileState("example.", 7, "00000000000000000000000000000000"); err != nil {
		t.Fatalf("seed file state: %v", err)
	}

	zd := persistedSecondary(t, kdb, dir, "127.0.0.1:1")
	_, _ = zd.Refresh(context.Background(), false, false, false, conf)

	if zd.publishedSnapshot() == nil {
		t.Fatal("precondition: the copy should be adopted")
	}
	if !zd.LatestRefresh.Equal(hourAgo) {
		t.Errorf("LatestRefresh = %v, want the recorded %v. If this now fails "+
			"because the identity was consulted, WriteDynamicZoneFile has "+
			"presumably started recording -- restore the digest check in "+
			"restoreRefreshStateAtFirstBind.", zd.LatestRefresh, hourAgo)
	}
}

// TestFirstBindCompletesEvenWhenTheTransferFails drives the refresh engine
// itself, because that is where the failure mode lives: initialLoadZone
// returns early on a failed refresh, so before this work the engine would
// `continue` past completeFirstZonePolicyAndLoad. A zone that adopted its
// persisted copy has data and a spent FirstZoneLoad, so falling through would
// hand it to the EXISTING ZONE branch forever -- serving, but never policy-
// bound, never drained, never replayed.
func TestFirstBindCompletesEvenWhenTheTransferFails(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf, dir := persistentConf(t, kdb)
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 1)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)
	if err := os.WriteFile(filepath.Join(dir, "example.zone"), []byte(s2Zone), 0644); err != nil {
		t.Fatalf("write zone file: %v", err)
	}
	t.Cleanup(func() { Zones.Remove("example.") })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); RefreshEngine(ctx, conf) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("RefreshEngine did not shut down")
		}
	})

	conf.Internal.RefreshZoneCh <- ZoneRefresher{
		Name:         "example.",
		ZoneType:     Secondary,
		ZoneStore:    MapZone,
		Primaries:    []PeerConf{{Addr: "127.0.0.1:1"}}, // nothing listening
		ConfigUpdate: true,
		Options:      map[ZoneOption]bool{OptApiManagedZone: true},
	}

	deadline := time.Now().Add(5 * time.Second)
	var zd *ZoneData
	for time.Now().Before(deadline) {
		if z, ok := Zones.Get("example."); ok && z.publishedSnapshot() != nil {
			zd = z
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if zd == nil {
		t.Fatal("the zone never came to hold data: a restart with the primary " +
			"down still serves nothing")
	}
	if !zd.HasError(RefreshError) {
		t.Error("expected RefreshError to be recorded for the failed transfer")
	}
	if zd.FirstZoneLoad {
		t.Error("FirstZoneLoad still set after the copy was adopted")
	}

	// Ready is the discriminator, and it has to be: FirstZoneLoad is cleared
	// by the adoption itself, and hasPendingOnFirstLoad is vacuously false for
	// a fixture that registered no callbacks -- neither would notice the
	// completion being skipped. InstallInitialSnapshot, the first thing
	// completeFirstZonePolicyAndLoad does, is what flips Ready on an
	// already-published zone, so this fails if the call goes away.
	if !zd.Ready {
		t.Error("zone is not Ready: the first-bind completion did not run for the " +
			"adopted copy, so it would serve without ever being policy-bound, " +
			"replayed or drained -- for the life of the process")
	}
	if got := zd.GetStatus(); got != ZoneStatusReady {
		t.Errorf("status %v, want ZoneStatusReady", got)
	}

	// And the ticker got the zone's own refresh interval rather than the
	// caller's 300s "no counter yet" fallback.
	if refresh, err := FindSoaRefresh(zd); err != nil {
		t.Errorf("FindSoaRefresh on the adopted copy: %v", err)
	} else if refresh == 0 {
		t.Error("no SOA refresh derivable from the adopted copy")
	}
}

// startTestPrimary serves one zone as a real primary would: SOA over UDP,
// which is what DoTransfer's probe uses, and AXFR over TCP, which is what
// ZoneTransferIn uses -- both on the same address, which is the reason this
// exists. The two harnesses already in the tree do one or the other, so
// nothing could previously drive a secondary through probe-then-transfer.
//
// The served ZoneData is deliberately NOT registered in the global Zones map:
// the secondary under test carries the same name, and registering both would
// have one shadow the other.
func startTestPrimary(t *testing.T, zoneStr string) (string, func()) {
	t.Helper()
	pzd := &ZoneData{
		ZoneName:  "example.",
		ZoneStore: MapZone,
		ZoneType:  Primary,
		Logger:    discardLogger(),
		Ready:     true,
		Status:    ZoneStatusReady,
		// Without a downstream ACL every transfer-out is REFUSED, which is
		// the correct default and not what this fixture is testing.
		Downstreams: []AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY}},
	}
	if _, _, err := pzd.ReadZoneData(zoneStr, true); err != nil {
		t.Fatalf("primary ReadZoneData: %v", err)
	}
	pzd.InstallInitialSnapshot()
	t.Cleanup(pzd.stopPublisher)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		ln.Close()
		t.Fatalf("listen udp on the tcp port: %v", err)
	}

	srvCtx, srvCancel := context.WithCancel(context.Background())
	mux := dns.NewServeMux()
	mux.HandleFunc("example.", func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 1 {
			switch r.Question[0].Qtype {
			case dns.TypeAXFR, dns.TypeIXFR:
				_, _ = pzd.ZoneTransferOut(srvCtx, w, r, nil)
				return
			}
		}
		m := new(dns.Msg)
		m.SetReply(r)
		if soa, err := pzd.GetSOA(); err == nil && soa != nil {
			m.Answer = append(m.Answer, soa)
		}
		_ = w.WriteMsg(m)
	})

	var started sync.WaitGroup
	started.Add(2)
	tcpSrv := &dns.Server{Listener: ln, Handler: mux, MsgAcceptFunc: MsgAcceptFunc,
		NotifyStartedFunc: started.Done}
	udpSrv := &dns.Server{PacketConn: pc, Handler: mux, NotifyStartedFunc: started.Done}
	go func() { _ = tcpSrv.ActivateAndServe() }()
	go func() { _ = udpSrv.ActivateAndServe() }()

	done := make(chan struct{})
	go func() { started.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("test primary did not start")
	}

	return ln.Addr().String(), func() {
		srvCancel()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = tcpSrv.ShutdownContext(ctx)
		_ = udpSrv.ShutdownContext(ctx)
	}
}

// TestFirstBindTransferReplacesTheAdoptedCopy is the §7 case the first cut of
// this PR could not reach, and it carries the regression test for the stamp
// serial with it.
//
// The zone adopts serial 7 off disk, then transfers serial 8. Two things must
// be true afterwards, and the second is the one that was wrong: the zone must
// serve the transferred copy, and the persisted confirmation must describe
// THAT copy. DoTransfer stamps the serial held at probe time -- correct when
// the transfer then fails -- so without re-stamping after FetchFromUpstream
// the row says 7 while the zone says 8, and the identity check at the next
// first bind throws away a confirmation we genuinely have.
func TestFirstBindTransferReplacesTheAdoptedCopy(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf, dir := persistentConf(t, kdb)

	newer := `example.	3600	IN	SOA	ns.example. hostmaster.example. 8 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.3
fresh.example.	3600	IN	A	10.0.0.8
`
	addr, stop := startTestPrimary(t, newer)
	defer stop()

	// A confirmation for the copy on disk, from an hour ago.
	hourAgo := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	if err := kdb.SetZoneRefreshState("example.", 7, hourAgo); err != nil {
		t.Fatalf("seed stamp: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "example.zone"), []byte(s2Zone), 0644); err != nil {
		t.Fatalf("write zone file: %v", err)
	}
	zd := &ZoneData{
		ZoneName: "example.", ZoneStore: MapZone, ZoneType: Secondary,
		Logger: discardLogger(), KeyDB: kdb,
		Options:   map[ZoneOption]bool{OptApiManagedZone: true},
		Upstreams: []PeerConf{{Addr: addr}},
	}
	// Registered because publishWorkingSetLocked drops a publish for a zone
	// that is not live in the Zones map. The primary fixture is deliberately
	// NOT registered, so there is no collision on the shared name.
	registerZones(t, zd)
	t.Cleanup(zd.stopPublisher)

	if _, err := zd.Refresh(context.Background(), false, false, false, conf); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// The transferred copy is what is served, so adoption did not get in the
	// way of the transfer that follows it.
	if zd.IncomingSerial != 8 {
		t.Errorf("IncomingSerial = %d, want 8 from the transfer", zd.IncomingSerial)
	}
	if owner, _ := zd.GetOwner("fresh.example."); owner == nil {
		t.Error("the transferred copy is not being served; the adopted file copy " +
			"should have been replaced")
	}

	// And the stamp describes the copy we now hold.
	st, ok, err := kdb.GetZoneRefreshState("example.")
	if err != nil || !ok {
		t.Fatalf("no confirmation persisted: ok=%v err=%v", ok, err)
	}
	if st.Serial != 8 {
		t.Errorf("stamp serial = %d, want 8: it describes the copy that was "+
			"transferred, not the one held when the SOA was probed. At the next "+
			"first bind the identity check would discard this confirmation and "+
			"restart a full expire budget from load time.", st.Serial)
	}
	if !st.LastConfirmed.After(hourAgo) {
		t.Errorf("LastConfirmed = %v, want a fresh stamp, not the seeded %v",
			st.LastConfirmed, hourAgo)
	}
}

// TestRestartAfterATransferPreservesTheBudget is the §7 line "restart with a
// persisted timestamp preserves the remaining expire budget", exercised across
// the case that used to lose it: the last confirmation came with a transfer
// rather than an unchanged serial.
func TestRestartAfterATransferPreservesTheBudget(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf, dir := persistentConf(t, kdb)

	// Process 1: transfer serial 8, then write the copy to disk as the
	// refresh engine would.
	newer := `example.	3600	IN	SOA	ns.example. hostmaster.example. 8 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
ns.example.	3600	IN	A	10.0.0.1
www.example.	3600	IN	A	10.0.0.3
`
	addr, stop := startTestPrimary(t, newer)
	if err := os.WriteFile(filepath.Join(dir, "example.zone"), []byte(s2Zone), 0644); err != nil {
		t.Fatalf("write zone file: %v", err)
	}
	first := &ZoneData{
		ZoneName: "example.", ZoneStore: MapZone, ZoneType: Secondary,
		Logger: discardLogger(), KeyDB: kdb,
		Options:   map[ZoneOption]bool{OptApiManagedZone: true},
		Upstreams: []PeerConf{{Addr: addr}},
	}
	Zones.Set("example.", first)
	t.Cleanup(func() { Zones.Remove("example.") })
	if _, err := first.Refresh(context.Background(), false, false, false, conf); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	if _, err := first.WriteDynamicZoneFile(dir); err != nil {
		t.Fatalf("persist the transferred copy: %v", err)
	}
	confirmed := first.LatestRefresh
	first.stopPublisher()
	stop()

	// Process 2: same database and directory, primary now unreachable.
	second := &ZoneData{
		ZoneName: "example.", ZoneStore: MapZone, ZoneType: Secondary,
		Logger: discardLogger(), KeyDB: kdb,
		Options:   map[ZoneOption]bool{OptApiManagedZone: true},
		Upstreams: []PeerConf{{Addr: "127.0.0.1:1"}},
	}
	Zones.Set("example.", second) // the restarted process's ZoneData
	t.Cleanup(second.stopPublisher)
	_, _ = second.Refresh(context.Background(), false, false, false, conf)

	if second.publishedSnapshot() == nil {
		t.Fatal("the persisted copy was not adopted")
	}
	if !second.LatestRefresh.Equal(confirmed) {
		t.Errorf("LatestRefresh = %v, want the confirmation carried over from "+
			"before the restart (%v). Losing it restarts the whole expire "+
			"budget, so a zone six days into a seven-day EXPIRE serves another "+
			"seven.", second.LatestRefresh, confirmed)
	}
}
