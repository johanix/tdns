/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"log"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func registerAlgZone(t *testing.T, zd *ZoneData) {
	t.Helper()
	Zones.Set(zd.ZoneName, zd)
	t.Cleanup(func() { Zones.Remove(zd.ZoneName) })
}

func activeKeyIDsFromDB(t *testing.T, kdb *KeyDB, zone string) map[uint16]bool {
	t.Helper()
	rows, err := GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
	if err != nil {
		t.Fatalf("GetDnssecKeysByState: %v", err)
	}
	out := map[uint16]bool{}
	for _, k := range rows {
		out[k.KeyTag] = true
	}
	return out
}

func activeKeyIDsFromSnap(dak *DnssecKeys) map[uint16]bool {
	out := map[uint16]bool{}
	if dak == nil {
		return out
	}
	for _, k := range dak.KSKs {
		out[k.KeyId] = true
	}
	for _, k := range dak.ZSKs {
		if k.DnskeyRR.Flags == 256 {
			out[k.KeyId] = true
		}
	}
	return out
}

func assertSnapMatchesDB(t *testing.T, kdb *KeyDB, zd *ZoneData) {
	t.Helper()
	want := activeKeyIDsFromDB(t, kdb, zd.ZoneName)
	got := activeKeyIDsFromSnap(zd.ActiveDnssecKeys())
	if len(want) != len(got) {
		t.Fatalf("snapshot/DB keyid count mismatch: snap=%v db=%v", got, want)
	}
	for id := range want {
		if !got[id] {
			t.Fatalf("snapshot missing keyid %d (db=%v snap=%v)", id, want, got)
		}
	}
	s := zd.SigningKeys()
	if !s.built {
		t.Fatal("expected built=true after successful mutation/republish")
	}
}

// TestSigningKeysSnapshotNoRace hammers concurrent snapshot reads against a
// republishing mutator. Must stay clean under -race.
func TestSigningKeysSnapshotNoRace(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := algTestZone(dns.ED25519, dns.ED25519)
	zd.KeyDB = kdb
	registerAlgZone(t, zd)

	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, dns.ED25519)
	if err := zd.republishSigningKeys(kdb); err != nil {
		t.Fatalf("initial republish: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	var republishErr atomic.Pointer[error]

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				if err := zd.republishSigningKeys(kdb); err != nil {
					e := err
					republishErr.CompareAndSwap(nil, &e)
				}
			}
		}
	}()

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					dak := zd.ActiveDnssecKeys()
					_ = len(dak.KSKs) + len(dak.ZSKs)
					_ = zd.SigningKeys().built
				}
			}
		}()
	}

	time.Sleep(40 * time.Millisecond)
	close(stop)
	wg.Wait()
	if errp := republishErr.Load(); errp != nil {
		t.Fatalf("republishSigningKeys failed during race: %v", *errp)
	}
}

// TestSigningKeysMassResignDoesNotStore asserts SignZone without key mutation
// leaves the signing-keys pointer unchanged.
func TestSigningKeysMassResignDoesNotStore(t *testing.T) {
	kdb := newTestKeyDB(t)
	zoneStr := `zsk-alg.example.		3600	IN	SOA	ns.zsk-alg.example. hostmaster.zsk-alg.example. 1 7200 1800 604800 7200
zsk-alg.example.		3600	IN	NS	ns.zsk-alg.example.
ns.zsk-alg.example.		3600	IN	A	192.0.2.1
`
	zd := &ZoneData{
		ZoneName:  algZone,
		ZoneStore: MapZone,
		Options:   map[ZoneOption]bool{OptOnlineSigning: true},
		DnssecPolicy: &DnssecPolicy{
			Mode:         DnssecPolicyModeKSKZSK,
			KSKAlgorithm: dns.ED25519,
			ZSKAlgorithm: dns.ED25519,
		},
		DnssecPolicyName: "base",
		KeyDB:            kdb,
		Logger:           log.New(os.Stderr, "", 0),
	}
	if _, _, err := zd.ReadZoneData(zoneStr, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	zd.Ready = true
	zd.InstallInitialSnapshot()
	t.Cleanup(zd.stopPublisher)
	registerAlgZone(t, zd)

	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, dns.ED25519)
	if err := zd.republishSigningKeys(kdb); err != nil {
		t.Fatalf("republish: %v", err)
	}
	before := zd.signingKeys.Load()
	if before == nil || !before.built {
		t.Fatal("expected built snapshot before resign")
	}

	_ = zd.ActiveDnssecKeys()
	if zd.signingKeys.Load() != before {
		t.Fatal("ActiveDnssecKeys read republished keys snapshot")
	}

	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	if zd.signingKeys.Load() != before {
		t.Fatal("SignZone without key mutation republished signing-keys snapshot")
	}

	// Explicit republish must install a new pointer.
	genZSK(t, kdb, DnskeyStateStandby, dns.ED25519)
	if err := zd.republishSigningKeys(kdb); err != nil {
		t.Fatalf("republish after standby: %v", err)
	}
	afterMut := zd.signingKeys.Load()
	if afterMut == before {
		t.Fatal("expected new snapshot pointer after explicit republish")
	}
}

func TestSigningKeysFreshnessGenerate(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := algTestZone(dns.ED25519, dns.ED25519)
	zd.KeyDB = kdb
	registerAlgZone(t, zd)

	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, dns.ED25519)
	assertSnapMatchesDB(t, kdb, zd)
}

func TestSigningKeysFreshnessPromote(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := algTestZone(dns.ED25519, dns.ED25519)
	zd.KeyDB = kdb
	registerAlgZone(t, zd)

	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, dns.ED25519)
	pub := genZSK(t, kdb, DnskeyStatePublished, dns.ED25519)
	stampPublishedAt(t, kdb, pub, time.Now().Add(-time.Hour))

	if err := kdb.PromoteDnssecKey(algZone, pub, DnskeyStatePublished, DnskeyStateActive); err != nil {
		t.Fatalf("PromoteDnssecKey: %v", err)
	}
	assertSnapMatchesDB(t, kdb, zd)
}

func TestSigningKeysFreshnessRollover(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := algTestZone(dns.ED25519, dns.ED25519)
	zd.KeyDB = kdb
	registerAlgZone(t, zd)

	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, dns.ED25519)
	sb := genZSK(t, kdb, DnskeyStateStandby, dns.ED25519)
	stampPublishedAt(t, kdb, sb, time.Now().Add(-time.Hour))

	if _, _, err := kdb.RolloverKey(algZone, "ZSK", nil); err != nil {
		t.Fatalf("RolloverKey: %v", err)
	}
	assertSnapMatchesDB(t, kdb, zd)
}

func TestSigningKeysFreshnessForceRoles(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := algTestZone(dns.ED25519, dns.ED25519)
	zd.KeyDB = kdb
	registerAlgZone(t, zd)

	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, dns.ED25519)

	pol := &DnssecPolicy{
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		Algorithm:    dns.ED25519,
	}
	if _, err := kdb.forceZoneKeysToPolicyRoles(zd, pol, false, true); err != nil {
		t.Fatalf("forceZoneKeysToPolicyRoles: %v", err)
	}
	assertSnapMatchesDB(t, kdb, zd)
}

// TestSigningKeysCASLazyVsMutation (M1): concurrent lazy fill must not leave
// a stale pre-mutation snapshot installed after a mutation republish.
func TestSigningKeysCASLazyVsMutation(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := algTestZone(dns.ED25519, dns.ED25519)
	zd.KeyDB = kdb
	registerAlgZone(t, zd)

	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	oldZSK := genZSK(t, kdb, DnskeyStateActive, dns.ED25519)
	if err := zd.republishSigningKeys(kdb); err != nil {
		t.Fatalf("republish: %v", err)
	}
	oldIDs := activeKeyIDsFromSnap(zd.ActiveDnssecKeys())

	// Force unbuilt so the next read takes the lazy CAS path.
	zd.signingKeys.Store(&signingKeysSnapshot{built: false, Active: &DnssecKeys{}})

	casErr := make(chan error, 1)
	go func() {
		_, err := zd.activeKeysCAS(kdb)
		casErr <- err
	}()

	// Mutate active set while lazy fill may be in flight.
	sb := genZSK(t, kdb, DnskeyStateStandby, dns.ED25519)
	stampPublishedAt(t, kdb, sb, time.Now().Add(-time.Hour))
	if _, _, err := kdb.RolloverKey(algZone, "ZSK", nil); err != nil {
		t.Fatalf("RolloverKey: %v", err)
	}
	if err := <-casErr; err != nil {
		t.Fatalf("activeKeysCAS: %v", err)
	}

	assertSnapMatchesDB(t, kdb, zd)
	newIDs := activeKeyIDsFromSnap(zd.ActiveDnssecKeys())
	if newIDs[oldZSK] && len(newIDs) == len(oldIDs) {
		// After rollover the old active ZSK is retired — must not equal old set.
		t.Fatalf("snapshot still looks like pre-mutation set: old=%v new=%v", oldIDs, newIDs)
	}
}

// TestSigningKeysRepublishFailureMarksUnbuilt (M3).
func TestSigningKeysRepublishFailureMarksUnbuilt(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := algTestZone(dns.ED25519, dns.ED25519)
	zd.KeyDB = kdb
	registerAlgZone(t, zd)

	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, dns.ED25519)
	if err := zd.republishSigningKeys(kdb); err != nil {
		t.Fatalf("republish: %v", err)
	}
	if !zd.SigningKeys().built {
		t.Fatal("expected built before failure")
	}

	// Close DB so rebuild fails.
	if err := kdb.DB.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	err := zd.republishSigningKeys(kdb)
	if err == nil {
		t.Fatal("expected republish error after DB close")
	}
	s := zd.SigningKeys()
	if s.built {
		t.Fatal("M3: failed republish must not leave built=true stale snapshot")
	}
	// Must not be the shared sentinel (ABA).
	if s == emptySigningKeys {
		t.Fatal("M3: must not Store the shared emptySigningKeys sentinel")
	}
}

func TestSigningKeysBuiltNegativeCache(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := algTestZone(dns.ED25519, dns.ED25519)
	zd.KeyDB = kdb
	registerAlgZone(t, zd)

	// No keys — build empty with built=true.
	if err := zd.republishSigningKeys(kdb); err != nil {
		t.Fatalf("republish empty: %v", err)
	}
	s := zd.SigningKeys()
	if !s.built {
		t.Fatal("keyless zone must have built=true (negative cache)")
	}
	if len(s.Active.KSKs)+len(s.Active.ZSKs) != 0 {
		t.Fatalf("expected empty active set, got KSK=%d ZSK=%d", len(s.Active.KSKs), len(s.Active.ZSKs))
	}
	// Second CAS must return without replacing (still built).
	dak, err := zd.activeKeysCAS(kdb)
	if err != nil {
		t.Fatalf("activeKeysCAS: %v", err)
	}
	if zd.signingKeys.Load() != s {
		t.Fatal("built keyless snapshot must not be replaced on second read")
	}
	if len(dak.KSKs)+len(dak.ZSKs) != 0 {
		t.Fatal("expected empty from negative-cached snapshot")
	}
}

func TestSigningKeysAccessorNeverNil(t *testing.T) {
	zd := &ZoneData{ZoneName: "nil-snap.example."}
	if zd.SigningKeys() == nil || zd.ActiveDnssecKeys() == nil {
		t.Fatal("accessors must never return nil")
	}
	if zd.SigningKeys().built {
		t.Fatal("fresh ZoneData should report unbuilt")
	}
}

// TestSigningKeysRepublishGenerationGate: an older overlapping republish must
// not overwrite a newer published snapshot (generation check at Store time).
func TestSigningKeysRepublishGenerationGate(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := algTestZone(dns.ED25519, dns.ED25519)
	zd.KeyDB = kdb
	registerAlgZone(t, zd)

	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, dns.ED25519)
	if err := zd.republishSigningKeys(kdb); err != nil {
		t.Fatalf("republish: %v", err)
	}
	newer := zd.signingKeys.Load()
	oldGen := zd.signingKeysGen.Load()

	// A newer republish starts (bumps gen) and publishes.
	if err := zd.republishSigningKeys(kdb); err != nil {
		t.Fatalf("second republish: %v", err)
	}
	latest := zd.signingKeys.Load()
	if latest == newer {
		t.Fatal("expected a new snapshot pointer from second republish")
	}

	// Late finish of the older generation must not Store.
	stale := &signingKeysSnapshot{built: true, Active: &DnssecKeys{}}
	if zd.signingKeysGen.Load() == oldGen {
		zd.signingKeys.Store(stale)
	}
	if zd.signingKeys.Load() != latest {
		t.Fatal("older generation must not overwrite newer snapshot")
	}
}
