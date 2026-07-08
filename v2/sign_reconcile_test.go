package tdns

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

// testZone parses a small zone from a string into a Ready MapZone ZoneData.
func testZone(t *testing.T, name, zoneStr string) *ZoneData {
	t.Helper()
	zd := &ZoneData{
		ZoneName:  name,
		ZoneStore: MapZone,
		Logger:    log.New(os.Stderr, "", 0),
	}
	if _, _, err := zd.ReadZoneData(zoneStr, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	zd.Ready = true
	// Publish the initial snapshot so post-B3 readers (GetOwner etc.) see the
	// data, mirroring the refresh engine (and testSnapshotZone/newMapZone).
	zd.InstallInitialSnapshot()
	t.Cleanup(zd.stopPublisher)
	return zd
}

func TestStripZoneRRSIGs(t *testing.T) {
	zone := `example.		3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.		3600	IN	NS	ns.example.
www.example.		3600	IN	A	192.0.2.1
`
	zd := testZone(t, "example.", zone)
	// Register the zone so StripZoneRRSIGs' publishLocked is not dropped by the
	// zoneStillLive (registry + generation) guard — in production the zone is
	// always registered.
	registerZones(t, zd)

	// Attach two RRSIGs (keytags 1111 and 2222) to the www A RRset via the live
	// store, then re-publish so the snapshot carries them. Post-B3, GetOwner
	// returns the immutable snapshot, so it must not be mutated in place.
	od, ok := zd.Data.Get("www.example.")
	if !ok {
		t.Fatal("www owner missing from zd.Data")
	}
	rrset := od.RRtypes.GetOnlyRRSet(dns.TypeA)
	mkSig := func(keytag uint16) *dns.RRSIG {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			TypeCovered: dns.TypeA,
			KeyTag:      keytag,
			SignerName:  "example.",
		}
	}
	rrset.RRSIGs = []dns.RR{mkSig(1111), mkSig(2222)}
	od.RRtypes.Set(dns.TypeA, rrset)
	zd.InstallInitialSnapshot()

	// Strip only keytag 1111.
	removed, err := zd.StripZoneRRSIGs(context.Background(), func(s *dns.RRSIG) bool { return s.KeyTag == 1111 })
	if err != nil {
		t.Fatalf("StripZoneRRSIGs: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}

	got := zd.mustRRSIGKeytags(t, "www.example.", dns.TypeA)
	if len(got) != 1 || got[0] != 2222 {
		t.Fatalf("surviving keytags = %v, want [2222]", got)
	}
}

// mustRRSIGKeytags returns the keytags of the RRSIGs on (name, rrtype).
func (zd *ZoneData) mustRRSIGKeytags(t *testing.T, name string, rrtype uint16) []uint16 {
	t.Helper()
	owner, err := zd.GetOwner(name)
	if err != nil || owner == nil {
		t.Fatalf("GetOwner %s: owner=%v err=%v", name, owner, err)
	}
	rrset := owner.RRtypes.GetOnlyRRSet(rrtype)
	var tags []uint16
	for _, s := range rrset.RRSIGs {
		tags = append(tags, s.(*dns.RRSIG).KeyTag)
	}
	return tags
}

func newTestKeyDB(t *testing.T) *KeyDB {
	t.Helper()
	f := filepath.Join(t.TempDir(), "test.db")
	if err := os.WriteFile(f, nil, 0664); err != nil {
		t.Fatalf("create db file: %v", err)
	}
	kdb, err := NewKeyDB(f, false, nil)
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	return kdb
}

// withCompleteness sets the global completeness mode for the duration of a test
// and restores it on cleanup. The reconcile reads Conf.Internal.Completeness.
func withCompleteness(t *testing.T, mode string) {
	t.Helper()
	prev := Conf.Internal.Completeness
	Conf.Internal.Completeness = mode
	t.Cleanup(func() { Conf.Internal.Completeness = prev })
}

// STRICT mode: a wrong-algorithm active ZSK is REFUSED (strict-mode algorithm
// rollover is not implemented), not retired. This replaces the old
// immediate-retire assertion — under the relaxed-mode design the synchronous
// swap is exactly the unsafe §2 path and is gated off in both modes.
func TestReconcileActiveZSKWrongAlgStrictRefuses(t *testing.T) {
	withCompleteness(t, CompletenessStrict)
	kdb := newTestKeyDB(t)

	zd := &ZoneData{
		ZoneName: "example.",
		Options:  map[ZoneOption]bool{OptOnlineSigning: true},
		DnssecPolicy: &DnssecPolicy{
			Mode:         DnssecPolicyModeKSKZSK,
			KSKAlgorithm: dns.ED25519,
			ZSKAlgorithm: dns.RSASHA256,
		},
		Logger: log.New(os.Stderr, "", 0),
	}

	// Matching active KSK + wrong-alg active ZSK (ED25519, policy wants RSASHA256).
	if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("generate KSK: %v", err)
	}
	if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "ZSK", nil); err != nil {
		t.Fatalf("generate ZSK: %v", err)
	}

	dak, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil {
		t.Fatalf("GetDnssecKeys: %v", err)
	}
	retired, err := zd.reconcileActiveKeyAlgorithms(kdb, dak)
	if err == nil {
		t.Fatal("strict-mode ZSK alg mismatch should be refused with an error")
	}
	if retired {
		t.Fatal("refusal must not retire any key")
	}

	// The wrong-alg ZSK is STILL active (no synchronous swap happened).
	dak2, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil {
		t.Fatalf("GetDnssecKeys after refused reconcile: %v", err)
	}
	realZSKs := 0
	for _, z := range dak2.ZSKs {
		if z.DnskeyRR.Flags == 256 {
			realZSKs++
		}
	}
	if realZSKs != 1 {
		t.Fatalf("wrong-alg ZSK must remain active after a refusal, got %d real ZSK(s)", realZSKs)
	}
}

// A wrong-algorithm active KSK is REFUSED in BOTH completeness modes — a KSK
// algorithm rollover is parent-coordinated engine work (not yet built), and the
// legacy immediate retire would bypass the standby DS gate and bogus the parent
// chain (the §2 path). The reconcile must error and leave the KSK active.
func TestReconcileActiveKSKWrongAlgRefuses(t *testing.T) {
	for _, mode := range []string{CompletenessStrict, CompletenessRelaxed} {
		t.Run(mode, func(t *testing.T) {
			withCompleteness(t, mode)
			kdb := newTestKeyDB(t)
			zd := &ZoneData{
				ZoneName: "example.",
				Options:  map[ZoneOption]bool{OptOnlineSigning: true},
				DnssecPolicy: &DnssecPolicy{
					Mode:         DnssecPolicyModeKSKZSK,
					KSKAlgorithm: dns.ED25519,   // policy wants ED25519 KSK
					ZSKAlgorithm: dns.RSASHA256, // matching ZSK so only the KSK mismatches
				},
				Logger: log.New(os.Stderr, "", 0),
			}

			// Wrong-alg active KSK (RSASHA256, policy wants ED25519) + matching ZSK.
			if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.RSASHA256, "KSK", nil); err != nil {
				t.Fatalf("generate KSK: %v", err)
			}
			if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.RSASHA256, "ZSK", nil); err != nil {
				t.Fatalf("generate ZSK: %v", err)
			}

			dak, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
			if err != nil {
				t.Fatalf("GetDnssecKeys: %v", err)
			}
			removed, err := zd.reconcileActiveKeyAlgorithms(kdb, dak)
			if err == nil {
				t.Fatal("KSK alg mismatch must be refused with an error (both modes)")
			}
			if removed {
				t.Fatal("refusal must not remove/retire any key")
			}

			// The wrong-alg KSK is STILL active (no synchronous swap).
			dak2, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
			if err != nil {
				t.Fatalf("GetDnssecKeys after refused reconcile: %v", err)
			}
			if len(dak2.KSKs) != 1 || dak2.KSKs[0].DnskeyRR.Algorithm != dns.RSASHA256 {
				t.Fatalf("wrong-alg KSK must remain active after refusal, got %d KSK(s)", len(dak2.KSKs))
			}
		})
	}
}

// Same-algorithm reconcile is a no-op in both modes (the common case): no
// mismatch, no error, no key change.
func TestReconcileActiveKeysSameAlgNoop(t *testing.T) {
	for _, mode := range []string{CompletenessStrict, CompletenessRelaxed} {
		t.Run(mode, func(t *testing.T) {
			withCompleteness(t, mode)
			kdb := newTestKeyDB(t)
			zd := &ZoneData{
				ZoneName: "example.",
				Options:  map[ZoneOption]bool{OptOnlineSigning: true},
				DnssecPolicy: &DnssecPolicy{
					Mode:         DnssecPolicyModeKSKZSK,
					KSKAlgorithm: dns.ED25519,
					ZSKAlgorithm: dns.RSASHA256,
				},
				Logger: log.New(os.Stderr, "", 0),
			}
			if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
				t.Fatalf("generate KSK: %v", err)
			}
			if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.RSASHA256, "ZSK", nil); err != nil {
				t.Fatalf("generate ZSK: %v", err)
			}
			dak, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
			if err != nil {
				t.Fatalf("GetDnssecKeys: %v", err)
			}
			changed, err := zd.reconcileActiveKeyAlgorithms(kdb, dak)
			if err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			if changed {
				t.Fatal("same-alg reconcile should be a no-op")
			}
		})
	}
}

// Wrong-algorithm STANDBY/PUBLISHED keys (leftovers from a prior policy) are
// removed by the reconcile too — otherwise they keep appearing in the DNSKEY
// RRset. They never signed, so removal is safe (no orphan RRSIGs).
func TestReconcileRemovesNonActiveWrongAlgKeys(t *testing.T) {
	// STRICT mode: the algorithm-based standby/published deletion is the strict
	// shape (relaxed skips it for same-role ZSK keys — see the relaxed-mode
	// tests). The active keys here all match the policy, so the active loops
	// pass and only the sweep acts.
	withCompleteness(t, CompletenessStrict)
	kdb := newTestKeyDB(t)
	zd := &ZoneData{
		ZoneName: "example.",
		Options:  map[ZoneOption]bool{OptOnlineSigning: true},
		DnssecPolicy: &DnssecPolicy{
			Mode:         DnssecPolicyModeKSKZSK,
			KSKAlgorithm: dns.ED25519,
			ZSKAlgorithm: dns.RSASHA256,
		},
		Logger: log.New(os.Stderr, "", 0),
	}

	// Correct-algorithm active keys.
	if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("generate active KSK: %v", err)
	}
	if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.RSASHA256, "ZSK", nil); err != nil {
		t.Fatalf("generate active ZSK: %v", err)
	}
	// Correct-algorithm STANDBY ZSK (a legitimate pipeline key — must survive).
	if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateStandby, dns.TypeDNSKEY, dns.RSASHA256, "ZSK", nil); err != nil {
		t.Fatalf("generate good standby ZSK: %v", err)
	}
	// Wrong-algorithm STANDBY ZSK + PUBLISHED ZSK (prior-policy leftovers).
	if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateStandby, dns.TypeDNSKEY, dns.ED25519, "ZSK", nil); err != nil {
		t.Fatalf("generate stale standby ZSK: %v", err)
	}
	if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStatePublished, dns.TypeDNSKEY, dns.ED25519, "ZSK", nil); err != nil {
		t.Fatalf("generate stale published ZSK: %v", err)
	}

	dak, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil {
		t.Fatalf("GetDnssecKeys: %v", err)
	}
	if _, err := zd.reconcileActiveKeyAlgorithms(kdb, dak); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// The wrong-alg standby/published ZSKs are gone (removed); the correct-alg
	// standby ZSK survives.
	for _, state := range []string{DnskeyStateStandby, DnskeyStatePublished} {
		keys, err := GetDnssecKeysByState(kdb, zd.ZoneName, state)
		if err != nil {
			t.Fatalf("GetDnssecKeysByState %s: %v", state, err)
		}
		for _, k := range keys {
			if k.Algorithm != dns.RSASHA256 {
				t.Fatalf("%s key %d alg %s should have been removed (policy ZSK alg is RSASHA256)", state, k.KeyTag, dns.AlgorithmToString[k.Algorithm])
			}
		}
	}
	good, err := GetDnssecKeysByState(kdb, zd.ZoneName, DnskeyStateStandby)
	if err != nil {
		t.Fatalf("GetDnssecKeysByState standby: %v", err)
	}
	if len(good) != 1 || good[0].Algorithm != dns.RSASHA256 {
		t.Fatalf("the correct-alg standby ZSK should survive, got %d standby keys", len(good))
	}
}
