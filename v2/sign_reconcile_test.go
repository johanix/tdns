package tdns

import (
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
	return zd
}

func TestStripZoneRRSIGs(t *testing.T) {
	zone := `example.		3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.		3600	IN	NS	ns.example.
www.example.		3600	IN	A	192.0.2.1
`
	zd := testZone(t, "example.", zone)

	// Attach two RRSIGs (keytags 1111 and 2222) to the www A RRset.
	owner, err := zd.GetOwner("www.example.")
	if err != nil || owner == nil {
		t.Fatalf("GetOwner www: owner=%v err=%v", owner, err)
	}
	rrset := owner.RRtypes.GetOnlyRRSet(dns.TypeA)
	mkSig := func(keytag uint16) *dns.RRSIG {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			TypeCovered: dns.TypeA,
			KeyTag:      keytag,
			SignerName:  "example.",
		}
	}
	rrset.RRSIGs = []dns.RR{mkSig(1111), mkSig(2222)}
	owner.RRtypes.Set(dns.TypeA, rrset)

	// Strip only keytag 1111.
	removed, err := zd.StripZoneRRSIGs(func(s *dns.RRSIG) bool { return s.KeyTag == 1111 })
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

func TestReconcileActiveKeyAlgorithms(t *testing.T) {
	kdb := newTestKeyDB(t)

	// Policy wants KSK=ED25519, ZSK=RSASHA256 (both built-in; no liboqs).
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

	// Seed an active KSK that matches the policy and an active ZSK that does
	// NOT (ED25519 instead of RSASHA256) — the wrong-algorithm leftover.
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
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !retired {
		t.Fatal("reconcile should have retired the wrong-algorithm ZSK")
	}

	// The matching KSK stays active; the wrong-alg ZSK is gone from active.
	dak2, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil {
		t.Fatalf("GetDnssecKeys after reconcile: %v", err)
	}
	if len(dak2.KSKs) != 1 || dak2.KSKs[0].DnskeyRR.Algorithm != dns.ED25519 {
		t.Fatalf("active KSKs = %d (want 1 ED25519)", len(dak2.KSKs))
	}
	realZSKs := 0
	for _, z := range dak2.ZSKs {
		if z.DnskeyRR.Flags == 256 {
			realZSKs++
		}
	}
	if realZSKs != 0 {
		t.Fatalf("wrong-alg ZSK should have been retired, still %d active real ZSK(s)", realZSKs)
	}

	// Idempotency: a second reconcile against the now-correct active set
	// (only the matching KSK active) retires nothing.
	if again, err := zd.reconcileActiveKeyAlgorithms(kdb, dak2); err != nil {
		t.Fatalf("reconcile (2nd): %v", err)
	} else if again {
		t.Fatal("second reconcile should be a no-op (no thrashing)")
	}
}
