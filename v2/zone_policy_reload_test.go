package tdns

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// First-load / restart-survival coverage for syncZoneDnssecPolicyFromConfig
// (PR-2 sites b/c ordering: Ready → sync → first-sign).

func TestSyncZonePolicy_SignedZonefilePrimaryBackfills(t *testing.T) {
	kdb := newTestKeyDB(t)
	pol := kskzsk(dns.ED25519, dns.ED25519)
	withLivePolicies(t, map[string]DnssecPolicy{"base": pol})

	zd := readySignedApexZone(t, algZone, dns.ED25519)
	zd.Options = map[ZoneOption]bool{OptOnlineSigning: true}
	zd.ZoneType = Primary
	zd.KeyDB = kdb
	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, dns.ED25519)

	conf := &Config{}
	if err := syncZoneDnssecPolicyFromConfig(context.Background(), zd, kdb, conf, "base"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	name, _, ok, err := GetZoneAppliedPolicy(kdb, algZone)
	if err != nil || !ok || name != "base" {
		t.Fatalf("applied: got (%q,%v,%v), want (base,true,nil)", name, ok, err)
	}
	if zd.DnssecPolicyName != "base" || zd.DnssecPolicy == nil {
		t.Fatalf("binding after backfill: name=%q pol=%v", zd.DnssecPolicyName, zd.DnssecPolicy != nil)
	}
}

func TestSyncZonePolicy_OnlineSigningFromUnsignedPrimaryApplies(t *testing.T) {
	kdb := newTestKeyDB(t)
	pol := kskzsk(dns.ED25519, dns.ED25519)
	withLivePolicies(t, map[string]DnssecPolicy{"base": pol})

	// Ready apex but NO SOA RRSIGs and no keys — Branch 0b first apply.
	zone := algZone + "\t3600\tIN\tSOA\tns." + algZone + " hostmaster." + algZone + " 1 7200 1800 604800 7200\n" +
		algZone + "\t3600\tIN\tNS\tns." + algZone + "\n"
	zd := testZone(t, algZone, zone)
	zd.Options = map[ZoneOption]bool{OptOnlineSigning: true}
	zd.ZoneType = Primary
	zd.KeyDB = kdb
	zd.DnssecPolicy = &pol
	zd.DnssecPolicyName = "base"

	conf := &Config{}
	if err := syncZoneDnssecPolicyFromConfig(context.Background(), zd, kdb, conf, "base"); err != nil {
		t.Fatalf("sync (first apply): %v", err)
	}
	name, source, ok, err := GetZoneAppliedPolicy(kdb, algZone)
	if err != nil || !ok || name != "base" || source != "config" {
		t.Fatalf("applied after first apply: got (%q,%q,%v,%v)", name, source, ok, err)
	}
	// Apply path must have produced keys.
	match, err := zoneActiveKeysMatchAlgs(kdb, algZone, &pol)
	if err != nil || !match {
		t.Fatalf("expected active keys after first apply (match=%v err=%v)", match, err)
	}
}

func TestSyncZonePolicy_SecondaryInlineSigningBackfills(t *testing.T) {
	kdb := newTestKeyDB(t)
	pol := kskzsk(dns.ED25519, dns.ED25519)
	withLivePolicies(t, map[string]DnssecPolicy{"base": pol})

	zd := readySignedApexZone(t, algZone, dns.ED25519)
	zd.Options = map[ZoneOption]bool{OptInlineSigning: true}
	zd.ZoneType = Secondary
	zd.KeyDB = kdb
	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, dns.ED25519)

	conf := &Config{}
	if err := syncZoneDnssecPolicyFromConfig(context.Background(), zd, kdb, conf, "base"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	name, _, ok, err := GetZoneAppliedPolicy(kdb, algZone)
	if err != nil || !ok || name != "base" {
		t.Fatalf("inline-signing secondary must backfill applied: got (%q,%v,%v)", name, ok, err)
	}
}

func TestSyncZonePolicy_SecondaryWithoutSigningOptionsNoops(t *testing.T) {
	kdb := newTestKeyDB(t)
	pol := kskzsk(dns.ED25519, dns.ED25519)
	withLivePolicies(t, map[string]DnssecPolicy{"base": pol})

	zd := readySignedApexZone(t, algZone, dns.ED25519)
	zd.Options = map[ZoneOption]bool{}
	zd.ZoneType = Secondary
	zd.KeyDB = kdb

	conf := &Config{}
	if err := syncZoneDnssecPolicyFromConfig(context.Background(), zd, kdb, conf, "base"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if _, _, ok, _ := GetZoneAppliedPolicy(kdb, algZone); ok {
		t.Fatal("plain secondary must not write applied")
	}
}

func TestSyncZonePolicy_DeletedAppliedKeepBindingOnReload(t *testing.T) {
	kdb := newTestKeyDB(t)
	bound := kskzsk(dns.ED25519, dns.ED25519)
	intent := kskzsk(dns.ED25519, dns.ED25519)
	// Intent exists; applied name "gone" does not.
	withLivePolicies(t, map[string]DnssecPolicy{"intent": intent})
	if err := SetZoneAppliedPolicy(kdb, algZone, "gone", "config"); err != nil {
		t.Fatalf("SetZoneAppliedPolicy: %v", err)
	}

	zd := readySignedApexZone(t, algZone, dns.ED25519)
	zd.Options = map[ZoneOption]bool{OptOnlineSigning: true}
	zd.KeyDB = kdb
	zd.DnssecPolicy = &bound
	zd.DnssecPolicyName = "bound-kept"

	conf := &Config{}
	if err := syncZoneDnssecPolicyFromConfig(context.Background(), zd, kdb, conf, "intent"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if zd.DnssecPolicyName != "bound-kept" || zd.DnssecPolicy != &bound {
		t.Fatalf("§5.6 must keep binding: name=%q", zd.DnssecPolicyName)
	}
	if !zd.HasError(DnssecPolicyWarning) {
		t.Fatal("§5.6 must set DnssecPolicyWarning")
	}
}

func TestSyncZonePolicy_DeletedAppliedFirstBindProceedsTowardIntent(t *testing.T) {
	kdb := newTestKeyDB(t)
	intent := kskzsk(dns.ED25519, dns.ED25519)
	withLivePolicies(t, map[string]DnssecPolicy{"intent": intent})
	if err := SetZoneAppliedPolicy(kdb, algZone, "gone", "config"); err != nil {
		t.Fatalf("SetZoneAppliedPolicy: %v", err)
	}

	zone := algZone + "\t3600\tIN\tSOA\tns." + algZone + " hostmaster." + algZone + " 1 7200 1800 604800 7200\n" +
		algZone + "\t3600\tIN\tNS\tns." + algZone + "\n"
	zd := testZone(t, algZone, zone)
	zd.Options = map[ZoneOption]bool{OptOnlineSigning: true}
	zd.ZoneType = Primary
	zd.KeyDB = kdb
	zd.DnssecPolicyName = "intent" // config-base hint only; struct nil
	// DnssecPolicy left nil — first-bind §5.6

	conf := &Config{}
	if err := syncZoneDnssecPolicyFromConfig(context.Background(), zd, kdb, conf, "intent"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if zd.DnssecPolicyName != "intent" || zd.DnssecPolicy == nil {
		t.Fatalf("first-bind §5.6 must proceed toward intent: name=%q", zd.DnssecPolicyName)
	}
}

func TestDrainAndRunOnFirstLoadRunsOnce(t *testing.T) {
	zd := &ZoneData{ZoneName: "once.example."}
	n := 0
	zd.OnFirstLoad = []func(*ZoneData){
		func(*ZoneData) { n++ },
		func(*ZoneData) { n++ },
	}
	drainAndRunOnFirstLoad(zd)
	if n != 2 {
		t.Fatalf("callbacks ran %d times, want 2", n)
	}
	if len(zd.OnFirstLoad) != 0 {
		t.Fatal("OnFirstLoad must be cleared (one-shot)")
	}
	drainAndRunOnFirstLoad(zd) // no-op
	if n != 2 {
		t.Fatalf("second drain must not re-run callbacks; n=%d", n)
	}
}
