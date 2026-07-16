package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// TestRefreshActiveDnssecKeysRepublishesFromDB is the G3 replacement for the
// stale KeystoreDnskeyCache regression: after the keystore changes underneath
// a published snapshot, refreshActiveDnssecKeys must republish from the
// committed DB so the subsequent re-sign sees the real active keys.
func TestRefreshActiveDnssecKeysRepublishesFromDB(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := algTestZone(dns.ED25519, dns.ED25519)
	zd.KeyDB = kdb
	registerAlgZone(t, zd)

	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, dns.ED25519)
	if err := zd.republishSigningKeys(kdb); err != nil {
		t.Fatalf("prime snapshot: %v", err)
	}
	if len(zd.ActiveDnssecKeys().KSKs)+len(zd.ActiveDnssecKeys().ZSKs) == 0 {
		t.Fatal("expected primed active keys")
	}

	// Drop all keys DIRECTLY (bypassing republish), so the snapshot is stale.
	if _, err := kdb.DB.Exec(`DELETE FROM DnssecKeyStore WHERE zonename=?`, algZone); err != nil {
		t.Fatalf("direct delete: %v", err)
	}

	// Snapshot still serves the deleted keys...
	stale := zd.ActiveDnssecKeys()
	if len(stale.KSKs)+len(stale.ZSKs) == 0 {
		t.Fatal("expected stale snapshot to still hold keys before refresh")
	}

	// ...but refreshActiveDnssecKeys republishes from the committed DB.
	fresh, err := zd.refreshActiveDnssecKeys(kdb, "test")
	if err != nil {
		t.Fatalf("refreshActiveDnssecKeys: %v", err)
	}
	if len(fresh.KSKs)+len(fresh.ZSKs) != 0 {
		t.Fatalf("refresh returned stale keys: KSKs=%d ZSKs=%d, want 0 (DB was emptied)", len(fresh.KSKs), len(fresh.ZSKs))
	}
	assertSnapMatchesDB(t, kdb, zd)
}
