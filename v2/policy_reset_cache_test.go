package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// TestRefreshActiveDnssecKeysBypassesStaleCache is the regression for the
// policy-reset stale active-key cache. The active-key cache can hold a STALE set
// after the keystore changes underneath it (the uncommitted-window re-cache the
// keystore `clear` path hits: a GetDnssecKeys during the DELETE+regen tx
// re-caches the OLD keys). Once the DB has changed without a cache invalidation,
// GetDnssecKeys keeps serving the old set; refreshActiveDnssecKeys must
// invalidate + re-read from the committed DB so the subsequent re-sign sees the
// real active keys (else policy-reset re-signs against stale keys and refuses on
// an algorithm mismatch — the SERVFAIL the testbed hit).
func TestRefreshActiveDnssecKeysBypassesStaleCache(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := algTestZone(dns.ED25519, dns.ED25519)

	if _, _, err := kdb.GenerateKeypair(algZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	genZSK(t, kdb, DnskeyStateActive, dns.ED25519)

	// Prime the active-key cache.
	primed, err := kdb.GetDnssecKeys(algZone, DnskeyStateActive)
	if err != nil {
		t.Fatalf("prime cache: %v", err)
	}
	if len(primed.KSKs)+len(primed.ZSKs) == 0 {
		t.Fatal("expected primed active keys")
	}

	// Drop all keys DIRECTLY (bypassing the keystore's cache invalidation), so
	// the active-key cache is now stale — the shape of the clear-window re-cache.
	if _, err := kdb.DB.Exec(`DELETE FROM DnssecKeyStore WHERE zonename=?`, algZone); err != nil {
		t.Fatalf("direct delete: %v", err)
	}

	// The cache still serves the deleted keys...
	stale, err := kdb.GetDnssecKeys(algZone, DnskeyStateActive)
	if err != nil {
		t.Fatalf("stale read: %v", err)
	}
	if len(stale.KSKs)+len(stale.ZSKs) == 0 {
		t.Skip("GetDnssecKeys did not serve from cache here; nothing to regress")
	}

	// ...but refreshActiveDnssecKeys invalidates and re-reads the committed DB.
	fresh, err := zd.refreshActiveDnssecKeys(kdb, "test")
	if err != nil {
		t.Fatalf("refreshActiveDnssecKeys: %v", err)
	}
	if len(fresh.KSKs)+len(fresh.ZSKs) != 0 {
		t.Fatalf("refresh returned stale keys: KSKs=%d ZSKs=%d, want 0 (DB was emptied)", len(fresh.KSKs), len(fresh.ZSKs))
	}
}
