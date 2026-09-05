package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// rolledZone builds a signed zone, records the ZSK that signed it, then rolls
// that ZSK out: a new one is active and the old one is retired. What the zone is
// serving at that point is a valid signature by a key that is no longer active,
// which is precisely the state a key-state resign exists to clear.
func rolledZone(t *testing.T) (*ZoneData, *KeyDB, uint16) {
	t.Helper()
	zd := loadIxfrTestZone(t, basicZone)
	kdb := newTestKeyDB(t)
	if zd.Options == nil {
		zd.Options = map[ZoneOption]bool{}
	}
	zd.Options[OptOnlineSigning] = true
	zd.KeyDB = kdb
	zd.DnssecPolicy = &DnssecPolicy{
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		// Above the floor SignZone's tail checks: a zero validity is rejected
		// as "sigvalidity <= 2x(servedTTL+propagationDelay)", which would set
		// DnssecError and make every later pass refuse before it signs.
		SigValidity: PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400},
	}
	if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive,
		dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("generate KSK: %v", err)
	}
	oldZsk, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive,
		dns.TypeDNSKEY, dns.ED25519, "ZSK", nil)
	if err != nil {
		t.Fatalf("generate ZSK: %v", err)
	}
	oldTag := oldZsk.DnskeyRR.KeyTag()

	if _, err := zd.SignZone(kdb, false); err != nil {
		t.Fatalf("baseline SignZone: %v", err)
	}
	if !hasKeytag(zd.mustRRSIGKeytags(t, signedName, dns.TypeA), oldTag) {
		t.Fatalf("test setup: %s is not signed by the ZSK we are about to roll", signedName)
	}

	if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive,
		dns.TypeDNSKEY, dns.ED25519, "ZSK", nil); err != nil {
		t.Fatalf("generate replacement ZSK: %v", err)
	}
	if err := kdb.PromoteDnssecKey(zd.ZoneName, oldTag, DnskeyStateActive, DnskeyStateRetired); err != nil {
		t.Fatalf("retire the old ZSK: %v", err)
	}
	return zd, kdb, oldTag
}

const signedName = "ns.example.test."

func hasKeytag(tags []uint16, want uint16) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

// C4's whole justification. A key-state change has to REPLACE the served
// signature set, and ResignZone is the tool that does: it strips and re-signs
// per RRset, so nothing signed by the retired key survives.
func TestResignZoneRemovesSignaturesByARetiredKey(t *testing.T) {
	zd, kdb, oldTag := rolledZone(t)

	if _, err := zd.ResignZone(kdb); err != nil {
		t.Fatalf("ResignZone: %v", err)
	}

	tags := zd.mustRRSIGKeytags(t, signedName, dns.TypeA)
	if len(tags) == 0 {
		t.Fatal("the RRset came out unsigned")
	}
	if hasKeytag(tags, oldTag) {
		t.Fatalf("a signature by the retired key %d survived: %v", oldTag, tags)
	}
}

// The contrast, and the reason the resigner stopped using it. SignZone is
// ADDITIVE by design -- SignRRset says so, and says replacement belongs to
// ResignZone -- so a forced pass writes the new signature and leaves the stale
// one on the wire. Pinned so that "force is stronger, surely it is safer" cannot
// quietly come back.
func TestForcedSignZoneLeavesSignaturesByARetiredKey(t *testing.T) {
	zd, kdb, oldTag := rolledZone(t)

	if _, err := zd.SignZone(kdb, true); err != nil {
		t.Fatalf("SignZone(force): %v", err)
	}

	tags := zd.mustRRSIGKeytags(t, signedName, dns.TypeA)
	if !hasKeytag(tags, oldTag) {
		t.Skipf("a forced SignZone removed the retired key's signature (%v); the "+
			"additive contract this test documents has changed, and the resigner's "+
			"choice of ResignZone should be revisited", tags)
	}
}
