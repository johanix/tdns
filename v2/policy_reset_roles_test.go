package tdns

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// Algorithms used across the per-role tests (all built-in; no liboqs needed).
const (
	algA = dns.ED25519
	algB = dns.RSASHA256
	algC = dns.RSASHA512
	algD = dns.ECDSAP256SHA256
)

func genRoleKey(t *testing.T, kdb *KeyDB, state string, alg uint8, role string) uint16 {
	t.Helper()
	pkc, _, err := kdb.GenerateKeypair(algZone, "test", state, dns.TypeDNSKEY, alg, role, nil)
	if err != nil {
		t.Fatalf("GenerateKeypair(%s,%s,%s): %v", state, dns.AlgorithmToString[alg], role, err)
	}
	return pkc.KeyId
}

func splitPol(ksk, zsk uint8) *DnssecPolicy {
	return &DnssecPolicy{Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: ksk, ZSKAlgorithm: zsk}
}
func cskPol(alg uint8) *DnssecPolicy {
	return &DnssecPolicy{Mode: DnssecPolicyModeCSK, Algorithm: alg, KSKAlgorithm: alg, ZSKAlgorithm: alg}
}

// activeRoleKeys splits the zone's active keys into KSK/CSK (SEP) and ZSK (non-SEP).
func activeRoleKeys(t *testing.T, kdb *KeyDB) (seps, zsks []DnssecKeyWithTimestamps) {
	t.Helper()
	active, err := GetDnssecKeysByState(kdb, algZone, DnskeyStateActive)
	if err != nil {
		t.Fatalf("GetDnssecKeysByState: %v", err)
	}
	for _, k := range active {
		if k.Flags&0x0001 == 0x0001 {
			seps = append(seps, k)
		} else {
			zsks = append(zsks, k)
		}
	}
	return seps, zsks
}

// TestZoneActiveKeyRoleChanges covers the per-role keep/drop decision across the
// four split cases, CSK, mode changes, missing roles, and a mid-rollover mix.
func TestZoneActiveKeyRoleChanges(t *testing.T) {
	cases := []struct {
		name             string
		setup            func(t *testing.T, kdb *KeyDB)
		pol              *DnssecPolicy
		wantKSK, wantZSK bool
	}{
		{"split no-op", func(t *testing.T, kdb *KeyDB) {
			genRoleKey(t, kdb, DnskeyStateActive, algA, "KSK")
			genRoleKey(t, kdb, DnskeyStateActive, algB, "ZSK")
		}, splitPol(algA, algB), false, false},

		{"split zsk-only", func(t *testing.T, kdb *KeyDB) {
			genRoleKey(t, kdb, DnskeyStateActive, algA, "KSK")
			genRoleKey(t, kdb, DnskeyStateActive, algB, "ZSK")
		}, splitPol(algA, algC), false, true},

		{"split ksk-only", func(t *testing.T, kdb *KeyDB) {
			genRoleKey(t, kdb, DnskeyStateActive, algA, "KSK")
			genRoleKey(t, kdb, DnskeyStateActive, algB, "ZSK")
		}, splitPol(algC, algB), true, false},

		{"split both", func(t *testing.T, kdb *KeyDB) {
			genRoleKey(t, kdb, DnskeyStateActive, algA, "KSK")
			genRoleKey(t, kdb, DnskeyStateActive, algB, "ZSK")
		}, splitPol(algC, algD), true, true},

		{"no active keys", func(t *testing.T, kdb *KeyDB) {}, splitPol(algA, algB), true, true},

		{"ksk role missing", func(t *testing.T, kdb *KeyDB) {
			genRoleKey(t, kdb, DnskeyStateActive, algB, "ZSK")
		}, splitPol(algA, algB), true, false},

		{"zsk mid-rollover mix", func(t *testing.T, kdb *KeyDB) {
			genRoleKey(t, kdb, DnskeyStateActive, algA, "KSK")
			genRoleKey(t, kdb, DnskeyStateActive, algB, "ZSK") // right alg
			genRoleKey(t, kdb, DnskeyStateActive, algC, "ZSK") // wrong alg (in flight)
		}, splitPol(algA, algB), false, true},

		{"csk no-op", func(t *testing.T, kdb *KeyDB) {
			genRoleKey(t, kdb, DnskeyStateActive, algA, "CSK")
		}, cskPol(algA), false, false},

		{"csk alg change", func(t *testing.T, kdb *KeyDB) {
			genRoleKey(t, kdb, DnskeyStateActive, algA, "CSK")
		}, cskPol(algB), true, false},

		{"mode change split->csk", func(t *testing.T, kdb *KeyDB) {
			genRoleKey(t, kdb, DnskeyStateActive, algA, "KSK")
			genRoleKey(t, kdb, DnskeyStateActive, algB, "ZSK")
		}, cskPol(algA), true, true},

		{"mode change csk->split", func(t *testing.T, kdb *KeyDB) {
			genRoleKey(t, kdb, DnskeyStateActive, algA, "CSK")
		}, splitPol(algA, algB), true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kdb := newTestKeyDB(t)
			c.setup(t, kdb)
			ksk, zsk, err := zoneActiveKeyRoleChanges(kdb, algZone, c.pol)
			if err != nil {
				t.Fatalf("zoneActiveKeyRoleChanges: %v", err)
			}
			if ksk != c.wantKSK || zsk != c.wantZSK {
				t.Fatalf("got (kskChanged=%v, zskChanged=%v), want (%v, %v)", ksk, zsk, c.wantKSK, c.wantZSK)
			}
		})
	}
}

// TestPolicyResetReport asserts the DS-break warning fires iff the KSK changed.
func TestPolicyResetReport(t *testing.T) {
	cases := []struct {
		ksk, zsk bool
		wantWarn bool
		phrase   string
	}{
		{false, false, false, "KSK and parent DS unchanged"},
		{false, true, false, "KSK and parent DS unchanged"},
		{true, false, true, "BREAKS the chain of trust"},
		{true, true, true, "BREAKS the chain of trust"},
	}
	for _, c := range cases {
		msg := policyResetReport("z.example.", "pol", c.ksk, c.zsk, 42)
		hasWarn := strings.Contains(msg, "BREAKS the chain of trust")
		if hasWarn != c.wantWarn {
			t.Fatalf("ksk=%v zsk=%v: DS warning present=%v, want %v\nmsg: %s", c.ksk, c.zsk, hasWarn, c.wantWarn, msg)
		}
		if !strings.Contains(msg, c.phrase) {
			t.Fatalf("ksk=%v zsk=%v: message missing %q\nmsg: %s", c.ksk, c.zsk, c.phrase, msg)
		}
	}
}

// TestForceZoneKeysToPolicyRoles verifies the surgical drop/regen: the kept
// role's keytag is preserved, the dropped role gets a fresh key of the config
// algorithm. StripZoneRRSIGs no-ops on the data-less test zone.
func TestForceZoneKeysToPolicyRoles(t *testing.T) {
	t.Run("zsk-only keeps KSK keytag", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		zd := algTestZone(algA, algB)
		kskTag := genRoleKey(t, kdb, DnskeyStateActive, algA, "KSK")
		zskTag := genRoleKey(t, kdb, DnskeyStateActive, algB, "ZSK")

		if err := kdb.forceZoneKeysToPolicyRoles(context.Background(), zd, splitPol(algA, algC), false, true); err != nil {
			t.Fatalf("forceZoneKeysToPolicyRoles: %v", err)
		}
		seps, zsks := activeRoleKeys(t, kdb)
		if len(seps) != 1 || seps[0].KeyTag != kskTag || seps[0].Algorithm != algA {
			t.Fatalf("KSK not preserved: got %+v, want 1 KSK keytag %d alg %s", seps, kskTag, dns.AlgorithmToString[algA])
		}
		if len(zsks) != 1 || zsks[0].Algorithm != algC || zsks[0].KeyTag == zskTag {
			t.Fatalf("ZSK not rolled to new alg: got %+v, want 1 ZSK alg %s with a new keytag (old %d)", zsks, dns.AlgorithmToString[algC], zskTag)
		}
	})

	t.Run("ksk-only keeps ZSK keytag", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		zd := algTestZone(algA, algB)
		kskTag := genRoleKey(t, kdb, DnskeyStateActive, algA, "KSK")
		zskTag := genRoleKey(t, kdb, DnskeyStateActive, algB, "ZSK")

		if err := kdb.forceZoneKeysToPolicyRoles(context.Background(), zd, splitPol(algC, algB), true, false); err != nil {
			t.Fatalf("forceZoneKeysToPolicyRoles: %v", err)
		}
		seps, zsks := activeRoleKeys(t, kdb)
		if len(seps) != 1 || seps[0].Algorithm != algC || seps[0].KeyTag == kskTag {
			t.Fatalf("KSK not rolled: got %+v, want 1 KSK alg %s new keytag (old %d)", seps, dns.AlgorithmToString[algC], kskTag)
		}
		if len(zsks) != 1 || zsks[0].KeyTag != zskTag || zsks[0].Algorithm != algB {
			t.Fatalf("ZSK not preserved: got %+v, want 1 ZSK keytag %d alg %s", zsks, zskTag, dns.AlgorithmToString[algB])
		}
	})

	t.Run("both rolls both roles", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		zd := algTestZone(algA, algB)
		genRoleKey(t, kdb, DnskeyStateActive, algA, "KSK")
		genRoleKey(t, kdb, DnskeyStateActive, algB, "ZSK")

		if err := kdb.forceZoneKeysToPolicyRoles(context.Background(), zd, splitPol(algC, algD), true, true); err != nil {
			t.Fatalf("forceZoneKeysToPolicyRoles: %v", err)
		}
		seps, zsks := activeRoleKeys(t, kdb)
		if len(seps) != 1 || seps[0].Algorithm != algC {
			t.Fatalf("KSK: got %+v, want 1 KSK alg %s", seps, dns.AlgorithmToString[algC])
		}
		if len(zsks) != 1 || zsks[0].Algorithm != algD {
			t.Fatalf("ZSK: got %+v, want 1 ZSK alg %s", zsks, dns.AlgorithmToString[algD])
		}
	})

	t.Run("csk collapses to a single CSK", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		zd := algTestZone(algA, algA)
		zd.DnssecPolicy.Mode = DnssecPolicyModeCSK
		// A split starting set (KSK+ZSK) to prove the leftover ZSK is removed.
		genRoleKey(t, kdb, DnskeyStateActive, algA, "KSK")
		genRoleKey(t, kdb, DnskeyStateActive, algB, "ZSK")

		if err := kdb.forceZoneKeysToPolicyRoles(context.Background(), zd, cskPol(algC), true, false); err != nil {
			t.Fatalf("forceZoneKeysToPolicyRoles: %v", err)
		}
		seps, zsks := activeRoleKeys(t, kdb)
		if len(zsks) != 0 {
			t.Fatalf("CSK reset should leave no separate ZSK, got %+v", zsks)
		}
		if len(seps) != 1 || seps[0].Algorithm != algC {
			t.Fatalf("CSK: got %+v, want 1 SEP key alg %s", seps, dns.AlgorithmToString[algC])
		}
	})
}

// TestForceZoneKeysDNSKEYRRSIGStrip covers the ZSK-only flip's subtle case: the
// DNSKEY RRset content changes (old ZSK's DNSKEY out, new ZSK's in), so the KEPT
// KSK's DNSKEY RRSIG now covers a stale key set. It is NOT an orphan (its key is
// still active), so the orphan strip alone would leave it as bogus cruft. The
// force op must strip ALL DNSKEY RRSIGs; the kept KSK's non-DNSKEY (SOA) RRSIG
// must survive, and the dropped ZSK's orphans must go.
func TestForceZoneKeysDNSKEYRRSIGStrip(t *testing.T) {
	kdb := newTestKeyDB(t)
	kskTag := genRoleKey(t, kdb, DnskeyStateActive, algA, "KSK")
	zskTag := genRoleKey(t, kdb, DnskeyStateActive, algB, "ZSK")

	zone := `zsk-alg.example.	3600	IN	SOA	ns.zsk-alg.example. hostmaster.zsk-alg.example. 1 7200 1800 604800 7200
zsk-alg.example.	3600	IN	NS	ns.zsk-alg.example.
`
	zd := testZone(t, algZone, zone)
	registerZones(t, zd)

	mkSig := func(covered, keytag uint16) *dns.RRSIG {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: algZone, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			TypeCovered: covered,
			KeyTag:      keytag,
			SignerName:  algZone,
		}
	}
	apex, ok := zd.Data.Get(algZone)
	if !ok {
		t.Fatal("apex owner missing from zd.Data")
	}
	// DNSKEY RRset signed by BOTH the kept KSK and the dropped ZSK.
	dk := apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY)
	dk.Name = algZone
	dk.RRtype = dns.TypeDNSKEY
	dk.RRSIGs = []dns.RR{mkSig(dns.TypeDNSKEY, kskTag), mkSig(dns.TypeDNSKEY, zskTag)}
	apex.RRtypes.Set(dns.TypeDNSKEY, dk)
	// SOA RRset signed by both roles.
	soa := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	soa.RRSIGs = []dns.RR{mkSig(dns.TypeSOA, kskTag), mkSig(dns.TypeSOA, zskTag)}
	apex.RRtypes.Set(dns.TypeSOA, soa)
	zd.InstallInitialSnapshot()

	// ZSK-only flip: keep KSK (algA), drop+regen ZSK (→ algC).
	if err := kdb.forceZoneKeysToPolicyRoles(context.Background(), zd, splitPol(algA, algC), false, true); err != nil {
		t.Fatalf("forceZoneKeysToPolicyRoles: %v", err)
	}

	// DNSKEY RRSIGs: ALL stripped — the kept KSK's stale one AND the ZSK orphan.
	if tags := zd.mustRRSIGKeytags(t, algZone, dns.TypeDNSKEY); len(tags) != 0 {
		t.Fatalf("DNSKEY RRSIGs after ZSK flip = %v, want none (incl. the kept KSK's stale one)", tags)
	}
	// SOA RRSIGs: kept KSK's survives (not DNSKEY-covered, key still active); the
	// dropped ZSK's orphan is stripped.
	if tags := zd.mustRRSIGKeytags(t, algZone, dns.TypeSOA); len(tags) != 1 || tags[0] != kskTag {
		t.Fatalf("SOA RRSIGs after ZSK flip = %v, want [%d] (kept KSK only)", tags, kskTag)
	}
}
