package tdns

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

func intentTestKeyDB(t *testing.T) *KeyDB {
	t.Helper()
	f := filepath.Join(t.TempDir(), "intent.db")
	if err := os.WriteFile(f, nil, 0664); err != nil {
		t.Fatalf("create db file: %v", err)
	}
	kdb, err := NewKeyDB(f, false, nil)
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	return kdb
}

// seedKey writes one keystore row. flags 257 = ZONE|SEP (a KSK), 256 = ZONE
// only (a ZSK, which must never contribute a DS).
func seedKey(t *testing.T, kdb *KeyDB, zone, state string, flags uint16, pubkey string) {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: pubkey,
	}
	keyid := key.KeyTag()
	_, err := kdb.DB.Exec(
		`INSERT INTO DnssecKeyStore (zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		zone, state, keyid, flags, dns.ED25519, "test", "", key.String())
	if err != nil {
		t.Fatalf("seed key (%s,%s,keyid=%d): %v", zone, state, keyid, err)
	}
}

// Distinct ED25519 public keys, so the seeded rows get distinct key tags.
const (
	pubA = "0F+2q0hUwq0k2iVfSmJDVWCMPRZ7hhQVR/4Gh0DBSD0="
	pubB = "1G+3r1iVxr1l3jWgTnKEWXDNQSa8iiRWS/5Hi1ECTE1="
	pubC = "2H+4s2jWys2m4kXhUoLFXYEORTb9jjSXT/6Ij2FDUF2="
	pubD = "3I+5t3kXzt3n5lYiVpMGYZFPSUc0kkTYU/7Jk3GEVG3="
)

// dsBelongsAtParent is the whole of D1: under multi-DS a KSK gets its DS at the
// parent BEFORE its DNSKEY is published, so everything from ds-published
// onwards should have one.
func TestDSBelongsAtParent(t *testing.T) {
	yes := []string{DnskeyStateDsPublished, DnskeyStatePublished, DnskeyStateStandby, DnskeyStateActive}
	no := []string{DnskeyStateCreated, DnskeyStateRetired, DnskeyStateRemoved}

	for _, st := range yes {
		if !dsBelongsAtParent(st) {
			t.Errorf("state %q should have a DS at the parent, got false", st)
		}
	}
	for _, st := range no {
		if dsBelongsAtParent(st) {
			t.Errorf("state %q should NOT have a DS at the parent, got true", st)
		}
	}
	// An unrecognised state must not read as a DS removal.
	if dsBelongsAtParent("some-future-state") {
		t.Error("an unrecognised state was counted toward the DS set")
	}
}

// The distinction Known exists for: no keystore rows means tdns does not manage
// this zone's keys, which is NOT the same as the zone being unsigned. Getting
// this wrong withdraws the DS of a zone signed elsewhere and served here.
func TestDSIntentUnknownWhenZoneHasNoKeys(t *testing.T) {
	kdb := intentTestKeyDB(t)
	seedKey(t, kdb, "other.example.", DnskeyStateActive, 257, pubA)

	intent, err := DSIntentForZone(kdb, "child.example.", dns.SHA256)
	if err != nil {
		t.Fatalf("DSIntentForZone: %v", err)
	}
	if intent.Known {
		t.Fatal("a zone with no keystore KSKs reported a known DS intent;" +
			" a zone signed elsewhere would have its DS withdrawn")
	}
	if len(intent.Set) != 0 {
		t.Errorf("unknown intent carried %d DS records", len(intent.Set))
	}
}

// The other half: tdns holds keys for the zone and none of them should have a
// DS. That IS an answer -- withdraw.
func TestDSIntentKnownAndEmptyWhenZoneIsUnsigned(t *testing.T) {
	kdb := intentTestKeyDB(t)
	seedKey(t, kdb, "child.example.", DnskeyStateRetired, 257, pubA)

	intent, err := DSIntentForZone(kdb, "child.example.", dns.SHA256)
	if err != nil {
		t.Fatalf("DSIntentForZone: %v", err)
	}
	if !intent.Known {
		t.Fatal("a zone whose keys tdns holds reported an unknown intent;" +
			" un-signing would never withdraw the DS")
	}
	if len(intent.Set) != 0 {
		t.Errorf("retired keys contributed %d DS records, want 0", len(intent.Set))
	}
}

// The rollover case this whole change exists for: a key in ds-published has its
// DS at the parent and no DNSKEY in the zone. A set derived from published
// DNSKEYs would miss it and report it for deletion.
func TestDSIntentIncludesDsPublishedAndExcludesCreated(t *testing.T) {
	kdb := intentTestKeyDB(t)
	seedKey(t, kdb, "child.example.", DnskeyStateActive, 257, pubA)
	seedKey(t, kdb, "child.example.", DnskeyStateDsPublished, 257, pubB)
	seedKey(t, kdb, "child.example.", DnskeyStateCreated, 257, pubC)

	intent, err := DSIntentForZone(kdb, "child.example.", dns.SHA256)
	if err != nil {
		t.Fatalf("DSIntentForZone: %v", err)
	}
	if !intent.Known {
		t.Fatal("intent not known")
	}
	if len(intent.Set) != 2 {
		t.Fatalf("DS set has %d records, want 2 (active + ds-published): %v", len(intent.Set), intent.Set)
	}
}

// ZSKs never produce a DS, whatever their state.
func TestDSIntentIgnoresNonSEPKeys(t *testing.T) {
	kdb := intentTestKeyDB(t)
	seedKey(t, kdb, "child.example.", DnskeyStateActive, 256, pubD)

	intent, err := DSIntentForZone(kdb, "child.example.", dns.SHA256)
	if err != nil {
		t.Fatalf("DSIntentForZone: %v", err)
	}
	if intent.Known {
		t.Error("a zone with only ZSKs reported a known DS intent")
	}
	if len(intent.Set) != 0 {
		t.Errorf("a ZSK contributed %d DS records", len(intent.Set))
	}
}

// Replace mode must act on the DS question only when it has been answered.
// This is the distinction that a len(newDS) > 0 test cannot make: on the
// update-driven path NewDS is left nil whenever the update touched no DNSKEY,
// so treating that emptiness as "the child has no DS" would delete the parent's
// DS on an ordinary NS edit.
func TestReplaceUpdateHonoursDSIntent(t *testing.T) {
	const (
		parent = "example."
		child  = "child.example."
	)
	ns := []dns.RR{mustRR(t, child+" 3600 IN NS ns1."+child)}

	countDS := func(m *dns.Msg) (del, add int) {
		for _, rr := range m.Ns {
			if rr.Header().Rrtype != dns.TypeDS {
				continue
			}
			if rr.Header().Class == dns.ClassANY {
				del++
				continue
			}
			add++
		}
		return del, add
	}

	t.Run("unanswered and empty leaves DS alone", func(t *testing.T) {
		m, err := CreateChildReplaceUpdateWithDS(parent, child, ns, nil, nil, nil, false)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if del, add := countDS(m); del != 0 || add != 0 {
			t.Errorf("DS deletions=%d additions=%d, want 0/0: an unanswered DS question must not touch the parent DS", del, add)
		}
	})

	t.Run("answered and empty withdraws the DS", func(t *testing.T) {
		m, err := CreateChildReplaceUpdateWithDS(parent, child, ns, nil, nil, nil, true)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		del, add := countDS(m)
		if del != 1 {
			t.Errorf("DS deletions=%d, want 1: an unsigned child must clear the parent DS", del)
		}
		if add != 0 {
			t.Errorf("DS additions=%d, want 0", add)
		}
	})

	t.Run("the legacy wrapper still means no-opinion-when-empty", func(t *testing.T) {
		m, err := CreateChildReplaceUpdate(parent, child, ns, nil, nil, nil)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if del, _ := countDS(m); del != 0 {
			t.Errorf("DS deletions=%d, want 0: existing callers must keep today's behaviour", del)
		}
	})
}
