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
	// Through the one insert, as every writer is: a raw insert would leave
	// pub and sign unset, and the key would be neither served nor signing.
	tx, err := kdb.Begin("seedKey")
	if err != nil {
		t.Fatalf("seed key: begin: %v", err)
	}
	row := KeyRow{
		Zone: zone, State: state, Keyid: keyid, Flags: flags,
		Algorithm: dns.AlgorithmToString[dns.ED25519], Creator: "test", KeyRR: key.String(),
	}
	if f, known := keyFlagsForState(state); known {
		if _, loaded := dsModelForKeyWrite(zone); !loaded {
			// The zone is not loaded with a policy, so the writer cannot
			// resolve ds from its DS model; the test writes it the way a zone
			// without automated rollover gets it (design §3.4). A loaded zone
			// gets ds from the writer, per its model.
			f.DS = dsFlagFor(DSModelNone, state, flags&dns.SEP != 0)
		}
		row.RowFlags = &f
	} else {
		// A state nobody classified: written the way an owner writes its
		// own, with the flags given, so the test can seed one.
		row.RowFlags = &KeyRowFlags{}
	}
	err = insertKeyRowTx(tx, row)
	if err == nil {
		err = tx.Commit()
	} else {
		tx.Rollback()
	}
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
	no := []string{DnskeyStateCreated, DnskeyStateMpdist, DnskeyStateRetired, DnskeyStateRemoved}

	for _, st := range yes {
		belongs, recognised := dsBelongsAtParent(st)
		if !recognised {
			t.Errorf("state %q was not recognised", st)
		}
		if !belongs {
			t.Errorf("state %q should have a DS at the parent, got false", st)
		}
	}
	for _, st := range no {
		belongs, recognised := dsBelongsAtParent(st)
		if !recognised {
			t.Errorf("state %q was not recognised", st)
		}
		if belongs {
			t.Errorf("state %q should NOT have a DS at the parent, got true", st)
		}
	}
	if _, recognised := dsBelongsAtParent("some-future-state"); recognised {
		t.Error("an unrecognised state was reported as recognised")
	}
}

// A state this code does not classify must make the whole intent unknown, not
// merely trim the set. Reporting Known with a short set would have replace mode
// delete DS records on the strength of a state nobody has classified -- turning
// a schema addition into a DS removal, which is exactly what the predicate
// exists to prevent.
func TestDSIntentUnknownWhenAKeyHasAnUnrecognisedState(t *testing.T) {
	kdb := intentTestKeyDB(t)
	seedKey(t, kdb, "child.example.", DnskeyStateActive, 257, pubA)
	seedKey(t, kdb, "child.example.", "some-future-state", 257, pubB)

	intent, err := DSIntentForZone(kdb, "child.example.", dns.SHA256)
	if err != nil {
		t.Fatalf("DSIntentForZone: %v", err)
	}
	if intent.Known {
		t.Fatal("an unrecognised key state still produced an authoritative intent;" +
			" replace mode would delete the parent DS on the strength of it")
	}
	if len(intent.Set) != 0 {
		t.Errorf("unknown intent carried %d DS records", len(intent.Set))
	}
}

// intentDS is the DS a KSK with this public key hashes to.
func intentDS(zone, pubkey string) *dns.DS {
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: pubkey,
	}
	return key.ToDS(dns.SHA256)
}

// An mpdist key is a multi-provider zone's own key, served while it is
// distributed to the other providers and before it is promoted. Its ds is its
// owner's to write (design §3.4): while unset, nobody has decided, and the
// intent is unknown; once the owner has written 0, the zone's other keys
// answer.
func TestDSIntentGivesAnMpdistKeyNoDS(t *testing.T) {
	kdb := intentTestKeyDB(t)
	seedKey(t, kdb, "child.example.", DnskeyStateActive, 257, pubA)
	seedKey(t, kdb, "child.example.", DnskeyStateMpdist, 257, pubB)

	intent, err := DSIntentForZone(kdb, "child.example.", dns.SHA256)
	if err != nil {
		t.Fatalf("DSIntentForZone: %v", err)
	}
	if intent.Known {
		t.Fatalf("an mpdist key with ds unset gave a known intent (%d records); nobody has decided its DS", len(intent.Set))
	}
	if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET ds=0 WHERE zonename=? AND state=?`, "child.example.", DnskeyStateMpdist); err != nil {
		t.Fatal(err)
	}
	intent, err = DSIntentForZone(kdb, "child.example.", dns.SHA256)
	if err != nil {
		t.Fatalf("DSIntentForZone: %v", err)
	}
	if !intent.Known {
		t.Fatal("with the owner's ds=0 on the mpdist key the intent is unknown; the zone's active key still warrants its DS")
	}
	want := intentDS("child.example.", pubA)
	if len(intent.Set) != 1 || intent.Set[0].(*dns.DS).Digest != want.Digest {
		t.Errorf("intent = %v, want only the active key's DS %v", intent.Set, want)
	}
}

// An mpdist key is served, so a zone holding one is signed. If none of the
// zone's keys warrants a DS, that is a key on its way to promotion, not a zone
// that has been un-signed: an empty, known intent would have replace mode
// withdraw the parent's DS.
func TestDSIntentIsUnknownWhenOnlyAnMpdistKeyIsLeft(t *testing.T) {
	cases := []struct {
		name   string
		others []string
	}{
		{"mpdist only", nil},
		{"mpdist beside a retired key", []string{DnskeyStateRetired}},
		{"mpdist beside a created key", []string{DnskeyStateCreated}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kdb := intentTestKeyDB(t)
			seedKey(t, kdb, "child.example.", DnskeyStateMpdist, 257, pubA)
			for i, st := range tc.others {
				seedKey(t, kdb, "child.example.", st, 257, []string{pubB, pubC}[i])
			}

			intent, err := DSIntentForZone(kdb, "child.example.", dns.SHA256)
			if err != nil {
				t.Fatalf("DSIntentForZone: %v", err)
			}
			if intent.Known {
				t.Fatalf("stated a known intent (%d DS) for a zone that still serves an mpdist key;"+
					" replace mode would withdraw the parent's DS", len(intent.Set))
			}
		})
	}
}

// A foreign key is another provider's. Whether its DS belongs at the parent is
// not this zone's decision, and every consumer of the intent acts on the whole
// DS set -- replace mode rewrites it, delta mode removes what it lacks -- so no
// set tdns could state would leave that DS alone. The intent is unknown.
func TestDSIntentDeclinesForAZoneHoldingAForeignKSK(t *testing.T) {
	t.Run("foreign KSK", func(t *testing.T) {
		kdb := intentTestKeyDB(t)
		seedKey(t, kdb, "child.example.", DnskeyStateActive, 257, pubA)
		seedKey(t, kdb, "child.example.", DnskeyStateForeign, 257, pubB)

		intent, err := DSIntentForZone(kdb, "child.example.", dns.SHA256)
		if err != nil {
			t.Fatalf("DSIntentForZone: %v", err)
		}
		if intent.Known {
			t.Fatalf("stated a DS intent (%d records) for a zone holding another provider's KSK;"+
				" the parent's DS for that key is not this zone's to keep or remove", len(intent.Set))
		}
		if len(intent.Set) != 0 {
			t.Errorf("unknown intent carried %d DS records", len(intent.Set))
		}
	})

	// mpremove is tdns-mp's state for a key on its way out of a multi-provider
	// zone. tdns does not act on it: leaving it out of the set while stating an
	// intent would have replace mode remove its DS.
	t.Run("mpremove KSK", func(t *testing.T) {
		kdb := intentTestKeyDB(t)
		seedKey(t, kdb, "child.example.", DnskeyStateActive, 257, pubA)
		seedKey(t, kdb, "child.example.", DnskeyStateMpremove, 257, pubB)

		intent, err := DSIntentForZone(kdb, "child.example.", dns.SHA256)
		if err != nil {
			t.Fatalf("DSIntentForZone: %v", err)
		}
		if intent.Known || len(intent.Set) != 0 {
			t.Errorf("intent = {known %v, %d DS} for a zone holding an mpremove KSK, want unknown and empty",
				intent.Known, len(intent.Set))
		}
	})

	t.Run("a foreign ZSK has no DS and changes nothing", func(t *testing.T) {
		kdb := intentTestKeyDB(t)
		seedKey(t, kdb, "child.example.", DnskeyStateActive, 257, pubA)
		seedKey(t, kdb, "child.example.", DnskeyStateForeign, 256, pubB)

		intent, err := DSIntentForZone(kdb, "child.example.", dns.SHA256)
		if err != nil {
			t.Fatalf("DSIntentForZone: %v", err)
		}
		if !intent.Known || len(intent.Set) != 1 {
			t.Errorf("intent = {known %v, %d DS}, want known with the active KSK's DS", intent.Known, len(intent.Set))
		}
	})
}

// The regression the gated insert prevents: a producer with no DS opinion must
// not add DS records while declining to remove the old ones, which would leave
// the parent holding both.
func TestReplaceUpdateAddsNoDSWhenTheQuestionIsUnanswered(t *testing.T) {
	dk := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "child.example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: pubA,
	}
	ds := dk.ToDS(dns.SHA256)

	m, err := CreateChildReplaceUpdateWithDS("example.", "child.example.",
		[]dns.RR{mustRR(t, "child.example. 3600 IN NS ns1.child.example.")},
		nil, nil, []dns.RR{ds}, false)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, rr := range m.Ns {
		if rr.Header().Rrtype == dns.TypeDS {
			t.Fatalf("an unanswered DS question still produced a DS record: %v", rr)
		}
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
