package tdns

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// tdns#709: a fresh key whose tag the zone already uses must not take that
// key's row. The mint draws again, and the insert never replaces.

// stubKeyMaterial replaces generateKeyMaterial for the test. pick sees the
// call number, from 1; a nil answer draws a real key. It returns the count.
func stubKeyMaterial(t *testing.T, pick func(call int) *PrivateKeyCache) *int {
	t.Helper()
	prev := generateKeyMaterial
	t.Cleanup(func() { generateKeyMaterial = prev })
	calls := 0
	generateKeyMaterial = func(owner string, rrtype uint16, alg uint8, keytype string) (*PrivateKeyCache, error) {
		calls++
		if pkc := pick(calls); pkc != nil {
			return pkc, nil
		}
		return prev(owner, rrtype, alg, keytype)
	}
	return &calls
}

// captureDnsLog swaps lgDns for one writing into a buffer.
func captureDnsLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := lgDns
	lgDns = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() { lgDns = prev })
	return &buf
}

type keyStoreRow struct{ state, privkey, keyrr string }

func readKeyStoreRow(t *testing.T, kdb *KeyDB, table, zone string, keyid uint16) keyStoreRow {
	t.Helper()
	var r keyStoreRow
	err := kdb.DB.QueryRow("SELECT state, privatekey, keyrr FROM "+table+" WHERE zonename=? AND keyid=?",
		zone, int(keyid)).Scan(&r.state, &r.privkey, &r.keyrr)
	if err != nil {
		t.Fatalf("%s %s keyid %d: %v", table, zone, keyid, err)
	}
	return r
}

func countKeyStoreRows(t *testing.T, kdb *KeyDB, table, zone string) int {
	t.Helper()
	var n int
	if err := kdb.DB.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE zonename=?", zone).Scan(&n); err != nil {
		t.Fatalf("count %s %s: %v", table, zone, err)
	}
	return n
}

// seedDnskey stores fresh ZSK material for zone in the given state and
// returns it, so a stub can hand the same key tag out again.
func seedDnskey(t *testing.T, kdb *KeyDB, zone, state string) *PrivateKeyCache {
	t.Helper()
	pkc, err := GenerateKeyMaterial(zone, dns.TypeDNSKEY, dns.ED25519, "ZSK")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := kdb.Begin("seedDnskey")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertKeyRowTx(tx, KeyRow{
		Zone: zone, State: state, Keyid: pkc.KeyId, Flags: pkc.DnskeyRR.Flags,
		Algorithm: dns.AlgorithmToString[pkc.Algorithm], Creator: "test",
		PrivateKey: pkc.PrivateKey, KeyRR: pkc.DnskeyRR.String(),
	}); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return pkc
}

// Any state holds its tag: the active key, and a removed one, which nothing
// purges.
func TestGenerateKeypairRedrawsUsedKeyTag(t *testing.T) {
	for _, state := range []string{DnskeyStateActive, DnskeyStateRemoved} {
		t.Run(state, func(t *testing.T) {
			kdb := newTestKeyDB(t)
			zone := "tagclash.example."
			old := seedDnskey(t, kdb, zone, state)
			before := readKeyStoreRow(t, kdb, "DnssecKeyStore", zone, old.KeyId)

			logbuf := captureDnsLog(t)
			calls := stubKeyMaterial(t, func(call int) *PrivateKeyCache {
				if call == 1 {
					return old
				}
				return nil
			})
			pkc, _, err := kdb.GenerateKeypair(zone, "test", DnskeyStateCreated, dns.TypeDNSKEY, dns.ED25519, "ZSK", nil)
			if err != nil {
				t.Fatalf("GenerateKeypair: %v", err)
			}
			if pkc.KeyId == old.KeyId {
				t.Fatalf("new key has the used tag %d", old.KeyId)
			}
			if *calls < 2 {
				t.Errorf("generator called %d times, want a second draw", *calls)
			}
			if after := readKeyStoreRow(t, kdb, "DnssecKeyStore", zone, old.KeyId); after != before {
				t.Errorf("key %d changed:\n before %+v\n after  %+v", old.KeyId, before, after)
			}
			if got := readKeyStoreRow(t, kdb, "DnssecKeyStore", zone, pkc.KeyId).state; got != DnskeyStateCreated {
				t.Errorf("new key %d state %q, want %q", pkc.KeyId, got, DnskeyStateCreated)
			}
			if n := countKeyStoreRows(t, kdb, "DnssecKeyStore", zone); n != 2 {
				t.Errorf("%d rows for %s, want 2", n, zone)
			}
			if log := logbuf.String(); !strings.Contains(log, "key tag is in use") || !strings.Contains(log, fmt.Sprintf("keyid=%d", old.KeyId)) {
				t.Errorf("no info line naming key tag %d; log:\n%s", old.KeyId, log)
			}
		})
	}
}

func TestGenerateKeypairGivesUpOnUsedKeyTags(t *testing.T) {
	kdb := newTestKeyDB(t)
	zone := "tagclash.example."
	old := seedDnskey(t, kdb, zone, DnskeyStateActive)
	before := readKeyStoreRow(t, kdb, "DnssecKeyStore", zone, old.KeyId)

	calls := stubKeyMaterial(t, func(int) *PrivateKeyCache { return old })
	if _, _, err := kdb.GenerateKeypair(zone, "test", DnskeyStateCreated, dns.TypeDNSKEY, dns.ED25519, "ZSK", nil); err == nil {
		t.Fatal("GenerateKeypair succeeded with every draw on a used tag")
	}
	if *calls != maxKeyTagDraws {
		t.Errorf("generator called %d times, want %d", *calls, maxKeyTagDraws)
	}
	if after := readKeyStoreRow(t, kdb, "DnssecKeyStore", zone, old.KeyId); after != before {
		t.Errorf("key %d changed:\n before %+v\n after  %+v", old.KeyId, before, after)
	}
	if n := countKeyStoreRows(t, kdb, "DnssecKeyStore", zone); n != 1 {
		t.Errorf("%d rows for %s, want 1", n, zone)
	}
}

func TestGenerateKeypairRedrawsUsedSig0KeyTag(t *testing.T) {
	kdb := newTestKeyDB(t)
	zone := "tagclash.example."
	old, _, err := kdb.GenerateKeypair(zone, "test", "active", dns.TypeKEY, dns.ED25519, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	before := readKeyStoreRow(t, kdb, "Sig0KeyStore", zone, old.KeyId)

	calls := stubKeyMaterial(t, func(call int) *PrivateKeyCache {
		if call == 1 {
			return old
		}
		return nil
	})
	pkc, _, err := kdb.GenerateKeypair(zone, "test", "created", dns.TypeKEY, dns.ED25519, "", nil)
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if pkc.KeyId == old.KeyId {
		t.Fatalf("new key has the used tag %d", old.KeyId)
	}
	if *calls < 2 {
		t.Errorf("generator called %d times, want a second draw", *calls)
	}
	if after := readKeyStoreRow(t, kdb, "Sig0KeyStore", zone, old.KeyId); after != before {
		t.Errorf("key %d changed:\n before %+v\n after  %+v", old.KeyId, before, after)
	}
	if n := countKeyStoreRows(t, kdb, "Sig0KeyStore", zone); n != 2 {
		t.Errorf("%d rows for %s, want 2", n, zone)
	}
}

// The backstop for a collision the check cannot see: without Replace the
// insert fails on the unique constraint and the row stays.
func TestInsertKeyRowWithoutReplaceRefusesUsedKeyTag(t *testing.T) {
	kdb := newTestKeyDB(t)
	zone := "tagclash.example."
	old := seedDnskey(t, kdb, zone, DnskeyStateActive)
	before := readKeyStoreRow(t, kdb, "DnssecKeyStore", zone, old.KeyId)

	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatal(err)
	}
	err = insertKeyRowTx(tx, KeyRow{
		Zone: zone, State: DnskeyStateCreated, Keyid: old.KeyId, Flags: old.DnskeyRR.Flags,
		Algorithm: dns.AlgorithmToString[old.Algorithm], Creator: "test",
		PrivateKey: "not the key", KeyRR: old.DnskeyRR.String(),
	})
	tx.Rollback()
	if err == nil || !strings.Contains(err.Error(), "UNIQUE") {
		t.Fatalf("insert over key %d: err %v, want the unique constraint", old.KeyId, err)
	}
	if after := readKeyStoreRow(t, kdb, "DnssecKeyStore", zone, old.KeyId); after != before {
		t.Errorf("key %d changed:\n before %+v\n after  %+v", old.KeyId, before, after)
	}
}
