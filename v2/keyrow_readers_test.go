package tdns

import (
	"context"
	"sort"
	"testing"

	"github.com/miekg/dns"
)

// The readers of pub and sign (design §3.3): the served DNSKEY RRset is the
// pub=1 rows, once each; the signing set is the sign=1 rows, whatever their
// state says.

func dnskeyIdentities(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		if _, ok := rr.(*dns.DNSKEY); ok {
			out = append(out, dnskeyIdentity(rr))
		}
	}
	sort.Strings(out)
	return out
}

func pubRowIdentities(t *testing.T, kdb *KeyDB, zone string) []string {
	t.Helper()
	rows, err := kdb.Query(`SELECT keyrr FROM DnssecKeyStore WHERE zonename=? AND pub=1`, zone)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var keyrr string
		if err := rows.Scan(&keyrr); err != nil {
			t.Fatal(err)
		}
		out = append(out, dnskeyIdentity(parseRR(t, keyrr)))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestServedDnskeyRRsetIsThePubRowsOnceEach(t *testing.T) {
	const zone = "example."
	kdb := newTestKeyDB(t)
	zd := testZone(t, zone, csyncTestZone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptOnlineSigning: true}

	genKey(t, kdb, zone, DnskeyStateActive, "KSK")
	genKey(t, kdb, zone, DnskeyStateActive, "ZSK")
	genKey(t, kdb, zone, DnskeyStateStandby, "ZSK")
	genKey(t, kdb, zone, DnskeyStateRetired, "ZSK")
	genKey(t, kdb, zone, DnskeyStateCreated, "KSK")
	genKey(t, kdb, zone, DnskeyStateRemoved, "ZSK")
	tx, err := kdb.Begin("foreign")
	if err != nil {
		t.Fatal(err)
	}
	if err := InsertKeyRowTx(tx, testKeyRow(zone, ownerStateForeign, "KSK", newTestRand(21))); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	want := pubRowIdentities(t, kdb, zone)
	if len(want) != 5 {
		t.Fatalf("pub=1 rows: %d, want 5 (active x2, standby, retired, foreign)", len(want))
	}

	dak, err := kdb.GetDnssecKeys(zone, DnskeyStateActive)
	if err != nil {
		t.Fatal(err)
	}
	if err := zd.PublishDnskeyRRs(dak); err != nil {
		t.Fatalf("PublishDnskeyRRs: %v", err)
	}
	// PublishDnskeyRRs stages; the publish path swaps the snapshot in later.
	zd.mu.Lock()
	zd.publishLocked(zd.generation.Load())
	zd.mu.Unlock()
	served, err := zd.RRsetForAnalysis(zone, dns.TypeDNSKEY)
	if err != nil || served == nil {
		t.Fatalf("served DNSKEY RRset: %v", err)
	}
	if got := dnskeyIdentities(served.RRs); !equalStrings(got, want) {
		t.Errorf("served DNSKEY RRset has %d keys %v, want the %d pub=1 rows %v", len(got), got, len(want), want)
	}

	// The refresh-time collector builds the same set from the same helper.
	var collected []dns.RR
	for _, rs := range zd.CollectDynamicRRs(&Config{}) {
		if rs.RRtype == dns.TypeDNSKEY {
			collected = rs.RRs
		}
	}
	if got := dnskeyIdentities(collected); !equalStrings(got, want) {
		t.Errorf("CollectDynamicRRs has %d keys %v, want %v", len(got), got, want)
	}
}

// D3: the signer reads sign, not the state. A row whose owner set sign on a
// state that is not "active" signs; a row in state active with sign cleared
// does not.
func TestSigningKeysFollowTheSignColumnNotTheState(t *testing.T) {
	const zone = "columns.example."
	kdb := newTestKeyDB(t)
	ksk := genKey(t, kdb, zone, DnskeyStateActive, "KSK")
	signingStandby := genKey(t, kdb, zone, DnskeyStateStandby, "ZSK")
	idleActive := genKey(t, kdb, zone, DnskeyStateActive, "ZSK")
	if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET sign=1 WHERE zonename=? AND keyid=?`, zone, signingStandby); err != nil {
		t.Fatal(err)
	}
	if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET sign=0 WHERE zonename=? AND keyid=?`, zone, idleActive); err != nil {
		t.Fatal(err)
	}
	dak, err := kdb.GetDnssecKeys(zone, DnskeyStateActive)
	if err != nil {
		t.Fatal(err)
	}
	var got []uint16
	for _, k := range dak.KSKs {
		got = append(got, k.KeyId)
	}
	for _, k := range dak.ZSKs {
		got = append(got, k.KeyId)
	}
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	want := []uint16{ksk, signingStandby}
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("signing keys %v, want %v (sign=1 rows: the KSK and the standby the owner released)", got, want)
	}
	rowsSigning, err := GetSigningKeyRows(kdb, zone)
	if err != nil {
		t.Fatal(err)
	}
	if len(rowsSigning) != 2 {
		t.Errorf("GetSigningKeyRows: %d rows, want 2", len(rowsSigning))
	}
}

func genKey(t *testing.T, kdb *KeyDB, zone, state, role string) uint16 {
	t.Helper()
	pkc, _, err := kdb.GenerateKeypair(zone, "test", state, dns.TypeDNSKEY, dns.ED25519, role, nil)
	if err != nil {
		t.Fatalf("generate %s %s: %v", state, role, err)
	}
	return pkc.KeyId
}

func servedDnskeyTags(t *testing.T, zd *ZoneData) map[uint16]bool {
	t.Helper()
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("GetOwner(apex): owner=%v err=%v", apex, err)
	}
	tags := map[uint16]bool{}
	for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs {
		tags[rr.(*dns.DNSKEY).KeyTag()] = true
	}
	return tags
}

// Rows in an owner's served-only states (another provider's foreign key, a
// key of our own on its way out to the other providers) are in the served
// DNSKEY RRset, from a sign and from a refresh, and neither ever signs
// anything: the readers go by pub and sign, not by the state's name.
func TestOwnerStateRowsAreServedAndNeverSign(t *testing.T) {
	zd := loadIxfrTestZone(t, basicZone)
	kdb := makeZoneSigning(t, zd)
	active, err := kdb.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil || len(active.KSKs) != 1 || len(active.ZSKs) != 1 {
		t.Fatalf("active keys: %v %v", active, err)
	}
	activeTags := map[uint16]bool{active.KSKs[0].KeyId: true, active.ZSKs[0].KeyId: true}

	// A foreign key: another signer's public DNSKEY, no private half.
	foreign, err := GenerateKeyMaterial(zd.ZoneName, dns.TypeDNSKEY, dns.ED25519, "ZSK")
	if err != nil {
		t.Fatalf("GenerateKeyMaterial: %v", err)
	}
	foreignTag := foreign.DnskeyRR.KeyTag()
	// Written as an owner writes a foreign row: through InsertKeyRowTx, so
	// the row carries pub from its registered state.
	tx, err := kdb.Begin("foreign")
	if err != nil {
		t.Fatal(err)
	}
	if err := InsertKeyRowTx(tx, KeyRow{
		Zone: zd.ZoneName, State: ownerStateForeign, Keyid: foreignTag, Flags: 256,
		Algorithm: dns.AlgorithmToString[dns.ED25519], Creator: "test", KeyRR: foreign.DnskeyRR.String(),
	}); err != nil {
		tx.Rollback()
		t.Fatalf("insert foreign row: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	stagedTag := genKey(t, kdb, zd.ZoneName, ownerStateMpdist, "ZSK")

	if _, err := zd.SignZone(context.Background(), kdb, false); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	check := func(when string) {
		t.Helper()
		served := servedDnskeyTags(t, zd)
		for tag, why := range map[uint16]string{foreignTag: ownerStateForeign, stagedTag: ownerStateMpdist, active.KSKs[0].KeyId: "active KSK", active.ZSKs[0].KeyId: "active ZSK"} {
			if !served[tag] {
				t.Errorf("%s: the %s key %d is not in the served DNSKEY RRset %v", when, why, tag, served)
			}
		}
		for _, rrtype := range []uint16{dns.TypeSOA, dns.TypeDNSKEY} {
			for _, tag := range zd.mustRRSIGKeytags(t, zd.ZoneName, rrtype) {
				if !activeTags[tag] {
					t.Errorf("%s: %s signed by key %d, which is not an active key", when, dns.TypeToString[rrtype], tag)
				}
			}
		}
		for _, tag := range zd.mustRRSIGKeytags(t, signedName, dns.TypeA) {
			if !activeTags[tag] {
				t.Errorf("%s: %s A signed by key %d, which is not an active key", when, signedName, tag)
			}
		}
	}
	check("after SignZone")

	// A refresh rebuilds the RRset from the keystore: the same predicate, so
	// the same set.
	dynamic := zd.CollectDynamicRRs(&Config{})
	newZd := draftZone(t, zd.ZoneName, basicZone)
	zd.mu.Lock()
	err = zd.applyRefreshReplacementLocked(newZd, dynamic, false, true)
	zd.mu.Unlock()
	if err != nil {
		t.Fatalf("applyRefreshReplacementLocked: %v", err)
	}
	check("after a refresh")
}
