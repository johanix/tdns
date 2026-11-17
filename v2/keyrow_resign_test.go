/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// keyedZone is a zone signed here with an active KSK and ZSK, loaded, and --
// when signed is true -- serving the DNSKEY RRset its keystore asks for. Its
// re-sign requests land on the returned queue: the write path asks through
// Conf, as the daemons' conf is.
func keyedZone(t *testing.T, signed bool) (*ZoneData, *KeyDB, chan ResignRequest) {
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
		SigValidity:  PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400},
	}
	for _, keytype := range []string{"KSK", "ZSK"} {
		if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive,
			dns.TypeDNSKEY, dns.ED25519, keytype, nil); err != nil {
			t.Fatalf("generate %s: %v", keytype, err)
		}
	}
	if signed {
		if _, err := zd.SignZone(context.Background(), kdb, false); err != nil {
			t.Fatalf("SignZone: %v", err)
		}
	}

	q := make(chan ResignRequest, 4)
	prev := Conf.Internal.ResignQ
	Conf.Internal.ResignQ = q
	t.Cleanup(func() { Conf.Internal.ResignQ = prev })
	return zd, kdb, q
}

func servesKey(zd *ZoneData, pkc *PrivateKeyCache) bool {
	rrset := getRRsetFrom(zd.publishedSnapshot(), zd.ZoneName, dns.TypeDNSKEY)
	if rrset == nil {
		return false
	}
	_, ok := keyIdentities(rrset.RRs)[dnskeyIdentity(&pkc.DnskeyRR)]
	return ok
}

// waitServes waits for the resigner to bring the served DNSKEY RRset to want
// for pkc.
func waitServes(t *testing.T, zd *ZoneData, pkc *PrivateKeyCache, want bool, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for servesKey(zd, pkc) != want {
		if time.Now().After(deadline) {
			t.Fatalf("%s: key %d served=%v ten seconds after the write, want %v", what,
				pkc.KeyId, !want, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// An owner (tdns-mp's key lifecycle) publishes and removes keys with
// UpdateKeyRowFrom and asks for a re-sign only when it promotes one. The
// served DNSKEY RRset is rebuilt only by a signing pass, so the owning signer
// served a published key late and a removed one long after its removal (#918).
// The write itself now asks; nothing else here does.
func TestAnOwnersPubWritesReachTheServedDnskeyRRset(t *testing.T) {
	zd, kdb, q := keyedZone(t, true)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { ResignerEngine(ctx, q); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	pkc, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateCreated,
		dns.TypeDNSKEY, dns.ED25519, "ZSK", nil)
	if err != nil {
		t.Fatalf("generate ZSK: %v", err)
	}
	if servesKey(zd, pkc) {
		t.Fatal("test setup: a created key is already served")
	}

	if err := UpdateKeyRowFrom(kdb, zd.ZoneName, pkc.KeyId, DnskeyStatePublished,
		DnskeyStateCreated, KeyRowFlags{Pub: true}); err != nil {
		t.Fatalf("publish write: %v", err)
	}
	waitServes(t, zd, pkc, true, "publish write")

	// The second write proves the first request was taken off the books:
	// were the zone still marked as having one queued, this one would wait.
	if err := UpdateKeyRowFrom(kdb, zd.ZoneName, pkc.KeyId, DnskeyStateRemoved,
		DnskeyStatePublished, KeyRowFlags{}); err != nil {
		t.Fatalf("removal write: %v", err)
	}
	waitServes(t, zd, pkc, false, "removal write")
}

// A write that leaves the served keys as they are asks for nothing: a re-sign
// replaces every signature in the zone, and the DS engine's ds writes and an
// owner's same-state rewrites come on every tick.
func TestAKeyWriteThatLeavesTheServedKeysAloneDoesNotResign(t *testing.T) {
	zd, kdb, q := keyedZone(t, true)

	if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateCreated,
		dns.TypeDNSKEY, dns.ED25519, "ZSK", nil); err != nil {
		t.Fatalf("generate ZSK: %v", err)
	}
	if len(q) != 0 {
		t.Fatal("a key minted unpublished queued a re-sign")
	}

	active, err := GetDnssecKeysByState(kdb, zd.ZoneName, DnskeyStateActive)
	if err != nil || len(active) == 0 {
		t.Fatalf("test setup: active keys %v, err %v", active, err)
	}
	for _, k := range active {
		if err := UpdateKeyRowFrom(kdb, zd.ZoneName, k.KeyTag, DnskeyStateActive,
			DnskeyStateActive, KeyRowFlags{Pub: true, Sign: true}); err != nil {
			t.Fatalf("same-state rewrite of key %d: %v", k.KeyTag, err)
		}
	}
	if len(q) != 0 {
		t.Error("a same-state rewrite of the served keys queued a re-sign")
	}
	if zd.resignPendingSet() {
		t.Error("the zone is marked as owing a replace with nothing changed")
	}
}

// A write can commit and its republish then fail. The error cannot undo the
// write, and without a snapshot nothing can tell whether the served keys
// changed, so the re-sign is asked for anyway: it reads the keys from the
// keystore, or fails and stays owed until it can.
func TestAKeyWriteWhoseRepublishFailsStillResigns(t *testing.T) {
	zd, kdb, q := keyedZone(t, true)

	pkc, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateCreated,
		dns.TypeDNSKEY, dns.ED25519, "ZSK", nil)
	if err != nil {
		t.Fatalf("generate ZSK: %v", err)
	}
	// A signing row whose private key does not parse fails every build.
	if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET privatekey='not a key' WHERE zonename=? AND keyid=?`,
		zd.ZoneName, int(pkc.KeyId)); err != nil {
		t.Fatalf("corrupt the private key: %v", err)
	}

	err = UpdateKeyRowFrom(kdb, zd.ZoneName, pkc.KeyId, DnskeyStateActive,
		DnskeyStateCreated, KeyRowFlags{Pub: true, Sign: true})
	if err == nil {
		t.Fatal("test setup: the republish after the write did not fail")
	}
	if len(q) != 1 {
		t.Errorf("%d re-signs queued after a committed write whose republish failed, want 1;"+
			" the served DNSKEY RRset stays behind the keystore with nothing to retry it", len(q))
	}
}

// A zone not signed yet serves no DNSKEY RRset to bring into line; its first
// signing builds one from the keystore. An owned zone at cold start publishes
// its keys before it can sign, and a re-sign then would fail until the owner
// promotes, and be retried by every sweep.
func TestAKeyWriteDoesNotResignAZoneNotSignedYet(t *testing.T) {
	zd, kdb, q := keyedZone(t, false)

	if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStatePublished,
		dns.TypeDNSKEY, dns.ED25519, "ZSK", nil); err != nil {
		t.Fatalf("generate ZSK: %v", err)
	}
	if len(q) != 0 {
		t.Error("a key write queued a re-sign of a zone that has never been signed")
	}
}

// The write path asks, and most callers ask again after it. One queued
// request covers both: the resigner reads the keystore when it takes it.
func TestAQueuedResignIsNotQueuedTwice(t *testing.T) {
	zd, _, _ := rolledZone(t)
	conf := triggerResignConf(t, zd, 4)

	triggerResign(conf, zd.ZoneName)
	triggerResign(conf, zd.ZoneName)

	if n := len(conf.Internal.ResignQ); n != 1 {
		t.Errorf("%d requests queued, want 1: each one replaces every signature in the zone", n)
	}
	if !zd.resignPendingSet() {
		t.Error("the zone is not marked as owing a replace")
	}
}
