/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"context"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The child publishes CDNSKEY alongside CDS (#753; design
// docs/2026-09-24-cds-publication-and-rfc-conformance.md §4.2, tests §4.4):
// RFC 7344 §4 says to publish both, and a parent applying RFC 9975 §3.1 treats
// a CDS whose keys the CDNSKEY does not name as inconsistent.

// keyIdentitiesOf is the identity set of these keys, as a served CDNSKEY
// RRset naming exactly them has.
func keyIdentitiesOf(keys ...*dns.DNSKEY) map[string]struct{} {
	var rrs []dns.RR
	for _, k := range keys {
		rrs = append(rrs, k)
	}
	return keyIdentities(rrs)
}

func servedCdnskey(t *testing.T, zd *ZoneData) []dns.RR {
	t.Helper()
	rrs, err := servedCdnskeyRRs(zd)
	if err != nil {
		t.Fatalf("read the served CDNSKEY: %v", err)
	}
	return rrs
}

// assertDSSignals: the zone serves the CDS and the CDNSKEY for exactly these
// keys, and the two agree as a parent applying RFC 9975 checks them.
func assertDSSignals(t *testing.T, zd *ZoneData, keys ...*dns.DNSKEY) {
	t.Helper()
	assertServedCDS(t, zd, keys...)
	cdnskey := servedCdnskey(t, zd)
	if got, want := keyIdentities(cdnskey), keyIdentitiesOf(keys...); !sameKeyIdentities(got, want) {
		t.Errorf("served CDNSKEY %v, want the keys %v", cdnskey, keyTags(keys...))
	}
	cds, err := servedCDSRRs(zd)
	if err != nil {
		t.Fatal(err)
	}
	if ok, why := cdnskeyAgreesWithCDS(cds, cdnskey); !ok {
		t.Errorf("the served CDS and CDNSKEY disagree: %s", why)
	}
}

// stageCdnskey publishes the CDNSKEY for keys at the apex directly, as a
// CDNSKEY already on the wire.
func stageCdnskey(t *testing.T, zd *ZoneData, keys ...*dns.DNSKEY) {
	t.Helper()
	var rrs []dns.RR
	for _, k := range keys {
		rrs = append(rrs, cdnskeyOf(zd.ZoneName, k))
	}
	stageApexRRset(t, zd, dns.TypeCDNSKEY, rrs, nil)
}

func assertNoCdnskey(t *testing.T, zd *ZoneData) {
	t.Helper()
	if got := servedCdnskey(t, zd); len(got) != 0 {
		t.Errorf("the zone serves CDNSKEY %v, want none", got)
	}
}

// waitForDSSignals waits until the zone serves the CDS and CDNSKEY for
// exactly these keys.
func waitForDSSignals(t *testing.T, zd *ZoneData, keys ...*dns.DNSKEY) {
	t.Helper()
	want := keyIdentitiesOf(keys...)
	deadline := time.Now().Add(2 * time.Second)
	for !sameKeyIdentities(keyIdentities(servedCdnskey(t, zd)), want) {
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	assertDSSignals(t, zd, keys...)
}

// captureDSEngineLog swaps lgDSEngine for one writing into a buffer.
func captureDSEngineLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := lgDSEngine
	lgDSEngine = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() { lgDSEngine = prev })
	return &buf
}

// Every writer of the CDS writes the matching CDNSKEY, in the same update.
func TestEveryCdsWriterPublishesTheMatchingCdnskey(t *testing.T) {
	ctx := context.Background()

	t.Run("following the keys", func(t *testing.T) {
		r := newSigningRig(t, false)
		r.kdb.followKeysWithCDS(ctx, r.zd)
		assertDSSignals(t, r.zd, r.kskA)
		if events := r.log.snapshot(); len(events) != 1 || events[0] != "published CDS,CDNSKEY" {
			t.Errorf("updates %v, want one that carries both", events)
		}
	})

	t.Run("delegation sync's ensureCDS", func(t *testing.T) {
		r := newSigningRig(t, false)
		if res := r.kdb.ensureCDS(ctx, r.zd); res.err != nil {
			t.Fatalf("ensureCDS: %v", res.err)
		}
		assertDSSignals(t, r.zd, r.kskA)
	})

	t.Run("a standby KSK and a manual roll", func(t *testing.T) {
		r := newSigningRig(t, true)
		kskB := r.genKey(t, DnskeyStatePublished, "KSK")
		r.serveKeys(t)
		r.kdb.KeysChanged(r.zd)
		waitForDSSignals(t, r.zd, r.kskA)
		if err := UpdateDnssecKeyState(r.kdb, "example.", kskB.KeyTag(), DnskeyStateStandby); err != nil {
			t.Fatalf("published -> standby: %v", err)
		}
		waitForDSSignals(t, r.zd, r.kskA, kskB)
		if _, _, err := r.kdb.RolloverKey("example.", "KSK", nil); err != nil {
			t.Fatalf("manual KSK roll: %v", err)
		}
		waitForDSSignals(t, r.zd, kskB)
	})

	t.Run("the multi-DS rollover target, and its cleanup", func(t *testing.T) {
		r := newDSEngineRig(t, 0, false)
		r.zd.DnssecPolicy = &DnssecPolicy{Rollover: RolloverPolicy{Method: RolloverMethodMultiDS}}
		seedKeyWithIndex(t, r.kdb, "example.", DnskeyStateActive, pubA, 3)
		seedKeyWithIndex(t, r.kdb, "example.", DnskeyStateCreated, pubB, 4)

		res := r.kdb.askDSEngine(ctx, DSEngineRequest{cmd: dsCmdEnsureCDS, zd: r.zd})
		if res.err != nil || res.deferred != "" {
			t.Fatalf("ensure: err=%v deferred=%q", res.err, res.deferred)
		}
		// The target includes the key whose DS goes to the parent before its
		// DNSKEY is published: its CDNSKEY comes from the keystore row.
		assertDSSignals(t, r.zd, testKSK("example.", pubA), testKSK("example.", pubB))

		cleanupCdsAfterConfirm(ctx, r.zd, r.kdb)
		if got := servedCDS(t, r.zd); len(got) != 0 {
			t.Errorf("the cleanup left CDS keyids %v", tupleKeyids(got))
		}
		assertNoCdnskey(t, r.zd)
	})

	t.Run("an owned zone, and its restore after a transfer", func(t *testing.T) {
		r := buildDSEngineRig(t, 0, false)
		r.zd.Options = map[ZoneOption]bool{OptAllowUpdates: true, OptMultiProvider: true, OptInlineSigning: true}
		// The owner's DS set names this provider's key and another's.
		seedKey(t, r.kdb, "example.", DnskeyStateActive, 257, pubA)
		seedKey(t, r.kdb, "example.", DnskeyStateForeign, 257, pubB)
		installOwner(t, &testOwner{owns: map[string]bool{"example.": true},
			intent: map[string]DSIntent{"example.": {Set: dsFor("example.", pubA, pubB), Known: true}}})

		r.kdb.followKeysWithCDS(ctx, r.zd)
		assertDSSignals(t, r.zd, testKSK("example.", pubA), testKSK("example.", pubB))

		var cds, cdnskey []dns.RR
		for _, rs := range r.zd.CollectDynamicRRs(&Config{}) {
			switch rs.RRtype {
			case dns.TypeCDS:
				cds = rs.RRs
			case dns.TypeCDNSKEY:
				cdnskey = rs.RRs
			}
		}
		if got, want := keyIdentities(cdnskey), keyIdentitiesOf(testKSK("example.", pubA), testKSK("example.", pubB)); !sameKeyIdentities(got, want) {
			t.Errorf("the collector's CDNSKEY %v, want the owner's two keys", cdnskey)
		}
		if ok, why := cdnskeyAgreesWithCDS(cds, cdnskey); !ok {
			t.Errorf("the collector's CDS and CDNSKEY disagree: %s", why)
		}
	})

	t.Run("PublishCDSAndWait, for an owner", func(t *testing.T) {
		r := newSigningRig(t, false)
		if err := r.zd.PublishCDSAndWait(ctx, r.kdb, cdsOfKeys("example.", r.kskA)); err != nil {
			t.Fatalf("PublishCDSAndWait: %v", err)
		}
		assertDSSignals(t, r.zd, r.kskA)
	})

	t.Run("PublishCdsRRs, for tdns-mp", func(t *testing.T) {
		r := newSigningRig(t, false)
		if err := r.zd.PublishCdsRRs(); err != nil {
			t.Fatalf("PublishCdsRRs: %v", err)
		}
		waitForDSSignals(t, r.zd, r.kskA)
	})
}

// Every withdrawal of the CDS withdraws the CDNSKEY.
func TestWithdrawingTheCdsWithdrawsTheCdnskey(t *testing.T) {
	ctx := context.Background()

	t.Run("unpublish", func(t *testing.T) {
		r := newSigningRig(t, false)
		r.kdb.followKeysWithCDS(ctx, r.zd)
		assertDSSignals(t, r.zd, r.kskA)
		if err := r.zd.UnpublishCDSAndWait(ctx, r.kdb); err != nil {
			t.Fatalf("UnpublishCDSAndWait: %v", err)
		}
		if got := servedCDS(t, r.zd); len(got) != 0 {
			t.Errorf("CDS keyids %v left", tupleKeyids(got))
		}
		assertNoCdnskey(t, r.zd)
	})

	t.Run("no key warrants a DS any more", func(t *testing.T) {
		r := newSigningRig(t, false)
		r.kdb.followKeysWithCDS(ctx, r.zd)
		assertDSSignals(t, r.zd, r.kskA)
		if _, err := r.kdb.DB.Exec(`UPDATE DnssecKeyStore SET ds=0 WHERE zonename=?`, "example."); err != nil {
			t.Fatal(err)
		}
		r.kdb.followKeysWithCDS(ctx, r.zd)
		if got := servedCDS(t, r.zd); len(got) != 0 {
			t.Errorf("CDS keyids %v left", tupleKeyids(got))
		}
		assertNoCdnskey(t, r.zd)
	})

	t.Run("a CDNSKEY left without its CDS", func(t *testing.T) {
		r := newSigningRig(t, false)
		stageCdnskey(t, r.zd, r.kskA)
		if _, err := r.kdb.DB.Exec(`UPDATE DnssecKeyStore SET ds=0 WHERE zonename=?`, "example."); err != nil {
			t.Fatal(err)
		}
		r.kdb.followKeysWithCDS(ctx, r.zd)
		assertNoCdnskey(t, r.zd)
	})

	t.Run("UnpublishCdsRRs, for tdns-mp", func(t *testing.T) {
		r := newSigningRig(t, false)
		r.kdb.followKeysWithCDS(ctx, r.zd)
		if err := r.zd.UnpublishCdsRRs(); err != nil {
			t.Fatalf("UnpublishCdsRRs: %v", err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for len(servedCdnskey(t, r.zd)) > 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		assertNoCdnskey(t, r.zd)
	})
}

// cdnskey: false publishes the CDS alone. Turning it on or off reaches a zone
// whose CDS is already in step on the next run, in both directions: the
// comparison covers the CDNSKEY, not only the CDS.
func TestCdnskeyFalsePublishesTheCdsAlone(t *testing.T) {
	ctx := context.Background()
	r := newSigningRig(t, false)
	r.zd.DnssecPolicy.SuppressCDNSKEY = true

	r.kdb.followKeysWithCDS(ctx, r.zd)
	assertServedCDS(t, r.zd, r.kskA)
	assertNoCdnskey(t, r.zd)

	r.zd.DnssecPolicy.SuppressCDNSKEY = false
	r.kdb.followKeysWithCDS(ctx, r.zd)
	assertDSSignals(t, r.zd, r.kskA)

	r.zd.DnssecPolicy.SuppressCDNSKEY = true
	r.kdb.followKeysWithCDS(ctx, r.zd)
	assertServedCDS(t, r.zd, r.kskA)
	assertNoCdnskey(t, r.zd)
}

func TestTheCdnskeyPolicySetting(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  *bool
		want bool // SuppressCDNSKEY
	}{
		{"unset", nil, false},
		{"true", ptrBool(true), false},
		{"false", ptrBool(false), true},
	} {
		conf := DnssecPolicyConf{Algorithm: "ED25519", Cdnskey: tc.set}
		conf.KSK.Lifetime = "forever"
		conf.ZSK.Lifetime = "forever"
		conf.SigValidity.Default = "14d"
		pol, err := ParseDnssecPolicyConfQuiet("p", &conf)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if pol.SuppressCDNSKEY != tc.want {
			t.Errorf("cdnskey %s: SuppressCDNSKEY %v, want %v", tc.name, pol.SuppressCDNSKEY, tc.want)
		}
	}
	// An explicit value in a policy wins over its template's, as for cds.
	tmpl := DnssecPolicyConf{Cdnskey: ptrBool(false)}
	if got := ExpandPolicyTemplate(DnssecPolicyConf{Cdnskey: ptrBool(true)}, &tmpl); got.Cdnskey == nil || !*got.Cdnskey {
		t.Errorf("the template's cdnskey: false overrode the policy's true")
	}
	if got := ExpandPolicyTemplate(DnssecPolicyConf{}, &tmpl); got.Cdnskey == nil || *got.Cdnskey {
		t.Errorf("a policy without cdnskey did not inherit the template's false")
	}
}

func ptrBool(b bool) *bool { return &b }

// A zone that serves the CDS its keys call for but no CDNSKEY -- one signed by
// a build from before #753 -- gets its CDNSKEY on the next run, from the
// follow path and from ensureCDS alike. A zone serving both, in step,
// publishes nothing.
func TestACdsInStepWithoutItsCdnskeyIsCompleted(t *testing.T) {
	ctx := context.Background()

	t.Run("following the keys", func(t *testing.T) {
		r := newSigningRig(t, false)
		stageCDS(t, r.zd, cdsOfKeys("example.", r.kskA))
		r.kdb.followKeysWithCDS(ctx, r.zd)
		assertDSSignals(t, r.zd, r.kskA)
	})

	t.Run("ensureCDS", func(t *testing.T) {
		r := newSigningRig(t, false)
		stageCDS(t, r.zd, cdsOfKeys("example.", r.kskA))
		if res := r.kdb.ensureCDS(ctx, r.zd); res.err != nil {
			t.Fatalf("ensureCDS: %v", res.err)
		}
		assertDSSignals(t, r.zd, r.kskA)
	})

	t.Run("both in step", func(t *testing.T) {
		r := newSigningRig(t, false)
		stageCDS(t, r.zd, cdsOfKeys("example.", r.kskA))
		stageApexRRset(t, r.zd, dns.TypeCDNSKEY, []dns.RR{cdnskeyOf("example.", r.kskA)}, nil)
		r.kdb.followKeysWithCDS(ctx, r.zd)
		if res := r.kdb.ensureCDS(ctx, r.zd); res.err != nil {
			t.Fatalf("ensureCDS: %v", res.err)
		}
		if events := r.log.snapshot(); len(events) != 0 {
			t.Errorf("CDS and CDNSKEY already in step were republished: %v", events)
		}
	})

	t.Run("a hand-added CDNSKEY is replaced", func(t *testing.T) {
		r := newSigningRig(t, false)
		stageCDS(t, r.zd, cdsOfKeys("example.", r.kskA))
		stageApexRRset(t, r.zd, dns.TypeCDNSKEY, []dns.RR{cdnskeyOf("example.", testKSK("example.", pubB))}, nil)
		r.kdb.followKeysWithCDS(ctx, r.zd)
		assertDSSignals(t, r.zd, r.kskA)
	})
}

// A CDS naming a key tdns holds no copy of is published alone, and says so:
// an owner's DS set naming another provider's key with no row here.
func TestACdsNamingAKeyWithNoRowIsPublishedAlone(t *testing.T) {
	logbuf := captureDSEngineLog(t)
	r := buildDSEngineRig(t, 0, false)
	r.zd.Options = map[ZoneOption]bool{OptAllowUpdates: true, OptMultiProvider: true, OptInlineSigning: true}
	seedKey(t, r.kdb, "example.", DnskeyStateActive, 257, pubA)
	installOwner(t, &testOwner{owns: map[string]bool{"example.": true},
		intent: map[string]DSIntent{"example.": {Set: dsFor("example.", pubA, pubB), Known: true}}})

	r.kdb.followKeysWithCDS(context.Background(), r.zd)

	if got, want := servedCDS(t, r.zd), cdsTuplesOf(cdsFor("example.", pubA, pubB)); !cdsTupleSetsEqual(got, want) {
		t.Errorf("served CDS keyids %v, want %v", tupleKeyids(got), tupleKeyids(want))
	}
	assertNoCdnskey(t, r.zd)
	missing := testKSK("example.", pubB).KeyTag()
	var warned bool
	for _, line := range strings.Split(logbuf.String(), "\n") {
		if strings.Contains(line, "level=WARN") && strings.Contains(line, "CDNSKEY") &&
			strings.Contains(line, "keyids") && strings.Contains(line, strconv.Itoa(int(missing))) {
			warned = true
		}
	}
	if !warned {
		t.Errorf("no warning naming key %d as the reason the CDS is published alone:\n%s", missing, logbuf.String())
	}
}

// I7 also compares the served CDNSKEY with the served CDS.
func TestCheckerI7ServedCdnskeyMatchesTheCds(t *testing.T) {
	c := newCheckerZone(t)
	c.rawExec(t, `UPDATE DnssecKeyStore SET ds = CASE state WHEN 'active' THEN 1 ELSE 0 END WHERE zonename=? AND (flags & 1) = 1`, c.zd.ZoneName)
	active := parseRR(t, c.row(DnskeyStateActive, "KSK").KeyRR).(*dns.DNSKEY)
	created := parseRR(t, c.row(DnskeyStateCreated, "KSK").KeyRR).(*dns.DNSKEY)
	stageApexRRset(t, c.zd, dns.TypeCDS, cdsOfKeys(c.zd.ZoneName, active), nil)
	stageApexRRset(t, c.zd, dns.TypeCDNSKEY, []dns.RR{cdnskeyOf(c.zd.ZoneName, active)}, nil)
	if vs := CheckKeyInvariants(c.kdb, c.zd); len(vs) != 0 {
		t.Fatalf("CDS and CDNSKEY in step: %s", violationList(vs))
	}
	stageApexRRset(t, c.zd, dns.TypeCDNSKEY, []dns.RR{cdnskeyOf(c.zd.ZoneName, created)}, nil)
	expectOnly(t, CheckKeyInvariants(c.kdb, c.zd), "I7")
}
