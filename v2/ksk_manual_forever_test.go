/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// manualForeverZone builds a multi-DS zone whose KSK lifetime schedules no
// roll, with one successor KSK waiting in ds-published: its DS is at the
// parent, its DNSKEY is not in the zone. That is where a manual rollover
// starts from on such a zone.
func manualForeverZone(t *testing.T, lifetime uint32) (*ZoneData, *KeyDB, uint16, RolloverEngineDeps) {
	t.Helper()
	kdb := newTestKeyDB(t)
	zd := testZone(t, "forever.example.", `forever.example. 3600 IN SOA ns.forever.example. h.forever.example. 1 3600 600 604800 300
forever.example. 3600 IN NS ns.forever.example.
ns.forever.example. 3600 IN A 192.0.2.1
`)
	registerZones(t, zd)
	zd.KeyDB = kdb
	pol := &DnssecPolicy{
		Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.ED25519, ZSKAlgorithm: dns.ED25519,
		KSK:      KeyLifetime{Lifetime: lifetime},
		Rollover: RolloverPolicy{Method: RolloverMethodMultiDS},
		TTLS:     DnssecPolicyTTLS{DNSKEY: 3600},
	}
	zd.DnssecPolicy = pol

	if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive,
		dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("active KSK: %v", err)
	}
	succ, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateDsPublished,
		dns.TypeDNSKEY, dns.ED25519, "KSK", nil)
	if err != nil {
		t.Fatalf("ds-published KSK: %v", err)
	}
	tag := succ.DnskeyRR.KeyTag()
	if err := setRolloverKeyDsObservedAt(kdb, zd.ZoneName, tag, time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatalf("ds_observed_at: %v", err)
	}

	deps := RolloverEngineDeps{
		Conf: &Config{}, KDB: kdb, Zone: zd, Policy: pol,
		Logger:           lgSigner,
		PropagationDelay: time.Hour,
		Now:              time.Now,
	}
	return zd, kdb, tag, deps
}

func dsPublishedKSKs(t *testing.T, kdb *KeyDB, zone string) []*DnssecKeyWithTimestamps {
	t.Helper()
	keys, err := GetDnssecKeysByState(kdb, zone, DnskeyStateDsPublished)
	if err != nil {
		t.Fatalf("GetDnssecKeysByState: %v", err)
	}
	var out []*DnssecKeyWithTimestamps
	for i := range keys {
		if keys[i].Flags&dns.SEP != 0 {
			out = append(out, &keys[i])
		}
	}
	return out
}

func keyState(t *testing.T, kdb *KeyDB, zone string, tag uint16) string {
	t.Helper()
	for _, st := range []string{DnskeyStateDsPublished, DnskeyStatePublished, DnskeyStateStandby, DnskeyStateActive} {
		ks, err := GetDnssecKeysByState(kdb, zone, st)
		if err != nil {
			t.Fatalf("GetDnssecKeysByState(%s): %v", st, err)
		}
		for i := range ks {
			if ks[i].KeyTag == tag {
				return st
			}
		}
	}
	return "?"
}

// TestAManualRolloverOnAForeverZoneGetsItsSuccessorPublished.
//
// rolloverDue needs a standby before it will honour a manual request, and a
// multi-DS successor only becomes one via ds-published -> published -> standby.
// The first step was skipped outright for any lifetime that schedules no roll,
// so on such a zone `rollover asap` stayed pending and the successor stayed in
// ds-published indefinitely.
func TestAManualRolloverOnAForeverZoneGetsItsSuccessorPublished(t *testing.T) {
	for _, tc := range []struct {
		name     string
		lifetime uint32
	}{
		{"forever", foreverLifetimeSecs},
		{"unset", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zd, kdb, tag, deps := manualForeverZone(t, tc.lifetime)
			now := time.Now()
			if err := SetManualRolloverRequest(kdb, zd.ZoneName, now, now); err != nil {
				t.Fatalf("SetManualRolloverRequest: %v", err)
			}

			transitionDsPublishedToPublishedForZone(deps, dsPublishedKSKs(t, kdb, zd.ZoneName))

			if st := keyState(t, kdb, zd.ZoneName, tag); st != DnskeyStatePublished {
				t.Errorf("successor is %s, want %s; the manual rollover can never find a"+
					" standby and stays pending", st, DnskeyStatePublished)
			}
		})
	}
}

// The reason the step was skipped still holds. A DNSKEY reveals the public key
// and a DS does not; multi-DS exists to keep future keys' DNSKEYs out of the
// zone until they are needed. With no schedule and no request, nothing needs
// one.
func TestWithNoRequestAForeverZoneKeepsItsSuccessorOutOfTheZone(t *testing.T) {
	zd, kdb, tag, deps := manualForeverZone(t, foreverLifetimeSecs)

	transitionDsPublishedToPublishedForZone(deps, dsPublishedKSKs(t, kdb, zd.ZoneName))

	if st := keyState(t, kdb, zd.ZoneName, tag); st != DnskeyStateDsPublished {
		t.Errorf("successor moved to %s with no rollover requested; its DNSKEY is now in the"+
			" zone ahead of any need, which is exactly what multi-DS exists to prevent", st)
	}
}

// A request for a roll well in the future publishes nothing yet: the E12
// margin applies to the manual T_roll exactly as to a scheduled one.
func TestAManualRolloverScheduledLaterWaitsForItsPublishTime(t *testing.T) {
	zd, kdb, tag, deps := manualForeverZone(t, foreverLifetimeSecs)
	later := time.Now().Add(30 * 24 * time.Hour)
	if err := SetManualRolloverRequest(kdb, zd.ZoneName, time.Now(), later); err != nil {
		t.Fatalf("SetManualRolloverRequest: %v", err)
	}

	transitionDsPublishedToPublishedForZone(deps, dsPublishedKSKs(t, kdb, zd.ZoneName))

	if st := keyState(t, kdb, zd.ZoneName, tag); st != DnskeyStateDsPublished {
		t.Errorf("successor published a month ahead of a roll requested for %s; the DNSKEY"+
			" should wait until T_roll - propagation - TTL", later.Format(time.RFC3339))
	}
}
