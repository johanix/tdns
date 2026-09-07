/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * ZONE-UPDATE and the zone's role. The origination gate refuses one on a
 * secondary that may not originate content; the zones that DO get past it were
 * then handed to a `return nil` placeholder, which dropped the update and
 * reported success (#554).
 */
package tdns

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// runUpdaterForResult is runUpdaterOnce with the outcome captured. respond() is
// non-blocking, so Resp must be buffered or the answer is dropped on the floor.
func runUpdaterForResult(t *testing.T, kdb *KeyDB, ur UpdateRequest) ZoneUpdateResult {
	t.Helper()
	ur.Resp = make(chan ZoneUpdateResult, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = kdb.ZoneUpdaterEngine(ctx)
	}()

	kdb.UpdateQ <- ur
	kdb.UpdateQ <- UpdateRequest{Cmd: "PING"}
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	select {
	case res := <-ur.Resp:
		return res
	default:
		t.Fatal("the updater answered nothing at all")
		return ZoneUpdateResult{}
	}
}

// updaterZoneWithRealKeyDB is updaterTestZone with a KeyDB that has a database
// behind it. ApplyZoneUpdateToZoneData resolves DNSSEC keys before it looks at
// whether the zone signs at all, so the stub KeyDB the gate tests use (which
// never reaches the applier) dereferences a nil *sql.DB here.
func updaterZoneWithRealKeyDB(t *testing.T, ztype ZoneType, opts map[ZoneOption]bool) (*ZoneData, *KeyDB) {
	t.Helper()
	zd := loadIxfrTestZone(t, basicZone)
	zd.ZoneType = ztype
	zd.Options = opts
	kdb := newTestKeyDB(t)
	kdb.UpdateQ = make(chan UpdateRequest, 4)
	zd.KeyDB = kdb
	// The zone applier checks updatepolicy.zone itself, and denies by default.
	zd.UpdatePolicy = policyAllowing(dns.TypeTXT)
	return zd, kdb
}

// injectedPresent reads the PUBLISHED zone, which is what a query or a
// transfer sees. zd.Data is the staging store and is not the served view.
func injectedPresent(t *testing.T, zd *ZoneData) bool {
	t.Helper()
	snap := zd.publishedSnapshot()
	if snap == nil {
		return false
	}
	return getOwnerFrom(snap, "injected.example.test.") != nil
}

func injectedRR(t *testing.T) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(`injected.example.test. 60 IN TXT "mutation"`)
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	return rr
}

// The zones that pass the origination gate as secondaries are the ones the
// placeholder betrayed: a derived app whose secondaries mutate by design (the
// app-type escape in zoneMayOriginateContent), and an inline-signing secondary.
// Their updates must actually land.
func TestZoneUpdateOnAnOriginatingSecondaryIsApplied(t *testing.T) {
	withAppType(t, AppTypeAgent) // off tdns-auth the gate stands down entirely
	zd, kdb := updaterZoneWithRealKeyDB(t, Secondary, map[ZoneOption]bool{OptAllowUpdates: true})
	before := zd.CurrentSerial

	res := runUpdaterForResult(t, kdb, UpdateRequest{
		Cmd:         "ZONE-UPDATE",
		ZoneName:    zd.ZoneName,
		Actions:     []dns.RR{injectedRR(t)},
		Trusted:     true,
		Description: "test: update against a secondary that may originate",
	})

	if res.Err != nil {
		t.Fatalf("refused: %v", res.Err)
	}
	if !res.Applied {
		t.Error("reported as not applied")
	}
	if !injectedPresent(t, zd) {
		t.Error("the updater answered success and the published zone is unchanged:" +
			" the update went to the placeholder")
	}
	if zd.CurrentSerial == before {
		t.Errorf("serial did not move (%d): nothing was published", before)
	}
}

// The other half of the same switch: a zone whose type was never set fell
// straight through it, leaving updated=false and err=nil. A caller checking
// only the error reads that as success.
func TestZoneUpdateOnAZoneWithNoTypeIsRefused(t *testing.T) {
	withAppType(t, AppTypeAgent)
	zd, kdb := updaterZoneWithRealKeyDB(t, 0, map[ZoneOption]bool{OptAllowUpdates: true})

	res := runUpdaterForResult(t, kdb, UpdateRequest{
		Cmd:         "ZONE-UPDATE",
		ZoneName:    zd.ZoneName,
		Actions:     []dns.RR{injectedRR(t)},
		Trusted:     true,
		Description: "test: update against a zone with no type",
	})

	if res.Err == nil {
		t.Error("no error: a zone with no type silently answered as though the" +
			" update had been considered")
	}
	if res.Applied {
		t.Error("reported as applied")
	}
	if injectedPresent(t, zd) {
		t.Error("the update was applied to a zone with no type")
	}
}

// And the refusal that was already right, now asserted on the answer the caller
// receives rather than only on the zone being untouched.
func TestZoneUpdateOnAMirroringSecondaryIsRefusedWithAnError(t *testing.T) {
	withAppType(t, AppTypeAuth)
	zd, kdb := updaterZoneWithRealKeyDB(t, Secondary, map[ZoneOption]bool{OptAllowUpdates: true})

	res := runUpdaterForResult(t, kdb, UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{injectedRR(t)},
		InternalUpdate: true,
		Trusted:        true,
		Description:    "test: internal update against a mirroring secondary",
	})

	if res.Err == nil {
		t.Error("a mirroring secondary refused the update without saying so")
	}
	if res.Applied {
		t.Error("reported as applied")
	}
	if injectedPresent(t, zd) {
		t.Error("the update was applied to a mirroring secondary")
	}
}

// C1: the sanctioned tdns-auth exception, end to end. An inline-signing
// secondary may originate, so the gate lets it past while it still holds the
// Secondary role -- which is exactly the arm the placeholder used to swallow.
// The Agent test above covers the same switch arm through the app-type escape;
// this one is the shape a CDS/CSYNC publisher actually has: AppTypeAuth, an
// InternalUpdate, and a zone that signs what it applies.
func TestInternalUpdateOnAnInlineSigningSecondaryIsApplied(t *testing.T) {
	withAppType(t, AppTypeAuth)
	zd, kdb := updaterZoneWithRealKeyDB(t, Secondary, map[ZoneOption]bool{
		OptInlineSigning: true,
	})
	zd.DnssecPolicy = &DnssecPolicy{
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		SigValidity: PolicySigValidity{
			Default: 30 * 86400, DNSKEY: 30 * 86400, DS: 30 * 86400,
		},
	}
	if !zoneMayOriginateContent(zd) {
		t.Fatal("an inline-signing secondary must be allowed past the origination gate")
	}
	before := zd.CurrentSerial

	res := runUpdaterForResult(t, kdb, UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{injectedRR(t)},
		InternalUpdate: true,
		Trusted:        true,
		Description:    "test: internal update against an inline-signing secondary",
	})

	if res.Err != nil {
		t.Fatalf("refused: %v", res.Err)
	}
	if !res.Applied {
		t.Error("reported as not applied")
	}
	if !injectedPresent(t, zd) {
		t.Error("the sanctioned exception answered success and the published zone" +
			" is unchanged: the update went to the placeholder")
	}
	if zd.CurrentSerial == before {
		t.Errorf("serial did not move (%d): nothing was published", before)
	}
}
