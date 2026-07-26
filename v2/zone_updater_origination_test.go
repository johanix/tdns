package tdns

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Fix D: the fail-closed origination gate at the head of the ZoneUpdater loop.
//
// The per-command checks accept ZONE-UPDATE when allow-updates is set OR when
// the request is flagged InternalUpdate -- and every ops_* publisher sets
// InternalUpdate. These tests pin that a tdns-auth secondary which may not
// originate content has zone-content updates dropped regardless of that flag,
// while the keystore path and every originating zone are untouched.

// runUpdaterOnce starts a ZoneUpdaterEngine, feeds it one request, and returns
// once the engine has had a chance to process it.
func runUpdaterOnce(t *testing.T, kdb *KeyDB, ur UpdateRequest) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = kdb.ZoneUpdaterEngine(ctx)
	}()

	kdb.UpdateQ <- ur
	// A PING behind the request is only drained once the engine has finished
	// with the request ahead of it, so this orders our assertion after it.
	kdb.UpdateQ <- UpdateRequest{Cmd: "PING"}
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
}

// updaterTestZone registers a zone with a staged working set the applier would
// mutate, and returns it.
func updaterTestZone(t *testing.T, ztype ZoneType, opts map[ZoneOption]bool) (*ZoneData, *KeyDB) {
	t.Helper()
	zd := loadIxfrTestZone(t, basicZone)
	zd.ZoneType = ztype
	zd.Options = opts
	kdb := &KeyDB{UpdateQ: make(chan UpdateRequest, 4)}
	zd.KeyDB = kdb
	return zd, kdb
}

// TestApplierGateDropsInternalUpdateOnSecondary drives a full InternalUpdate
// ZONE-UPDATE -- the shape every ops_* publisher emits, and the shape that
// bypasses the allow-updates call-site convention -- through the engine against
// a mirroring secondary, and asserts the zone is untouched.
//
// HONESTY NOTE: this is a smoke test, not a mutation-verified one. Removing the
// gate does NOT make it fail, because the ZONE-UPDATE apply path for a
// ZoneType==Secondary calls kdb.ApplyZoneUpdateToDB, which is currently a
// `return nil` placeholder -- so today a ZONE-UPDATE against a secondary is
// already inert for a second, unrelated reason. The gate's real value here is
// that it forecloses the vector *before* that placeholder is implemented, at
// which point every InternalUpdate publisher would start mutating secondaries.
// The gate's logic itself is pinned by the unit-level tests below; the
// end-to-end behaviour on a secondary is on the testbed list.
func TestApplierGateDropsInternalUpdateOnSecondary(t *testing.T) {
	withAppType(t, AppTypeAuth)
	zd, kdb := updaterTestZone(t, Secondary, map[ZoneOption]bool{})
	before := zd.CurrentSerial

	rr, err := dns.NewRR("injected.example.test. 60 IN TXT \"mutation\"")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	runUpdaterOnce(t, kdb, UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{rr},
		InternalUpdate: true,
		Trusted:        true,
		Description:    "test: internal update against a mirroring secondary",
	})

	if zd.CurrentSerial != before {
		t.Errorf("serial moved (%d -> %d): the update was applied", before, zd.CurrentSerial)
	}
	if _, present := zd.Data.Get("injected.example.test."); present {
		t.Error("injected owner present: the update was applied to a mirroring secondary")
	}
}

// TestApplierGateAllowsInlineSigningSecondary guards the sanctioned exception:
// an inline-signing secondary may originate, so CDS/CSYNC-style internal
// updates must still reach the applier. Asserting "not dropped by the gate" —
// the request gets past it and into the command switch.
func TestApplierGateAllowsInlineSigningSecondary(t *testing.T) {
	withAppType(t, AppTypeAuth)
	zd, _ := updaterTestZone(t, Secondary, map[ZoneOption]bool{OptInlineSigning: true})

	if !zoneMayOriginateContent(zd) {
		t.Fatal("inline-signing secondary must be allowed past the applier gate")
	}
}

// TestApplierGateAllowsPrimaryAndNonAuth covers the two other must-not-regress
// cases: a primary is an originator, and off tdns-auth the gate stands down
// entirely (the §1.1 guarantee for tdns-mp / tdns-agent).
func TestApplierGateAllowsPrimaryAndNonAuth(t *testing.T) {
	withAppType(t, AppTypeAuth)
	primary, _ := updaterTestZone(t, Primary, map[ZoneOption]bool{})
	if !zoneMayOriginateContent(primary) {
		t.Error("primary must be allowed past the applier gate")
	}

	withAppType(t, AppTypeAgent)
	secondary, _ := updaterTestZone(t, Secondary, map[ZoneOption]bool{})
	if !zoneMayOriginateContent(secondary) {
		t.Error("non-auth secondary must be ungated (§1.1 app-scope guarantee)")
	}
}

// TestApplierGateScopedToZoneContentCommands pins the scope: TRUSTSTORE-UPDATE
// writes the keystore rather than zone content and must NOT be caught by the
// gate, even on a mirroring secondary. Verified through the same command
// classification the gate uses.
func TestApplierGateScopedToZoneContentCommands(t *testing.T) {
	withAppType(t, AppTypeAuth)
	zd, _ := updaterTestZone(t, Secondary, map[ZoneOption]bool{})

	if zoneMayOriginateContent(zd) {
		t.Fatal("setup: this zone should not be an originator")
	}

	gated := map[string]bool{
		"ZONE-UPDATE":  true, // writes zone content
		"CHILD-UPDATE": true, // writes child delegation data into the zone
		// Must NOT be gated: writes the keystore via TruststorePost, never
		// zone content. Gating it would break SIG(0) key management on
		// secondaries, which is legitimate and unrelated to origination.
		"TRUSTSTORE-UPDATE": false,
		"DEFERRED-UPDATE":   false, // rejected as wrong-queue by the loop
		"PING":              false, // handled before the zone is resolved
	}
	for cmd, want := range gated {
		if got := updaterCmdMutatesZoneContent(cmd); got != want {
			t.Errorf("updaterCmdMutatesZoneContent(%q) = %v, want %v", cmd, got, want)
		}
	}
}
