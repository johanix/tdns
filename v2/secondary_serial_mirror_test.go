package tdns

import (
	"strings"
	"testing"
)

// Fix A of the MUST-NOT-MODIFY invariant (design doc §3): a tdns-auth secondary
// that did not originate its content mirrors the upstream SOA serial verbatim
// instead of bumping it +1 on every refresh.
//
// These tests drive applyRefreshReplacementLocked directly, which is where the
// historical unconditional `CurrentSerial++` lived.

// withAppType sets the process-wide app type for the duration of a test. The
// origination predicate stands down off tdns-auth (that is what protects
// tdns-mp/tdns-agent), so a test asserting a gate must opt in explicitly.
func withAppType(t *testing.T, at AppType) {
	t.Helper()
	prev := Globals.App.Type
	Globals.App.Type = at
	t.Cleanup(func() { Globals.App.Type = prev })
}

// refreshTo replaces zd's content with basicZone carrying the given upstream
// serial, exactly as a completed AXFR would.
func refreshTo(t *testing.T, zd *ZoneData, upstreamSerial string) {
	t.Helper()
	newZone := strings.Replace(basicZone, "1 ; serial", upstreamSerial+" ; serial", 1)
	newZd := &ZoneData{
		ZoneName:  zd.ZoneName,
		ZoneStore: MapZone,
		ZoneType:  zd.ZoneType,
		Logger:    zd.Logger,
	}
	if _, _, err := newZd.ReadZoneData(newZone, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	zd.mu.Lock()
	err := zd.applyRefreshReplacementLocked(newZd, nil, false)
	zd.mu.Unlock()
	if err != nil {
		t.Fatalf("applyRefreshReplacementLocked: %v", err)
	}
}

// TestSecondaryMirrorsUpstreamSerial is the mutation-verified core of Fix A: it
// FAILS on the pre-fix code (which produced prev+1 = 6 and then 7) and passes
// with the mirror. Two refreshes, so the "+1 per refresh" drift the bug caused
// is visible rather than coincidentally matching.
func TestSecondaryMirrorsUpstreamSerial(t *testing.T) {
	withAppType(t, AppTypeAuth)

	zd := loadIxfrTestZone(t, basicZone)
	zd.ZoneType = Secondary
	zd.Options = map[ZoneOption]bool{}
	zd.CurrentSerial = 5
	zd.IncomingSerial = 5

	refreshTo(t, zd, "40")
	if zd.CurrentSerial != 40 {
		t.Fatalf("after first refresh: CurrentSerial = %d, want 40 (mirrored)", zd.CurrentSerial)
	}

	refreshTo(t, zd, "41")
	if zd.CurrentSerial != 41 {
		t.Fatalf("after second refresh: CurrentSerial = %d, want 41 (mirrored)", zd.CurrentSerial)
	}
	if zd.IncomingSerial != 41 {
		t.Errorf("IncomingSerial = %d, want 41", zd.IncomingSerial)
	}
}

// TestSecondaryMirrorAcceptsBackwardsSerial pins the migration behaviour: a
// secondary whose serial was inflated (by a pre-fix build, or by persist/
// unixtime mode) steps BACKWARDS to upstream's value rather than refusing or
// clamping. The step is logged at ERROR so the operator can force retransfers
// on the downstreams; here we assert the value, not the log.
func TestSecondaryMirrorAcceptsBackwardsSerial(t *testing.T) {
	withAppType(t, AppTypeAuth)

	zd := loadIxfrTestZone(t, basicZone)
	zd.ZoneType = Secondary
	zd.Options = map[ZoneOption]bool{}
	zd.CurrentSerial = 5000 // inflated by pre-fix bumping
	zd.IncomingSerial = 42

	refreshTo(t, zd, "43")
	if zd.CurrentSerial != 43 {
		t.Fatalf("CurrentSerial = %d, want 43 (mirror even when it moves backwards)", zd.CurrentSerial)
	}
}

// TestPrimaryStillBumpsSerial guards the other side: a primary is an originator
// and must keep advancing exactly as before.
func TestPrimaryStillBumpsSerial(t *testing.T) {
	withAppType(t, AppTypeAuth)

	zd := loadIxfrTestZone(t, basicZone)
	zd.ZoneType = Primary
	zd.Options = map[ZoneOption]bool{}
	zd.CurrentSerial = 5

	refreshTo(t, zd, "40")
	if zd.CurrentSerial != 6 {
		t.Fatalf("primary: CurrentSerial = %d, want 6 (prev+1, unchanged behaviour)", zd.CurrentSerial)
	}
}

// TestInlineSigningSecondaryStillBumpsSerial covers the one sanctioned
// exception: an inline-signing secondary transforms upstream content by adding
// its own RRSIGs, so its serial legitimately diverges and must still advance.
func TestInlineSigningSecondaryStillBumpsSerial(t *testing.T) {
	withAppType(t, AppTypeAuth)

	zd := loadIxfrTestZone(t, basicZone)
	zd.ZoneType = Secondary
	zd.Options = map[ZoneOption]bool{OptInlineSigning: true}
	zd.CurrentSerial = 5

	refreshTo(t, zd, "40")
	if zd.CurrentSerial != 6 {
		t.Fatalf("inline-signing secondary: CurrentSerial = %d, want 6 (may originate)", zd.CurrentSerial)
	}
}

// TestNonAuthAppSecondaryStillBumpsSerial is the §1.1 app-scope guarantee, the
// property that keeps tdns-mpcombiner / tdns-mpagent / tdns-agent working when
// they next bump their tdns pin: off tdns-auth the gate stands down entirely
// and a Secondary advances its serial exactly as it always did.
func TestNonAuthAppSecondaryStillBumpsSerial(t *testing.T) {
	withAppType(t, AppTypeAgent)

	zd := loadIxfrTestZone(t, basicZone)
	zd.ZoneType = Secondary
	zd.Options = map[ZoneOption]bool{}
	zd.CurrentSerial = 5

	refreshTo(t, zd, "40")
	if zd.CurrentSerial != 6 {
		t.Fatalf("non-auth app: CurrentSerial = %d, want 6 (gate must be a no-op)", zd.CurrentSerial)
	}
}

// TestNextOutboundSerialSuppressedForMirroringSecondary pins that unixtime mode
// cannot rewrite a mirroring secondary's serial into timestamp space:
// MUST-NOT-MODIFY is absolute, not keep-mode-only.
func TestNextOutboundSerialSuppressedForMirroringSecondary(t *testing.T) {
	withAppType(t, AppTypeAuth)

	zd := &ZoneData{
		ZoneName:          "example.test.",
		ZoneType:          Secondary,
		Options:           map[ZoneOption]bool{},
		CurrentSerial:     10,
		OutboundSoaSerial: OutboundSoaSerialUnixtime,
		KeyDB:             kdbWithSoaSerial(OutboundSoaSerialUnixtime),
	}
	if got := nextOutboundSerial(zd); got != 11 {
		t.Errorf("mirroring secondary in unixtime mode: got %d, want 11 (no timestamp rewrite)", got)
	}

	// A primary in the same mode is unaffected.
	zd.ZoneType = Primary
	if got := nextOutboundSerial(zd); got <= 11 {
		t.Errorf("primary in unixtime mode: got %d, want a unix timestamp", got)
	}
}

// TestZoneMayOriginateContent covers the shared predicate directly, including
// the app-scope short-circuit that every gate inherits from it.
func TestZoneMayOriginateContent(t *testing.T) {
	secondary := &ZoneData{ZoneType: Secondary, Options: map[ZoneOption]bool{}}
	primary := &ZoneData{ZoneType: Primary, Options: map[ZoneOption]bool{}}
	inline := &ZoneData{ZoneType: Secondary, Options: map[ZoneOption]bool{OptInlineSigning: true}}

	withAppType(t, AppTypeAuth)
	if zoneMayOriginateContent(secondary) {
		t.Error("auth secondary must NOT originate")
	}
	if !zoneMayOriginateContent(primary) {
		t.Error("auth primary must originate")
	}
	if !zoneMayOriginateContent(inline) {
		t.Error("auth inline-signing secondary must originate")
	}
	if !zoneMayOriginateContent(nil) {
		t.Error("nil zone must not be gated")
	}

	// Off tdns-auth every case is permitted — the §1.1 guarantee.
	withAppType(t, AppTypeAgent)
	if !zoneMayOriginateContent(secondary) {
		t.Error("non-auth secondary must be ungated")
	}
}
