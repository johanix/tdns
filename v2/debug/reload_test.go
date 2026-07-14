/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import "testing"

func TestI10LatchesThenCatchesUnsignedWindow(t *testing.T) {
	rep := NewReport("test", "reload")
	c := &SignednessChecker{report: rep}

	// A fully-signed transfer: no violation, and it latches the zone as signed.
	c.Observe(SignednessObs{Serial: 1, HasDNSKEY: true, HasRRSIG: true})
	if !c.EverSigned() {
		t.Fatal("a signed transfer must latch EverSigned")
	}
	if len(rep.Violations) != 0 {
		t.Fatalf("signed transfer must not violate, got %d", len(rep.Violations))
	}

	// After the latch, an unsigned transfer is the reload window → I10.
	c.Observe(SignednessObs{Serial: 2, HasDNSKEY: false, HasRRSIG: false})
	if len(rep.Violations) != 1 || rep.Violations[0].Invariant != "I10" {
		t.Fatalf("signed→unsigned must trip exactly one I10, got %+v", rep.Violations)
	}

	// Partial signedness after the latch (DNSKEY but no RRSIG) is also the window.
	c.Observe(SignednessObs{Serial: 3, HasDNSKEY: true, HasRRSIG: false})
	if len(rep.Violations) != 2 {
		t.Fatalf("partial-signed after latch must trip I10, got %d violations", len(rep.Violations))
	}
}

func TestI10IsFalsePositiveFreeBeforeLatch(t *testing.T) {
	// An unsigned transfer observed BEFORE the zone has ever been seen signed
	// (e.g. the zone is still completing its first sign at startup) must NOT
	// violate — I10 only asserts once it has proof the zone is a signed zone.
	rep := NewReport("test", "reload")
	c := &SignednessChecker{report: rep}

	c.Observe(SignednessObs{Serial: 1, HasDNSKEY: false, HasRRSIG: false})
	c.Observe(SignednessObs{Serial: 1, HasDNSKEY: false, HasRRSIG: false})

	if c.EverSigned() {
		t.Error("unsigned transfers must not latch EverSigned")
	}
	if len(rep.Violations) != 0 {
		t.Errorf("unsigned-before-latch must not violate, got %d", len(rep.Violations))
	}
}
