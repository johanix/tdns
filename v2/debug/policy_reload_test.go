/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// --- snapshot fixtures ------------------------------------------------------

func sig(covered, keytag uint16, alg uint8, inception uint32) RRSIGObs {
	return RRSIGObs{
		CoveredType: covered,
		KeyTag:      keytag,
		Algorithm:   alg,
		Inception:   inception,
		Expiration:  inception + 1209600, // +14d, unused by the compare
	}
}

// signedZone is a healthy signed zone: an RRSIG(SOA) (ZSK) and an RRSIG(DNSKEY)
// (KSK), both at the same inception.
func signedZone(zone string, serial uint32, inception uint32) ZoneSnapshot {
	return ZoneSnapshot{
		Zone:   dns.Fqdn(zone),
		OK:     true,
		Serial: serial,
		Signed: true,
		RRSIGs: []RRSIGObs{
			sig(dns.TypeSOA, 1111, 13, inception),
			sig(dns.TypeDNSKEY, 2222, 13, inception),
		},
	}
}

func withApplied(zs ZoneSnapshot, present bool, source string) ZoneSnapshot {
	if present {
		zs.Applied = AppliedRec{Present: true, Policy: "default", Source: source}
	} else {
		zs.Applied = AppliedRec{Present: false}
	}
	return zs
}

func statOf(rep *Report, key string) int64 { return rep.Stats[key] }

func compare(tol int, appliedCapable bool, before, after map[string]ZoneSnapshot) *Report {
	rep := NewReport("test", "policy-reload")
	c := &PolicyReloadChecker{report: rep, tolerance: tol, appliedCapable: appliedCapable}
	c.Compare(before, after)
	return rep
}

// --- tests ------------------------------------------------------------------

// The clean A2 case: every zone keeps its exact RRSIG inceptions across the
// reload (a backfill, not a re-sign), and applied went absent→config for all N.
func TestPolicyReloadCleanBackfillNoResign(t *testing.T) {
	before := map[string]ZoneSnapshot{
		"a.example.": withApplied(signedZone("a.example.", 10, 1_700_000_000), false, ""),
		"b.example.": withApplied(signedZone("b.example.", 20, 1_700_000_000), false, ""),
		"c.example.": withApplied(signedZone("c.example.", 30, 1_700_000_000), false, ""),
	}
	after := map[string]ZoneSnapshot{
		"a.example.": withApplied(signedZone("a.example.", 10, 1_700_000_000), true, "config"),
		"b.example.": withApplied(signedZone("b.example.", 20, 1_700_000_000), true, "config"),
		"c.example.": withApplied(signedZone("c.example.", 30, 1_700_000_000), true, "config"),
	}
	rep := compare(0, true, before, after)

	if len(rep.Violations) != 0 {
		t.Fatalf("clean backfill must not violate, got %+v", rep.Violations)
	}
	if got := statOf(rep, "applied.backfilled"); got != 3 {
		t.Errorf("expected 3 backfilled zones, got %d", got)
	}
	if got := statOf(rep, "applied.after-config"); got != 3 {
		t.Errorf("expected 3 after-config zones, got %d", got)
	}
	if got := statOf(rep, "zones.compared"); got != 3 {
		t.Errorf("expected 3 compared zones, got %d", got)
	}
}

// The coverage guard: if the operator forgot to arm applied_*→NULL, every zone
// already has an applied record before the reload, the sync takes the same-name
// no-op branch, and a "no re-sign" result proves nothing. Compare must surface
// that as an "A2 backfill coverage" Skip (not silently pass), with no violation.
func TestPolicyReloadBackfillCoverageGuard(t *testing.T) {
	before := map[string]ZoneSnapshot{
		"a.example.": withApplied(signedZone("a.example.", 10, 1_700_000_000), true, "config"),
		"b.example.": withApplied(signedZone("b.example.", 20, 1_700_000_000), true, "config"),
	}
	after := map[string]ZoneSnapshot{
		"a.example.": withApplied(signedZone("a.example.", 10, 1_700_000_000), true, "config"),
		"b.example.": withApplied(signedZone("b.example.", 20, 1_700_000_000), true, "config"),
	}
	rep := compare(0, true, before, after)

	if len(rep.Violations) != 0 {
		t.Fatalf("no re-sign must not violate, got %+v", rep.Violations)
	}
	if !skipContains(rep, "A2 backfill coverage") {
		t.Fatalf("all-applied-present (unarmed) must emit the backfill-coverage skip, skips=%v", rep.Skipped)
	}
	if got := statOf(rep, "applied.backfilled"); got != 0 {
		t.Errorf("no backfill expected in the unarmed case, got applied.backfilled=%d", got)
	}
}

// The armed case must NOT emit the coverage skip: at least one zone was
// before-absent, so the backfill path was actually exercised.
func TestPolicyReloadBackfillCoverageArmedNoSkip(t *testing.T) {
	before := map[string]ZoneSnapshot{
		"a.example.": withApplied(signedZone("a.example.", 10, 1_700_000_000), false, ""),
	}
	after := map[string]ZoneSnapshot{
		"a.example.": withApplied(signedZone("a.example.", 10, 1_700_000_000), true, "config"),
	}
	rep := compare(0, true, before, after)
	if skipContains(rep, "A2 backfill coverage") {
		t.Fatalf("an armed run (a before-absent zone) must not emit the coverage skip, skips=%v", rep.Skipped)
	}
	if got := statOf(rep, "applied.backfilled"); got != 1 {
		t.Errorf("expected applied.backfilled=1, got %d", got)
	}
}

// A single zone re-signed: its apex RRSIG inception advanced. With tolerance 0
// that is exactly one A2 violation, and it must name the re-signed zone (not the
// two clean ones).
func TestPolicyReloadDetectsResign(t *testing.T) {
	before := map[string]ZoneSnapshot{
		"a.example.": signedZone("a.example.", 10, 1_700_000_000),
		"b.example.": signedZone("b.example.", 20, 1_700_000_000),
	}
	after := map[string]ZoneSnapshot{
		"a.example.": signedZone("a.example.", 10, 1_700_000_000), // untouched
		"b.example.": signedZone("b.example.", 21, 1_700_000_500), // fresh inception → re-signed
	}
	rep := compare(0, false, before, after)

	if len(rep.Violations) != 1 {
		t.Fatalf("one re-sign must trip exactly one A2 violation, got %d: %+v", len(rep.Violations), rep.Violations)
	}
	v := rep.Violations[0]
	if v.Invariant != "A2" {
		t.Fatalf("expected an A2 violation, got %q", v.Invariant)
	}
	if !contains(v.Summary, "b.example.") {
		t.Errorf("violation must name the re-signed zone b.example., got %q", v.Summary)
	}
	if contains(v.Summary, "a.example.") {
		t.Errorf("violation must not name the untouched zone a.example., got %q", v.Summary)
	}
	if got := statOf(rep, "a2.resigned"); got != 1 {
		t.Errorf("expected a2.resigned=1, got %d", got)
	}
}

// The re-sign check is per-keytag: a re-sign of the KSK-signed DNSKEY alone
// (SOA/ZSK signature untouched) still trips A2.
func TestPolicyReloadDetectsResignOnDnskeyKeytagOnly(t *testing.T) {
	before := map[string]ZoneSnapshot{
		"a.example.": signedZone("a.example.", 10, 1_700_000_000),
	}
	a := signedZone("a.example.", 10, 1_700_000_000)
	// advance ONLY the RRSIG(DNSKEY) inception, leave RRSIG(SOA) identical.
	a.RRSIGs = []RRSIGObs{
		sig(dns.TypeSOA, 1111, 13, 1_700_000_000),
		sig(dns.TypeDNSKEY, 2222, 13, 1_700_000_900),
	}
	after := map[string]ZoneSnapshot{"a.example.": a}

	rep := compare(0, false, before, after)
	if !has(rep, "A2") {
		t.Fatalf("a DNSKEY-only re-sign must trip A2, got %+v", rep.Violations)
	}
}

// Tolerance absorbs coincidental background-resigner ticks: two advanced zones
// with --tolerance 2 is clean (surfaced as a Skip, no violation); a third pushes
// it over and every advanced zone becomes a violation.
func TestPolicyReloadTolerance(t *testing.T) {
	mk := func(resignN int) (before, after map[string]ZoneSnapshot) {
		before = map[string]ZoneSnapshot{}
		after = map[string]ZoneSnapshot{}
		for i, z := range []string{"a.", "b.", "c."} {
			before[z] = signedZone(z, uint32(i), 1_700_000_000)
			inc := uint32(1_700_000_000)
			if i < resignN {
				inc = 1_700_001_000 // advanced
			}
			after[z] = signedZone(z, uint32(i), inc)
		}
		return
	}

	b2, a2 := mk(2)
	rep := compare(2, false, b2, a2)
	if len(rep.Violations) != 0 {
		t.Fatalf("2 advances within --tolerance 2 must not violate, got %+v", rep.Violations)
	}
	if got := statOf(rep, "a2.resigned-within-tolerance"); got != 2 {
		t.Errorf("expected 2 within-tolerance advances, got %d", got)
	}

	b3, a3 := mk(3)
	rep = compare(2, false, b3, a3)
	if len(rep.Violations) != 3 {
		t.Fatalf("3 advances over --tolerance 2 must violate for all 3, got %d: %+v", len(rep.Violations), rep.Violations)
	}
}

// A zone that dropped from signed to unsigned across the reload is an A2-signed
// violation (reuses the SignednessChecker latch). A genuinely-unsigned zone in
// both snapshots must NOT (false-positive guard).
func TestPolicyReloadSignednessDrop(t *testing.T) {
	unsigned := ZoneSnapshot{Zone: "a.example.", OK: true, Serial: 11, Signed: false}
	before := map[string]ZoneSnapshot{
		"a.example.": signedZone("a.example.", 10, 1_700_000_000),
		"b.example.": {Zone: "b.example.", OK: true, Serial: 20, Signed: false}, // never signed
	}
	after := map[string]ZoneSnapshot{
		"a.example.": unsigned,                                                  // dropped!
		"b.example.": {Zone: "b.example.", OK: true, Serial: 20, Signed: false}, // still unsigned
	}
	rep := compare(0, false, before, after)

	if n := countInvariant(rep, "A2-signed"); n != 1 {
		t.Fatalf("exactly one zone dropped unsigned → one A2-signed, got %d: %+v", n, rep.Violations)
	}
	for _, v := range rep.Violations {
		if v.Invariant == "A2-signed" && !contains(v.Summary, "a.example.") {
			t.Errorf("A2-signed must name the dropped zone a.example., got %q", v.Summary)
		}
	}
}

// A zone that goes SERVFAIL / stops answering after the trigger is the same
// drop, surfaced directly (OK=false in the after snapshot).
func TestPolicyReloadServfailAfterTrigger(t *testing.T) {
	before := map[string]ZoneSnapshot{"a.example.": signedZone("a.example.", 10, 1_700_000_000)}
	after := map[string]ZoneSnapshot{"a.example.": {Zone: "a.example.", OK: false, ErrMsg: "SERVFAIL"}}
	rep := compare(0, false, before, after)
	if !has(rep, "A2-signed") {
		t.Fatalf("a zone that stopped answering must trip A2-signed, got %+v", rep.Violations)
	}
}

// A transient apex-RRSIG probe failure in the AFTER snapshot (the SOA still
// answers) must NOT read as a signed→unsigned drop: Signed=false there is a
// probe artifact, not a confirmed regression. This guards the framework's
// false-positive-free contract.
func TestPolicyReloadAfterRRSIGProbeErrorIsNotADrop(t *testing.T) {
	before := map[string]ZoneSnapshot{
		"a.example.": signedZone("a.example.", 10, 1_700_000_000),
	}
	after := map[string]ZoneSnapshot{
		"a.example.": {Zone: "a.example.", OK: true, Serial: 11, Signed: false, RRSIGErr: "read udp 127.0.0.1:5354: i/o timeout"},
	}
	rep := compare(0, false, before, after)
	if len(rep.Violations) != 0 {
		t.Fatalf("an after-snapshot RRSIG probe error must not violate, got %+v", rep.Violations)
	}
	if got := statOf(rep, "signedness.inconclusive"); got != 1 {
		t.Errorf("expected signedness.inconclusive=1, got %d", got)
	}
}

// A key rollover (a keytag present only in the after snapshot) is a config
// change, not a re-sign of existing content — it must not trip A2 on its own.
func TestPolicyReloadRolloverNewKeytagNotResign(t *testing.T) {
	before := map[string]ZoneSnapshot{"a.example.": signedZone("a.example.", 10, 1_700_000_000)}
	a := signedZone("a.example.", 11, 1_700_000_000)
	// same SOA/DNSKEY inceptions, PLUS a brand-new ZSK keytag (rollover in flight)
	a.RRSIGs = append(a.RRSIGs, sig(dns.TypeSOA, 9999, 13, 1_700_000_800))
	after := map[string]ZoneSnapshot{"a.example.": a}

	rep := compare(0, false, before, after)
	if len(rep.Violations) != 0 {
		t.Fatalf("a new keytag (rollover) must not be read as a re-sign, got %+v", rep.Violations)
	}
}

// When the applied-readback capability is absent, the backfill confirmation is
// skipped (not failed) and the inception no-re-sign check still runs and still
// fires on a real re-sign.
func TestPolicyReloadAppliedCapabilityAbsentSkips(t *testing.T) {
	before := map[string]ZoneSnapshot{"a.example.": signedZone("a.example.", 10, 1_700_000_000)}
	after := map[string]ZoneSnapshot{"a.example.": signedZone("a.example.", 11, 1_700_000_500)} // re-signed
	rep := compare(0, false, before, after)

	if len(rep.Skipped) == 0 {
		t.Fatalf("absent applied capability must record a SKIP")
	}
	if got := statOf(rep, "applied.backfilled"); got != 0 {
		t.Errorf("applied stats must not be counted when the capability is absent, got %d", got)
	}
	if !has(rep, "A2") {
		t.Errorf("the inception check must still fire when applied readback is unavailable")
	}
}

// A zone that vanished / appeared across the trigger is a config change, counted
// but never asserted as a re-sign.
func TestPolicyReloadZoneSetChurnCounted(t *testing.T) {
	before := map[string]ZoneSnapshot{
		"a.example.": signedZone("a.example.", 10, 1_700_000_000),
		"gone.":      signedZone("gone.", 10, 1_700_000_000),
	}
	after := map[string]ZoneSnapshot{
		"a.example.": signedZone("a.example.", 10, 1_700_000_000),
		"new.":       signedZone("new.", 10, 1_700_000_000),
	}
	rep := compare(0, false, before, after)
	if len(rep.Violations) != 0 {
		t.Fatalf("zone-set churn must not violate, got %+v", rep.Violations)
	}
	if got := statOf(rep, "zones.vanished"); got != 1 {
		t.Errorf("expected 1 vanished zone, got %d", got)
	}
	if got := statOf(rep, "zones.appeared"); got != 1 {
		t.Errorf("expected 1 appeared zone, got %d", got)
	}
	if got := statOf(rep, "zones.compared"); got != 1 {
		t.Errorf("expected 1 compared zone, got %d", got)
	}
}

// --- test helpers -----------------------------------------------------------

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func skipContains(rep *Report, sub string) bool {
	for _, s := range rep.Skipped {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func countInvariant(rep *Report, inv string) int {
	n := 0
	for _, v := range rep.Violations {
		if v.Invariant == inv {
			n++
		}
	}
	return n
}
