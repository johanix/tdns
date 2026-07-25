/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Tests for the config-reload DNSSEC-policy-change guardrail (PR-B).
 */

package tdns

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// Pure predicate: policyAlgStrandsActiveKeys
// ---------------------------------------------------------------------------

func ksz(ksk, zsk uint8) policyRoleAlgs {
	return policyRoleAlgs{mode: DnssecPolicyModeKSKZSK, ksk: ksk, zsk: zsk}
}
func csk(alg uint8) policyRoleAlgs { return policyRoleAlgs{mode: DnssecPolicyModeCSK, ksk: alg} }
func active(ksk, zsk []uint8) zoneActiveAlgs {
	a := zoneActiveAlgs{ksk: map[uint8]bool{}, zsk: map[uint8]bool{}}
	for _, k := range ksk {
		a.ksk[k] = true
	}
	for _, z := range zsk {
		a.zsk[z] = true
	}
	return a
}

func TestPolicyAlgStrandsActiveKeys(t *testing.T) {
	const (
		ed  = dns.ED25519
		rsa = dns.RSASHA256
		// A stand-in "new" algorithm; codepoint value is irrelevant to the pure
		// predicate (it compares codepoints), only that it differs from ed/rsa.
		fal = uint8(200)
	)

	tests := []struct {
		name     string
		want     policyRoleAlgs
		active   zoneActiveAlgs
		relaxed  bool
		wantMiss []string // roles expected to be flagged, in order
	}{
		{
			// The core blind spot: KSK Ed25519 -> new alg, zone still bound to the
			// same policy, active KSK is Ed25519 -> STRAND.
			name:     "same-name KSK alg change caught",
			want:     ksz(fal, ed),
			active:   active([]uint8{ed}, []uint8{ed}),
			wantMiss: []string{"KSK"},
		},
		{
			name:     "benign: active keys match the new policy",
			want:     ksz(ed, ed),
			active:   active([]uint8{ed}, []uint8{ed}),
			wantMiss: nil,
		},
		{
			// Zero active keys for the ZSK role: the signer would generate fresh
			// keys of the policy algorithm, so this is not a strand.
			name:     "zero active keys for a role is not a strand",
			want:     ksz(ed, fal),
			active:   active([]uint8{ed}, nil),
			wantMiss: nil,
		},
		{
			// Mid-rollover: both the old and the wanted KSK alg are active -> the
			// zone can already sign under the new alg, so not a strand.
			name:     "mid-rollover (wanted alg already present) is not a strand",
			want:     ksz(fal, ed),
			active:   active([]uint8{ed, fal}, []uint8{ed}),
			wantMiss: nil,
		},
		{
			// ZSK alg change is carried by the gradual FIFO roll in relaxed mode.
			name:     "ZSK alg change in relaxed mode is not flagged",
			want:     ksz(ed, fal),
			active:   active([]uint8{ed}, []uint8{ed}),
			relaxed:  true,
			wantMiss: nil,
		},
		{
			name:     "ZSK alg change in strict mode is flagged",
			want:     ksz(ed, fal),
			active:   active([]uint8{ed}, []uint8{ed}),
			relaxed:  false,
			wantMiss: []string{"ZSK"},
		},
		{
			// KSK change is a strand in relaxed mode too (no automatic KSK-alg roll).
			name:     "KSK alg change is flagged even in relaxed mode",
			want:     ksz(fal, ed),
			active:   active([]uint8{ed}, []uint8{ed}),
			relaxed:  true,
			wantMiss: []string{"KSK"},
		},
		{
			name:     "both roles change -> both flagged (strict)",
			want:     ksz(fal, fal),
			active:   active([]uint8{ed}, []uint8{rsa}),
			wantMiss: []string{"KSK", "ZSK"},
		},
		{
			name:     "CSK alg change caught",
			want:     csk(fal),
			active:   active([]uint8{ed}, nil),
			wantMiss: []string{"CSK"},
		},
		{
			name:     "CSK match is benign",
			want:     csk(ed),
			active:   active([]uint8{ed}, nil),
			wantMiss: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			miss := policyAlgStrandsActiveKeys(tc.want, tc.active, tc.relaxed)
			var got []string
			for _, m := range miss {
				got = append(got, m.role)
			}
			if strings.Join(got, ",") != strings.Join(tc.wantMiss, ",") {
				t.Fatalf("roles flagged = %v, want %v", got, tc.wantMiss)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The confirm gate: reloadGuardrailDecision
// ---------------------------------------------------------------------------

func TestReloadGuardrailDecision(t *testing.T) {
	findings := []ReloadGuardrailZone{{
		Zone:       "example.",
		PolicyName: "foo",
		Roles:      []ReloadGuardrailRole{{Role: "KSK", WantAlg: "FALCON512", HaveAlgs: []string{"ED25519"}}},
	}}

	// No findings -> always proceed.
	if err := reloadGuardrailDecision(nil, false); err != nil {
		t.Fatalf("no findings, no confirm: want nil, got %v", err)
	}
	// Findings without confirm -> refuse with a *ReloadGuardrailError.
	err := reloadGuardrailDecision(findings, false)
	if err == nil {
		t.Fatal("findings without confirm: want a refusal, got nil")
	}
	var ge *ReloadGuardrailError
	if !asReloadGuardrailError(err, &ge) {
		t.Fatalf("want *ReloadGuardrailError, got %T", err)
	}
	if len(ge.Zones) != 1 || ge.Zones[0].Zone != "example." {
		t.Fatalf("guardrail error lost its findings: %+v", ge.Zones)
	}
	msg := err.Error()
	for _, want := range []string{"example.", "foo", "KSK", "FALCON512", "ED25519", "--confirm"} {
		if !strings.Contains(msg, want) {
			t.Errorf("guardrail message missing %q:\n%s", want, msg)
		}
	}
	// Findings WITH confirm -> proceed (the gate lets it through).
	if err := reloadGuardrailDecision(findings, true); err != nil {
		t.Fatalf("findings with confirm: want nil (proceed), got %v", err)
	}
}

// asReloadGuardrailError is a tiny local errors.As wrapper kept out of the
// production file's import set.
func asReloadGuardrailError(err error, target **ReloadGuardrailError) bool {
	if e, ok := err.(*ReloadGuardrailError); ok {
		*target = e
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Collector end-to-end: detectStrandingPolicyChanges over live Zones + keystore
// ---------------------------------------------------------------------------

// addSignedZone registers a signed zone in the global Zones map bound to policyName
// with the given active keys, and returns it (auto-removed on cleanup).
func addSignedZone(t *testing.T, kdb *KeyDB, zone, policyName string, kskAlg, zskAlg uint8) *ZoneData {
	t.Helper()
	if _, _, err := kdb.GenerateKeypair(zone, "test", DnskeyStateActive, dns.TypeDNSKEY, kskAlg, "KSK", nil); err != nil {
		t.Fatalf("generate KSK for %s: %v", zone, err)
	}
	if _, _, err := kdb.GenerateKeypair(zone, "test", DnskeyStateActive, dns.TypeDNSKEY, zskAlg, "ZSK", nil); err != nil {
		t.Fatalf("generate ZSK for %s: %v", zone, err)
	}
	zd := &ZoneData{
		ZoneName:         zone,
		Options:          map[ZoneOption]bool{OptOnlineSigning: true},
		DnssecPolicyName: policyName,
	}
	Zones.Set(zone, zd)
	t.Cleanup(func() { Zones.Remove(zone) })
	return zd
}

func TestDetectStrandingPolicyChanges(t *testing.T) {
	withCompleteness(t, CompletenessStrict)
	kdb := newTestKeyDB(t)
	conf := &Config{}
	conf.Internal.KeyDB = kdb

	// Two zones, both bound to policy "foo", both currently keyed with Ed25519.
	danger := "danger.example."
	benign := "benign.example."
	addSignedZone(t, kdb, danger, "foo", dns.ED25519, dns.ED25519)
	addSignedZone(t, kdb, benign, "foo", dns.ED25519, dns.ED25519)

	// The NEW "foo" changes the KSK algorithm; a same-name edit. RSASHA256 stands
	// in for "a different algorithm than the active Ed25519 keys".
	newPolicies := map[string]DnssecPolicy{
		"foo": {Name: "foo", Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.RSASHA256, ZSKAlgorithm: dns.ED25519},
	}

	findings, err := conf.detectStrandingPolicyChanges(newPolicies, false)
	if err != nil {
		t.Fatalf("detectStrandingPolicyChanges: %v", err)
	}
	// Both zones share policy foo, so both would strand on the KSK alg change.
	if len(findings) != 2 {
		t.Fatalf("want 2 stranded zones, got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.PolicyName != "foo" || len(f.Roles) != 1 || f.Roles[0].Role != "KSK" {
			t.Fatalf("unexpected finding: %+v", f)
		}
		if f.Roles[0].WantAlg != dns.AlgorithmToString[dns.RSASHA256] {
			t.Errorf("want KSK alg %s, got %s", dns.AlgorithmToString[dns.RSASHA256], f.Roles[0].WantAlg)
		}
	}

	// Benign reload: the NEW foo keeps the algorithms the active keys already have.
	benignPolicies := map[string]DnssecPolicy{
		"foo": {Name: "foo", Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.ED25519, ZSKAlgorithm: dns.ED25519},
	}
	findings, err = conf.detectStrandingPolicyChanges(benignPolicies, false)
	if err != nil {
		t.Fatalf("detectStrandingPolicyChanges (benign): %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("benign reload must produce no findings, got %+v", findings)
	}

	// The confirm gate lets the dangerous change through unchanged.
	dangerFindings, _ := conf.detectStrandingPolicyChanges(newPolicies, false)
	if err := reloadGuardrailDecision(dangerFindings, true); err != nil {
		t.Fatalf("confirm=true must let the reload proceed, got %v", err)
	}
	if err := reloadGuardrailDecision(dangerFindings, false); err == nil {
		t.Fatal("confirm=false must refuse the dangerous reload")
	}
}

// A zone bound to a policy NAME that the new config removed is out of scope for the
// guardrail (handled by the parse fail-closed / keep-binding paths), so it must not
// be flagged as an algorithm-change strand.
func TestDetectStrandingSkipsRemovedPolicyName(t *testing.T) {
	withCompleteness(t, CompletenessStrict)
	kdb := newTestKeyDB(t)
	conf := &Config{}
	conf.Internal.KeyDB = kdb

	addSignedZone(t, kdb, "gone.example.", "removed-policy", dns.ED25519, dns.ED25519)

	// New config no longer defines "removed-policy" (only "other").
	newPolicies := map[string]DnssecPolicy{
		"other": {Name: "other", Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.RSASHA256, ZSKAlgorithm: dns.RSASHA256},
	}
	findings, err := conf.detectStrandingPolicyChanges(newPolicies, false)
	if err != nil {
		t.Fatalf("detectStrandingPolicyChanges: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("a removed policy name must not be flagged as an alg-change strand, got %+v", findings)
	}
}

// The collector must forward the relaxed (dnssec.completeness) flag end-to-end: a
// same-name ZSK algorithm change strands in strict mode but is carried by the
// gradual FIFO ZSK roll in relaxed mode (not flagged), while a KSK algorithm change
// strands in either mode. (The pure predicate's relaxed behavior is covered by
// TestPolicyAlgStrandsActiveKeys; this pins the collector's forwarding of the flag.)
func TestDetectStrandingRelaxedForwardsZSKSkip(t *testing.T) {
	withCompleteness(t, CompletenessStrict)
	kdb := newTestKeyDB(t)
	conf := &Config{}
	conf.Internal.KeyDB = kdb

	zone := "relaxed.example."
	addSignedZone(t, kdb, zone, "foo", dns.ED25519, dns.ED25519)

	// NEW "foo" changes ONLY the ZSK algorithm; the KSK stays Ed25519.
	zskChange := map[string]DnssecPolicy{
		"foo": {Name: "foo", Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.ED25519, ZSKAlgorithm: dns.RSASHA256},
	}

	// Strict mode (relaxed=false): the ZSK algorithm change strands the zone.
	strict, err := conf.detectStrandingPolicyChanges(zskChange, false)
	if err != nil {
		t.Fatalf("detectStrandingPolicyChanges (strict): %v", err)
	}
	if len(strict) != 1 || len(strict[0].Roles) != 1 || strict[0].Roles[0].Role != "ZSK" {
		t.Fatalf("strict: want 1 ZSK strand, got %+v", strict)
	}

	// Relaxed mode (relaxed=true): the same ZSK change is carried by the gradual roll,
	// so the collector must forward the flag and NOT flag it.
	relaxed, err := conf.detectStrandingPolicyChanges(zskChange, true)
	if err != nil {
		t.Fatalf("detectStrandingPolicyChanges (relaxed): %v", err)
	}
	if len(relaxed) != 0 {
		t.Fatalf("relaxed: a ZSK-only alg change must not strand, got %+v", relaxed)
	}

	// A KSK algorithm change is a strand even in relaxed mode.
	kskChange := map[string]DnssecPolicy{
		"foo": {Name: "foo", Mode: DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.RSASHA256, ZSKAlgorithm: dns.ED25519},
	}
	stillStrands, err := conf.detectStrandingPolicyChanges(kskChange, true)
	if err != nil {
		t.Fatalf("detectStrandingPolicyChanges (relaxed KSK): %v", err)
	}
	if len(stillStrands) != 1 || len(stillStrands[0].Roles) != 1 || stillStrands[0].Roles[0].Role != "KSK" {
		t.Fatalf("relaxed: a KSK alg change must still strand, got %+v", stillStrands)
	}
}
