package tdns

import "testing"

// TestExpandPolicyTemplateDeepMerge pins the deep-merge contract: a policy that
// sets only part of a nested block inherits the rest of that block from the
// template, and untouched blocks are inherited whole. The policy always wins.
func TestExpandPolicyTemplateDeepMerge(t *testing.T) {
	tmpl := &DnssecPolicyConf{
		Name:      "TEMPLATE", // must NOT be copied
		Algorithm: "ED25519",
		Mode:      "auto",
	}
	tmpl.KSK.Lifetime = "365d"
	tmpl.KSK.Algorithm = "ED25519"
	tmpl.ZSK.Lifetime = "30d"
	tmpl.Rollover.Method = "cds"
	tmpl.Rollover.NumDS = 2
	tmpl.Ttls.DNSKEY = "3600"
	tmpl.SigValidity.Default = "14d"

	p := DnssecPolicyConf{Name: "mypolicy"}
	p.KSK.Lifetime = "180d" // overrides exactly one leaf of an otherwise-inherited block

	got := ExpandPolicyTemplate(p, tmpl)

	// Top-level scalars gap-filled from the template.
	if got.Algorithm != "ED25519" {
		t.Errorf("Algorithm = %q, want ED25519 (template)", got.Algorithm)
	}
	if got.Mode != "auto" {
		t.Errorf("Mode = %q, want auto (template)", got.Mode)
	}
	// Deep merge within a partially-set block: policy's leaf wins, sibling inherited.
	if got.KSK.Lifetime != "180d" {
		t.Errorf("KSK.Lifetime = %q, want 180d (policy wins)", got.KSK.Lifetime)
	}
	if got.KSK.Algorithm != "ED25519" {
		t.Errorf("KSK.Algorithm = %q, want ED25519 (inherited within a partially-set block)", got.KSK.Algorithm)
	}
	// Untouched blocks inherited whole.
	if got.ZSK.Lifetime != "30d" {
		t.Errorf("ZSK.Lifetime = %q, want 30d (template)", got.ZSK.Lifetime)
	}
	if got.Rollover.Method != "cds" || got.Rollover.NumDS != 2 {
		t.Errorf("Rollover not inherited whole: %+v", got.Rollover)
	}
	if got.Ttls.DNSKEY != "3600" {
		t.Errorf("Ttls.DNSKEY = %q, want 3600 (template)", got.Ttls.DNSKEY)
	}
	if got.SigValidity.Default != "14d" {
		t.Errorf("SigValidity.Default = %q, want 14d (template)", got.SigValidity.Default)
	}
	// Name and Template are never copied from the template.
	if got.Name != "mypolicy" {
		t.Errorf("Name = %q, must not be overwritten by template", got.Name)
	}
	// Mutating the policy must not write back into the template.
	if tmpl.KSK.Lifetime != "365d" {
		t.Errorf("template KSK.Lifetime mutated to %q", tmpl.KSK.Lifetime)
	}
}

// TestExpandPolicyTemplateGapFillsSetBlock is the distinguishing case between
// deep and shallow merge: the policy sets one field of rollover, and the
// remaining rollover fields are still filled from the template. A shallow merge
// would leave NumDS at 0 because the policy's rollover block is non-zero.
func TestExpandPolicyTemplateGapFillsSetBlock(t *testing.T) {
	tmpl := &DnssecPolicyConf{Algorithm: "ED25519"}
	tmpl.Rollover.Method = "cds"
	tmpl.Rollover.NumDS = 2

	p := DnssecPolicyConf{Name: "p", Algorithm: "RSASHA256"}
	p.Rollover.Method = "csync" // sets one rollover leaf; NumDS left 0

	got := ExpandPolicyTemplate(p, tmpl)

	if got.Algorithm != "RSASHA256" {
		t.Errorf("Algorithm = %q, policy must win", got.Algorithm)
	}
	if got.Rollover.Method != "csync" {
		t.Errorf("Rollover.Method = %q, policy must win", got.Rollover.Method)
	}
	if got.Rollover.NumDS != 2 {
		t.Errorf("Rollover.NumDS = %d, want 2 (deep merge fills the gap in a set block)", got.Rollover.NumDS)
	}
}
