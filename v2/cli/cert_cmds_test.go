/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import "testing"

// TestCertValidityFlagBindings guards the shared-backing-variable footgun:
// every cobra flag registered against &certValidity writes its default to
// that one variable at registration time, so `cert ca` must use its own
// backing variable (certCAValidity) or it silently inherits the leaf/sign
// default (397) instead of 3650. This test would have caught that bug.
func TestCertValidityFlagBindings(t *testing.T) {
	caFlag := certCaCmd.Flags().Lookup("validity")
	if caFlag == nil {
		t.Fatal("cert ca has no --validity flag")
	}
	if caFlag.DefValue != "3650" {
		t.Fatalf("cert ca --validity default = %q, want 3650", caFlag.DefValue)
	}
	// The CA flag must NOT share the leaf/sign backing variable, or
	// addCommonLeafFlags rebinds it to 397.
	if certCAValidity != 3650 {
		t.Fatalf("certCAValidity = %d after init, want 3650 (shared-variable regression)", certCAValidity)
	}
	if certValidity != 397 {
		t.Fatalf("certValidity = %d after init, want 397 (leaf/sign default)", certValidity)
	}

	for _, cmd := range []string{"leaf", "sign"} {
		var f = certLeafCmd.Flags().Lookup("validity")
		if cmd == "sign" {
			f = certSignCmd.Flags().Lookup("validity")
		}
		if f == nil || f.DefValue != "397" {
			t.Fatalf("cert %s --validity default = %v, want 397", cmd, f)
		}
	}

	// Verify the binding DIRECTLY, not just the default: setting the CA
	// --validity value must land in certCAValidity and must NOT leak into
	// certValidity (the shared leaf/sign backing var). Defaults alone would
	// miss a mis-binding if the two defaults ever coincided. Restore both.
	origCA, origLeaf := certCAValidity, certValidity
	t.Cleanup(func() { certCAValidity, certValidity = origCA, origLeaf })
	if err := caFlag.Value.Set("1234"); err != nil {
		t.Fatalf("set cert ca --validity: %v", err)
	}
	if certCAValidity != 1234 {
		t.Fatalf("cert ca --validity wrote the wrong variable: certCAValidity = %d, want 1234", certCAValidity)
	}
	if certValidity != origLeaf {
		t.Fatalf("cert ca --validity leaked into certValidity (= %d, want %d): shared backing variable", certValidity, origLeaf)
	}
}
