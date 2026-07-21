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
}
