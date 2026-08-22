/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */

package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

// findSub returns the named subcommand of parent, or fails.
func findSub(t *testing.T, parent *cobra.Command, name string) *cobra.Command {
	t.Helper()
	for _, c := range parent.Commands() {
		if c.Name() == name {
			return c
		}
	}
	t.Fatalf("no %q subcommand under %q", name, parent.Name())
	return nil
}

// TestTransferSrcFlagNilVsEmpty pins the distinction the modify semantics rest
// on, through the REAL command tree rather than a replica of the flag setup.
//
// ModifyDynamicZone treats nil as "caller said nothing, keep the stored value"
// and non-nil as "replace" -- including a non-nil EMPTY slice, which clears the
// per-zone source so the zone falls back to the global default. That only works
// if the CLI can actually produce a non-nil empty slice, and whether it does is
// cobra's behaviour, not ours: it could change under us, and the failure would
// be silent (a clear that quietly becomes a no-op).
func TestTransferSrcFlagNilVsEmpty(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		wantNil bool
		wantLen int
		wantVal string
	}{
		{
			name:    "omitted leaves it nil: modify keeps the stored value",
			args:    []string{"modify", "-z", "example."},
			wantNil: true,
		},
		{
			name:    "a value replaces",
			args:    []string{"modify", "-z", "example.", "--transfer-src", "172.16.0.53"},
			wantNil: false, wantLen: 1, wantVal: "172.16.0.53",
		},
		{
			// The clear case. Non-nil and empty -- if cobra ever returns nil
			// here instead, clearing silently becomes "leave unchanged" and a
			// zone can never drop a wrong source address without delete+re-add.
			name:    "explicit empty is non-nil: modify clears",
			args:    []string{"modify", "-z", "example.", "--transfer-src="},
			wantNil: false, wantLen: 0,
		},
		{
			name:    "two families",
			args:    []string{"modify", "-z", "example.", "--transfer-src", "172.16.0.53,2a01:bad:cafe:f::53"},
			wantNil: false, wantLen: 2, wantVal: "172.16.0.53",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zoneCmd := NewZoneCmd("auth")
			sub := findSub(t, zoneCmd, tc.args[0])

			// Parse only: Run would talk to a daemon.
			if err := sub.ParseFlags(tc.args[1:]); err != nil {
				t.Fatalf("ParseFlags(%v): %v", tc.args, err)
			}
			got, err := sub.Flags().GetStringSlice("transfer-src")
			if err != nil {
				t.Fatalf("GetStringSlice: %v", err)
			}
			changed := sub.Flags().Changed("transfer-src")

			// "nil" in the sense that matters: the flag was never given, so the
			// caller said nothing and modify must keep the stored value.
			if tc.wantNil {
				if changed {
					t.Fatalf("flag reported as changed when omitted")
				}
				return
			}
			if !changed {
				t.Fatalf("flag given but not reported as changed")
			}
			// NON-NIL is the property that matters, not just the length.
			// ModifyDynamicZone branches on nil vs non-nil: nil means "keep the
			// stored value", non-nil means "replace" -- so if cobra ever handed
			// back nil for --transfer-src=, clearing a zone's source would
			// silently become a no-op and len(got)==0 would still pass.
			if got == nil {
				t.Fatalf("flag was given but parsed to a nil slice; clear would be indistinguishable from omitted")
			}
			if len(got) != tc.wantLen {
				t.Fatalf("len = %d, want %d (value %q)", len(got), tc.wantLen, got)
			}
			if tc.wantVal != "" && got[0] != tc.wantVal {
				t.Errorf("first entry = %q, want %q", got[0], tc.wantVal)
			}
		})
	}
}
