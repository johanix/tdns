/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * The hidden `zone dsync` alias (#493). It exists so existing invocations keep
 * working for one release, which is only true if every old command still maps
 * to a command the new endpoints implement -- a mapping table nothing else
 * checks.
 */
package cli

import "testing"

func TestDsyncAliasMapsEveryOldCommand(t *testing.T) {
	// The five commands newZoneDsyncCmd can send, and where each must land.
	for _, tc := range []struct {
		old        string
		wantParent bool   // true: /zone/parentsync, false: /zone/childsync
		wantCmd    string // command name on the new endpoint
	}{
		{"status", true, "status"},
		{"bootstrap-sig0-key", true, "bootstrap"},
		{"roll-sig0-key", true, "roll-key"},
		{"publish-dsync-rrset", false, "publish"},
		{"unpublish-dsync-rrset", false, "unpublish"},
	} {
		t.Run(tc.old, func(t *testing.T) {
			isParent := !parentSideCommands[tc.old]
			if isParent != tc.wantParent {
				t.Errorf("routed to parentsync=%v, want %v", isParent, tc.wantParent)
			}
			got := dsyncAliasCommand(tc.old)
			if got != tc.wantCmd {
				t.Errorf("maps to %q, want %q", got, tc.wantCmd)
			}
		})
	}
}
