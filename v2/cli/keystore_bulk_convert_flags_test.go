/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package cli

import (
	"strings"
	"testing"
)

func TestBulkConvertFlagsError(t *testing.T) {
	for _, tc := range []struct {
		name    string
		class   string
		f       bulkFlags
		wantErr string // "" means accepted
	}{
		{"bind needs --dir", "dnssec", bulkFlags{from: "bind"}, "--dir is required"},
		{"bind", "dnssec", bulkFlags{from: "bind", dir: "/k"}, ""},
		{"bind is the default", "sig0", bulkFlags{dir: "/k"}, ""},
		{"bind refuses cascade flags", "dnssec", bulkFlags{from: "bind", dir: "/k", dest: "/out"}, "only to --from cascade"},
		{"cascade", "dnssec", bulkFlags{from: "cascade", stateFiles: []string{"/k/z.state"}, dest: "/out"}, ""},
		{"cascade needs a state file", "dnssec", bulkFlags{from: "cascade", dest: "/out"}, "--state-file"},
		{"cascade needs --dest", "dnssec", bulkFlags{from: "cascade", stateFiles: []string{"/k/z.state"}}, "--dest"},
		{"cascade refuses bind flags", "dnssec", bulkFlags{from: "cascade", stateFiles: []string{"/k/z.state"}, dest: "/out", dir: "/k"}, "only to --from bind"},
		{"cascade is DNSSEC only", "sig0", bulkFlags{from: "cascade", stateFiles: []string{"/k/z.state"}, dest: "/out"}, "DNSSEC keys only"},
		{"unknown signer", "dnssec", bulkFlags{from: "knot", dir: "/k"}, "unknown --from"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := bulkConvertFlagsError(tc.class, &tc.f)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("refused: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Errorf("err = %v, want one mentioning %q", err, tc.wantErr)
			}
		})
	}
}
