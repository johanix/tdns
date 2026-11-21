/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"os"
	"path/filepath"
	"testing"
)

// config status reports the keystore path the daemon resolved: a relative
// db.file must not reach a CLI that would resolve it against its own working
// directory, and an unset one must stay unset.
func TestReportedDBFileIsAbsolute(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		"":                   "",
		"agent2.db":          filepath.Join(wd, "agent2.db"),
		"/var/tdns/agent.db": "/var/tdns/agent.db",
	} {
		if got := reportedDBFile(in); got != want {
			t.Errorf("reportedDBFile(%q) = %q, want %q", in, got, want)
		}
	}
}
