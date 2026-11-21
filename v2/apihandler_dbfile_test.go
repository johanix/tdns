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

// config status reports the file the keystore was opened from, not db.file
// as written: InitializeKeyDB trims and cleans it before opening it.
func TestOpenedDBFileIsTheOneOpened(t *testing.T) {
	conf := &Config{}
	conf.Db.File = " agent2.db "
	if got := openedDBFile(conf); got != "" {
		t.Errorf("no keystore open: %q, want none", got)
	}
	conf.Internal.KeyDB = &KeyDB{DBFile: "agent2.db"}
	if got := openedDBFile(conf); got != "agent2.db" {
		t.Errorf("openedDBFile = %q, want the opened agent2.db", got)
	}
}
