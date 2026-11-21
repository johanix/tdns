//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Two `config add` runs on one file take turns: the second waits for the
// first to release the lock, and then gets it.
func TestLockCliConfigTakesTurns(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tdns-ncli.yaml")
	unlock, err := lockCliConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan func(), 1)
	go func() {
		u, err := lockCliConfig(p)
		if err != nil {
			t.Error(err)
			u = func() {}
		}
		got <- u
	}()
	select {
	case u := <-got:
		u()
		t.Fatal("a second lock was granted while the first was held")
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	select {
	case u := <-got:
		u()
	case <-time.After(5 * time.Second):
		t.Fatal("the second lock was not granted once the first was released")
	}
}

// A CLI config not created yet, named through two aliases of a symlinked
// directory (--config one way, --file the other), is one lock, taken once.
// Two lock names for one lock file would have the add wait on itself.
func TestLockCliConfigsThroughADirectoryAlias(t *testing.T) {
	dir := t.TempDir()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Skip("no symlinks here")
	}
	a := filepath.Join(dir, "tdns-ncli.yaml") // does not exist
	b := filepath.Join(alias, "tdns-ncli.yaml")
	if cliConfigLockPath(a) != cliConfigLockPath(b) {
		t.Errorf("two lock names for one file: %s and %s", cliConfigLockPath(a), cliConfigLockPath(b))
	}
	done := make(chan error, 1)
	go func() {
		u, err := lockCliConfigs(a, b)
		if err == nil {
			u()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lockCliConfigs waited on its own lock")
	}
}

// An add that edits another file than the CLI config (--file, here the
// cli.localconfig that holds the list) still waits for an add that holds the
// CLI config's lock: both edit one effective list.
func TestAddToAnotherFileWaitsForTheCliConfigLock(t *testing.T) {
	env := newAddEnv(t)
	local := filepath.Join(env.dir, "local.yaml")
	writeFile(t, local, "apiservers:\n   - name: tdns-auth\n     baseurl: https://127.0.0.1:8989/api/v1\n     apikey: k\n     authmethod: X-API-Key\n")
	writeFile(t, env.cli, "cli:\n   localconfig: "+local+"\n")
	d := env.daemon(t, "tdns-auth2.yaml", "TDNS-AUTH", "127.0.0.1:8990")

	unlock, err := lockCliConfig(env.cli) // another add, busy with the CLI config
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := AddDaemonConfig(AddOptions{CliConfig: env.cli, DaemonConfig: d, TargetFile: local})
		done <- err
	}()
	select {
	case err := <-done:
		unlock()
		t.Fatalf("the add did not wait for the CLI config's lock (err = %v)", err)
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the add did not go ahead once the lock was released")
	}

	// Locks taken together are taken in one order, each once.
	u, err := lockCliConfigs(local, env.cli, local)
	if err != nil {
		t.Fatal(err)
	}
	u()
}
