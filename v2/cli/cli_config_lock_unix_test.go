//go:build unix

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Two `config add` runs on one file take turns: the second waits for the
// first to release the lock, and then gets it.
func TestLockCliConfigTakesTurns(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tdns-ncli.yaml")
	unlock, err := lockCliConfig(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan func(), 1)
	go func() {
		u, err := lockCliConfig(context.Background(), p)
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
		u, err := lockCliConfigs(context.Background(), a, b)
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
	writeFile(t, local, "apiservers:\n   - name: auth\n     baseurl: https://127.0.0.1:8989/api/v1\n     apikey: k\n     authmethod: X-API-Key\n")
	writeFile(t, env.cli, "cli:\n   localconfig: "+local+"\n")
	d := env.daemon(t, "tdns-auth2.yaml", "TDNS-AUTH", "127.0.0.1:8990")

	unlock, err := lockCliConfig(context.Background(), env.cli) // another add, busy with the CLI config
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

	// Locks taken together are taken in one order, each once: a path named
	// twice must not wait on its own lock.
	locked := make(chan error, 1)
	go func() {
		u, err := lockCliConfigs(context.Background(), local, env.cli, local)
		if err == nil {
			u()
		}
		locked <- err
	}()
	select {
	case err := <-locked:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lockCliConfigs waited on its own lock")
	}
}

// Ctrl-C while an add waits for another add's lock: the wait ends, and the
// add neither reads nor writes the config.
func TestCancelledAddStopsWaitingForTheLock(t *testing.T) {
	env := newAddEnv(t)
	d := env.daemon(t, "tdns-auth.yaml", "TDNS-AUTH", "127.0.0.1:8989")
	unlock, err := lockCliConfig(context.Background(), env.cli) // another add, busy
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := AddDaemonConfig(AddOptions{Ctx: ctx, CliConfig: env.cli, DaemonConfig: d})
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want the cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the add kept waiting for the lock after its context was cancelled")
	}
	if _, err := os.Stat(env.cli); !os.IsNotExist(err) {
		t.Errorf("the cancelled add wrote the CLI config (stat: %v)", err)
	}
}

// The CLI config does not exist yet, and --file names it through another
// alias of its directory. It is the same file, so the add creates it, as it
// would with no --file, instead of failing to read it.
func TestAddCreatesTheCliConfigNamedThroughADirectoryAlias(t *testing.T) {
	env := newAddEnv(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(env.dir, alias); err != nil {
		t.Skip("no symlinks here")
	}
	d := env.daemon(t, "tdns-auth.yaml", "TDNS-AUTH", "127.0.0.1:8989")
	res, err := env.add(t, d, func(o *AddOptions) { o.TargetFile = filepath.Join(alias, "tdns-ncli.yaml") })
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created {
		t.Errorf("not reported as created: %+v", res)
	}
	if got := env.entries(t); len(got) != 1 || got[0].Name != "auth" {
		t.Errorf("entries: %+v", got)
	}
}
