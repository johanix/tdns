//go:build unix

package cli

import (
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
