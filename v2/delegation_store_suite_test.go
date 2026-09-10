/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns_test

import (
	"os"
	"path/filepath"
	"testing"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/delegationtest"
)

// The sqlite store against the shared equivalence suite. The external-db
// store runs the same suite from its own module; the two must agree on every
// operation or the (store, writer) split has regressed something.
func TestSqliteDelegationStoreSuite(t *testing.T) {
	delegationtest.RunStoreSuite(t, func(t *testing.T) tdns.DelegationStore {
		t.Helper()
		f := filepath.Join(t.TempDir(), "test.db")
		if err := os.WriteFile(f, nil, 0664); err != nil {
			t.Fatalf("create db file: %v", err)
		}
		kdb, err := tdns.NewKeyDB(f, false, nil)
		if err != nil {
			t.Fatalf("NewKeyDB: %v", err)
		}
		b, err := tdns.LookupDelegationBackend("db", kdb, nil)
		if err != nil {
			t.Fatalf("LookupDelegationBackend(db): %v", err)
		}
		return b
	})
}
