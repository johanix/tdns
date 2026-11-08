/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns_test

import (
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
		kdb, err := tdns.NewKeyDBInMemory(t.Name())
		if err != nil {
			t.Fatalf("NewKeyDBInMemory: %v", err)
		}
		t.Cleanup(func() { kdb.Close() })
		b, err := tdns.LookupDelegationBackend("db", kdb, nil)
		if err != nil {
			t.Fatalf("LookupDelegationBackend(db): %v", err)
		}
		return b
	})
}
