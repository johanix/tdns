package tdns

import (
	"fmt"
	"testing"
)

// T1a.2: the signing set and the served DNSKEY set computed today's way (the
// reference queries in keyrow_helpers_test.go) equal the same sets computed
// from the columns, over every small keystore and over seeded random ones.

// Every (state, role) with zero, one and two keys, on top of a baseline of one
// active KSK and one active ZSK.
func TestOldAndNewKeySetsAgreeOnEverySmallKeystore(t *testing.T) {
	kdb := newTestKeyDB(t)
	rng := newTestRand(10)
	for _, state := range keyStatesForRowTests {
		for _, role := range keyRolesForRowTests {
			for n := 0; n <= 2; n++ {
				zone := fmt.Sprintf("%s-%s-%d.example.", state, role, n)
				insertTestKeyRow(t, kdb, zone, DnskeyStateActive, "KSK", rng)
				insertTestKeyRow(t, kdb, zone, DnskeyStateActive, "ZSK", rng)
				for i := 0; i < n; i++ {
					insertTestKeyRow(t, kdb, zone, state, role, rng)
				}
				assertKeySetsAgree(t, kdb, zone)
			}
		}
	}
	if diffs := kdb.CheckKeyColumnEquivalence(); len(diffs) != 0 {
		t.Errorf("the startup equivalence check disagrees: %v", diffs)
	}
}

// Seeded random keystores: zero to two keys of every (state, role).
func TestOldAndNewKeySetsAgreeOnRandomKeystores(t *testing.T) {
	kdb := newTestKeyDB(t)
	const seeds = 200
	for seed := uint64(0); seed < seeds; seed++ {
		rng := newTestRand(seed)
		zone := fmt.Sprintf("seed%d.example.", seed)
		for _, state := range keyStatesForRowTests {
			for _, role := range keyRolesForRowTests {
				for i, n := 0, rng.IntN(3); i < n; i++ {
					insertTestKeyRow(t, kdb, zone, state, role, rng)
				}
			}
		}
		assertKeySetsAgree(t, kdb, zone)
	}
	if diffs := kdb.CheckKeyColumnEquivalence(); len(diffs) != 0 {
		t.Errorf("the startup equivalence check disagrees: %v", diffs)
	}
}
