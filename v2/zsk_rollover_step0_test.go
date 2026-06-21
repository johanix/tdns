package tdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Step 0 (ZSK rollover robustness parity) tests: manual asap/cancel request,
// roll-due manual override, active_at self-heal, and the active_seq counter.
// Driven against a real on-disk KeyDB via newTestKeyDB (sign_reconcile_test.go).

const zskTestZone = "zsk-step0.example."

// seedActiveZSK generates one active + (optionally) one standby ZSK so the
// roll path has something to work with. Returns the active keyid.
func seedActiveZSK(t *testing.T, kdb *KeyDB, withStandby bool) uint16 {
	t.Helper()
	pkc, _, err := kdb.GenerateKeypair(zskTestZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "ZSK", nil)
	if err != nil {
		t.Fatalf("generate active ZSK: %v", err)
	}
	if withStandby {
		if _, _, err := kdb.GenerateKeypair(zskTestZone, "test", DnskeyStateStandby, dns.TypeDNSKEY, dns.ED25519, "ZSK", nil); err != nil {
			t.Fatalf("generate standby ZSK: %v", err)
		}
	}
	return pkc.KeyId
}

// T0.1 — manual asap request persists and reads back; cancel clears it.
func TestZskManualRequestPersistAndCancel(t *testing.T) {
	kdb := newTestKeyDB(t)
	now := time.Now()

	if m, err := LoadZskManualRollover(kdb, zskTestZone); err != nil || m.Earliest != "" || m.RequestedAt != "" {
		t.Fatalf("no request yet: got (%+v, %v)", m, err)
	}
	if err := SetZskManualRolloverRequest(kdb, zskTestZone, now, now); err != nil {
		t.Fatalf("SetZskManualRolloverRequest: %v", err)
	}
	m, err := LoadZskManualRollover(kdb, zskTestZone)
	if err != nil || m.Earliest == "" || m.RequestedAt == "" {
		t.Fatalf("after set: got (%+v, %v), want both fields populated", m, err)
	}
	if err := ClearZskManualRolloverRequest(kdb, zskTestZone); err != nil {
		t.Fatalf("ClearZskManualRolloverRequest: %v", err)
	}
	if m, err := LoadZskManualRollover(kdb, zskTestZone); err != nil || m.Earliest != "" || m.RequestedAt != "" {
		t.Fatalf("after clear: got (%+v, %v), want empty", m, err)
	}
}

// T0.2 — roll-due returns true (manual) when a manual request is set even
// though the lifetime has not elapsed; false otherwise.
func TestZskRollDueManualOverride(t *testing.T) {
	now := time.Now()
	justActive := now.Add(-1 * time.Minute) // far younger than lifetime
	lifetime := uint32((24 * time.Hour).Seconds())

	// No manual request, young key: not due.
	if due, manual := zskRollDue(now, &justActive, lifetime, ""); due || manual {
		t.Fatalf("young key, no manual: got due=%v manual=%v, want false,false", due, manual)
	}
	// Manual request with earliest in the past: due (manual), despite young key.
	past := now.Add(-1 * time.Second).UTC().Format(time.RFC3339)
	if due, manual := zskRollDue(now, &justActive, lifetime, past); !due || !manual {
		t.Fatalf("manual override: got due=%v manual=%v, want true,true", due, manual)
	}
	// Manual request with earliest in the future: not yet due.
	future := now.Add(1 * time.Hour).UTC().Format(time.RFC3339)
	if due, manual := zskRollDue(now, &justActive, lifetime, future); due || manual {
		t.Fatalf("future manual: got due=%v manual=%v, want false,false", due, manual)
	}
	// Lifetime elapsed, no manual: due (scheduled, not manual).
	old := now.Add(-48 * time.Hour)
	if due, manual := zskRollDue(now, &old, lifetime, ""); !due || manual {
		t.Fatalf("lifetime elapsed: got due=%v manual=%v, want true,false", due, manual)
	}
	// lifetime 0 = never, no manual: not due.
	if due, _ := zskRollDue(now, &old, 0, ""); due {
		t.Fatalf("lifetime 0: got due=%v, want false", due)
	}
}

// T0.3 — a manual ZSK roll (RolloverKey) with a standby present swaps
// standby→active / active→retired. With no standby it errors (no key loss).
func TestZskRolloverKeySwapAndNoStandby(t *testing.T) {
	kdb := newTestKeyDB(t)
	oldActive := seedActiveZSK(t, kdb, true)

	old, neu, err := kdb.RolloverKey(zskTestZone, "ZSK", nil)
	if err != nil {
		t.Fatalf("RolloverKey: %v", err)
	}
	if old != oldActive {
		t.Fatalf("old active = %d, want %d", old, oldActive)
	}
	// old key now retired, new key active.
	retired, _ := GetDnssecKeysByState(kdb, zskTestZone, DnskeyStateRetired)
	if len(retired) != 1 || retired[0].KeyTag != old {
		t.Fatalf("expected retired key %d, got %+v", old, retired)
	}
	active, _ := GetDnssecKeysByState(kdb, zskTestZone, DnskeyStateActive)
	if len(active) != 1 || active[0].KeyTag != neu {
		t.Fatalf("expected active key %d, got %+v", neu, active)
	}

	// No standby remains → a second roll must error (and not lose the active).
	if _, _, err := kdb.RolloverKey(zskTestZone, "ZSK", nil); err == nil {
		t.Fatalf("expected error rolling with no standby")
	}
	active, _ = GetDnssecKeysByState(kdb, zskTestZone, DnskeyStateActive)
	if len(active) != 1 {
		t.Fatalf("active key lost after failed roll: %+v", active)
	}
}

// T0.4 — persistence across a no-standby tick is the engine's responsibility
// (rolloverZskForZone does NOT clear on the no-standby no-op). Here we assert
// the helper-level contract that a manual request set with no standby is not
// auto-cleared by reading it back (the worker only clears after a committed
// roll). This complements the engine wiring in rolloverZskForZone.
func TestZskManualRequestSurvivesNoStandby(t *testing.T) {
	kdb := newTestKeyDB(t)
	seedActiveZSK(t, kdb, false) // active only, no standby
	now := time.Now()
	if err := SetZskManualRolloverRequest(kdb, zskTestZone, now, now); err != nil {
		t.Fatalf("set request: %v", err)
	}
	// Simulate what the worker reads: request is present and due.
	m, err := LoadZskManualRollover(kdb, zskTestZone)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	due, manual := zskRollDue(now, nil, 0, m.Earliest)
	if !due || !manual {
		t.Fatalf("manual due with no active_at: got due=%v manual=%v, want true,true", due, manual)
	}
	// The request must still be present (worker would NOT clear it without a
	// standby to roll to).
	if m2, err := LoadZskManualRollover(kdb, zskTestZone); err != nil || m2.Earliest == "" || m2.RequestedAt == "" {
		t.Fatalf("request must persist with no standby: got (%+v, %v)", m2, err)
	}
}

// T0.5 — active_at self-heal: an active ZSK with NULL active_at gets stamped;
// a real active_at is not overwritten.
func TestZskActiveAtSelfHeal(t *testing.T) {
	kdb := newTestKeyDB(t)
	keyid := seedActiveZSK(t, kdb, false)

	// Force active_at NULL (GenerateKeypair into active stamps active_at; clear it).
	if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET active_at=NULL, active_seq=NULL WHERE zonename=? AND keyid=?`, zskTestZone, int(keyid)); err != nil {
		t.Fatalf("null active_at: %v", err)
	}
	active, _ := GetDnssecKeysByState(kdb, zskTestZone, DnskeyStateActive)
	if len(active) != 1 || active[0].ActiveAt != nil {
		t.Fatalf("precondition: want one active ZSK with nil active_at, got %+v", active)
	}

	healZskActiveAt(kdb, zskTestZone, &active[0])

	active, _ = GetDnssecKeysByState(kdb, zskTestZone, DnskeyStateActive)
	if active[0].ActiveAt == nil {
		t.Fatalf("active_at not healed")
	}
	if active[0].ActiveSeq == nil {
		t.Fatalf("active_seq not healed")
	}
	stampedAt := *active[0].ActiveAt

	// Re-heal must NOT overwrite the now-real active_at.
	healZskActiveAt(kdb, zskTestZone, &active[0])
	active, _ = GetDnssecKeysByState(kdb, zskTestZone, DnskeyStateActive)
	if active[0].ActiveAt == nil || !active[0].ActiveAt.Equal(stampedAt) {
		t.Fatalf("re-heal overwrote active_at: was %v now %v", stampedAt, active[0].ActiveAt)
	}
}

// T0.6 — active_seq increments by one per roll; KSK keys are not counted in
// the ZSK seq (independent counters).
func TestZskActiveSeqCounter(t *testing.T) {
	kdb := newTestKeyDB(t)

	// Seed an active ZSK + standby, plus a KSK (must not affect ZSK seq).
	seedActiveZSK(t, kdb, true)
	if _, _, err := kdb.GenerateKeypair(zskTestZone, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("generate KSK: %v", err)
	}

	// First roll: the promoted ZSK gets active_seq from MAX(seq)+1. No ZSK has
	// a seq yet (GenerateKeypair doesn't stamp it), so first promotion = 0.
	_, neu, err := kdb.RolloverKey(zskTestZone, "ZSK", nil)
	if err != nil {
		t.Fatalf("roll 1: %v", err)
	}
	seq1 := zskActiveSeqOf(t, kdb, neu)
	if seq1 == nil {
		t.Fatalf("roll 1: new active ZSK has no active_seq")
	}

	// Add another standby and roll again; seq must increment.
	if _, _, err := kdb.GenerateKeypair(zskTestZone, "test", DnskeyStateStandby, dns.TypeDNSKEY, dns.ED25519, "ZSK", nil); err != nil {
		t.Fatalf("generate standby 2: %v", err)
	}
	_, neu2, err := kdb.RolloverKey(zskTestZone, "ZSK", nil)
	if err != nil {
		t.Fatalf("roll 2: %v", err)
	}
	seq2 := zskActiveSeqOf(t, kdb, neu2)
	if seq2 == nil {
		t.Fatalf("roll 2: new active ZSK has no active_seq")
	}
	if *seq2 != *seq1+1 {
		t.Fatalf("seq did not increment: roll1=%d roll2=%d", *seq1, *seq2)
	}

	// The KSK must not have a ZSK-counter value bleeding into it (independent).
	ksks, _ := GetDnssecKeysByState(kdb, zskTestZone, DnskeyStateActive)
	for _, k := range ksks {
		if k.Flags == 257 && k.ActiveSeq != nil {
			t.Fatalf("KSK got a ZSK active_seq: %+v", k)
		}
	}
}

// Display parity: a removed ZSK shows a state_since timestamp (sourced from
// retired_at, since ZSKs have no RolloverKeyState row), not blank; and the
// removed-key display cap + hidden count apply to ZSKs like KSKs.
func TestZskRemovedDisplayParity(t *testing.T) {
	kdb := newTestKeyDB(t)

	// Create several removed ZSKs with retired_at set, distinct active_seq.
	for i := 0; i < 5; i++ {
		pkc, _, err := kdb.GenerateKeypair(zskTestZone, "test", DnskeyStateRemoved, dns.TypeDNSKEY, dns.ED25519, "ZSK", nil)
		if err != nil {
			t.Fatalf("generate removed ZSK %d: %v", i, err)
		}
		ts := time.Now().Add(time.Duration(-i) * time.Hour).UTC().Format(time.RFC3339)
		if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET retired_at=?, active_seq=? WHERE zonename=? AND keyid=?`,
			ts, i, zskTestZone, int(pkc.KeyId)); err != nil {
			t.Fatalf("stamp removed ZSK %d: %v", i, err)
		}
	}

	zsks, hidden := loadRolloverKeyEntries(kdb, zskTestZone, false)
	// Cap: only rolloverStatusRemovedDisplayCap shown, rest hidden.
	if len(zsks) != rolloverStatusRemovedDisplayCap {
		t.Fatalf("shown removed ZSKs = %d, want %d", len(zsks), rolloverStatusRemovedDisplayCap)
	}
	if hidden != 5-rolloverStatusRemovedDisplayCap {
		t.Fatalf("hidden removed ZSKs = %d, want %d", hidden, 5-rolloverStatusRemovedDisplayCap)
	}
	// Shown keys are the highest active_seq (most recent), descending.
	if zsks[0].ActiveSeq == nil || *zsks[0].ActiveSeq != 4 {
		t.Fatalf("first shown removed ZSK seq = %v, want 4", zsks[0].ActiveSeq)
	}
	// state_since resolves (non-empty) for a removed ZSK via retired_at.
	zd := testZone(t, zskTestZone, zskTestZone+" IN SOA . . 1 1 1 1 1\n")
	zd.KeyDB = kdb
	k := &DnssecKeyWithTimestamps{ZoneName: zskTestZone, KeyTag: zsks[0].KeyID, Flags: 256, State: DnskeyStateRemoved}
	// reload the full key (with retired_at) for the state-since check
	removed, _ := GetDnssecKeysByState(kdb, zskTestZone, DnskeyStateRemoved)
	for i := range removed {
		if removed[i].KeyTag == zsks[0].KeyID {
			k = &removed[i]
		}
	}
	if ts := StateSinceForDnssecKey(kdb, zskTestZone, k); ts.IsZero() {
		t.Fatalf("removed ZSK state_since is zero; want retired_at")
	}
}

func zskActiveSeqOf(t *testing.T, kdb *KeyDB, keyid uint16) *int {
	t.Helper()
	for _, st := range []string{DnskeyStateActive, DnskeyStateRetired, DnskeyStateStandby} {
		keys, _ := GetDnssecKeysByState(kdb, zskTestZone, st)
		for i := range keys {
			if keys[i].KeyTag == keyid {
				return keys[i].ActiveSeq
			}
		}
	}
	return nil
}
