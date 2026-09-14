package tdns

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// KT-10 (D-9) and P1-1 / R2: "at most one active key per (role, algorithm)".

const ktInvZone = "inv.example."

func ktPickActive(t *testing.T, kdb *KeyDB) (uint16, error) {
	t.Helper()
	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	return pickActiveSEPTx(tx, ktInvZone)
}

func ktPickActiveByAlg(t *testing.T, kdb *KeyDB, alg uint8) (uint16, error) {
	t.Helper()
	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	return pickActiveSEPByAlgTx(tx, ktInvZone, alg)
}

func TestKT10PickActiveSEP(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		kid, err := ktPickActive(t, kdb)
		if err != nil || kid != 0 {
			t.Fatalf("no active SEP: got kid=%d err=%v, want 0/nil", kid, err)
		}
	})

	t.Run("single", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		a := ktGenKSK(t, kdb, ktInvZone, DnskeyStateActive, dns.ED25519)
		kid, err := ktPickActive(t, kdb)
		if err != nil || kid != a {
			t.Fatalf("single active SEP: got kid=%d err=%v, want %d/nil", kid, err, a)
		}
	})

	t.Run("two-same-algorithm", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		ktGenKSK(t, kdb, ktInvZone, DnskeyStateActive, dns.ED25519)
		ktGenKSK(t, kdb, ktInvZone, DnskeyStateActive, dns.ED25519)
		_, err := ktPickActive(t, kdb)
		if err == nil || !strings.Contains(err.Error(), "invariant violated") {
			t.Fatalf("two active SEPs of one algorithm must be an invariant error, got %v", err)
		}
	})

	t.Run("two-algorithms", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		a := ktGenKSK(t, kdb, ktInvZone, DnskeyStateActive, dns.ED25519)
		b := ktGenKSK(t, kdb, ktInvZone, DnskeyStateActive, dns.RSASHA256)
		_, err := ktPickActive(t, kdb)
		if err == nil || !strings.Contains(err.Error(), "algorithm rollover") {
			t.Fatalf("two active SEPs of different algorithms must name the in-flight algorithm rollover, got %v", err)
		}
		// The per-algorithm pick still resolves each head.
		if kid, err := ktPickActiveByAlg(t, kdb, dns.ED25519); err != nil || kid != a {
			t.Fatalf("by-alg ED25519: kid=%d err=%v, want %d", kid, err, a)
		}
		if kid, err := ktPickActiveByAlg(t, kdb, dns.RSASHA256); err != nil || kid != b {
			t.Fatalf("by-alg RSASHA256: kid=%d err=%v, want %d", kid, err, b)
		}
		if kid, err := ktPickActiveByAlg(t, kdb, dns.ECDSAP256SHA256); err != nil || kid != 0 {
			t.Fatalf("by-alg absent algorithm: kid=%d err=%v, want 0/nil", kid, err)
		}
	})

	t.Run("by-alg-duplicate", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		ktGenKSK(t, kdb, ktInvZone, DnskeyStateActive, dns.ED25519)
		ktGenKSK(t, kdb, ktInvZone, DnskeyStateActive, dns.ED25519)
		if _, err := ktPickActiveByAlg(t, kdb, dns.ED25519); err == nil {
			t.Fatal("two active SEPs of the requested algorithm must error")
		}
	})
}

// R2: the manual `keystore rollover` path must not pick between the two
// active KSKs of an algorithm rollover.
func TestKT10ManualKSKRolloverRefusedDuringAlgRoll(t *testing.T) {
	kdb := newTestKeyDB(t)
	a := ktGenKSK(t, kdb, ktInvZone, DnskeyStateActive, dns.ED25519)
	b := ktGenKSK(t, kdb, ktInvZone, DnskeyStateActive, dns.RSASHA256)
	standby := ktGenKSK(t, kdb, ktInvZone, DnskeyStateStandby, dns.RSASHA256)

	_, _, err := kdb.RolloverKey(ktInvZone, "KSK", nil)
	if err == nil || !strings.Contains(err.Error(), "algorithm rollover is in progress") {
		t.Fatalf("manual KSK rollover during an algorithm roll must be refused, got %v", err)
	}
	for _, kid := range []uint16{a, b} {
		if st := ktKeyState(t, kdb, ktInvZone, kid); st != DnskeyStateActive {
			t.Fatalf("refusal must not touch key %d: state=%s", kid, st)
		}
	}
	if st := ktKeyState(t, kdb, ktInvZone, standby); st != DnskeyStateStandby {
		t.Fatalf("refusal must not promote the standby: state=%s", st)
	}
}

// P1-1: RolloverKey errors rather than silently retiring one of two
// same-algorithm actives; the ordinary one-active case still rolls.
func TestKT10ManualRolloverSingleActiveGuard(t *testing.T) {
	t.Run("two-active-ZSKs", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		z1 := ktGenZSK(t, kdb, ktInvZone, DnskeyStateActive, dns.ED25519)
		z2 := ktGenZSK(t, kdb, ktInvZone, DnskeyStateActive, dns.ED25519)
		ktGenZSK(t, kdb, ktInvZone, DnskeyStateStandby, dns.ED25519)
		_, _, err := kdb.RolloverKey(ktInvZone, "ZSK", nil)
		if err == nil || !strings.Contains(err.Error(), "one active key per role and algorithm") {
			t.Fatalf("two active ZSKs must be refused, got %v", err)
		}
		for _, kid := range []uint16{z1, z2} {
			if st := ktKeyState(t, kdb, ktInvZone, kid); st != DnskeyStateActive {
				t.Fatalf("refusal must not retire key %d: state=%s", kid, st)
			}
		}
	})

	t.Run("ordinary-roll", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		z1 := ktGenZSK(t, kdb, ktInvZone, DnskeyStateActive, dns.ED25519)
		z2 := ktGenZSK(t, kdb, ktInvZone, DnskeyStateStandby, dns.ED25519)
		oldKid, newKid, err := kdb.RolloverKey(ktInvZone, "ZSK", nil)
		if err != nil {
			t.Fatalf("ordinary ZSK roll: %v", err)
		}
		if oldKid != z1 || newKid != z2 {
			t.Fatalf("roll picked %d→%d, want %d→%d", oldKid, newKid, z1, z2)
		}
	})
}
