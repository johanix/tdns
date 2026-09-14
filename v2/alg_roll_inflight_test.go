package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// Role-generalized in-flight predicate (plan commit 3, P0-4, KT-2d
// precursor): kskAlgRollInFlight mirrors zskAlgRollInFlight, FromAlgs is a
// set, and the singular FromAlg is deterministic.

const ktInflightZone = "inflight.example."

func TestKskAlgRollInFlight(t *testing.T) {
	t.Run("fresh-zone-not-in-flight", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		ktGenKSK(t, kdb, ktInflightZone, DnskeyStateActive, dns.ED25519)
		ktGenKSK(t, kdb, ktInflightZone, DnskeyStateStandby, dns.ED25519)
		st, err := kskAlgRollInFlight(kdb, ktInflightZone, dns.ED25519)
		if err != nil {
			t.Fatalf("kskAlgRollInFlight: %v", err)
		}
		if st.InFlight || st.Role != "KSK" || st.Total != 2 || st.Done != 2 {
			t.Fatalf("fresh same-alg zone must not be in flight: %+v", st)
		}
	})

	t.Run("overlap-two-active-heads", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		ktGenKSK(t, kdb, ktInflightZone, DnskeyStateActive, dns.ED25519)
		ktGenKSK(t, kdb, ktInflightZone, DnskeyStateActive, dns.RSASHA256)
		st, err := kskAlgRollInFlight(kdb, ktInflightZone, dns.RSASHA256)
		if err != nil {
			t.Fatalf("kskAlgRollInFlight: %v", err)
		}
		if !st.InFlight || st.FromAlg() != dns.ED25519 || st.ToAlg != dns.RSASHA256 {
			t.Fatalf("overlap must read in flight ED25519→RSASHA256: %+v", st)
		}
		if st.Done != 1 || st.Total != 2 {
			t.Fatalf("progress = %d/%d, want 1/2", st.Done, st.Total)
		}
	})

	t.Run("pre-spawn-pipeline-member-counts", func(t *testing.T) {
		// A wrong-algorithm KSK still in the DS pipeline keeps the roll in
		// flight for the re-entrancy guard, even with no active mismatch.
		kdb := newTestKeyDB(t)
		ktGenKSK(t, kdb, ktInflightZone, DnskeyStateActive, dns.RSASHA256)
		ktGenKSK(t, kdb, ktInflightZone, DnskeyStateDsPublished, dns.ED25519)
		st, err := kskAlgRollInFlight(kdb, ktInflightZone, dns.RSASHA256)
		if err != nil {
			t.Fatalf("kskAlgRollInFlight: %v", err)
		}
		if !st.InFlight {
			t.Fatalf("old-algorithm ds-published KSK must keep the roll in flight: %+v", st)
		}
	})

	t.Run("zsk-keys-do-not-count", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		ktGenKSK(t, kdb, ktInflightZone, DnskeyStateActive, dns.RSASHA256)
		ktGenZSK(t, kdb, ktInflightZone, DnskeyStateActive, dns.ED25519)
		st, err := kskAlgRollInFlight(kdb, ktInflightZone, dns.RSASHA256)
		if err != nil {
			t.Fatalf("kskAlgRollInFlight: %v", err)
		}
		if st.InFlight || st.Total != 1 {
			t.Fatalf("a wrong-alg ZSK must not read as a KSK roll: %+v", st)
		}
	})
}

// P0-4: FromAlgs is a set and FromAlg is the most-populated source
// algorithm (lowest codepoint on a tie), not whichever key the keystore
// happened to return first.
func TestAlgRollFromAlgsIsDeterministicSet(t *testing.T) {
	kdb := newTestKeyDB(t)
	// Target RSASHA256; two ED25519 ZSKs and one ECDSAP256SHA256 ZSK left over.
	ktGenZSK(t, kdb, ktInflightZone, DnskeyStateActive, dns.RSASHA256)
	ktGenZSK(t, kdb, ktInflightZone, DnskeyStateRetired, dns.ECDSAP256SHA256)
	ktGenZSK(t, kdb, ktInflightZone, DnskeyStateRetired, dns.ED25519)
	ktGenZSK(t, kdb, ktInflightZone, DnskeyStateStandby, dns.ED25519)

	st, err := zskAlgRollInFlight(kdb, ktInflightZone, dns.RSASHA256)
	if err != nil {
		t.Fatalf("zskAlgRollInFlight: %v", err)
	}
	if !st.InFlight {
		t.Fatalf("must be in flight: %+v", st)
	}
	if len(st.FromAlgs) != 2 || st.FromAlgs[0] != dns.ED25519 || st.FromAlgs[1] != dns.ECDSAP256SHA256 {
		t.Fatalf("FromAlgs = %v, want [ED25519 ECDSAP256SHA256] (most keys first)", st.FromAlgs)
	}
	if st.FromAlg != dns.ED25519 {
		t.Fatalf("FromAlg = %s, want ED25519", dns.AlgorithmToString[st.FromAlg])
	}
	if st.Done != 1 || st.Total != 4 {
		t.Fatalf("progress = %d/%d, want 1/4", st.Done, st.Total)
	}
}
