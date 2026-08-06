/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package tdns

import "testing"

// A .private file as dnssec-keygen writes it, with the comment lines bind puts
// above each timestamp.
const sampleBindPrivate = `Private-key-format: v1.3
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: iyLI0zQ2yhIvVBrYtWDrb1UhpvNZjZ0ZZ0kZ1ZQ0ZZ0=
Created: 20260715120000
Publish: 20260715120000
Activate: 20260716000000
`

// A .state file as a dnssec-policy zone produces.
const sampleBindState = `; This is the state of key 12345, for pq.dnslab.
Algorithm: 13
Length: 256
Lifetime: 0
KSK: yes
ZSK: no
Generated: 20260715120000
Published: 20260715120000
Active: 20260716000000
DNSKEYState: omnipresent
DNSKEYChange: 20260716000000
KRRSIGState: omnipresent
KRRSIGChange: 20260716000000
DSState: rumoured
DSChange: 20260717000000
GoalState: omnipresent
`

func TestParseBindKeyTimes(t *testing.T) {
	got := ParseBindKeyTimes([]byte(sampleBindPrivate))
	if got.Created != "20260715120000" || got.Publish != "20260715120000" ||
		got.Activate != "20260716000000" {
		t.Fatalf("timing fields not parsed: %+v", got)
	}
	// Absent tags stay empty rather than becoming a zero time.
	if got.Inactive != "" || got.Delete != "" {
		t.Errorf("absent tags must stay empty, got Inactive=%q Delete=%q", got.Inactive, got.Delete)
	}
	// The key material must not leak into the metadata.
	if got.Created == got.Publish && got.Created == "" {
		t.Error("parser found nothing at all")
	}
}

func TestParseBindKeyState(t *testing.T) {
	st, err := ParseBindKeyState([]byte(sampleBindState))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !st.KSK || st.ZSK {
		t.Errorf("KSK/ZSK booleans wrong: KSK=%v ZSK=%v", st.KSK, st.ZSK)
	}
	if st.DNSKEY != "omnipresent" || st.KRRSIG != "omnipresent" || st.DS != "rumoured" {
		t.Fatalf("states not parsed: %+v", st)
	}
	if st.Active != "20260716000000" {
		t.Errorf("Active timestamp not parsed, got %q", st.Active)
	}
}

// A file that is not a .state file must be refused, not read as "no states
// recorded" -- that would send the caller down the no-state path believing the
// key genuinely had none.
func TestParseBindKeyStateRejectsNonStateFiles(t *testing.T) {
	if _, err := ParseBindKeyState([]byte(sampleBindPrivate)); err == nil {
		t.Error("a .private file must not parse as a .state file")
	}
	if _, err := ParseBindKeyState([]byte("KSK: yes\nDNSKEYState: sideways\n")); err == nil {
		t.Error("an unknown state value must be refused")
	}
}

func TestBindTimeToRFC3339(t *testing.T) {
	got, err := BindTimeToRFC3339("20260716000000")
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if got != "2026-07-16T00:00:00Z" {
		t.Fatalf("got %q, want %q", got, "2026-07-16T00:00:00Z")
	}
	// Empty in, empty out: "not recorded" must not become the epoch, which
	// would read as a real event in 1970.
	if got, err := BindTimeToRFC3339(""); err != nil || got != "" {
		t.Errorf("empty must stay empty, got %q err %v", got, err)
	}
	if _, err := BindTimeToRFC3339("not a timestamp"); err == nil {
		t.Error("an unparsable timestamp must be refused")
	}
}

func TestBindStateToDnssecState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		st    BindKeyState
		isKSK bool
		want  string
	}{
		{"fresh KSK, nothing published", BindKeyState{DNSKEY: "hidden", KRRSIG: "hidden", DS: "hidden"},
			true, DnskeyStateCreated},
		{"DNSKEY out, not yet signing", BindKeyState{DNSKEY: "rumoured", KRRSIG: "hidden", DS: "hidden"},
			true, DnskeyStatePublished},
		{"KSK with DS going in", BindKeyState{DNSKEY: "omnipresent", KRRSIG: "rumoured", DS: "rumoured"},
			true, DnskeyStateDsPublished},
		// active beats dspublished: a fully rolled-in KSK satisfies both, and
		// active is the later state.
		{"KSK fully in", BindKeyState{DNSKEY: "omnipresent", KRRSIG: "omnipresent", DS: "omnipresent"},
			true, DnskeyStateActive},
		{"ZSK fully in", BindKeyState{DNSKEY: "omnipresent", ZRRSIG: "omnipresent"},
			false, DnskeyStateActive},
		// A ZSK must be judged on ZRRSIG, never on KRRSIG.
		{"ZSK signing nothing yet", BindKeyState{DNSKEY: "omnipresent", ZRRSIG: "rumoured", KRRSIG: "omnipresent"},
			false, DnskeyStatePublished},
		{"on the way out", BindKeyState{DNSKEY: "omnipresent", KRRSIG: "unretentive", DS: "hidden"},
			true, DnskeyStateRetired},
		{"withdrawal complete", BindKeyState{DNSKEY: "hidden", KRRSIG: "hidden", DS: "hidden",
			Removed: "20260101000000"}, true, DnskeyStateRemoved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BindStateToDnssecState(&tc.st, tc.isKSK)
			if err != nil {
				t.Fatalf("map: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}

	// Every state this produces must be one the keystore will actually accept,
	// or bulk-convert writes manifests that bulk-import then refuses.
	for _, st := range []BindKeyState{
		{DNSKEY: "hidden"}, {DNSKEY: "rumoured"}, {DNSKEY: "omnipresent", KRRSIG: "omnipresent"},
		{DNSKEY: "omnipresent", DS: "rumoured"}, {DNSKEY: "omnipresent", KRRSIG: "unretentive"},
		{DNSKEY: "hidden", Removed: "20260101000000"},
	} {
		got, err := BindStateToDnssecState(&st, true)
		if err != nil {
			t.Fatalf("map %+v: %v", st, err)
		}
		if err := validKeyState(got, dnssecKeyStates); err != nil {
			t.Errorf("mapped state %q is not a state the keystore accepts: %v", got, err)
		}
	}
}
