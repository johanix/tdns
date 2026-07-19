/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package core

import (
	"testing"
)

func TestParseTransportString_ClampAndDefaults(t *testing.T) {
	m, err := ParseTransportString("doq:20,dot:10")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m["doq"] != 20 || m["dot"] != 10 {
		t.Errorf("got %#v", m)
	}
	if m["do53"] != 100 {
		t.Errorf("absent do53 default: got %d, want 100", m["do53"])
	}
	if m["doh"] != 0 {
		t.Errorf("absent doh default: got %d, want 0", m["doh"])
	}
}

func TestParseTransportString_ClampAbove100(t *testing.T) {
	m, err := ParseTransportString("doq:150,do53:0")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m["doq"] != 100 {
		t.Errorf("doq clamp: got %d, want 100", m["doq"])
	}
	if m["do53"] != 0 {
		t.Errorf("explicit do53:0 must be kept, got %d", m["do53"])
	}
}

func TestParseTransportString_DuplicateRejected(t *testing.T) {
	if _, err := ParseTransportString("doq:10,doq:20"); err == nil {
		t.Fatal("expected duplicate key error")
	}
}

func TestParseTransportString_EmptyDefaultsDo53(t *testing.T) {
	m, err := ParseTransportString("")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m["do53"] != 100 {
		t.Errorf("empty → do53=100, got %d", m["do53"])
	}
}
