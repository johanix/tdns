/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package core

import (
	"maps"
	"strings"
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
	if m["udp"] != 100 || m["tcp"] != 100 {
		t.Errorf("absent udp and tcp default: got %#v, want 100 each", m)
	}
	if _, ok := m["do53"]; ok {
		t.Errorf("do53 left in %#v: it is read as udp and tcp", m)
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
	if v, ok := m["udp"]; !ok || v != 0 || m["tcp"] != 0 {
		t.Errorf("explicit do53:0 must be kept, as udp:0 and tcp:0, got %#v", m)
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
	if m["udp"] != 100 || m["tcp"] != 100 {
		t.Errorf("empty → udp=100 tcp=100, got %#v", m)
	}
}

// The token split (the alternative-endpoint design, section 2): udp and tcp
// default to 100, do53:N reads as udp:N and tcp:N, and an explicit udp or tcp
// wins over it.
func TestApplyTransportDefaults_TokenSplit(t *testing.T) {
	for _, tc := range []struct {
		in, want map[string]uint8
	}{
		{map[string]uint8{}, map[string]uint8{"udp": 100, "tcp": 100, "dot": 0, "doh": 0, "doq": 0}},
		{map[string]uint8{"tcp": 30}, map[string]uint8{"udp": 100, "tcp": 30, "dot": 0, "doh": 0, "doq": 0}},
		{map[string]uint8{"udp": 0}, map[string]uint8{"udp": 0, "tcp": 100, "dot": 0, "doh": 0, "doq": 0}},
		{map[string]uint8{"do53": 0, "dot": 10}, map[string]uint8{"udp": 0, "tcp": 0, "dot": 10, "doh": 0, "doq": 0}},
		{map[string]uint8{"do53": 40, "tcp": 5}, map[string]uint8{"udp": 40, "tcp": 5, "dot": 0, "doh": 0, "doq": 0}},
		{map[string]uint8{"do53": 40, "udp": 90, "tcp": 5}, map[string]uint8{"udp": 90, "tcp": 5, "dot": 0, "doh": 0, "doq": 0}},
	} {
		got := maps.Clone(tc.in)
		ApplyTransportDefaults(got)
		if !maps.Equal(got, tc.want) {
			t.Errorf("ApplyTransportDefaults(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
	// The shorthand alone, without the defaults.
	m := map[string]uint8{"do53": 7, "tcp": 3, "doq": 1}
	ExpandDo53Shorthand(m)
	if want := map[string]uint8{"udp": 7, "tcp": 3, "doq": 1}; !maps.Equal(m, want) {
		t.Errorf("ExpandDo53Shorthand = %v, want %v", m, want)
	}
}

// udp is TransportDo53 (UDP, retried over TCP after truncation), tcp is
// TransportDo53TCP, and only the latter is kept out of selection.
func TestUDPAndTCPTokens(t *testing.T) {
	for tok, want := range map[string]Transport{"udp": TransportDo53, "tcp": TransportDo53TCP, "do53": TransportDo53} {
		if got, err := StringToTransport(tok); err != nil || got != want {
			t.Errorf("StringToTransport(%q) = %v, %v; want %v", tok, got, err, want)
		}
	}
	if TransportToSignalToken[TransportDo53] != "udp" || TransportToSignalToken[TransportDo53TCP] != "tcp" {
		t.Errorf("TransportToSignalToken = %v", TransportToSignalToken)
	}
	if TransportToString[TransportDo53] != "do53" {
		t.Errorf("TransportToString[TransportDo53] = %q: the transport keeps its name", TransportToString[TransportDo53])
	}
	for _, tr := range []Transport{TransportDo53, TransportDoT, TransportDoH, TransportDoQ} {
		if !SelectableTransport(tr) {
			t.Errorf("SelectableTransport(%v) = false", tr)
		}
	}
	if SelectableTransport(TransportDo53TCP) {
		t.Error("SelectableTransport(TransportDo53TCP) = true: tdns chooses no optional TCP")
	}
}

// udp and tcp are received but not yet published: the publisher emits them
// only once every node that can re-pack the record keeps them.
func TestValidatePublishedTransportSignal_NoUDPOrTCPYet(t *testing.T) {
	for _, s := range []string{"do53:100,dot:10", "doq:5", ""} {
		if err := ValidatePublishedTransportSignal(s); err != nil {
			t.Errorf("ValidatePublishedTransportSignal(%q) = %v", s, err)
		}
	}
	for _, s := range []string{"udp:100", "tcp:30,dot:10", "xyz:1"} {
		err := ValidatePublishedTransportSignal(s)
		if err == nil || !strings.Contains(err.Error(), "do53, doh, doq, dot") {
			t.Errorf("ValidatePublishedTransportSignal(%q) = %v, want a refusal naming the publishable tokens", s, err)
		}
	}
}
