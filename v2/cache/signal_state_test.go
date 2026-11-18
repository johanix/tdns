/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"testing"

	core "github.com/johanix/tdns/v2/core"
)

// A signal records four states: Secure, Insecure, Bogus, and unknown for
// anything that is not a verdict.
func TestSignalState(t *testing.T) {
	for in, want := range map[ValidationState]ValidationState{
		0:                            SignalStateUnknown,
		ValidationStateNone:          SignalStateUnknown,
		ValidationStateIndeterminate: SignalStateUnknown,
		ValidationStateSecure:        ValidationStateSecure,
		ValidationStateInsecure:      ValidationStateInsecure,
		ValidationStateBogus:         ValidationStateBogus,
	} {
		if got := SignalState(in); got != want {
			t.Errorf("SignalState(%d) = %d, want %d", in, got, want)
		}
	}
	if got := SignalStateString(ValidationStateIndeterminate); got != "unknown" {
		t.Errorf("SignalStateString(indeterminate) = %q", got)
	}
}

// A path is Secure only when every hop is (R5). Bogus outranks Insecure,
// which no later lookup turns Secure, and Insecure outranks unknown.
func TestSignalPathState(t *testing.T) {
	s, i, b, u := ValidationStateSecure, ValidationStateInsecure, ValidationStateBogus, SignalStateUnknown
	path := func(states ...ValidationState) []SignalHop {
		out := make([]SignalHop, len(states))
		for n, st := range states {
			out[n] = SignalHop{Owner: "_dns.ns.example.", State: st}
		}
		return out
	}
	for _, tc := range []struct {
		path []SignalHop
		want ValidationState
	}{
		{nil, u},
		{path(s), s},
		{path(s, s, s), s},
		{path(s, u), u},
		{path(u, i), i},
		{path(i, s), i},
		{path(s, i, b), b},
		{path(b, u), b},
		{path(ValidationStateIndeterminate, s), u},
	} {
		if got := SignalPathState(tc.path); got != tc.want {
			t.Errorf("SignalPathState(%s) = %s, want %s", FormatSignalPath(tc.path), SignalStateString(got), SignalStateString(tc.want))
		}
	}
}

func TestFormatSignalPath(t *testing.T) {
	got := FormatSignalPath([]SignalHop{
		{Owner: "_dns.ns.example.", State: ValidationStateSecure},
		{Owner: "_dns.ns.provider.example."},
	})
	if want := "_dns.ns.example. secure -> _dns.ns.provider.example. unknown"; got != want {
		t.Errorf("FormatSignalPath = %q, want %q", got, want)
	}
}

// The path travels with the signal and a reader's copy shares nothing with
// the server's.
func TestReceivedSignalPathIsCopied(t *testing.T) {
	as := NewAuthServer("ns.example.")
	as.SetTransportSignal([]core.Transport{core.TransportDoT}, []string{"dot"},
		map[core.Transport]uint8{core.TransportDoT: 30},
		&ReceivedSignal{Source: "oots", Weights: map[core.Transport]uint8{core.TransportDoT: 30},
			Via: SignalViaReferral, Path: []SignalHop{{Owner: "_dns.ns.example.", State: ValidationStateSecure}}})
	got := as.GetReceivedSignal()
	if got.Via != SignalViaReferral || got.PathState() != ValidationStateSecure {
		t.Fatalf("got Via %q, state %s", got.Via, SignalStateString(got.PathState()))
	}
	got.Path[0].State = ValidationStateBogus
	if again := as.GetReceivedSignal(); again.PathState() != ValidationStateSecure {
		t.Errorf("a reader's change reached the server: %s", SignalStateString(again.PathState()))
	}
	var none *ReceivedSignal
	if none.PathState() != SignalStateUnknown {
		t.Errorf("nil signal: not unknown")
	}
}
