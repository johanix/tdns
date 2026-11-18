/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The token split, receiving side (step S4 of the alternative-endpoint plan):
 * cleartext is udp and tcp, both 100 when absent; do53:N reads as udp:N and
 * tcp:N, and an explicit udp or tcp wins over it. udp maps to TransportDo53
 * and tcp to TransportDo53TCP. A tcp weight caps only the TCP the resolver
 * chooses on its own, and tdns chooses none. Design: the alternative-endpoint
 * note, sections 2 and 3.
 */
package tdns

import (
	"reflect"
	"testing"

	core "github.com/johanix/tdns/v2/core"
)

// The stats name a received signal by its tokens, udp and tcp apart.
func TestStatsShowUDPAndTCPApart(t *testing.T) {
	got := signalWeightsToTokens(map[core.Transport]uint8{core.TransportDo53: 50, core.TransportDo53TCP: 10, core.TransportDoT: 20})
	if want := map[string]uint8{"udp": 50, "tcp": 10, "dot": 20}; !reflect.DeepEqual(got, want) {
		t.Errorf("signalWeightsToTokens = %v, want %v", got, want)
	}
}

// From S5 on the publisher emits udp and tcp: a do53 entry is emitted as the
// two, an explicit one winning, and nothing cleartext the operator did not
// name is written out. A signal naming udp or tcp is accepted at load; one
// naming an undefined token is not.
func TestPublisherEmitsUDPAndTCP(t *testing.T) {
	for sig, want := range map[string]string{
		"dot:10":         "dot:10",
		"do53:100":       "tcp:100,udp:100",
		"do53:0,dot:10":  "dot:10,tcp:0,udp:0",
		"do53:40,tcp:5":  "tcp:5,udp:40",
		"udp:0,doq:20":   "doq:20,udp:0",
		"tcp:30,doh:0":   "tcp:30",
		"udp:50,tcp:100": "tcp:100,udp:50",
	} {
		oots, err := transportSignalToSVCBOots(sig)
		if err != nil {
			t.Fatalf("transportSignalToSVCBOots(%q): %v", sig, err)
		}
		if got := oots.String(); got != want {
			t.Errorf("%q published as %q, want %q", sig, got, want)
		}
	}
	for _, sig := range []string{"udp:100,dot:10", "tcp:30", "do53:10,udp:20"} {
		if err := (TransportConf{Type: "svcb", Signal: sig}).Validate(); err != nil {
			t.Errorf("Validate(%q) = %v", sig, err)
		}
	}
	// The TSYNC form carries the signal as written, unless it names do53.
	for sig, want := range map[string]string{
		"doq:20,dot:10": "doq:20,dot:10",
		"udp:10,tcp:0":  "udp:10,tcp:0",
		"do53:40,dot:5": "dot:5,tcp:40,udp:40",
	} {
		if got := publishedTSYNCSignal(sig); got != want {
			t.Errorf("publishedTSYNCSignal(%q) = %q, want %q", sig, got, want)
		}
	}
}
