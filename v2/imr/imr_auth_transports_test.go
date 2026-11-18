/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package imr

import (
	"context"
	"fmt"
	"testing"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// #840: the signal is kept as the server gave it, beside the weights with the
// absence defaults that selection uses; an ALPN-only signal says so.
func TestReceivedSignalIsWhatTheServerSaid(t *testing.T) {
	svcb := &dns.SVCB{Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{
		&dns.SVCBOots{Oots: []dns.SVCBOotsEntry{{Proto: "do53", Weight: 100}, {Proto: "doq", Weight: 50}, {Proto: "doh", Weight: 30}}},
	}}
	raw, ok, err := GetTransportParamRaw(svcb)
	if !ok || err != nil || len(raw) != 3 {
		t.Fatalf("GetTransportParamRaw = %v, %v, %v; want the three transports named", raw, ok, err)
	}
	// The absence defaults, with do53 read as udp and tcp.
	if full, _, _ := GetTransportParam(svcb); len(full) != 5 || full["dot"] != 0 || full["udp"] != 100 || full["tcp"] != 100 {
		t.Errorf("GetTransportParam = %v, want the absence defaults (dot:0 added, do53 as udp and tcp)", full)
	}
	server := cache.NewAuthServer("ns.example.")
	applyTransportMapToServer(server, raw)
	got := server.GetReceivedSignal()
	if got == nil || got.Source != "oots" || len(got.Weights) != 4 {
		t.Fatalf("received %+v, want the transports named (do53 as udp and tcp), source oots", got)
	}
	if _, named := got.Weights[core.TransportDoT]; named {
		t.Errorf("received %v names DoT, which the server did not", got.Weights)
	}
	if w := server.GetTransportWeights(); w[core.TransportDoT] != 0 || w[core.TransportDoQ] != 50 || w[core.TransportDo53TCP] != 100 || len(w) != 5 {
		t.Errorf("weights %v, want the defaults filled in for selection, udp and tcp apart", w)
	}

	imr := &Imr{}
	if !imr.applyTransportSignalToServer(server, "do53:100,dot:50") {
		t.Fatal("applyTransportSignalToServer refused a TSYNC-style signal")
	}
	if got := server.GetReceivedSignal(); len(got.Weights) != 3 || got.Weights[core.TransportDoT] != 50 || got.Weights[core.TransportDo53TCP] != 100 {
		t.Errorf("received %+v after a TSYNC-style signal, want do53:100 dot:50, as udp:100 tcp:100 dot:50", got)
	}

	applyAlpnSignalToServer(server, "dot,doq")
	if got := server.GetReceivedSignal(); got.Source != "alpn" || len(got.Weights) != 2 {
		t.Errorf("received %+v after an ALPN signal, want source alpn, dot and doq", got)
	}
}

// ExpectedShares mirrors candidateTransports: over many names, the first
// picks fall in the proportions it states. #854's example signal.
func TestExpectedSharesMatchSelection(t *testing.T) {
	server := cache.NewAuthServer("ns.example.")
	applyTransportMapToServer(server, map[string]uint8{"do53": 100, "dot": 10, "doq": 10, "doh": 1})
	transports, weights := server.GetTransportSignal()
	for _, tc := range []struct {
		level edns0.PrivacyLevel
		want  map[core.Transport]uint8
	}{
		{edns0.PrivacyNone, map[core.Transport]uint8{core.TransportDo53: 80, core.TransportDoT: 10, core.TransportDoQ: 10}},
		{edns0.PrivacyOpportunistic, map[core.Transport]uint8{core.TransportDoT: 50, core.TransportDoQ: 50}},
		{edns0.PrivacyStrict, map[core.Transport]uint8{core.TransportDoT: 50, core.TransportDoQ: 50}},
	} {
		got := ExpectedShares(transports, weights, tc.level)
		if len(got) != len(tc.want) {
			t.Errorf("%s: expected %v, want %v (DoH's weight of 1 is not used)", tc.level, got, tc.want)
			continue
		}
		for tr, w := range tc.want {
			if got[tr] != w {
				t.Errorf("%s: expected %v, want %v", tc.level, got, tc.want)
			}
		}
		const n = 20000
		picks := map[core.Transport]int{}
		for i := 0; i < n; i++ {
			picks[candidateTransports(server, fmt.Sprintf("q%d.example.", i), tc.level)[0]]++
		}
		for tr, w := range tc.want {
			if share := picks[tr] * 100 / n; share < int(w)-3 || share > int(w)+3 {
				t.Errorf("%s: %s picked %d%% of %d names, expected %d%%", tc.level, core.TransportToString[tr], share, n, w)
			}
		}
	}
}

// Whose query: a client's by its level, the resolver's own otherwise, and an
// own lookup inside a client's query is the resolver's.
func TestTrafficClass(t *testing.T) {
	ctx := context.Background()
	client := withClientQuery(ctx)
	for _, tc := range []struct {
		ctx     context.Context
		privacy edns0.PrivacyLevel
		want    cache.TrafficClass
	}{
		{ctx, edns0.PrivacyNone, cache.ClassInternal},
		{ctx, edns0.PrivacyStrict, cache.ClassInternal},
		{client, edns0.PrivacyNone, cache.ClassNone},
		{client, edns0.PrivacyOpportunistic, cache.ClassOpportunistic},
		{client, edns0.PrivacyStrict, cache.ClassStrict},
		{withOwnTraffic(client), edns0.PrivacyNone, cache.ClassInternal},
		{nil, edns0.PrivacyNone, cache.ClassInternal},
	} {
		if got := trafficClass(tc.ctx, tc.privacy); got != tc.want {
			t.Errorf("trafficClass(%v, %s) = %s, want %s", tc.ctx, tc.privacy, got, tc.want)
		}
	}
}
