/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package imr

import (
	"testing"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func TestSignalPortRefused(t *testing.T) {
	for p, want := range map[uint16]bool{
		0: false, 53: false, 443: false, 853: false, 1234: false, 5353: false, 8853: false,
		1: true, 22: true, 25: true, 587: true, 6667: true, 10080: true,
	} {
		if got := signalPortRefused(p); got != want {
			t.Errorf("port %d: refused %v, want %v", p, got, want)
		}
	}
}

// A port on the bad-port list sends the record's transports to the
// nameserver itself on their default port, on every path, with a target or
// without; any other port, the transports' default ports included, is used as
// signalled. A record with a target that the path does not allow stays
// ignored whole: a bad port does not bring it back as one about the
// nameserver itself (R2).
func TestOOTSBadPortGoesToTheNameserver(t *testing.T) {
	dkc := signerTestDnskeyCache(t)
	held := newSignerTestKey(t, stateZone, 256)
	held.holdSecure(dkc)
	records := []dns.RR{
		mustRR(t, pathOwner+` 3600 IN SVCB 1 `+dotTarget+` port=22 oots="dot:30"`),
		mustRR(t, pathOwner+` 3600 IN SVCB 1 . port=25 oots="udp:100"`),
		mustRR(t, pathOwner+` 3600 IN SVCB 1 . port=5353 oots="tcp:40"`),
		mustRR(t, pathOwner+` 3600 IN SVCB 1 . port=853 oots="doq:20"`),
	}
	signed := signedSection(t, held, records, pathOwner)

	for _, tc := range []struct {
		name    string
		section []dns.RR
		lookup  cache.ValidationState
		dot     bool // the record with a target is honoured
	}{
		{"secure", signed, cache.ValidationStateSecure, true},
		{"insecure", records, cache.ValidationStateInsecure, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for via, server := range stateOnEachPath(t, tc.section, tc.lookup, nil) {
				rec := server.GetReceivedSignal()
				if rec == nil {
					t.Fatalf("%s: no signal", via)
				}
				_, hasDoT := rec.Weights[core.TransportDoT]
				if hasDoT != tc.dot || (tc.dot && rec.Weights[core.TransportDoT] != 30) {
					t.Errorf("%s: DoT weight %d (present %v), want present %v", via, rec.Weights[core.TransportDoT], hasDoT, tc.dot)
				}
				if ep := server.GetTransportEndpoint(core.TransportDoT); !ep.IsDefault() {
					t.Errorf("%s: DoT endpoint %v, want the nameserver on 853", via, ep)
				}
				if rec.Targets[core.TransportDoT] != "" {
					t.Errorf("%s: received targets %v, want none", via, rec.Targets)
				}
				if ep := server.GetTransportEndpoint(core.TransportDo53); !ep.IsDefault() || rec.Weights[core.TransportDo53] != 100 {
					t.Errorf("%s: udp endpoint %v weight %d, want the nameserver on 53", via, ep, rec.Weights[core.TransportDo53])
				}
				if ep := server.GetTransportEndpoint(core.TransportDo53TCP); ep != (cache.Endpoint{Port: 5353}) {
					t.Errorf("%s: tcp endpoint %v, want port 5353", via, ep)
				}
				if ep := server.GetTransportEndpoint(core.TransportDoQ); ep != (cache.Endpoint{Port: 853}) {
					t.Errorf("%s: DoQ endpoint %v, want port 853 as signalled", via, ep)
				}
			}
		})
	}
}
