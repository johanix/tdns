/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"testing"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// mapZoneWithSignal builds a ready MapZone whose apex has a single NS and which
// carries the given _dns.<ns> owner RRs, with add-transport-signal enabled.
func mapZoneWithSignal(name, nsName string, signalRRs []dns.RR) *ZoneData {
	owners := map[string][]dns.RR{
		name: {mustNS(name, nsName)},
	}
	if len(signalRRs) > 0 {
		owners["_dns."+nsName] = signalRRs
	}
	zd := newMapZone(name, Primary, owners)
	zd.Options[OptAddTransportSignal] = true
	return zd
}

func mustNS(owner, ns string) dns.RR {
	rr, err := dns.NewRR(owner + " 3600 IN NS " + ns)
	if err != nil {
		panic(err)
	}
	return rr
}

func mustSVCB(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("parse SVCB %q: %v", s, err)
	}
	return rr
}

func hasSignal(sigs []core.RRset, owner string) bool {
	for _, rs := range sigs {
		if rs.Name == owner {
			return true
		}
	}
	return false
}

func TestCollectSignalRRsets_InBailiwick(t *testing.T) {
	zd := mapZoneWithSignal("example.com.", "ns.example.com.",
		[]dns.RR{mustSVCB(t, `_dns.ns.example.com. 10800 IN SVCB 1 . alpn="dot"`)})
	registerZones(t, zd)

	sigs := zd.collectSignalRRsets(zd.publishedSnapshot())
	if len(sigs) != 1 {
		t.Fatalf("want 1 signal RRset, got %d: %+v", len(sigs), sigs)
	}
	if sigs[0].Name != "_dns.ns.example.com." {
		t.Fatalf("want owner _dns.ns.example.com., got %q", sigs[0].Name)
	}
}

func TestCollectSignalRRsets_AliasChasedCrossZone(t *testing.T) {
	child := mapZoneWithSignal("example.com.", "ns.example.com.",
		[]dns.RR{mustSVCB(t, `_dns.ns.example.com. 10800 IN SVCB 0 ns.provider.com.`)})
	provider := mapZoneWithSignal("provider.com.", "ns.provider.com.",
		[]dns.RR{mustSVCB(t, `_dns.ns.provider.com. 10800 IN SVCB 1 . alpn="dot"`)})
	registerZones(t, child, provider)

	sigs := child.collectSignalRRsets(child.publishedSnapshot())
	if len(sigs) != 2 {
		t.Fatalf("want alias + chased target (2), got %d: %+v", len(sigs), sigs)
	}
	if !hasSignal(sigs, "_dns.ns.example.com.") {
		t.Errorf("missing local alias signal")
	}
	if !hasSignal(sigs, "_dns.ns.provider.com.") {
		t.Errorf("missing cross-zone target signal")
	}
}

func TestCollectSignalRRsets_UnresolvableTargetStillReturnsAlias(t *testing.T) {
	// provider.com is NOT registered, so the alias target cannot be resolved.
	child := mapZoneWithSignal("example.com.", "ns.example.com.",
		[]dns.RR{mustSVCB(t, `_dns.ns.example.com. 10800 IN SVCB 0 ns.provider.com.`)})
	registerZones(t, child)

	sigs := child.collectSignalRRsets(child.publishedSnapshot())
	if len(sigs) != 1 {
		t.Fatalf("want just the alias (1), got %d: %+v", len(sigs), sigs)
	}
	if sigs[0].Name != "_dns.ns.example.com." {
		t.Fatalf("want the alias owner, got %q", sigs[0].Name)
	}
}

func TestCollectSignalRRsets_DisabledOption(t *testing.T) {
	zd := mapZoneWithSignal("example.com.", "ns.example.com.",
		[]dns.RR{mustSVCB(t, `_dns.ns.example.com. 10800 IN SVCB 1 . alpn="dot"`)})
	zd.Options[OptAddTransportSignal] = false
	registerZones(t, zd)

	if sigs := zd.collectSignalRRsets(zd.publishedSnapshot()); len(sigs) != 0 {
		t.Fatalf("disabled option must yield no signals, got %d", len(sigs))
	}
}

func TestAddTransportSignal_DedupAgainstAnswer(t *testing.T) {
	zd := mapZoneWithSignal("example.com.", "ns.example.com.",
		[]dns.RR{mustSVCB(t, `_dns.ns.example.com. 10800 IN SVCB 1 . alpn="dot"`)})
	registerZones(t, zd)
	sigs := zd.collectSignalRRsets(zd.publishedSnapshot())

	// Simulate a direct query for the signal: it is already in the Answer.
	m := new(dns.Msg)
	m.Answer = append(m.Answer, mustSVCB(t, `_dns.ns.example.com. 10800 IN SVCB 1 . alpn="dot"`))
	if zd.addTransportSignal(m, sigs, &edns0.MsgOptions{}) {
		t.Fatalf("signal already in Answer must not be re-added to Extra")
	}
	if len(m.Extra) != 0 {
		t.Fatalf("Extra must stay empty, got %d", len(m.Extra))
	}

	// A plain query (signal not in Answer) should inject it into Extra.
	m2 := new(dns.Msg)
	if !zd.addTransportSignal(m2, sigs, &edns0.MsgOptions{}) {
		t.Fatalf("signal not in Answer must be injected into Extra")
	}
	if len(m2.Extra) != 1 {
		t.Fatalf("want 1 injected RR, got %d", len(m2.Extra))
	}
}
