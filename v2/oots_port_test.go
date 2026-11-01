/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"testing"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v3"
)

func ootsSVCB(owner string, port uint16, entries ...dns.SVCBOotsEntry) *dns.SVCB {
	var values []dns.SVCBKeyValue
	if port != 0 {
		values = append(values, &dns.SVCBPort{Port: port})
	}
	if len(entries) > 0 {
		values = append(values, &dns.SVCBOots{Oots: entries})
	}
	return &dns.SVCB{
		Hdr:      dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 3600},
		Priority: 1,
		Target:   ".",
		Value:    values,
	}
}

func portsEqual(got, want map[core.Transport]uint16) bool {
	if len(got) != len(want) {
		return false
	}
	for t, p := range want {
		if got[t] != p {
			return false
		}
	}
	return true
}

func TestPortsFromOOTSRecord(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  map[string]uint8
		port uint16
		want map[core.Transport]uint16
	}{
		{"dot and doq share it, doh on the same record does not",
			map[string]uint8{"dot": 30, "doq": 20, "doh": 10}, 1234,
			map[core.Transport]uint16{core.TransportDoT: 1234, core.TransportDoQ: 1234}},
		{"dot alone", map[string]uint8{"dot": 30}, 1234, map[core.Transport]uint16{core.TransportDoT: 1234}},
		{"doq alone", map[string]uint8{"doq": 20}, 1235, map[core.Transport]uint16{core.TransportDoQ: 1235}},
		{"doh alone", map[string]uint8{"doh": 100}, 8443, map[core.Transport]uint16{core.TransportDoH: 8443}},
		{"doh beside do53 does not", map[string]uint8{"doh": 10, "do53": 100}, 8443, nil},
		{"do53 never takes it", map[string]uint8{"do53": 100}, 553, nil},
		{"no port key", map[string]uint8{"dot": 30}, 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := portsFromOOTSRecord(tc.raw, tc.port); !portsEqual(got, tc.want) {
				t.Errorf("ports %v, want %v", got, tc.want)
			}
		})
	}
}

// Two SVCB records are one signal. Defaults are applied once to the combined
// weights, and a transport named twice keeps the later record.
func TestCombineOOTSRecords(t *testing.T) {
	raw, ports := combineOOTSRecords([]ootsRecord{
		{raw: map[string]uint8{"dot": 30}, port: 1234},
		{raw: map[string]uint8{"doq": 20}, port: 1235},
	})
	if raw["dot"] != 30 || raw["doq"] != 20 || len(raw) != 2 {
		t.Errorf("combined weights %v, want dot:30 doq:20", raw)
	}
	if !portsEqual(ports, map[core.Transport]uint16{core.TransportDoT: 1234, core.TransportDoQ: 1235}) {
		t.Errorf("combined ports %v", ports)
	}

	raw, ports = combineOOTSRecords([]ootsRecord{
		{raw: map[string]uint8{"dot": 30}, port: 1111},
		{raw: map[string]uint8{"dot": 40}, port: 2222},
	})
	if raw["dot"] != 40 || ports[core.TransportDoT] != 2222 {
		t.Errorf("last record: weight %d port %d, want 40 and 2222", raw["dot"], ports[core.TransportDoT])
	}

	// The later record names DoT and assigns no port, so the earlier port goes.
	_, ports = combineOOTSRecords([]ootsRecord{
		{raw: map[string]uint8{"dot": 30}, port: 1111},
		{raw: map[string]uint8{"dot": 40}, port: 0},
	})
	if ports[core.TransportDoT] != 0 {
		t.Errorf("later record without a port left port %d", ports[core.TransportDoT])
	}
}

func assertCombinedPorts(t *testing.T, server *cache.AuthServer) {
	t.Helper()
	if server.GetTransportPort(core.TransportDoT) != 1234 || server.GetTransportPort(core.TransportDoQ) != 1235 {
		t.Errorf("ports dot=%d doq=%d, want 1234 and 1235",
			server.GetTransportPort(core.TransportDoT), server.GetTransportPort(core.TransportDoQ))
	}
	if server.GetTransportPort(core.TransportDoH) != 0 || server.GetTransportPort(core.TransportDo53) != 0 {
		t.Errorf("DoH port %d Do53 port %d, want both 0",
			server.GetTransportPort(core.TransportDoH), server.GetTransportPort(core.TransportDo53))
	}
	w := server.GetTransportWeights()
	if w[core.TransportDoT] != 30 || w[core.TransportDoQ] != 20 || w[core.TransportDo53] != 100 || w[core.TransportDoH] != 0 {
		t.Errorf("selection weights %v, want dot 30, doq 20, do53 100, doh 0", w)
	}
	got := server.GetReceivedSignal()
	if got == nil || got.Source != "oots" || len(got.Weights) != 2 || got.Weights[core.TransportDoT] != 30 || got.Weights[core.TransportDoQ] != 20 {
		t.Errorf("received %+v, want oots dot:30 doq:20 and nothing else", got)
	}
	if got != nil && (got.Ports[core.TransportDoT] != 1234 || got.Ports[core.TransportDoQ] != 1235 || len(got.Ports) != 2) {
		t.Errorf("received ports %v", got.Ports)
	}
}

func TestAdditionalOOTSPortsAreCombined(t *testing.T) {
	imr := newTestImr(t)
	imr.Quiet = true
	server := cache.NewAuthServer("ns.example.")
	r := new(dns.Msg)
	r.SetQuestion("example.", dns.TypeA)
	r.Extra = []dns.RR{
		ootsSVCB("_dns.ns.example.", 1234, dns.SVCBOotsEntry{Proto: "dot", Weight: 30}),
		ootsSVCB("_dns.ns.example.", 1235, dns.SVCBOotsEntry{Proto: "doq", Weight: 20}),
	}
	imr.parseTransportForServerFromAdditional(context.Background(), server, r)
	assertCombinedPorts(t, server)
	if server.ConnectionMode() != cache.ConnModeOpportunistic {
		t.Errorf("connection mode %s, want opportunistic", server.ConnectionMode())
	}

	// A later signal replaces the whole set, ports included.
	r2 := new(dns.Msg)
	r2.SetQuestion("example.", dns.TypeA)
	r2.Extra = []dns.RR{ootsSVCB("_dns.ns.example.", 0, dns.SVCBOotsEntry{Proto: "dot", Weight: 10})}
	imr.parseTransportForServerFromAdditional(context.Background(), server, r2)
	if server.GetTransportPort(core.TransportDoT) != 0 || server.GetTransportPort(core.TransportDoQ) != 0 {
		t.Errorf("later signal left ports dot=%d doq=%d",
			server.GetTransportPort(core.TransportDoT), server.GetTransportPort(core.TransportDoQ))
	}
	if got := server.GetReceivedSignal(); got == nil || len(got.Weights) != 1 || got.Weights[core.TransportDoT] != 10 {
		t.Errorf("later signal received %+v, want only dot:10", got)
	}
}

func TestReferralOOTSPortsAreCombined(t *testing.T) {
	imr := newTestImr(t)
	imr.Quiet = true
	const zone = "kid.p.test."
	const ns = "ns.kid.p.test."
	r := new(dns.Msg)
	r.SetQuestion("www."+zone, dns.TypeA)
	r.Response = true
	r.Ns = []dns.RR{mustRR(t, zone+" 3600 IN NS "+ns)}
	r.Extra = []dns.RR{
		ootsSVCB("_dns."+ns, 1234, dns.SVCBOotsEntry{Proto: "dot", Weight: 30}),
		ootsSVCB("_dns."+ns, 1235, dns.SVCBOotsEntry{Proto: "doq", Weight: 20}),
	}
	nsrrset := &core.RRset{Name: zone, Class: dns.ClassINET, RRtype: dns.TypeNS, RRs: r.Ns}
	if _, err := imr.ParseAdditionalForNSAddrs(context.Background(), "authority", nsrrset, zone, "p.test.",
		map[string]bool{ns: true}, r); err != nil {
		t.Fatalf("ParseAdditionalForNSAddrs: %v", err)
	}
	assertCombinedPorts(t, imr.Cache.GetOrCreateAuthServer(ns))
}

func TestAnswerOOTSPortsAreCombined(t *testing.T) {
	imr := newTestImr(t)
	imr.Quiet = true
	server := cache.NewAuthServer("ns.example.")
	imr.Cache.ServerMap.Set("example.", map[string]*cache.AuthServer{
		cache.ServerKey("ns.example."): server,
	})
	imr.applyTransportRRsetFromAnswer("_dns.ns.example.", &core.RRset{
		Name:   "_dns.ns.example.",
		RRtype: dns.TypeSVCB,
		RRs: []dns.RR{
			ootsSVCB("_dns.ns.example.", 1234, dns.SVCBOotsEntry{Proto: "dot", Weight: 30}),
			ootsSVCB("_dns.ns.example.", 1235, dns.SVCBOotsEntry{Proto: "doq", Weight: 20}),
		},
	}, cache.ValidationStateIndeterminate)
	assertCombinedPorts(t, server)
}

// One record names dot, doq and doh. The port is for dot and doq. DoH stays
// on 443, and its weight is still recorded.
func TestSharedPortSkipsDoH(t *testing.T) {
	server := cache.NewAuthServer("ns.example.")
	raw, ports := combineOOTSRecords([]ootsRecord{{
		raw:  map[string]uint8{"dot": 30, "doq": 20, "doh": 10},
		port: 1234,
	}})
	if !applyTransportMapWithPorts(server, raw, ports) {
		t.Fatal("signal was not applied")
	}
	if server.GetTransportPort(core.TransportDoT) != 1234 || server.GetTransportPort(core.TransportDoQ) != 1234 {
		t.Errorf("dot/doq ports %d %d, want 1234", server.GetTransportPort(core.TransportDoT), server.GetTransportPort(core.TransportDoQ))
	}
	if server.GetTransportPort(core.TransportDoH) != 0 {
		t.Errorf("DoH took port %d", server.GetTransportPort(core.TransportDoH))
	}
	if w := server.GetTransportWeights(); w[core.TransportDoH] != 10 {
		t.Errorf("DoH weight %d, want 10", w[core.TransportDoH])
	}
}

func TestDoHTakesPortOnlyWhenAlone(t *testing.T) {
	alone := cache.NewAuthServer("alone.example.")
	raw, ports := combineOOTSRecords([]ootsRecord{{raw: map[string]uint8{"doh": 100}, port: 8443}})
	applyTransportMapWithPorts(alone, raw, ports)
	if alone.GetTransportPort(core.TransportDoH) != 8443 {
		t.Errorf("DoH alone port %d, want 8443", alone.GetTransportPort(core.TransportDoH))
	}

	withDo53 := cache.NewAuthServer("with.example.")
	raw, ports = combineOOTSRecords([]ootsRecord{{raw: map[string]uint8{"doh": 10, "do53": 100}, port: 8443}})
	applyTransportMapWithPorts(withDo53, raw, ports)
	if withDo53.GetTransportPort(core.TransportDoH) != 0 {
		t.Errorf("DoH beside Do53 took port %d", withDo53.GetTransportPort(core.TransportDoH))
	}
}

func TestDo53PortIsNotDialed(t *testing.T) {
	server := cache.NewAuthServer("ns.example.")
	raw, ports := combineOOTSRecords([]ootsRecord{{raw: map[string]uint8{"do53": 100}, port: 553}})
	applyTransportMapWithPorts(server, raw, ports)
	if server.GetTransportPort(core.TransportDo53) != 0 || len(server.GetTransportPorts()) != 0 {
		t.Errorf("cleartext port stored: %v", server.GetTransportPorts())
	}
	if got := server.DialAddr("192.0.2.1", core.TransportDo53); got != "192.0.2.1" {
		t.Errorf("Do53 dial %q, want the bare address", got)
	}
	if got := server.DialAddr("2001:db8::1", core.TransportDo53); got != "2001:db8::1" {
		t.Errorf("Do53 v6 dial %q, want the bare address", got)
	}
}

// ALPN-only SVCB still means DoT at weight 100, and its port key is ignored.
// An oots record in the same message wins, and the ALPN list is not applied.
func TestAlpnPortIsIgnoredUnlessOotsIsPresent(t *testing.T) {
	imr := newTestImr(t)
	imr.Quiet = true
	server := cache.NewAuthServer("ns.example.")
	r := new(dns.Msg)
	r.SetQuestion("example.", dns.TypeA)
	r.Extra = []dns.RR{&dns.SVCB{
		Hdr:      dns.RR_Header{Name: "_dns.ns.example.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 3600},
		Priority: 1,
		Target:   ".",
		Value:    []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: []string{"dot"}}, &dns.SVCBPort{Port: 1234}},
	}}
	imr.parseTransportForServerFromAdditional(context.Background(), server, r)
	if server.GetTransportPort(core.TransportDoT) != 0 {
		t.Errorf("ALPN-only signal stored port %d", server.GetTransportPort(core.TransportDoT))
	}
	if got := server.GetReceivedSignal(); got == nil || got.Source != "alpn" {
		t.Errorf("received %+v, want an alpn signal", got)
	}

	r.Extra = append(r.Extra, ootsSVCB("_dns.ns.example.", 1234, dns.SVCBOotsEntry{Proto: "dot", Weight: 30}))
	imr.parseTransportForServerFromAdditional(context.Background(), server, r)
	if got := server.GetReceivedSignal(); got == nil || got.Source != "oots" || got.Weights[core.TransportDoT] != 30 {
		t.Errorf("mixed message received %+v, want the oots record", got)
	}
	if server.GetTransportPort(core.TransportDoT) != 1234 {
		t.Errorf("oots port %d, want 1234", server.GetTransportPort(core.TransportDoT))
	}
}

func TestTryServerDialsSignalPort(t *testing.T) {
	imr := newTestImr(t)
	imr.Quiet = true
	q := new(dns.Msg)
	q.SetQuestion("example.", dns.TypeA)
	reply := new(dns.Msg)
	reply.SetReply(q)

	dot := core.NewFakeDNSClient(core.TransportDoT)
	do53 := core.NewFakeDNSClient(core.TransportDo53)
	doq := core.NewFakeDNSClient(core.TransportDoQ)
	for _, addr := range []string{"192.0.2.1:1234", "192.0.2.1", "[2001:db8::1]:1234", "192.0.2.1:1235"} {
		dot.Set("example.", addr, core.FakeResponse{Msg: reply})
		do53.Set("example.", addr, core.FakeResponse{Msg: reply})
		doq.Set("example.", addr, core.FakeResponse{Msg: reply})
	}
	imr.Cache.DNSClient[core.TransportDoT] = dot
	imr.Cache.DNSClient[core.TransportDo53] = do53
	imr.Cache.DNSClient[core.TransportDoQ] = doq

	server := cache.NewAuthServer("ns.example.")
	raw, ports := combineOOTSRecords([]ootsRecord{{
		raw:  map[string]uint8{"dot": 30, "doq": 20},
		port: 1234,
	}})
	// Two transports on one record share the port. DoQ's is what a DNSKEY
	// bypass dials, because the bypass prefers DoQ and ignores weights.
	applyTransportMapWithPorts(server, raw, ports)

	ctx := context.Background()
	if _, _, _, err := imr.tryServer(ctx, server, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone); err != nil {
		t.Fatalf("DoT: %v", err)
	}
	if _, _, _, err := imr.tryServer(ctx, server, "192.0.2.1", core.TransportDo53, q, "example.", dns.TypeA, false, cache.ClassNone); err != nil {
		t.Fatalf("Do53: %v", err)
	}
	if _, _, _, err := imr.tryServer(ctx, server, "2001:db8::1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone); err != nil {
		t.Fatalf("DoT v6: %v", err)
	}
	if _, _, wire, err := imr.tryServer(ctx, server, "192.0.2.1", core.TransportDo53, q, "example.", dns.TypeA, true, cache.ClassInternal); err != nil {
		t.Fatalf("DNSKEY bypass: %v", err)
	} else if wire != core.TransportDoQ {
		t.Errorf("bypass wire transport %s, want doq", core.TransportToString[wire])
	}

	if got := dot.Calls(); len(got) != 2 || got[0].Addr != "192.0.2.1:1234" || got[1].Addr != "[2001:db8::1]:1234" {
		t.Errorf("DoT dials %v, want 192.0.2.1:1234 and [2001:db8::1]:1234", addrsOf(got))
	}
	if got := do53.Calls(); len(got) != 1 || got[0].Addr != "192.0.2.1" {
		t.Errorf("Do53 dials %v, want the bare address", addrsOf(got))
	}
	if got := doq.Calls(); len(got) != 1 || got[0].Addr != "192.0.2.1:1234" {
		t.Errorf("DoQ bypass dials %v, want 192.0.2.1:1234", addrsOf(got))
	}

	// The next signal has no port. DoT goes back to the bare address.
	applyTransportMapToServer(server, map[string]uint8{"dot": 30})
	if _, _, _, err := imr.tryServer(ctx, server, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone); err != nil {
		t.Fatalf("DoT after a port-less signal: %v", err)
	}
	if got := dot.Calls(); got[len(got)-1].Addr != "192.0.2.1" {
		t.Errorf("DoT after a port-less signal dialed %q", got[len(got)-1].Addr)
	}
}

func addrsOf(qs []core.FakeQuery) []string {
	out := make([]string, len(qs))
	for i, q := range qs {
		out[i] = q.Addr
	}
	return out
}

func TestBuildServerSVCBPublishesPort(t *testing.T) {
	prev := Globals.ServerSVCB
	Globals.ServerSVCB = &dns.SVCB{Priority: 1, Target: "."}
	t.Cleanup(func() { Globals.ServerSVCB = prev })

	conf := &Config{}
	conf.Service.Transport = TransportConf{
		Type: "svcb",
		Records: []TransportSignalRecord{
			{Signal: "dot:30", Port: 1234},
			{Signal: "doq:20", Port: 1235},
		},
	}
	rrset, err := (&ZoneData{}).buildServerSVCB(conf, "ns.example.", nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(rrset.RRs) != 2 {
		t.Fatalf("got %d RRs, want one per record", len(rrset.RRs))
	}
	wantPort := []uint16{1234, 1235}
	wantProto := []string{"dot", "doq"}
	for i, rr := range rrset.RRs {
		parsed, err := dns.NewRR(rr.String())
		if err != nil {
			t.Fatalf("reparse %q: %v", rr.String(), err)
		}
		svcb, ok := parsed.(*dns.SVCB)
		if !ok {
			t.Fatalf("reparsed %T", parsed)
		}
		if svcbPortValue(svcb) != wantPort[i] {
			t.Errorf("RR %d port %d, want %d (%s)", i, svcbPortValue(svcb), wantPort[i], rr.String())
		}
		m, present, err := GetTransportParamRaw(svcb)
		if err != nil || !present || m[wantProto[i]] == 0 {
			t.Errorf("RR %d oots %v present %v err %v (%s)", i, m, present, err, rr.String())
		}
	}

	// The single-record form, no port: still one RR, and no port key.
	conf.Service.Transport = TransportConf{Type: "svcb", Signal: "doq:20,dot:10"}
	rrset, err = (&ZoneData{}).buildServerSVCB(conf, "ns.example.", nil, nil)
	if err != nil {
		t.Fatalf("build without port: %v", err)
	}
	if len(rrset.RRs) != 1 {
		t.Fatalf("got %d RRs, want 1", len(rrset.RRs))
	}
	parsed, err := dns.NewRR(rrset.RRs[0].String())
	if err != nil {
		t.Fatalf("reparse %q: %v", rrset.RRs[0].String(), err)
	}
	if svcbPortValue(parsed.(*dns.SVCB)) != 0 {
		t.Errorf("port key present on %s", rrset.RRs[0].String())
	}

	Globals.ServerSVCB = nil
	if _, err := (&ZoneData{}).buildServerSVCB(conf, "ns.example.", nil, nil); err == nil {
		t.Error("build without a server SVCB succeeded")
	}
}

func TestTransportSignalConfigForms(t *testing.T) {
	decode := func(t *testing.T, text string) (*Config, error) {
		t.Helper()
		var raw map[string]interface{}
		if err := yaml.Unmarshal([]byte(text), &raw); err != nil {
			t.Fatalf("yaml: %v", err)
		}
		conf := &Config{}
		var md mapstructure.Metadata
		if err := decodeConfigMap(raw, conf, &md); err != nil {
			return nil, err
		}
		if conf.Service.Transport.Type == "" {
			conf.Service.Transport.Type = "none"
		}
		if err := conf.checkTransportSignal(); err != nil {
			return conf, err
		}
		return conf, nil
	}

	conf, err := decode(t, `
service:
  name: T
  transport:
    type: svcb
    records:
      - signal: "dot:30"
        port: 1234
      - signal: "doq:20"
        port: 1235
`)
	if err != nil {
		t.Fatalf("records form: %v", err)
	}
	if len(conf.Service.Transport.Records) != 2 || conf.Service.Transport.Records[0].Port != 1234 || conf.Service.Transport.Records[1].Signal != "doq:20" {
		t.Errorf("decoded %+v", conf.Service.Transport)
	}

	conf, err = decode(t, `
service:
  name: T
  transport:
    type: svcb
    signal: "dot:30,doq:20"
    port: 1234
`)
	if err != nil {
		t.Fatalf("single record: %v", err)
	}
	if conf.Service.Transport.Signal != "dot:30,doq:20" || conf.Service.Transport.Port != 1234 {
		t.Errorf("decoded %+v", conf.Service.Transport)
	}

	if _, err := decode(t, `
service:
  name: T
  transport:
    type: svcb
    signal: "dot:30"
    records:
      - signal: "doq:20"
        port: 1235
`); err == nil {
		t.Fatal("signal and records together were accepted")
	}
}
