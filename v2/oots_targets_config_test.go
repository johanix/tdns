/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v3"
)

// service.transport.targets (plan step S7; design 2026-11-14 sections 2 and
// 5): a transport with a target gets a record of its own, the target as its
// TargetName and its port beside it.

func TestTransportSignalLayoutWithTargets(t *testing.T) {
	const o = pathOwner + " 10800 IN SVCB "
	for _, tc := range []struct {
		name    string
		signal  string
		ports   map[string]uint16
		targets map[string]string
		want    []string
	}{
		{"one transport on another host", "doq:20,dot:10", nil, map[string]string{"dot": "dot.provider.example."},
			[]string{
				o + `1 . oots="doq:20"`,
				o + `1 dot.provider.example. oots="dot:10"`,
			}},
		{"a target without the final dot is made absolute; nothing left for \".\"", "dot:10", nil, map[string]string{"dot": "dot.provider.example"},
			[]string{o + `1 dot.provider.example. oots="dot:10"`}},
		{"a target and a port in one record", "doq:20,dot:10", map[string]uint16{"dot": 1234}, map[string]string{"dot": "dot.provider.example."},
			[]string{
				o + `1 . oots="doq:20"`,
				o + `1 dot.provider.example. port=1234 oots="dot:10"`,
			}},
		{"one moved by target, one by port, fixed order", "doh:5,doq:20,dot:10",
			map[string]uint16{"doh": 8443}, map[string]string{"doq": "doq.provider.example."},
			[]string{
				o + `1 . oots="dot:10"`,
				o + `1 doq.provider.example. oots="doq:20"`,
				o + `1 . port=8443 oots="doh:5"`,
			}},
		{"\".\" is the nameserver itself: absent", "doq:20,dot:10", nil, map[string]string{"dot": "."},
			[]string{o + `1 . oots="doq:20,dot:10"`}},
		{"a target on the standard port carries no port", "dot:10,doq:20", map[string]uint16{"dot": 853}, map[string]string{"dot": "dot.provider.example."},
			[]string{
				o + `1 . oots="doq:20"`,
				o + `1 dot.provider.example. oots="dot:10"`,
			}},
		{"do53 emitted as udp and tcp beside a target", "do53:50,dot:10", nil, map[string]string{"dot": "dot.provider.example."},
			[]string{
				o + `1 . oots="tcp:50,udp:50"`,
				o + `1 dot.provider.example. oots="dot:10"`,
			}},
		{"udp and tcp on another host, stated at their default", "dot:10", nil, map[string]string{"udp": "dns.provider.example.", "tcp": "dns.provider.example."},
			[]string{
				o + `1 . oots="dot:10"`,
				o + `1 dns.provider.example. oots="udp:100"`,
				o + `1 dns.provider.example. oots="tcp:100"`,
			}},
		{"no signal, no port, no target: an empty SVCB", "", nil, nil,
			[]string{o + `1 .`}},
		{"no signal with a udp port: udp stated at its default", "", map[string]uint16{"udp": 5353}, nil,
			[]string{o + `1 . port=5353 oots="udp:100"`}},
		{"no signal with a udp target: the target is kept", "", nil, map[string]string{"udp": "dns.provider.example."},
			[]string{o + `1 dns.provider.example. oots="udp:100"`}},
		{"no signal with a tcp port and target", "", map[string]uint16{"tcp": 5353}, map[string]string{"tcp": "dns.provider.example."},
			[]string{o + `1 dns.provider.example. port=5353 oots="tcp:100"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := buildSignalRRs(t, TransportConf{Type: "svcb", Signal: tc.signal, Ports: tc.ports, Targets: tc.targets})
			if len(got) != len(tc.want) {
				t.Fatalf("got %d RRs, want %d:\n%v", len(got), len(tc.want), got)
			}
			for i, text := range tc.want {
				if !bytes.Equal(rrWire(t, got[i]), rrWire(t, mustRR(t, text))) {
					t.Errorf("RR %d:\n got  %s\n want %s", i, got[i], text)
				}
			}
		})
	}
}

func TestTransportSignalTargetChecks(t *testing.T) {
	listening := ListenerPortsConf{DoT: []uint16{853}, DoQ: []uint16{853}, DoH: []uint16{443}}
	tg := func(kv ...string) map[string]string {
		m := map[string]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	for _, tc := range []struct {
		name    string
		conf    TransportConf
		wantErr string // "" for none
		warns   int
	}{
		{"a dot target", TransportConf{Type: "svcb", Signal: "dot:10", Targets: tg("dot", "dot.provider.example.")}, "", 0},
		{"a doq target without the final dot", TransportConf{Type: "svcb", Signal: "doq:10", Targets: tg("doq", "doq.provider.example")}, "", 0},
		{"\".\" is absent", TransportConf{Type: "svcb", Signal: "dot:10", Targets: tg("dot", ".")}, "", 0},
		{"a doh target is refused", TransportConf{Type: "svcb", Signal: "doh:10", Targets: tg("doh", "doh.provider.example.")}, "needs a path", 0},
		{"do53 takes no target", TransportConf{Type: "svcb", Signal: "dot:10", Targets: tg("do53", "ns.provider.example.")}, "targets.do53", 0},
		{"udp and tcp take a target without a weight", TransportConf{Type: "svcb", Signal: "dot:10", Targets: tg("udp", "dns.provider.example.", "tcp", "dns.provider.example.")}, "", 0},
		{"dot on tcp's port at the same other host", TransportConf{Type: "svcb", Signal: "dot:10", Ports: map[string]uint16{"dot": 53}, Targets: tg("dot", "x.provider.example.", "tcp", "x.provider.example.")}, "at x.provider.example.", 0},
		{"dot on tcp's port, tcp elsewhere", TransportConf{Type: "svcb", Signal: "dot:10", Ports: map[string]uint16{"dot": 53}, Targets: tg("dot", "x.provider.example.")}, "", 0},
		{"doq on udp's port at the same other host", TransportConf{Type: "svcb", Signal: "doq:10", Ports: map[string]uint16{"doq": 5353, "udp": 5353}, Targets: tg("doq", "x.provider.example.", "udp", "x.provider.example.")}, "both are UDP", 0},
		{"doq on udp's port at the same other host, spelled in another case", TransportConf{Type: "svcb", Signal: "doq:10", Ports: map[string]uint16{"udp": 853}, Targets: tg("doq", "dns.provider.example.", "udp", "DNS.provider.example.")}, "both are UDP", 0},
		{"an unknown key", TransportConf{Type: "svcb", Signal: "dot:10", Targets: tg("tls", "ns.provider.example.")}, "targets.tls", 0},
		{"a target for a transport with no weight", TransportConf{Type: "svcb", Signal: "dot:10", Targets: tg("doq", "doq.provider.example.")}, "no weight", 0},
		{"an address is not a name", TransportConf{Type: "svcb", Signal: "dot:10", Targets: tg("dot", "192.0.2.1")}, "is an address", 0},
		{"an IPv6 address is not a name", TransportConf{Type: "svcb", Signal: "dot:10", Targets: tg("dot", "2001:db8::1")}, "is an address", 0},
		{"not a domain name", TransportConf{Type: "svcb", Signal: "dot:10", Targets: tg("dot", "a..b")}, "not a domain name", 0},
		{"empty", TransportConf{Type: "svcb", Signal: "dot:10", Targets: tg("dot", " ")}, "empty", 0},
		{"no signal: a udp target is accepted", TransportConf{Type: "svcb", Targets: tg("udp", "dns.provider.example.")}, "", 0},
		{"no signal: a dot target has no weight", TransportConf{Type: "svcb", Targets: tg("dot", "dot.provider.example.")}, "no weight", 0},
		{"targets with type tsync", TransportConf{Type: "tsync", Signal: "dot:10", Targets: tg("dot", "dot.provider.example.")}, "type is tsync", 0},
		{"targets with type none", TransportConf{Type: "none", Signal: "dot:10", Targets: tg("dot", "dot.provider.example.")}, "type is none", 0},
		{"dot and doh on one port, both here", TransportConf{Type: "svcb", Signal: "dot:10,doh:5", Ports: map[string]uint16{"dot": 443}}, "both are TCP", 0},
		{"dot on doh's port, but on another host", TransportConf{Type: "svcb", Signal: "dot:10,doh:5", Ports: map[string]uint16{"dot": 443}, Targets: tg("dot", "dot.provider.example.")}, "", 0},
		{"a target's port is not this daemon's to listen on", TransportConf{Type: "svcb", Signal: "dot:10", Ports: map[string]uint16{"dot": 1234}, Targets: tg("dot", "dot.provider.example.")}, "", 0},
		{"a port here still warns", TransportConf{Type: "svcb", Signal: "dot:10,doq:20", Ports: map[string]uint16{"dot": 1234}, Targets: tg("doq", "doq.provider.example.")}, "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			warns, err := validateTransportSignal(tc.conf, listening, []string{"127.0.0.1:53"})
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("error %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("accepted, want an error with %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q, want %q in it", err, tc.wantErr)
			}
			if len(warns) != tc.warns {
				t.Errorf("warnings %q, want %d", warns, tc.warns)
			}
		})
	}
}

// The map decodes from YAML as the loader decodes the config.
func TestTransportSignalTargetsDecode(t *testing.T) {
	var raw map[string]interface{}
	if err := yaml.Unmarshal([]byte(`
type: svcb
signal: "dot:10,doq:20"
targets:
   dot: dot.provider.example.
`), &raw); err != nil {
		t.Fatal(err)
	}
	var tc TransportConf
	if err := mapstructure.Decode(raw, &tc); err != nil {
		t.Fatal(err)
	}
	if tc.Targets["dot"] != "dot.provider.example." || len(tc.Targets) != 1 {
		t.Fatalf("targets decoded as %v", tc.Targets)
	}
}

// The start-up pass publishes the record with its target, and warns when
// the zone's signal goes out unsigned: no resolver honours a target from an
// unsigned signal.
func TestTheSignalPassWarnsAboutATargetInAnUnsignedZone(t *testing.T) {
	const z = "target.sig.example."
	logs := captureSignalLog(t)
	zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
ns1.`+z+`	3600	IN	A	127.0.0.1
`, "127.0.0.1:53")
	conf.Service.Identities = []string{"ns1." + z}
	conf.Service.Transport.Signal = "dot:10,doq:20"
	conf.Service.Transport.Targets = map[string]string{"dot": "dot.provider.example."}
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	got := svcbRecords(zd, "_dns.ns1."+z)
	var targeted *dns.SVCB
	for _, rr := range got {
		if s := rr.(*dns.SVCB); s.Target == "dot.provider.example." {
			targeted = s
		}
	}
	if len(got) != 2 || targeted == nil || !strings.Contains(targeted.String(), `oots="dot:10"`) {
		t.Fatalf("the targeted record is missing: %v", got)
	}
	if !strings.Contains(logs.String(), "names a target, but the signal in this zone is not signed") {
		t.Fatalf("no warning for a target in an unsigned zone:\n%s", logs.String())
	}

	// Injected with the rest of the signal; the target itself is not chased.
	sigs := zd.collectSignalRRsets(zd.publishedSnapshot())
	if len(sigs) != 1 || len(sigs[0].RRs) != 2 {
		t.Fatalf("the signal with a target was not injected whole: %v", sigs)
	}

	// A later run takes the targeted signal as its own, not as the
	// operator's (S2).
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "leaving the operator's") {
		t.Fatalf("the pass took its own targeted signal for the operator's:\n%s", logs.String())
	}
}

// Without a target there is nothing to warn about, though the signal is
// stored unsigned.
func TestTheSignalPassDoesNotWarnWithoutATarget(t *testing.T) {
	const z = "notarget.sig.example."
	logs := captureSignalLog(t)
	zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
ns1.`+z+`	3600	IN	A	127.0.0.1
`, "127.0.0.1:53")
	conf.Service.Identities = []string{"ns1." + z}
	conf.Service.Transport.Signal = "dot:10"
	conf.Service.Transport.Ports = map[string]uint16{"dot": 1234}
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if len(svcbRecords(zd, "_dns.ns1."+z)) == 0 {
		t.Fatal("no signal was stored; the test does not exercise the warning")
	}
	if strings.Contains(logs.String(), "names a target") {
		t.Fatalf("a warning about a target with none configured:\n%s", logs.String())
	}
}
