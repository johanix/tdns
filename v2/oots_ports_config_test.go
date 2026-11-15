/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v3"
)

func buildSignalRRs(t *testing.T, tc TransportConf) []dns.RR {
	t.Helper()
	prev := Globals.ServerSVCB
	Globals.ServerSVCB = &dns.SVCB{Priority: 1, Target: "."}
	t.Cleanup(func() { Globals.ServerSVCB = prev })
	conf := &Config{}
	conf.Service.Transport = tc
	rrset, err := (&ZoneData{}).buildServerSVCB(conf, pathNS, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return rrset.RRs
}

func rrWire(t *testing.T, rr dns.RR) []byte {
	t.Helper()
	buf := make([]byte, dns.Len(rr))
	off, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		t.Fatalf("pack %s: %v", rr, err)
	}
	return buf[:off]
}

// The published RRset for a configuration, record by record, compared on the
// wire.
func TestTransportSignalLayout(t *testing.T) {
	const o = pathOwner + " 10800 IN SVCB "
	for _, tc := range []struct {
		name   string
		signal string
		ports  map[string]uint16
		want   []string
	}{
		{"no signal: one empty SVCB, as before", "", nil,
			[]string{o + `1 .`}},
		{"no ports: one record, as before", "doq:20,dot:10", nil,
			[]string{o + `1 . oots="do53:100,doq:20,dot:10"`}},
		{"a standard port counts as absent", "doq:20,dot:10", map[string]uint16{"dot": 853, "doq": 853},
			[]string{o + `1 . oots="do53:100,doq:20,dot:10"`}},
		{"one transport moved", "doq:20,dot:10", map[string]uint16{"dot": 1234},
			[]string{
				o + `1 . oots="do53:100,doq:20"`,
				o + `1 . port=1234 oots="dot:10"`,
			}},
		{"every transport moved, fixed order", "doh:5,doq:20,dot:10",
			map[string]uint16{"doh": 8443, "doq": 1235, "dot": 1234},
			[]string{
				o + `1 . oots="do53:100"`,
				o + `1 . port=1234 oots="dot:10"`,
				o + `1 . port=1235 oots="doq:20"`,
				o + `1 . port=8443 oots="doh:5"`,
			}},
		{"DoH on a port", "doh:20", map[string]uint16{"doh": 8443},
			[]string{
				o + `1 . oots="do53:100"`,
				o + `1 . port=8443 oots="doh:20"`,
			}},
		{"the operator's do53 weight, stated once", "do53:0,dot:10,doq:20", map[string]uint16{"dot": 1234},
			[]string{
				o + `1 . oots="do53:0,doq:20"`,
				o + `1 . port=1234 oots="dot:10"`,
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := buildSignalRRs(t, TransportConf{Type: "svcb", Signal: tc.signal, Ports: tc.ports})
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

// A configuration without ports publishes the bytes it published before
// #994: one SVCB 1 . with only oots, the do53 default written out. Built
// here by the pre-#994 recipe, independently of transportSignalLayout.
func TestDefaultTransportSignalIsByteIdentical(t *testing.T) {
	for _, signal := range []string{"doq:20,dot:10", "dot:10,do53:0", "doh:5", ""} {
		got := buildSignalRRs(t, TransportConf{Type: "svcb", Signal: signal})
		if len(got) != 1 {
			t.Fatalf("%q: %d RRs, want 1", signal, len(got))
		}
		before := &dns.SVCB{
			Hdr:      dns.RR_Header{Name: pathOwner, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 10800},
			Priority: 1,
			Target:   ".",
		}
		if signal != "" {
			oots, err := transportSignalToSVCBOots(signal)
			if err != nil {
				t.Fatalf("%q: %v", signal, err)
			}
			if oots != nil {
				before.Value = []dns.SVCBKeyValue{oots}
			}
		}
		if !bytes.Equal(rrWire(t, got[0]), rrWire(t, before)) {
			t.Errorf("%q:\n got  %s\n want %s", signal, got[0], before)
		}
	}
}

func TestTransportSignalChecks(t *testing.T) {
	listening := ListenerPortsConf{DoT: []uint16{853, 1234}, DoQ: []uint16{853}, DoH: []uint16{443}}
	for _, tc := range []struct {
		name    string
		conf    TransportConf
		listen  ListenerPortsConf
		wantErr string // "" for none
		warns   int
	}{
		{"no ports", TransportConf{Type: "svcb", Signal: "doq:20,dot:10"}, listening, "", 0},
		{"signal does not parse", TransportConf{Type: "svcb", Signal: "dot30"}, listening, "service.transport.signal", 0},
		{"signal does not parse, type none", TransportConf{Type: "none", Signal: "dot:10,dot:20"}, listening, "duplicate", 0},
		{"a listened port", TransportConf{Type: "svcb", Signal: "dot:10", Ports: map[string]uint16{"dot": 1234}}, listening, "", 0},
		{"a port nothing listens on warns", TransportConf{Type: "svcb", Signal: "dot:10", Ports: map[string]uint16{"dot": 1235}}, listening, "", 1},
		{"a standard port is absent, no warning", TransportConf{Type: "svcb", Signal: "dot:10", Ports: map[string]uint16{"dot": 853}}, ListenerPortsConf{}, "", 0},
		{"do53 is not a key", TransportConf{Type: "svcb", Signal: "dot:10", Ports: map[string]uint16{"do53": 553}}, listening, "ports.do53", 0},
		{"an unknown key", TransportConf{Type: "svcb", Signal: "dot:10", Ports: map[string]uint16{"tls": 1234}}, listening, "ports.tls", 0},
		{"a port for a transport with no weight", TransportConf{Type: "svcb", Signal: "dot:10", Ports: map[string]uint16{"doq": 1235}}, listening, "no weight", 0},
		{"a port for a transport at weight 0", TransportConf{Type: "svcb", Signal: "dot:10,doq:0", Ports: map[string]uint16{"doq": 1235}}, listening, "no weight", 0},
		{"port 0", TransportConf{Type: "svcb", Signal: "dot:10", Ports: map[string]uint16{"dot": 0}}, listening, "0 is not a port", 0},
		{"dot and doh on one port", TransportConf{Type: "svcb", Signal: "dot:10,doh:5", Ports: map[string]uint16{"dot": 8443, "doh": 8443}}, listening, "both are TCP", 0},
		{"dot on the port doh keeps", TransportConf{Type: "svcb", Signal: "dot:10,doh:5", Ports: map[string]uint16{"dot": 443}}, listening, "both are TCP", 0},
		{"dot on 443 when the signal has no doh", TransportConf{Type: "svcb", Signal: "dot:10", Ports: map[string]uint16{"dot": 443}}, listening, "", 1},
		{"doq shares a port with dot", TransportConf{Type: "svcb", Signal: "dot:10,doq:20", Ports: map[string]uint16{"dot": 1234, "doq": 1234}}, listening, "", 1},
		{"ports with type tsync", TransportConf{Type: "tsync", Signal: "dot:10", Ports: map[string]uint16{"dot": 1234}}, listening, "type is tsync", 0},
		{"ports with type none", TransportConf{Type: "none", Signal: "dot:10", Ports: map[string]uint16{"dot": 1234}}, listening, "type is none", 0},
		{"ports with no signal", TransportConf{Type: "svcb", Ports: map[string]uint16{"dot": 1234}}, listening, "no weight", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			warns, err := validateTransportSignal(tc.conf, tc.listen)
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

// The map decodes from YAML through the loader's own decoder. A value that
// does not fit a port is refused, not truncated, and #994's keys are no
// longer known.
func TestTransportSignalPortsDecode(t *testing.T) {
	decode := func(t *testing.T, text string) (*Config, *mapstructure.Metadata, error) {
		t.Helper()
		var raw map[string]interface{}
		if err := yaml.Unmarshal([]byte(text), &raw); err != nil {
			t.Fatalf("yaml: %v", err)
		}
		conf := &Config{}
		md := &mapstructure.Metadata{}
		err := decodeConfigMap(raw, conf, md)
		return conf, md, err
	}

	conf, _, err := decode(t, `
service:
  name: T
  transport:
    type: svcb
    signal: "dot:10,doq:20,doh:5"
    ports:
      dot: 1234
      doq: 1235
      doh: 8443
`)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := map[string]uint16{"dot": 1234, "doq": 1235, "doh": 8443}
	if got := conf.Service.Transport.Ports; len(got) != 3 || got["dot"] != 1234 || got["doq"] != 1235 || got["doh"] != 8443 {
		t.Errorf("ports %v, want %v", got, want)
	}

	if _, _, err := decode(t, `
service:
  name: T
  transport:
    type: svcb
    signal: "dot:10"
    ports:
      dot: 70000
`); err == nil || !strings.Contains(err.Error(), "70000") {
		t.Errorf("port 70000: err %v, want a refusal", err)
	}

	_, md, err := decode(t, `
service:
  name: T
  transport:
    type: svcb
    signal: "dot:10"
    port: 1234
    records:
      - signal: "doq:20"
        port: 1235
`)
	if err != nil {
		t.Fatalf("decode #994 keys: %v", err)
	}
	for _, key := range []string{"service.transport.port", "service.transport.records"} {
		if !slices.ContainsFunc(md.Unused, func(u string) bool { return strings.EqualFold(u, key) }) {
			t.Errorf("%s is not reported unused: %v", key, md.Unused)
		}
	}
}

// config -> buildServerSVCB -> the resolver, on each path a signal arrives
// by and in both RR orders: each transport gets its weight and its port,
// DoH included, and do53 stays on 53 at its weight.
func TestTransportSignalConfigRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		conf TransportConf
		want string
	}{
		{"no ports",
			TransportConf{Type: "svcb", Signal: "doq:20,dot:10"},
			"oots w=do53:100,doq:20,dot:10 p="},
		{"every transport on a port",
			TransportConf{Type: "svcb", Signal: "doh:5,doq:20,dot:10", Ports: map[string]uint16{"dot": 1234, "doq": 1235, "doh": 8443}},
			"oots w=do53:100,doh:5,doq:20,dot:10 p=doh:8443,doq:1235,dot:1234"},
		{"DoH alone on a port",
			TransportConf{Type: "svcb", Signal: "dot:10,doh:5", Ports: map[string]uint16{"doh": 8443}},
			"oots w=do53:100,doh:5,dot:10 p=doh:8443"},
		{"do53 at the operator's weight",
			TransportConf{Type: "svcb", Signal: "do53:0,dot:10", Ports: map[string]uint16{"dot": 1234}},
			"oots w=do53:0,dot:10 p=dot:1234"},
		// Only the record without a port names do53, so no default in a
		// ported record can outrank the operator's do53:0.
		{"do53:0 with every other transport on a port",
			TransportConf{Type: "svcb", Signal: "do53:0,dot:30,doq:20", Ports: map[string]uint16{"dot": 1234, "doq": 1235}},
			"oots w=do53:0,doq:20,dot:30 p=doq:1235,dot:1234"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var texts []string
			for _, rr := range buildSignalRRs(t, tc.conf) {
				texts = append(texts, rr.String())
			}
			checkEveryPathBothOrders(t, texts, tc.want)
		})
	}
}
