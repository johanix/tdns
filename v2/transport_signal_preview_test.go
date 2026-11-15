/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// The bridge from synthesized to provisioned transport signals: tdns-cli's
// "config transport-signal" prints what the start-up pass writes at
// _dns.<name>, for the operator to provision in the zone.

func previewRRs(t *testing.T, p TransportSignalPreview) []dns.RR {
	t.Helper()
	return mustRRs(t, p.Records...)
}

// What the bridge prints is exactly what synthesis writes, ports, udp/tcp
// and targets included, for every identity.
func TestTheBridgePrintsWhatSynthesisWrites(t *testing.T) {
	const z = "bridge.sig.example."
	zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
`+z+`	3600	IN	NS	ns2.`+z+`
ns1.`+z+`	3600	IN	A	192.0.2.1
ns2.`+z+`	3600	IN	A	192.0.2.2
`, "127.0.0.1:53")
	conf.Service.Identities = []string{"ns1." + z, "ns2." + z}
	conf.Service.Transport.Signal = "do53:50,doq:20,dot:10"
	conf.Service.Transport.Ports = map[string]uint16{"doq": 8853}
	conf.Service.Transport.Targets = map[string]string{"dot": "dot.provider.example."}
	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	got, err := transportSignalPreview(conf, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("one preview per identity expected: %v", got)
	}
	for _, p := range got {
		stored := svcbRecords(zd, p.Owner)
		if len(stored) == 0 || !sameRecords(previewRRs(t, p), stored) {
			t.Fatalf("%s: the bridge printed\n%s\nbut synthesis wrote\n%v", p.Owner, strings.Join(p.Records, "\n"), stored)
		}
		if p.State != SignalStateSynthesized || p.Home != z || !p.Identity {
			t.Fatalf("%s: state %q home %q identity %v", p.Owner, p.State, p.Home, p.Identity)
		}
	}
	text := strings.Join(got[0].Records, "\n")
	for _, want := range []string{"8853", "dot.provider.example.", `"tcp:50,udp:50"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("%q missing from what the bridge printed:\n%s", want, text)
		}
	}
}

// The loop the bridge is for: print, provision, and synthesis stops. The
// provisioned records then read as provisioned and matching; a change to
// service.transport afterwards shows them as differing, and the pass still
// leaves them alone.
func TestTheBridgeRecordsOnceProvisionedStopSynthesis(t *testing.T) {
	const z = "provision.sig.example."
	const body = z + `	3600	IN	NS	ns1.` + z + `
ns1.` + z + `	3600	IN	A	192.0.2.1
`
	prevSVCB := Globals.ServerSVCB
	Globals.ServerSVCB = &dns.SVCB{Priority: 1, Target: "."}
	t.Cleanup(func() { Globals.ServerSVCB = prevSVCB })
	conf := &Config{}
	conf.Service.Transport.Type = "svcb"
	conf.Service.Transport.Signal = "dot:30"
	conf.Service.Identities = []string{"ns1." + z}
	printed, err := transportSignalPreview(conf, "")
	if err != nil {
		t.Fatal(err)
	}
	if printed[0].State != SignalStateNotHosted {
		t.Fatalf("before the zone exists: state %q", printed[0].State)
	}

	logs := captureSignalLog(t)
	zd, zconf := signalTestZone(t, z, body+strings.Join(printed[0].Records, "\n")+"\n", "127.0.0.1:53")
	zconf.Service.Identities = conf.Service.Identities
	zconf.Service.Transport.Signal = conf.Service.Transport.Signal
	before := zd.publishedSnapshot()
	if err := zd.CreateTransportSignalRRs(zconf); err != nil {
		t.Fatal(err)
	}
	if zd.publishedSnapshot() != before || !strings.Contains(logs.String(), "leaving the operator's records") {
		t.Fatalf("synthesis did not stop at the provisioned records:\n%s", logs.String())
	}
	p, err := transportSignalPreview(zconf, "")
	if err != nil {
		t.Fatal(err)
	}
	if p[0].State != SignalStateProvisioned || !p[0].Matches {
		t.Fatalf("provisioned records as printed read as %q matches=%v", p[0].State, p[0].Matches)
	}

	zconf.Service.Transport.Signal = "dot:60"
	if err := zd.CreateTransportSignalRRs(zconf); err != nil {
		t.Fatal(err)
	}
	if got := svcbRecords(zd, "_dns.ns1."+z); !sameRecords(got, previewRRs(t, printed[0])) {
		t.Fatalf("a later configuration replaced the provisioned records: %v", got)
	}
	p, _ = transportSignalPreview(zconf, "")
	if p[0].State != SignalStateProvisioned || p[0].Matches {
		t.Fatalf("after a configuration change: state %q matches=%v", p[0].State, p[0].Matches)
	}
}

// One name on the command line, whether or not it is an identity, and the
// states the bridge reports.
func TestTheBridgeForOneName(t *testing.T) {
	const z = "onename.sig.example."
	_, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
ns1.`+z+`	3600	IN	A	192.0.2.1
`, "127.0.0.1:53")
	conf.Service.Identities = []string{"ns1." + z}
	conf.Service.Transport.Signal = "dot:30"

	p, err := transportSignalPreview(conf, "NS9."+strings.TrimSuffix(z, "."))
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 1 || p[0].Name != "ns9."+z || p[0].Owner != "_dns.ns9."+z || p[0].Identity {
		t.Fatalf("one name, canonical, not an identity, was expected: %+v", p)
	}
	if p[0].State != SignalStateNone || p[0].Home != z {
		t.Fatalf("a name in a zone served here with nothing at its owner: state %q home %q", p[0].State, p[0].Home)
	}
	p, err = transportSignalPreview(conf, "ns.elsewhere.example.")
	if err != nil {
		t.Fatal(err)
	}
	if p[0].State != SignalStateNotHosted || p[0].Home != "" || len(p[0].Records) != 1 {
		t.Fatalf("a name no zone here holds: %+v", p[0])
	}
}

func TestTheBridgeRefuses(t *testing.T) {
	conf := &Config{}
	conf.Service.Transport.Type = "svcb"
	conf.Service.Transport.Signal = "dot:30"
	if _, err := transportSignalPreview(conf, ""); err == nil || !strings.Contains(err.Error(), "give a name") {
		t.Fatalf("no identities and no name: %v", err)
	}
	if _, err := transportSignalPreview(conf, "a..b"); err == nil {
		t.Fatal("a malformed name was accepted")
	}
	conf.Service.Transport.Type = "none"
	if _, err := transportSignalPreview(conf, "ns1.example."); err == nil || !strings.Contains(err.Error(), "only svcb") {
		t.Fatalf("type none: %v", err)
	}
}

// Through the API, as tdns-cli asks.
func TestTheBridgeThroughTheConfigAPI(t *testing.T) {
	const z = "api.sig.example."
	_, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
`, "127.0.0.1:53")
	conf.Service.Transport.Signal = "dot:30"
	body, _ := json.Marshal(ConfigPost{Command: "transport-signal", Name: "ns1." + z})
	w := httptest.NewRecorder()
	APIconfig(conf)(w, httptest.NewRequest("POST", "/config", bytes.NewReader(body)))
	var resp ConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response: %v\n%s", err, w.Body.String())
	}
	if resp.Error || len(resp.TransportSignal) != 1 || resp.TransportSignal[0].Owner != "_dns.ns1."+z {
		t.Fatalf("the API did not return the preview: %+v", resp)
	}
	want, err := signalRRsetFor(conf.Service.Transport, "ns1."+z)
	if err != nil {
		t.Fatal(err)
	}
	if !sameRecords(previewRRs(t, resp.TransportSignal[0]), want.RRs) {
		t.Fatalf("the API returned %v, synthesis gives %v", resp.TransportSignal[0].Records, want.RRs)
	}
}
