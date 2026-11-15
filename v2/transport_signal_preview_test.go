/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

// configAPI posts one /config command, as tdns-cli does.
func configAPI(t *testing.T, conf *Config, post ConfigPost) ConfigResponse {
	t.Helper()
	body, _ := json.Marshal(post)
	w := httptest.NewRecorder()
	APIconfig(conf)(w, httptest.NewRequest("POST", "/config", bytes.NewReader(body)))
	var resp ConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response: %v\n%s", err, w.Body.String())
	}
	return resp
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

// The external review's case (#1060, 2026-11-15): a name the pass has
// synthesized, the printed records pasted into the zone file byte for byte,
// the name released, then taken out of service.identities and the zone
// reloaded. The records stay, and a change to service.transport does not
// rewrite them. Without the release the pass still owns the bytes it stored,
// and withdraws them once the name leaves service.identities.
func TestTheBridgeReleaseHandsASynthesizedNameToTheOperator(t *testing.T) {
	const owner = "_dns.ns1.example."
	const head = `example.	3600	IN	SOA	ns1.example. hostmaster.example. %d 7200 1800 604800 7200
example.	3600	IN	NS	ns1.example.
ns1.example.	3600	IN	A	127.0.0.1
`
	for _, release := range []bool{true, false} {
		t.Run(fmt.Sprintf("release=%v", release), func(t *testing.T) {
			kdb := newTestKeyDB(t)
			zd := reloadZone(t, kdb, fmt.Sprintf(head, 1))
			zd.Options[OptAddTransportSignal] = true
			prevSVCB := Globals.ServerSVCB
			Globals.ServerSVCB = &dns.SVCB{Priority: 1, Target: "."}
			t.Cleanup(func() { Globals.ServerSVCB = prevSVCB })
			conf := &Config{}
			conf.Service.Transport.Type = "svcb"
			conf.Service.Transport.Signal = "dot:50"
			conf.Service.Identities = []string{"ns1.example."}
			reload := func(serial int, records []string) {
				t.Helper()
				operatorEdit(t, zd, fmt.Sprintf(head, serial)+strings.Join(records, "\n")+"\n")
				if _, err := zd.Refresh(context.Background(), false, false, true, conf); err != nil {
					t.Fatalf("Refresh: %v", err)
				}
			}

			if err := zd.CreateTransportSignalRRs(conf); err != nil {
				t.Fatal(err)
			}
			printed, err := transportSignalPreview(conf, "")
			if err != nil {
				t.Fatal(err)
			}
			if printed[0].State != SignalStateSynthesized {
				t.Fatalf("after the pass: state %q", printed[0].State)
			}
			pasted := previewRRs(t, printed[0])

			// Paste into the zone file, byte for byte, and reload. The
			// pass still owns what it stored: the bytes are the same.
			reload(2, printed[0].Records)
			if got := svcbRecords(zd, owner); !sameRecords(got, pasted) {
				t.Fatalf("after the paste: %v", got)
			}
			if p, _ := transportSignalPreview(conf, ""); p[0].State != SignalStateSynthesized {
				t.Fatalf("after the paste, before a release: state %q, want %q", p[0].State, SignalStateSynthesized)
			}

			if release {
				resp := configAPI(t, conf, ConfigPost{Command: "transport-signal-release", Name: "ns1.example."})
				if resp.Error || len(resp.TransportSignal) != 1 || !strings.Contains(resp.Msg, "released") {
					t.Fatalf("the release through the API: %+v", resp)
				}
				if p := resp.TransportSignal[0]; p.State != SignalStateProvisioned || !p.Matches {
					t.Fatalf("after the release: state %q matches=%v, want provisioned and matching", p.State, p.Matches)
				}
				if _, ok, err := kdb.GetTransportSignalStored(zd.ZoneName, owner); err != nil || ok {
					t.Fatalf("the KeyDB still holds the stored-signal record: ok=%v err=%v", ok, err)
				}
			}

			// The name leaves service.identities and the pass runs.
			conf.Service.Identities = nil
			if err := zd.CreateTransportSignalRRs(conf); err != nil {
				t.Fatal(err)
			}
			if !release {
				if got := svcbRecords(zd, owner); len(got) != 0 {
					t.Fatalf("without a release the pass was expected to withdraw what it stored: %v", got)
				}
				return
			}
			if got := svcbRecords(zd, owner); !sameRecords(got, pasted) {
				t.Fatalf("the pass withdrew the released records: %v", got)
			}

			// The zone reloads.
			reload(3, printed[0].Records)
			if got := svcbRecords(zd, owner); !sameRecords(got, pasted) {
				t.Fatalf("a reload lost the released records: %v", got)
			}

			// A change to service.transport does not rewrite them, with the
			// name out of service.identities or back in.
			conf.Service.Transport.Signal = "dot:60"
			for _, ids := range [][]string{nil, {"ns1.example."}} {
				conf.Service.Identities = ids
				if err := zd.CreateTransportSignalRRs(conf); err != nil {
					t.Fatal(err)
				}
				if got := svcbRecords(zd, owner); !sameRecords(got, pasted) {
					t.Fatalf("identities %v: a configuration change rewrote the released records: %v", ids, got)
				}
			}
			if p, _ := transportSignalPreview(conf, ""); p[0].State != SignalStateProvisioned || p[0].Matches {
				t.Fatalf("after the configuration change: state %q matches=%v, want provisioned, differing", p[0].State, p[0].Matches)
			}
		})
	}
}

// The release refuses an owner with nothing at it (synthesis would only
// start over), a name no zone here holds, no name, and a transport type
// other than svcb. Records the pass never stored are the operator's
// already: nothing to release, and no error.
func TestTheBridgeReleaseRefuses(t *testing.T) {
	const z = "release.sig.example."
	_, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
`+z+`	3600	IN	NS	ns2.`+z+`
ns1.`+z+`	3600	IN	A	192.0.2.1
ns2.`+z+`	3600	IN	A	192.0.2.2
_dns.ns2.`+z+`	300	IN	SVCB	1 . oots="dot:5"
`, "127.0.0.1:53")
	conf.Service.Identities = []string{"ns1." + z, "ns2." + z}
	conf.Service.Transport.Signal = "dot:30"

	for _, tc := range []struct{ name, want string }{
		{"ns1." + z, "holds nothing"},
		{"ns1.elsewhere.example.", "no zone served here"},
		{"", "give the name"},
		{"a..b", "not a nameserver name"},
	} {
		if _, _, err := transportSignalRelease(conf, tc.name); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("release %q: %v, want an error with %q", tc.name, err, tc.want)
		}
	}
	p, msg, err := transportSignalRelease(conf, "ns2."+z)
	if err != nil || !strings.Contains(msg, "nothing to release") || len(p) != 1 || p[0].State != SignalStateProvisioned {
		t.Fatalf("records the pass never stored: %v %q %+v", err, msg, p)
	}
	conf.Service.Transport.Type = "none"
	if _, _, err := transportSignalRelease(conf, "ns2."+z); err == nil || !strings.Contains(err.Error(), "only svcb") {
		t.Fatalf("type none: %v", err)
	}
}
