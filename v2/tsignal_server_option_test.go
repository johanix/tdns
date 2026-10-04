/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// The server-wide add-transport-signal: authengine.options turns the zone
// option on for every zone the server serves. It is resolved where the option
// is read, never written into a zone's options.

// serverOptions gives zd a KeyDB holding the server's auth options, as the
// daemon's KeyDB holds them after ParseConfig.
func serverOptions(zd *ZoneData, opts map[AuthOption]string) {
	kdb := &KeyDB{}
	kdb.SetOptions(opts)
	zd.KeyDB = kdb
}

func TestAuthOptionAddTransportSignalValues(t *testing.T) {
	for _, tc := range []struct {
		opts []string
		want string
		set  bool
	}{
		{nil, "", false},
		{[]string{"add-transport-signal"}, "true", true},
		{[]string{"add-transport-signal:true"}, "true", true},
		{[]string{"add-transport-signal:false"}, "false", true},
		// A mistyped value must not start publishing into every zone.
		{[]string{"add-transport-signal:yes"}, "false", true},
	} {
		conf := &Config{}
		conf.AuthEngine.OptionsStrs = tc.opts
		conf.ParseAuthOptions()
		got, ok := conf.AuthEngine.Options[AuthOptAddTransportSignal]
		if ok != tc.set || got != tc.want {
			t.Errorf("%q: add-transport-signal = %q (set %v), want %q (set %v)", tc.opts, got, ok, tc.want, tc.set)
		}
	}
}

// tdns-agent refuses the option, at ParseConfig, before the options reach the
// KeyDB: on the agent every zone may originate content, so a server-wide
// default would publish into every secondary it serves. "false" is refused
// too, so the config says what the app does.
func TestTdnsAgentRefusesTheServerWideTransportSignal(t *testing.T) {
	prev := Globals.App.Type
	Globals.App.Type = AppTypeAgent
	t.Cleanup(func() { Globals.App.Type = prev })

	for _, opt := range []string{"add-transport-signal", "add-transport-signal:false"} {
		loader := &Config{}
		loader.Internal.CfgFile = writeCfg(t, "authengine:\n   options: [ \""+opt+"\" ]\n")
		err := loader.ParseConfig(false)
		if err == nil || !strings.Contains(err.Error(), "not supported by tdns-agent") {
			t.Errorf("tdns-agent with authengine option %q: err = %v, want the option refused", opt, err)
		}
	}

	// The refusal is the agent's alone.
	opts := map[AuthOption]string{AuthOptAddTransportSignal: "true"}
	if err := refuseAuthOptionsForApp(AppTypeAuth, opts); err != nil {
		t.Errorf("tdns-auth refused the option: %v", err)
	}
	if err := refuseAuthOptionsForApp(AppTypeAgent, map[AuthOption]string{AuthOptMinimalResponses: "true"}); err != nil {
		t.Errorf("tdns-agent refused an unrelated option: %v", err)
	}
}

func TestTransportSignalSource(t *testing.T) {
	for _, tc := range []struct {
		name   string
		zone   bool
		server map[AuthOption]string // nil: no KeyDB
		want   string
	}{
		{"off", false, map[AuthOption]string{}, ""},
		{"zone", true, map[AuthOption]string{}, "zone"},
		{"server", false, map[AuthOption]string{AuthOptAddTransportSignal: "true"}, "global"},
		{"server set false", false, map[AuthOption]string{AuthOptAddTransportSignal: "false"}, ""},
		// The zone's own choice is what is reported when both say on.
		{"both", true, map[AuthOption]string{AuthOptAddTransportSignal: "true"}, "zone"},
		{"no KeyDB", false, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zd := &ZoneData{ZoneName: "src.example.", Options: map[ZoneOption]bool{}}
			if tc.zone {
				zd.Options[OptAddTransportSignal] = true
			}
			if tc.server != nil {
				serverOptions(zd, tc.server)
			}
			if got := zd.transportSignalSource(); got != tc.want {
				t.Errorf("source %q, want %q", got, tc.want)
			}
			if got := zd.addsTransportSignal(); got != (tc.want != "") {
				t.Errorf("addsTransportSignal() = %v with source %q", got, tc.want)
			}
		})
	}
}

// The join: a zone that does not set the option gets a stored signal from the
// real start-up postpass and has it injected, under the server-wide option
// alone, and the zone listing reports it as global without writing it into
// the zone's options.
func TestTheServerWideOptionReachesAZoneWithoutTheZoneOption(t *testing.T) {
	const z = "global.sig.example."
	zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
ns1.`+z+`	3600	IN	A	127.0.0.1
`, "127.0.0.1:53")
	delete(zd.Options, OptAddTransportSignal)

	serverOptions(zd, map[AuthOption]string{})
	runTransportSignalPostpass(conf)
	if served(zd, "_dns.ns1."+z, dns.TypeSVCB) {
		t.Fatal("a signal was stored with the option off on the zone and on the server")
	}

	serverOptions(zd, map[AuthOption]string{AuthOptAddTransportSignal: "true"})
	runTransportSignalPostpass(conf)
	if !served(zd, "_dns.ns1."+z, dns.TypeSVCB) {
		t.Fatal("the server-wide option did not reach a zone without the zone option")
	}
	if got := zd.collectSignalRRsets(zd.publishedSnapshot()); len(got) != 1 {
		t.Fatalf("the signal is not injected under the server-wide option: %d RRsets", len(got))
	}

	zc := buildListZoneConf(zd, z, zd.KeyDB)
	if zc.AddTransportSignalSource != "global" {
		t.Errorf("listing reports source %q, want global", zc.AddTransportSignalSource)
	}
	for _, opt := range zc.Options {
		if opt == OptAddTransportSignal {
			t.Error("the server-wide option was reported as the zone's own option")
		}
	}
	if zd.Options[OptAddTransportSignal] {
		t.Error("the server-wide option was written into the zone's options, which dynamic zones persist")
	}
}

// The warning about a zone that names no NS of this server is for an option
// the zone set itself. Under the server-wide option such a zone is ordinary:
// debug, not a warning per zone.
func TestTheServerWideOptionDoesNotWarnForAZoneThatIsNotThisServers(t *testing.T) {
	const z = "elsewhere.sig.example."
	var logs syncBuffer
	prev := lgDns
	lgDns = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() { lgDns = prev })
	zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
ns1.`+z+`	3600	IN	A	192.0.2.1
`, "127.0.0.1:53")
	delete(zd.Options, OptAddTransportSignal)
	serverOptions(zd, map[AuthOption]string{AuthOptAddTransportSignal: "true"})

	if err := zd.CreateTransportSignalRRs(conf); err != nil {
		t.Fatal(err)
	}
	if served(zd, "_dns.ns1."+z, dns.TypeSVCB) {
		t.Fatal("a signal was stored for a name that is not this server's")
	}
	out := logs.String()
	if strings.Contains(out, "level=WARN") {
		t.Errorf("a warning for a zone that only has the server-wide option:\n%s", out)
	}
	if !strings.Contains(out, "under the server-wide add-transport-signal") {
		t.Errorf("no debug line for the zone:\n%s", out)
	}
}
