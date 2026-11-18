package tdns

import (
	"slices"
	"strings"
	"testing"
)

// Reload atomicity of service.transport (CodeRabbit on #1118, issue #1135).
// A reload decodes service.transport and service.identities into the live
// Config before it validates, clearing service.transport first, and puts the
// running values back only after it refuses the file.

// keepLiveConfig puts the published runtime-config snapshot back when the
// test ends, so that no other test reads this one's.
func keepLiveConfig(t *testing.T) {
	t.Helper()
	prev := liveConfig.Load()
	t.Cleanup(func() { liveConfig.Store(prev) })
}

// A refused reload that also changed service.identities leaves the running
// identities, beside the running service.transport.
func TestARefusedReloadKeepsTheIdentities(t *testing.T) {
	keepLiveConfig(t)
	conf := &Config{}
	conf.Internal.KeyDB = newTestKeyDB(t)
	conf.Service.Identities = []string{"ns1.running.example."}
	conf.Service.Transport = TransportConf{Type: "svcb", Signal: "dot:50"}
	// The identities and the signal are decoded; the debug address is then
	// refused (it must be loopback), after the decode.
	conf.Internal.CfgFile = writeCfg(t, `service:
   identities: [ ns1.refused.example. ]
   transport:
      type: svcb
      signal: "dot:20"
listeners:
   imr-debug-address: "192.0.2.1:5353"
`)
	conf.publishRuntimeConfig()

	if _, err := conf.ReloadConfig(); err == nil || !strings.Contains(err.Error(), "imr-debug-address") {
		t.Fatalf("the reload was not refused for its debug address: %v", err)
	}
	if conf.Service.Transport.Signal != "dot:50" {
		t.Errorf("the refused reload left service.transport.signal %q", conf.Service.Transport.Signal)
	}
	if !slices.Equal(conf.Service.Identities, []string{"ns1.running.example."}) {
		t.Errorf("the refused reload left service.identities %v", conf.Service.Identities)
	}
	got := conf.transportSignalConfig()
	if got.Service.Transport.Signal != "dot:50" || !slices.Equal(got.Service.Identities, []string{"ns1.running.example."}) {
		t.Errorf("the readers see signal %q and identities %v after a refused reload", got.Service.Transport.Signal, got.Service.Identities)
	}
}

// While a reload has service.transport cleared or holds a refused value, the
// preview through the API and a zone's first-load pass read what was last
// accepted, not the live Config.
func TestTheSignalReadersSeeTheAcceptedConfigDuringAReload(t *testing.T) {
	keepLiveConfig(t)
	const z = "reloadwin.sig.example."
	const owner = "_dns.ns1." + z
	zd, conf := signalTestZone(t, z, z+`	3600	IN	NS	ns1.`+z+`
ns1.`+z+`	3600	IN	A	127.0.0.1
`, "127.0.0.1:53")
	conf.Service.Identities = []string{"ns1." + z}
	conf.Service.Transport.Signal = "dot:50"
	conf.publishRuntimeConfig()

	// What decodeConfigMap leaves while a reload runs: service.transport
	// cleared, and the identities of the file being read.
	conf.Service.Transport = TransportConf{}
	conf.Service.Identities = []string{"ns9.refused.example."}

	resp := configAPI(t, conf, ConfigPost{Command: "transport-signal"})
	if resp.Error || len(resp.TransportSignal) != 1 || resp.TransportSignal[0].Owner != owner ||
		!strings.Contains(strings.Join(resp.TransportSignal[0].Records, "\n"), "dot:50") {
		t.Fatalf("the preview during a reload: %+v, want the accepted signal for ns1.%s", resp, z)
	}
	if resp := configAPI(t, conf, ConfigPost{Command: "status"}); !slices.Equal(resp.Identities, []string{"ns1." + z}) {
		t.Errorf("config status during a reload reports identities %v", resp.Identities)
	}

	runTransportSignalPass(zd, conf)
	if got := svcbRecords(zd, owner); len(got) != 1 || !strings.Contains(got[0].String(), "dot:50") {
		t.Fatalf("the first-load pass during a reload stored %v, want the accepted signal", got)
	}
}

// The readers' copy shares nothing with the snapshot: a reader that changes
// it changes no later reader's.
func TestTheSignalReadersCopyIsTheirOwn(t *testing.T) {
	keepLiveConfig(t)
	conf := &Config{}
	conf.Service.Identities = []string{"ns1.example."}
	conf.Service.Transport = TransportConf{Type: "svcb", Signal: "dot:50", Ports: map[string]uint16{"dot": 8853}}
	conf.publishRuntimeConfig()

	c := conf.transportSignalConfig()
	c.Service.Identities[0] = "changed."
	c.Service.Transport.Ports["dot"] = 1
	again := conf.transportSignalConfig()
	if again.Service.Identities[0] != "ns1.example." || again.Service.Transport.Ports["dot"] != 8853 {
		t.Fatalf("a reader's change reached the snapshot: %v %v", again.Service.Identities, again.Service.Transport.Ports)
	}
}
