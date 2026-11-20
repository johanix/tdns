/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"strings"
	"testing"

	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v3"
)

// Decoding a new file into the running Config forgets the transport fields
// the new file leaves out. mapstructure does not clear an absent key, and it
// would keep a ports map the new file drops.
func TestTransportSignalReloadForgetsOldFields(t *testing.T) {
	conf := &Config{}
	decode := func(text string) {
		t.Helper()
		var raw map[string]interface{}
		if err := yaml.Unmarshal([]byte(text), &raw); err != nil {
			t.Fatalf("yaml: %v", err)
		}
		var md mapstructure.Metadata
		if err := decodeConfigMap(raw, conf, &md); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if err := conf.checkTransportSignal(); err != nil {
			t.Fatalf("check after decode: %v (%+v)", err, conf.Service.Transport)
		}
	}

	decode(`
service:
  transport:
    type: svcb
    signal: "dot:30,doq:20"
    ports:
      dot: 1234
      doq: 1235
`)
	decode(`
service:
  transport:
    type: svcb
    signal: "dot:30,doq:20"
    ports:
      dot: 1234
`)
	if p := conf.Service.Transport.Ports; len(p) != 1 || p["dot"] != 1234 {
		t.Errorf("after removing doq from ports: %v", p)
	}

	decode(`
service:
  transport:
    type: svcb
    signal: "dot:30,doq:20"
`)
	if p := conf.Service.Transport.Ports; len(p) != 0 {
		t.Errorf("after removing ports: %v", p)
	}

	decode(`
service:
  transport:
    type: svcb
`)
	if tr := conf.Service.Transport; tr.Signal != "" {
		t.Errorf("after removing signal: %+v", tr)
	}
}

// `config check` refuses what the daemon refuses.
func TestConfigCheckRefusesBadPorts(t *testing.T) {
	for _, tc := range []struct {
		yaml string
		want string
	}{
		{`
service:
  transport:
    type: none
    signal: "dot:30"
    ports:
      dot: 1234
`, "type is none"},
		{`
service:
  transport:
    type: svcb
    signal: "dot:30"
    ports:
      doq: 1235
`, "no weight"},
	} {
		err := ValidateConfig(nil, writeCfg(t, tc.yaml))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ValidateConfig: err = %v, want %q in it", err, tc.want)
		}
	}
}
