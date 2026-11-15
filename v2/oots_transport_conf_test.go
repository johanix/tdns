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
// the new file leaves out. mapstructure does not clear an absent key.
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
    signal: "dot:30"
    port: 1234
`)
	decode(`
service:
  transport:
    type: svcb
    records:
      - signal: "doq:20"
        port: 1235
`)
	if tr := conf.Service.Transport; tr.Signal != "" || tr.Port != 0 || len(tr.Records) != 1 {
		t.Errorf("after switching to records: %+v", tr)
	}

	decode(`
service:
  transport:
    type: svcb
    signal: "dot:30"
    port: 1234
`)
	decode(`
service:
  transport:
    type: svcb
    signal: "dot:30"
`)
	if tr := conf.Service.Transport; tr.Port != 0 || len(tr.Records) != 0 {
		t.Errorf("after removing port: %+v", tr)
	}
}

// `config check` refuses the mixed form the daemon refuses.
func TestConfigCheckRefusesSignalWithRecords(t *testing.T) {
	const mixed = `
service:
  transport:
    type: svcb
    signal: "dot:30"
    records:
      - signal: "doq:20"
        port: 1235
`
	err := ValidateConfig(nil, writeCfg(t, mixed))
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Errorf("ValidateConfig with signal and records: err = %v, want the service.transport refusal", err)
	}
}
