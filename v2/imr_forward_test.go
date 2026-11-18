/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// The forward form documented in cmdv2/imr/tdns-imr.sample.yaml must decode,
// including the hyphenated keys.
func TestImrForwardConfigDecodes(t *testing.T) {
	const documented = `
forward:
   - zone: foo.bar.
     upstreams:
        - addr:      192.0.2.1
          port:      8853
          transport: doq
          tls-server-name: dns.example.com
   - zone: company.com.
     trust-ad: true
     upstreams:
        - addr:      192.0.2.2
          transport: dot
          tls-server-name: resolver.company.com
   - zone: lab.example.
     upstreams:
        - addr:      192.0.2.4
          transport: tcp
        - addr:      2001:db8::53
          transport: dot
          insecure:  true
   - zone: .
     upstreams:
        - addr: 192.0.2.3
`
	var conf struct {
		Forward []ImrForwardConf `yaml:"forward"`
	}
	if err := yaml.Unmarshal([]byte(documented), &conf); err != nil {
		t.Fatalf("the documented forward form does not decode: %v", err)
	}
	if len(conf.Forward) != 4 {
		t.Fatalf("want 4 forward zones, got %d", len(conf.Forward))
	}
	f0 := conf.Forward[0]
	if f0.Zone != "foo.bar." || f0.TrustAD {
		t.Errorf("forward[0] = %+v", f0)
	}
	if f0.Upstreams[0].Port != 8853 || f0.Upstreams[0].Transport != "doq" ||
		f0.Upstreams[0].TLSServerName != "dns.example.com" {
		t.Errorf("forward[0].upstreams[0] = %+v", f0.Upstreams[0])
	}
	f1 := conf.Forward[1]
	if !f1.TrustAD || len(f1.Upstreams) != 1 || f1.Upstreams[0].TLSServerName != "resolver.company.com" {
		t.Errorf("forward[1] = %+v", f1)
	}
	f2 := conf.Forward[2]
	if f2.TrustAD || len(f2.Upstreams) != 2 || !f2.Upstreams[1].Insecure {
		t.Errorf("forward[2] = %+v", f2)
	}
}
