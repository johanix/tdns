package tdns

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// The stub form shown in the shipped sample config must actually decode. It did
// not: the sample listed `servers:` as bare IP strings while the struct wants
// AuthServer objects, so an operator following the documentation got a daemon
// that refused to start.
func TestImrSampleStubFormDecodes(t *testing.T) {
	// Exactly the shape documented in cmdv2/imr/tdns-imr.sample.yaml.
	const documented = `
stubs:
   - zone:  internal.example.
     servers:
        - name:   ns1.internal.example.
          addrs:  [ 192.0.2.53, 2001:db8::53 ]
          alpn:   [ do53 ]
`
	var conf struct {
		Stubs []ImrStubConf `yaml:"stubs"`
	}
	if err := yaml.Unmarshal([]byte(documented), &conf); err != nil {
		t.Fatalf("the documented stub form does not decode: %v", err)
	}
	if len(conf.Stubs) != 1 {
		t.Fatalf("want 1 stub, got %d", len(conf.Stubs))
	}
	st := conf.Stubs[0]
	if st.Zone != "internal.example." {
		t.Errorf("zone = %q", st.Zone)
	}
	if len(st.Servers) != 1 {
		t.Fatalf("want 1 server, got %d", len(st.Servers))
	}
	if got := st.Servers[0].Name; got != "ns1.internal.example." {
		t.Errorf("server name = %q", got)
	}
	if got := len(st.Servers[0].Addrs); got != 2 {
		t.Errorf("want 2 addrs, got %d", got)
	}
}

// The old sample's form must NOT decode, so this test keeps guarding something.
func TestImrBareAddressStubFormIsRejected(t *testing.T) {
	const oldSample = `
stubs:
   - zone:     internal.example.
     servers:  [ 192.0.2.53, 2001:db8::53 ]
`
	var conf struct {
		Stubs []ImrStubConf `yaml:"stubs"`
	}
	if err := yaml.Unmarshal([]byte(oldSample), &conf); err == nil {
		t.Fatal("the bare-address form decoded; the sample and the struct have" +
			" converged and this test is obsolete")
	}
}
