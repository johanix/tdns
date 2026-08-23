package tdns

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// TestDelegationSyncFullModel decodes every key of the delegationsync: block
// and asserts each one lands where a reader expects it.
//
// The block is now modelled in full and nothing reads it through viper, so a
// field that stops decoding no longer fails loudly at a viper call site -- it
// silently reads as a zero value. This test is what makes that visible.
//
// It also pins two things that are easy to break by accident: the embedded
// DsyncDnsSchemeConf must squash (mapstructure runs with TagName "yaml", so the
// squash keyword has to be in the YAML tag -- `yaml:",inline"` decodes to
// nothing at all), and an absent require-dnssec must stay nil rather than
// becoming false, since the reader treats absent as "default true".
func TestDelegationSyncFullModel(t *testing.T) {
	const y = `
delegationsync:
   parent:
      schemes: [ notify, update ]
      update:
         target: "updates.{ZONENAME}"
         port: 5354
         types: [ ANY ]
         addresses: [ 127.0.0.1 ]
         keygen:
            algorithm: ED25519
            generator: /usr/bin/keygen
         key-verification:
            mechanisms: [ dnssec, tlsa ]
            max-attempts: 7
            retry-interval: 5s
            require-dnssec: false
   child:
      schemes: [ update, notify ]
      update:
         keygen:
            algorithm: ED25519
            generator: /usr/bin/childkeygen
`
	var m map[string]interface{}
	if err := yaml.Unmarshal([]byte(y), &m); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	var c Config
	if err := decodeConfigMap(m, &c, nil); err != nil {
		t.Fatalf("decode: %v", err)
	}
	p := c.DelegationSync.Parent
	// The embedded DsyncDnsSchemeConf must still decode from the same node.
	if p.Update.Target != "updates.{ZONENAME}" || p.Update.Port != 5354 {
		t.Errorf("squashed scheme keys lost: target=%q port=%d", p.Update.Target, p.Update.Port)
	}
	if len(p.Update.Types) != 1 || len(p.Update.Addresses) != 1 {
		t.Errorf("squashed slices lost: types=%v addrs=%v", p.Update.Types, p.Update.Addresses)
	}
	if p.Update.Keygen.Algorithm != "ED25519" || p.Update.Keygen.Generator != "/usr/bin/keygen" {
		t.Errorf("parent keygen: %+v", p.Update.Keygen)
	}
	kv := p.Update.KeyVerification
	if len(kv.Mechanisms) != 2 || kv.MaxAttempts != 7 || kv.RetryInterval.String() != "5s" {
		t.Errorf("key-verification: %+v", kv)
	}
	if kv.RequireDnssec == nil || *kv.RequireDnssec {
		t.Errorf("require-dnssec: %v (want explicit false)", kv.RequireDnssec)
	}
	ch := c.DelegationSync.Child
	if ch.Update.Keygen.Generator != "/usr/bin/childkeygen" {
		t.Errorf("child keygen: %+v", ch.Update.Keygen)
	}
	// Absent require-dnssec must stay nil, not become false.
	var m2 map[string]interface{}
	_ = yaml.Unmarshal([]byte("delegationsync:\n   parent:\n      update:\n         target: x\n"), &m2)
	var c2 Config
	if err := decodeConfigMap(m2, &c2, nil); err != nil {
		t.Fatalf("decode 2: %v", err)
	}
	if c2.DelegationSync.Parent.Update.KeyVerification.RequireDnssec != nil {
		t.Error("an absent require-dnssec decoded as non-nil; absent and false must differ")
	}
}
