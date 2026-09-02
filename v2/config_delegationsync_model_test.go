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
// nothing at all), and an absent require-dnssec on a named policy must stay nil
// rather than becoming false, since compile treats absent as "default true".
func TestDelegationSyncFullModel(t *testing.T) {
	const y = `
delegationsync:
   policies:
      default:
         bootstrap:
            mechanisms: [ at-apex, at-ns ]
            require-dnssec: true
            retry:
               max-attempts: 7
               interval: 5s
      permissive:
         bootstrap:
            mechanisms: [ at-apex, at-ns ]
            require-dnssec: false
            manual: true
            allow-unvalidated-upload: true
      locked-down:
         bootstrap:
            mechanisms: []
            manual: true
            allow-unvalidated-upload: false
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
   child:
      schemes: [ update, notify ]
      update:
         keygen:
            algorithm: ED25519
            generator: /usr/bin/childkeygen
         bootstrap:
            methods: [ at-apex, at-ns ]
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
	def := c.DelegationSync.Policies["default"]
	if len(def.Bootstrap.Mechanisms) != 2 || def.Bootstrap.Retry.MaxAttempts != 7 || def.Bootstrap.Retry.Interval.String() != "5s" {
		t.Errorf("default policy: %+v", def.Bootstrap)
	}
	if def.Bootstrap.RequireDnssec == nil || !*def.Bootstrap.RequireDnssec {
		t.Errorf("default require-dnssec: %v (want explicit true)", def.Bootstrap.RequireDnssec)
	}
	perm := c.DelegationSync.Policies["permissive"]
	if perm.Bootstrap.RequireDnssec == nil || *perm.Bootstrap.RequireDnssec {
		t.Errorf("permissive require-dnssec: %v (want explicit false)", perm.Bootstrap.RequireDnssec)
	}
	if !perm.Bootstrap.Manual || !perm.Bootstrap.AllowUnvalidatedUpload {
		t.Errorf("permissive flags: %+v", perm.Bootstrap)
	}
	locked := c.DelegationSync.Policies["locked-down"]
	if locked.Bootstrap.Mechanisms == nil || len(locked.Bootstrap.Mechanisms) != 0 {
		t.Errorf("locked-down mechanisms: %v (want empty, not nil-or-filled)", locked.Bootstrap.Mechanisms)
	}
	ch := c.DelegationSync.Child
	if ch.Update.Keygen.Generator != "/usr/bin/childkeygen" {
		t.Errorf("child keygen: %+v", ch.Update.Keygen)
	}
	if len(ch.Update.Bootstrap.Methods) != 2 {
		t.Errorf("child bootstrap methods: %v", ch.Update.Bootstrap.Methods)
	}
	// Absent require-dnssec must stay nil, not become false.
	var m2 map[string]interface{}
	_ = yaml.Unmarshal([]byte("delegationsync:\n   policies:\n      custom:\n         bootstrap:\n            mechanisms: [ at-apex ]\n"), &m2)
	var c2 Config
	if err := decodeConfigMap(m2, &c2, nil); err != nil {
		t.Fatalf("decode 2: %v", err)
	}
	if c2.DelegationSync.Policies["custom"].Bootstrap.RequireDnssec != nil {
		t.Error("an absent require-dnssec decoded as non-nil; absent and false must differ")
	}
}
