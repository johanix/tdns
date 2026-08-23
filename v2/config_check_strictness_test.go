/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The checker exists to answer one question: would the daemon start on this
// file? These tests pin the two halves of that -- it must reject what the
// daemon rejects, and must not start rejecting what the daemon accepts.

// writeCfg puts text in a temp file and returns its path.
func writeCfg(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tdns-auth.yaml")
	if err := os.WriteFile(p, []byte(text), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return p
}

// TestConfigCheckRejectsWhatTheDaemonRejects. Every form here is one viper
// accepts and the daemon's decoder does not; the checker used to decode through
// viper.Unmarshal and so reported all of them clean.
func TestConfigCheckRejectsWhatTheDaemonRejects(t *testing.T) {
	for _, tc := range []struct{ name, yaml, want string }{
		{
			"scalar where a slice is required",
			"delegationsync:\n   parent:\n      schemes: notify\n",
			"schemes",
		},
		{
			"quoted integer where uint16 is required",
			"delegationsync:\n   parent:\n      notify:\n         port: \"5354\"\n",
			"port",
		},
		{
			"scalar addresses",
			"delegationsync:\n   parent:\n      notify:\n         addresses: 127.0.0.1\n",
			"addresses",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var conf Config
			_, _, _, err := decodeConfigFile(writeCfg(t, tc.yaml), &conf)
			if err == nil {
				t.Fatalf("the daemon decoder accepted %q; this test no longer proves anything", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error does not name %q: %v", tc.want, err)
			}

			// The checker must reach the same verdict.
			if verr := ValidateConfig(nil, writeCfg(t, tc.yaml)); verr == nil {
				t.Fatalf("config check PASSED a file the daemon refuses to decode:\n  daemon: %v", err)
			}
		})
	}
}

// TestConfigCheckAcceptsTheStrictSafeShape. The other half: a stricter checker
// is only useful if it does not start failing configs that boot fine. The list
// form and an unquoted integer are what every shipped sample uses.
func TestConfigCheckAcceptsTheStrictSafeShape(t *testing.T) {
	const good = `
delegationsync:
   parent:
      schemes: [ notify, update ]
      notify:
         target: "notifications.{ZONENAME}"
         port: 5354
         types: [ CDS, CSYNC ]
         addresses: [ 127.0.0.1, "::1" ]
`
	var conf Config
	if _, _, _, err := decodeConfigFile(writeCfg(t, good), &conf); err != nil {
		t.Fatalf("the daemon decoder refused the documented shape: %v", err)
	}
	if got := conf.DelegationSync.Parent.Schemes; len(got) != 2 {
		t.Fatalf("schemes decoded as %#v, want two entries", got)
	}
	if got := conf.DelegationSync.Parent.Notify.Port; got != 5354 {
		t.Fatalf("port decoded as %d, want 5354", got)
	}
}

// TestShippedSamplesStillValidate is the regression guard on the strictness
// change itself: the sample configs ship as documentation, so a checker that
// rejects them is wrong regardless of what it catches.
func TestShippedSamplesStillValidate(t *testing.T) {
	for _, s := range []string{
		"../cmdv2/auth/tdns-auth.sample.yaml",
		"../cmdv2/agent/tdns-agent.sample.yaml",
	} {
		t.Run(filepath.Base(s), func(t *testing.T) {
			if _, err := os.Stat(s); err != nil {
				t.Skipf("sample not present: %v", err)
			}
			var conf Config
			if _, _, _, err := decodeConfigFile(s, &conf); err != nil {
				t.Fatalf("the shipped sample no longer decodes: %v", err)
			}
		})
	}
}

// TestConfigCheckCatchesSwappedPeerAndAclShapes. notify:/primaries: take
// {addr, key}; downstreams:/allow-notify: take {prefix, key}. mapstructure
// silently drops a key the target struct lacks, so writing one shape under the
// other decodes clean and then quarantines the zone at load. The checker
// reported nothing at all.
func TestConfigCheckCatchesSwappedPeerAndAclShapes(t *testing.T) {
	for _, tc := range []struct{ name, yaml, want string }{
		{
			"addr: under downstreams:",
			`
zones:
   - name: example.com.
     type: primary
     zonefile: /tmp/example.com
     downstreams:
        - addr: "192.0.2.1:53"
`,
			"downstreams",
		},
		{
			"addr: under allow-notify:",
			`
zones:
   - name: example.com.
     type: secondary
     allow-notify:
        - addr: "192.0.2.1:53"
`,
			"allow-notify",
		},
		{
			"prefix: under notify:",
			`
zones:
   - name: example.com.
     type: primary
     zonefile: /tmp/example.com
     notify:
        - prefix: "192.0.2.1/32"
`,
			"notify",
		},
		{
			"the same mistake in a template",
			`
templates:
   - name: broken-tmpl
     type: primary
     downstreams:
        - addr: "192.0.2.1:53"
`,
			"template",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateConfig(nil, writeCfg(t, tc.yaml))
			if err == nil {
				t.Fatal("config check passed a shape that quarantines the zone at load")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error does not name %q: %v", tc.want, err)
			}
			// The message must say what to write instead, or the operator is
			// left staring at a valid-looking list.
			if !strings.Contains(err.Error(), "belongs in") {
				t.Fatalf("error does not point at the right list: %v", err)
			}
		})
	}
}

// And the correct shapes must still pass.
func TestConfigCheckAcceptsCorrectPeerAndAclShapes(t *testing.T) {
	const good = `
zones:
   - name: example.com.
     type: primary
     zonefile: /tmp/example.com
     notify:
        - addr: "192.0.2.1:53"
          key:  NOKEY
     downstreams:
        - prefix: "192.0.2.0/24"
          key:    NOKEY
     allow-notify:
        - prefix: "198.51.100.1/32"
          key:    NOKEY
`
	var conf Config
	if _, _, _, err := decodeConfigFile(writeCfg(t, good), &conf); err != nil {
		t.Fatalf("decode of the documented shape failed: %v", err)
	}
	if err := validateZonePeersAndAcls(&conf); err != nil {
		t.Fatalf("the documented shape was rejected: %v", err)
	}
}
