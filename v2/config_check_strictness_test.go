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
	if got := conf.ChildSync.Schemes; len(got) != 2 {
		t.Fatalf("schemes decoded as %#v, want two entries", got)
	}
	if got := conf.ChildSync.Notify.Port; got != 5354 {
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

// A `- peers: [ id ]` reference in downstreams: must survive config check.
//
// It did not between 2026-08-19 (b3df0dc7, which started validating the raw
// per-zone lists) and the fix. Because a downstreams entry's TLSIdentity is
// built only by peer expansion, rejecting the reference shape took every
// inbound client-certificate mechanism with it: a zone with
// downstream-auth: [ tls-pkix ] could not be configured at all, in any tdns
// deployment, and the daemon refused to start rather than failing at the
// zone.
//
// The ladder's own tests construct AclEntry values with TLSIdentity set
// directly in Go, so they kept passing throughout. This one goes through the
// config, which is the part that broke.
func TestConfigCheckAcceptsPeerReferencesInAcls(t *testing.T) {
	const good = `
peers:
   ca-member:
      keys:     [ NOKEY ]
      prefixes: [ "0.0.0.0/0", "::/0" ]
      ca-file:  /tmp/ca.crt
   a-secondary:
      addr: "192.0.2.9:853"
      keys: [ NOKEY ]

zones:
   - name: example.com.
     type: primary
     zonefile: /tmp/example.com
     downstream-auth: [ tls-pkix ]
     downstreams:
        - peers: [ ca-member ]
   - name: example.net.
     type: primary
     zonefile: /tmp/example.net
     allow-notify:
        - peers: [ a-secondary ]
     downstreams:
        - peers: [ a-secondary ]
        - prefix: "192.0.2.0/24"
          key:    NOKEY
`
	var conf Config
	if _, _, _, err := decodeConfigFile(writeCfg(t, good), &conf); err != nil {
		t.Fatalf("decode of a peer-referencing config failed: %v", err)
	}
	if err := validateZonePeersAndAcls(&conf); err != nil {
		t.Fatalf("a peer reference in an ACL was rejected: %v", err)
	}
}

// The exemption must not swallow the mistake the validator exists for.
func TestConfigCheckStillCatchesAddrUnderDownstreams(t *testing.T) {
	const bad = `
zones:
   - name: example.com.
     type: primary
     zonefile: /tmp/example.com
     downstreams:
        - addr: "192.0.2.1:53"
`
	err := ValidateConfig(nil, writeCfg(t, bad))
	if err == nil {
		t.Fatal("addr: under downstreams: passed config check")
	}
	if !strings.Contains(err.Error(), "downstreams") || !strings.Contains(err.Error(), "belongs in") {
		t.Fatalf("error does not point at the right list: %v", err)
	}
}

// ValidateACL is called by post-expansion callers too. After expansion there
// are no references left, so the exemption must be inert there -- in
// particular it must not let a genuinely malformed expanded entry through.
func TestValidateACLExemptionIsInertPostExpansion(t *testing.T) {
	defined := func(string) bool { return true }
	// What expandAclList produces: prefix and key set, PeersRef cleared.
	expanded := []AclEntry{{Prefix: "192.0.2.0/24", Key: NOKEY, PeerName: "ca-member"}}
	if err := ValidateACL(expanded, defined); err != nil {
		t.Fatalf("an expanded peer entry was rejected: %v", err)
	}
	// And a bad prefix in an expanded entry is still an error.
	if err := ValidateACL([]AclEntry{{Prefix: "garbage", Key: NOKEY}}, defined); err == nil {
		t.Fatal("a malformed prefix passed ValidateACL")
	}
}
