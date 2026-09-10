/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"strings"
	"testing"
)

// A `downstreams: - peers: [ id ]` entry, from YAML, through the two passes the
// daemon runs over it in that order: validateZonePeersAndAcls at config-load
// time (what ValidateConfig calls, and where the regression is) and
// expandPeerRefs at zone load.
//
// Regression for #595. ValidateACL required a parseable ip-spec on every entry,
// and validateZonePeersAndAcls called it on the RAW config -- before
// expandAclList has turned a reference into prefixes. The two therefore
// disagreed about the shape of a reference entry, and no third spelling
// satisfied both. Because TLSIdentity is populated only by peer expansion, that
// took every inbound client-cert mechanism with it: a zone with
// downstream-auth: [tls-pkix] could not authorise anyone, because the only
// entries able to carry an identity were the ones that would not start.
//
// Driven from YAML rather than from AclEntry values on purpose. The `peers:`
// key reaching PeersRef is part of what is under test, and a test that builds
// TLSIdentity in Go passes while no config on disk can produce it -- which is
// how this went unnoticed.
func TestConfigCheckAcceptsAPeerReferenceInDownstreams(t *testing.T) {
	ca := writeTestCAFile(t)
	var conf Config
	if _, _, _, err := decodeConfigFile(writeCfg(t, `peers:
   ca-member:
      keys:     [ NOKEY ]
      prefixes: [ 0.0.0.0/0, "::/0" ]
      ca-file:  `+ca+`

zones:
   - name:            xot.example.
     type:            primary
     store:           map
     downstream-auth: [ tls-pkix ]
     downstreams:
        - peers: [ ca-member ]
`), &conf); err != nil {
		t.Fatalf("decodeConfigFile: %v", err)
	}

	if err := validateZonePeersAndAcls(&conf); err != nil {
		t.Fatalf("the config check rejected a peer reference the daemon accepts: %v", err)
	}

	// And what the daemon builds from it carries the identity that
	// downstream-auth is matched on.
	broken := conf.ValidatePeers()
	if len(broken) != 0 {
		t.Fatalf("the peer should validate: %v", broken)
	}
	if len(conf.Zones) != 1 {
		t.Fatalf("want 1 zone, got %d", len(conf.Zones))
	}
	zc := conf.Zones[0]
	if err := conf.expandPeerRefs(&zc, broken); err != nil {
		t.Fatalf("expandPeerRefs: %v", err)
	}
	// 2 prefixes x 1 key, and the reference itself is consumed.
	if len(zc.Downstreams) != 2 {
		t.Fatalf("want 2 expanded entries, got %d: %+v", len(zc.Downstreams), zc.Downstreams)
	}
	for _, e := range zc.Downstreams {
		if len(e.PeersRef) != 0 {
			t.Errorf("expanded entry kept the reference: %+v", e)
		}
		if e.TLSIdentity == nil {
			t.Fatalf("expanded entry carries no TLS identity, so tls-pkix can never match: %+v", e)
		}
		if e.TLSIdentity.CAFile != ca {
			t.Errorf("ca-file = %q, want %q", e.TLSIdentity.CAFile, ca)
		}
		if e.PeerName != "ca-member" {
			t.Errorf("peer name = %q, want ca-member", e.PeerName)
		}
	}

	// The expanded list is what ValidateACL sees at runtime, and it must still
	// pass the check the raw list was exempted from.
	if err := ValidateACL(zc.Downstreams, func(string) bool { return true }); err != nil {
		t.Fatalf("the expanded list fails the same validator: %v", err)
	}
}

// The exemption must not reopen what validateZonePeersAndAcls was added to
// catch, nor accept the ambiguous entry expandAclList refuses.
func TestConfigCheckStillRejectsMalformedDownstreams(t *testing.T) {
	ca := writeTestCAFile(t)
	base := `peers:
   ca-member:
      keys:     [ NOKEY ]
      prefixes: [ 0.0.0.0/0 ]
      ca-file:  ` + ca + `

zones:
   - name:  xot.example.
     type:  primary
     store: map
     downstreams:
`
	for _, tc := range []struct{ name, entry, want string }{
		{
			// The mistake the validator exists for: notify:'s shape in an ACL.
			"addr where a prefix belongs",
			"        - addr: \"192.0.2.1:53\"\n",
			"ip-spec",
		},
		{
			// expandAclList rejects this at zone load; the checker now says so
			// first, so both bad spellings come from the same pass.
			"reference and inline at once",
			"        - { prefix: 0.0.0.0/0, key: NOKEY, peers: [ ca-member ] }\n",
			"not both",
		},
		{
			"prefix that does not parse",
			"        - { prefix: \"192.0.2.0/33\", key: NOKEY }\n",
			"ip-spec",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var conf Config
			if _, _, _, err := decodeConfigFile(writeCfg(t, base+tc.entry), &conf); err != nil {
				t.Fatalf("decodeConfigFile: %v", err)
			}
			err := validateZonePeersAndAcls(&conf)
			if err == nil {
				t.Fatalf("the config check accepted %q", strings.TrimSpace(tc.entry))
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error does not mention %q: %v", tc.want, err)
			}
		})
	}
}
