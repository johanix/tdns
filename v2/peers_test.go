/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"strings"
	"testing"
)

func validPin() string {
	return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32 zero bytes, b64
}

func writeTestCAFile(t *testing.T) string {
	t.Helper()
	_, leaf := newTestTLSCert(t, []string{"ca.test"}, nil)
	path := t.TempDir() + "/ca.pem"
	if err := writeCertPEM(path, leaf.Raw); err != nil {
		t.Fatalf("write ca file: %v", err)
	}
	return path
}

func TestPeers_ValidatePeerDef(t *testing.T) {
	caPath := writeTestCAFile(t)

	cases := []struct {
		name string
		peer PeerDef
		ok   bool
		frag string // expected error fragment when !ok
	}{
		{"minimal outbound", PeerDef{Addr: "192.0.2.1:53", Key: NOKEY}, true, ""},
		{"key sugar resolves", PeerDef{Addr: "192.0.2.1:53", Key: "k1"}, true, ""},
		{"keys list", PeerDef{Addr: "192.0.2.1:53", Keys: []string{"k1", "k2"}}, true, ""},
		{"key and keys both", PeerDef{Addr: "192.0.2.1:53", Key: "k1", Keys: []string{"k2"}}, false, "both key and keys"},
		{"no key at all", PeerDef{Addr: "192.0.2.1:53"}, false, "no TSIG key"},
		{"NOKEY mixed with named", PeerDef{Addr: "192.0.2.1:53", Keys: []string{NOKEY, "k1"}}, false, "NOKEY must be the only"},
		{"dot outbound needs tls-auth", PeerDef{Addr: "ns1.test:853", Key: NOKEY, Transport: "dot"}, false, "tls-auth"},
		{"dot outbound ok", PeerDef{Addr: "ns1.test:853", Key: NOKEY, Transport: "dot", TLSAuth: "dane"}, true, ""},
		{"outbound tls without addr", PeerDef{Key: NOKEY, Prefixes: []string{"192.0.2.1"}, Transport: "dot"}, false, "require addr"},
		{"inbound-only", PeerDef{Key: "k1", Prefixes: []string{"10.1.2.3"}}, true, ""},
		{"identity pins ok", PeerDef{Key: "k1", Prefixes: []string{"10.1.2.3"},
			TLSIdentity: &TLSIdentity{Pins: []string{validPin()}}}, true, ""},
		{"identity bad pin", PeerDef{Key: "k1", Prefixes: []string{"10.1.2.3"},
			TLSIdentity: &TLSIdentity{Pins: []string{"nope"}}}, false, "not a base64"},
		{"identity ca ok", PeerDef{Key: "k1", Prefixes: []string{"10.1.2.3"},
			TLSIdentity: &TLSIdentity{Name: "sec1.test", CAFile: caPath}}, true, ""},
		{"identity ca unreadable", PeerDef{Key: "k1", Prefixes: []string{"10.1.2.3"},
			TLSIdentity: &TLSIdentity{CAFile: "/nonexistent.pem"}}, false, "ca-file"},
		{"identity dane needs name", PeerDef{Key: "k1", Prefixes: []string{"10.1.2.3"},
			TLSIdentity: &TLSIdentity{Dane: true}}, false, "dane requires a name"},
		{"identity empty", PeerDef{Key: "k1", Prefixes: []string{"10.1.2.3"},
			TLSIdentity: &TLSIdentity{Name: "sec1.test"}}, false, "tls-identity is empty"},
	}
	for _, tc := range cases {
		p := tc.peer
		err := validatePeerDef(&p)
		if tc.ok && err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
		}
		if !tc.ok {
			if err == nil {
				t.Errorf("%s: expected error, got none", tc.name)
			} else if !strings.Contains(err.Error(), tc.frag) {
				t.Errorf("%s: error %q does not contain %q", tc.name, err, tc.frag)
			}
		}
	}
}

func TestPeers_Defaults(t *testing.T) {
	// IP-literal addr defaults the inbound prefix.
	p := PeerDef{Addr: "192.0.2.7:853", Key: NOKEY}
	if err := validatePeerDef(&p); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(p.Prefixes) != 1 || p.Prefixes[0] != "192.0.2.7" {
		t.Fatalf("prefix not defaulted from addr: %v", p.Prefixes)
	}
	// Hostname addr defaults the tls-identity name, not the prefix.
	p2 := PeerDef{Addr: "sec1.test:853", Key: NOKEY,
		TLSIdentity: &TLSIdentity{Pins: []string{validPin()}}}
	if err := validatePeerDef(&p2); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if p2.TLSIdentity.Name != "sec1.test" {
		t.Fatalf("tls-identity name not defaulted from addr: %q", p2.TLSIdentity.Name)
	}
	if len(p2.Prefixes) != 0 {
		t.Fatalf("hostname addr must not default a prefix: %v", p2.Prefixes)
	}
	// key: sugar resolved into keys.
	if len(p.Keys) != 1 || p.Keys[0] != NOKEY || p.Key != "" {
		t.Fatalf("key sugar not resolved: key=%q keys=%v", p.Key, p.Keys)
	}
}

func peersTestConf(t *testing.T) *Config {
	t.Helper()
	conf := &Config{Peers: map[string]PeerDef{
		"ns1": {Addr: "ns1.test:853", Key: NOKEY, Transport: "dot", TLSAuth: "dane"},
		"sec1": {Addr: "sec1.test:853",
			Prefixes: []string{"198.51.100.7", "2001:db8::7"},
			Keys:     []string{"xfr-key-2026", "xfr-key-2025"},
			TLSIdentity: &TLSIdentity{
				Name: "sec1.test",
				Pins: []string{validPin()},
			}},
		"sec-legacy": {Prefixes: []string{"10.1.2.3"}, Key: "xfr-key-2026"},
	}}
	broken := conf.ValidatePeers()
	if len(broken) != 0 {
		t.Fatalf("test peers should validate: %v", broken)
	}
	conf.Internal.BrokenPeers = broken
	return conf
}

func TestPeers_ExpandUpstreams(t *testing.T) {
	conf := peersTestConf(t)
	zc := ZoneConf{
		Name: "pulled.example.",
		Primaries: []PeerConf{
			{PeersRef: []string{"ns1"}},
			{Addr: "203.0.113.5:53", Key: NOKEY}, // inline survives untouched
		},
	}
	if err := conf.expandPeerRefs(&zc, conf.Internal.BrokenPeers); err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(zc.Primaries) != 2 {
		t.Fatalf("want 2 upstreams, got %+v", zc.Primaries)
	}
	up := zc.Primaries[0]
	if up.Addr != "ns1.test:853" || up.Key != NOKEY || up.Transport != "dot" || up.TLSAuth != "dane" {
		t.Fatalf("expanded upstream wrong: %+v", up)
	}
	if len(up.PeersRef) != 0 {
		t.Fatal("expanded entry must not keep the reference")
	}
	if zc.Primaries[1].Addr != "203.0.113.5:53" {
		t.Fatalf("inline entry disturbed: %+v", zc.Primaries[1])
	}
}

func TestPeers_ExpandDownstreamsCrossProduct(t *testing.T) {
	conf := peersTestConf(t)
	zc := ZoneConf{
		Name: "served.example.",
		Downstreams: []AclEntry{
			{PeersRef: []string{"sec1", "sec-legacy"}},
			{Prefix: "192.0.2.0/24", Key: NOKEY},
		},
	}
	if err := conf.expandPeerRefs(&zc, conf.Internal.BrokenPeers); err != nil {
		t.Fatalf("expand: %v", err)
	}
	// sec1: 2 prefixes x 2 keys = 4 entries; sec-legacy: 1x1; inline: 1.
	if len(zc.Downstreams) != 6 {
		t.Fatalf("want 6 entries (4+1+1), got %d: %+v", len(zc.Downstreams), zc.Downstreams)
	}
	// The sec1 entries carry identity + name; all 4 combinations exist.
	seen := map[string]bool{}
	for _, e := range zc.Downstreams[:4] {
		if e.PeerName != "sec1" || e.TLSIdentity == nil || e.TLSIdentity.Name != "sec1.test" {
			t.Fatalf("sec1 entry lost identity: %+v", e)
		}
		seen[e.Prefix+"/"+e.Key] = true
	}
	for _, want := range []string{
		"198.51.100.7/xfr-key-2026", "198.51.100.7/xfr-key-2025",
		"2001:db8::7/xfr-key-2026", "2001:db8::7/xfr-key-2025",
	} {
		if !seen[want] {
			t.Fatalf("missing cross-product entry %s (have %v)", want, seen)
		}
	}
	if e := zc.Downstreams[4]; e.PeerName != "sec-legacy" || e.TLSIdentity != nil {
		t.Fatalf("sec-legacy entry wrong: %+v", e)
	}
	if e := zc.Downstreams[5]; e.Prefix != "192.0.2.0/24" || e.PeerName != "" {
		t.Fatalf("inline entry disturbed: %+v", e)
	}
}

func TestPeers_ExpandAllowNotifyDropsIdentity(t *testing.T) {
	conf := peersTestConf(t)
	zc := ZoneConf{
		Name:        "pulled.example.",
		AllowNotify: []AclEntry{{PeersRef: []string{"sec1"}}},
	}
	if err := conf.expandPeerRefs(&zc, conf.Internal.BrokenPeers); err != nil {
		t.Fatalf("expand: %v", err)
	}
	for _, e := range zc.AllowNotify {
		if e.TLSIdentity != nil {
			t.Fatalf("allow-notify must not carry tls-identity: %+v", e)
		}
	}
}

func TestPeers_ExpandErrors(t *testing.T) {
	conf := peersTestConf(t)
	broken := map[string]string{"bad1": "no TSIG key"}

	// Unknown id.
	zc := ZoneConf{Primaries: []PeerConf{{PeersRef: []string{"nope"}}}}
	if err := conf.expandPeerRefs(&zc, broken); err == nil || !strings.Contains(err.Error(), "unknown peer") {
		t.Fatalf("want unknown-peer error, got %v", err)
	}
	// Broken peer.
	zc = ZoneConf{Primaries: []PeerConf{{PeersRef: []string{"bad1"}}}}
	if err := conf.expandPeerRefs(&zc, broken); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("want broken-peer error, got %v", err)
	}
	// Mixed reference + inline fields.
	zc = ZoneConf{Primaries: []PeerConf{{PeersRef: []string{"ns1"}, Addr: "192.0.2.1:53"}}}
	if err := conf.expandPeerRefs(&zc, nil); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("want mixed-entry error, got %v", err)
	}
	// No-addr peer used as upstream.
	zc = ZoneConf{Primaries: []PeerConf{{PeersRef: []string{"sec-legacy"}}}}
	if err := conf.expandPeerRefs(&zc, nil); err == nil || !strings.Contains(err.Error(), "no addr") {
		t.Fatalf("want no-addr error, got %v", err)
	}
	// No-prefix peer used as downstream (ns1 has a hostname addr, no prefixes).
	zc = ZoneConf{Downstreams: []AclEntry{{PeersRef: []string{"ns1"}}}}
	if err := conf.expandPeerRefs(&zc, nil); err == nil || !strings.Contains(err.Error(), "no prefixes") {
		t.Fatalf("want no-prefix error, got %v", err)
	}
}

func TestPeers_NormalizeXfrAliases(t *testing.T) {
	cm := map[string]interface{}{
		"zones": []interface{}{
			map[string]interface{}{ // alias renamed
				"name":      "a.example.",
				"upstreams": []interface{}{"x"},
			},
			map[string]interface{}{ // NSD pair
				"name":        "b.example.",
				"request-xfr": []interface{}{"x"},
				"provide-xfr": []interface{}{"y"},
			},
			map[string]interface{}{ // conflict: canonical + alias
				"name":      "c.example.",
				"primaries": []interface{}{"x"},
				"upstreams": []interface{}{"y"},
			},
			map[string]interface{}{ // untouched canonical
				"name":        "d.example.",
				"downstreams": []interface{}{"y"},
			},
		},
		"templates": []interface{}{
			map[string]interface{}{
				"name":        "t1",
				"secondaries": []interface{}{"y"},
			},
		},
	}
	conflicts := NormalizeXfrAliases(cm)

	zones := cm["zones"].([]interface{})
	za := zones[0].(map[string]interface{})
	if _, ok := za["primaries"]; !ok {
		t.Fatal("upstreams not renamed to primaries")
	}
	if _, ok := za["upstreams"]; ok {
		t.Fatal("alias key not removed")
	}
	zb := zones[1].(map[string]interface{})
	if _, ok := zb["primaries"]; !ok {
		t.Fatal("request-xfr not renamed")
	}
	if _, ok := zb["downstreams"]; !ok {
		t.Fatal("provide-xfr not renamed")
	}
	if _, ok := conflicts["c.example."]; !ok {
		t.Fatalf("conflict not recorded: %v", conflicts)
	}
	tm := cm["templates"].([]interface{})[0].(map[string]interface{})
	if _, ok := tm["downstreams"]; !ok {
		t.Fatal("template secondaries not renamed")
	}
	if got := aliasConflictFor(conflicts, "c.example."); got == "" {
		t.Fatal("aliasConflictFor miss")
	}
	if got := aliasConflictFor(conflicts, "d.example."); got != "" {
		t.Fatalf("false conflict: %q", got)
	}
}
