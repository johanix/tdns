package tdns

import (
	"net"
	"testing"
)

func aclIP(s string) net.IP { return net.ParseIP(s) }

func TestIpSpecMatch(t *testing.T) {
	cases := []struct {
		spec string
		ip   string
		want bool
	}{
		{"192.0.2.1", "192.0.2.1", true},
		{"192.0.2.1", "192.0.2.2", false},
		{"192.0.2.0/24", "192.0.2.55", true},
		{"192.0.2.0/24", "192.0.3.1", false},
		{"192.0.2.0&255.255.255.0", "192.0.2.99", true},
		{"192.0.2.0&255.255.255.0", "192.0.3.99", false},
		{"192.0.2.10-192.0.2.20", "192.0.2.15", true},
		{"192.0.2.10-192.0.2.20", "192.0.2.10", true}, // lo boundary
		{"192.0.2.10-192.0.2.20", "192.0.2.20", true}, // hi boundary
		{"192.0.2.10-192.0.2.20", "192.0.2.21", false},
		{"192.0.2.10-192.0.2.20", "192.0.2.9", false},
		{"0.0.0.0/0", "203.0.113.7", true},
		{"::/0", "2001:db8::1", true},
		{"2001:db8::/32", "2001:db8:1::5", true},
		{"2001:db8::/32", "2001:db9::5", false},
		{"not-an-ip", "192.0.2.1", false}, // malformed -> false
	}
	for _, c := range cases {
		if got := ipSpecMatch(c.spec, aclIP(c.ip)); got != c.want {
			t.Errorf("ipSpecMatch(%q, %q) = %v, want %v", c.spec, c.ip, got, c.want)
		}
	}
}

func TestMatchACL(t *testing.T) {
	if ok, _ := matchACL(nil, aclIP("192.0.2.1")); ok {
		t.Error("empty ACL should deny")
	}
	acl := []AclEntry{
		{Prefix: "192.0.2.5", Key: BLOCKED},           // deny this host
		{Prefix: "192.0.2.0/24", Key: "transfer-key"}, // allow the /24 with key
		{Prefix: "0.0.0.0/0", Key: NOKEY},             // catch-all, unsigned
	}
	if ok, _ := matchACL(acl, aclIP("192.0.2.5")); ok {
		t.Error("BLOCKED entry should deny 192.0.2.5")
	}
	if ok, k := matchACL(acl, aclIP("192.0.2.9")); !ok || k != "transfer-key" {
		t.Errorf("192.0.2.9: got ok=%v key=%q, want true/transfer-key", ok, k)
	}
	if ok, k := matchACL(acl, aclIP("203.0.113.1")); !ok || k != NOKEY {
		t.Errorf("203.0.113.1: got ok=%v key=%q, want true/NOKEY", ok, k)
	}
}

func TestMatchACL_BlockedSupersedesLaterOrder(t *testing.T) {
	acl := []AclEntry{
		{Prefix: "192.0.2.0/24", Key: "k"},
		{Prefix: "192.0.2.5", Key: BLOCKED}, // listed after the allow, still supersedes
	}
	if ok, _ := matchACL(acl, aclIP("192.0.2.5")); ok {
		t.Error("BLOCKED should supersede a preceding allow")
	}
	if ok, k := matchACL(acl, aclIP("192.0.2.6")); !ok || k != "k" {
		t.Errorf("192.0.2.6 should be allowed with k, got ok=%v key=%q", ok, k)
	}
}

func TestValidateACL(t *testing.T) {
	defined := func(name string) bool { return name == NOKEY || name == "good" }
	good := []AclEntry{
		{Prefix: "192.0.2.0/24", Key: "good"},
		{Prefix: "10.0.0.0&255.0.0.0", Key: NOKEY},
		{Prefix: "0.0.0.0/0", Key: BLOCKED},
	}
	if err := ValidateACL(good, defined); err != nil {
		t.Errorf("valid ACL rejected: %v", err)
	}
	if err := ValidateACL([]AclEntry{{Prefix: "garbage", Key: NOKEY}}, defined); err == nil {
		t.Error("bad prefix accepted")
	}
	if err := ValidateACL([]AclEntry{{Prefix: "192.0.2.1", Key: "undefined"}}, defined); err == nil {
		t.Error("unknown key accepted")
	}
}

func TestLoadTsigKeys_BlockedReserved(t *testing.T) {
	conf := &Config{}
	conf.Keys.Tsig = []TsigDetails{{Name: "BLOCKED", Algorithm: "hmac-sha256", Secret: "S"}}
	if err := conf.LoadTsigKeys(); err == nil {
		t.Error("a key named BLOCKED should be rejected")
	}
	if conf.Internal.TsigKeyStore.Has("BLOCKED") {
		t.Error("BLOCKED key should not be stored")
	}
}
