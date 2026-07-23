package tdns

import (
	"net/netip"
	"strings"
	"testing"
)

func aclIP(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestIpSpecMatch(t *testing.T) {
	cases := []struct {
		spec string
		ip   string
		want bool
	}{
		{"192.0.2.1/32", "192.0.2.1", true},  // single host, explicit mask
		{"192.0.2.1/32", "192.0.2.2", false}, // ...only that host
		{"192.0.2.1", "192.0.2.1", false},    // bare IP is no longer a valid spec -> never matches
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
		{Prefix: "192.0.2.5/32", Key: BLOCKED},        // deny this host
		{Prefix: "192.0.2.0/24", Key: "transfer-key"}, // allow the /24 with key
		{Prefix: "0.0.0.0/0", Key: NOKEY},             // catch-all, unsigned
	}
	if ok, _ := matchACL(acl, aclIP("192.0.2.5")); ok {
		t.Error("BLOCKED entry should deny 192.0.2.5")
	}
	// 192.0.2.9 matches the /24 (transfer-key) AND the catch-all (NOKEY): the source
	// is approved for BOTH (union of matching entries), not just the first.
	if ok, keys := matchACL(acl, aclIP("192.0.2.9")); !ok || !keysContain(keys, "transfer-key") || !keysContain(keys, NOKEY) {
		t.Errorf("192.0.2.9: got ok=%v keys=%v, want both transfer-key and NOKEY", ok, keys)
	}
	if ok, keys := matchACL(acl, aclIP("203.0.113.1")); !ok || !keysContain(keys, NOKEY) {
		t.Errorf("203.0.113.1: got ok=%v keys=%v, want NOKEY", ok, keys)
	}
}

func keysContain(keys []string, want string) bool {
	for _, k := range keys {
		if k == want {
			return true
		}
	}
	return false
}

// Two entries for the same source naming different keys (the rotation overlap):
// the source is approved for BOTH, so the server accepts either.
func TestMatchACL_DualKey(t *testing.T) {
	acl := []AclEntry{
		{Prefix: "192.0.2.0/24", Key: "oldkey"},
		{Prefix: "192.0.2.0/24", Key: "newkey"},
	}
	ok, keys := matchACL(acl, aclIP("192.0.2.10"))
	if !ok || !keysContain(keys, "oldkey") || !keysContain(keys, "newkey") {
		t.Errorf("dual-key: got ok=%v keys=%v, want both oldkey and newkey", ok, keys)
	}
}

func TestMatchACL_BlockedSupersedesLaterOrder(t *testing.T) {
	acl := []AclEntry{
		{Prefix: "192.0.2.0/24", Key: "k"},
		{Prefix: "192.0.2.5/32", Key: BLOCKED}, // listed after the allow, still supersedes
	}
	if ok, _ := matchACL(acl, aclIP("192.0.2.5")); ok {
		t.Error("BLOCKED should supersede a preceding allow")
	}
	if ok, keys := matchACL(acl, aclIP("192.0.2.6")); !ok || !keysContain(keys, "k") {
		t.Errorf("192.0.2.6 should be allowed with k, got ok=%v keys=%v", ok, keys)
	}
}

func TestValidateIPSpec_MixedFamilyMask(t *testing.T) {
	for _, s := range []string{"2001:db8::&255.255.255.0", "192.0.2.1&ffff:ffff::"} {
		if err := ValidateIPSpec(s); err == nil {
			t.Errorf("ValidateIPSpec(%q) = nil, want error (mixed IPv4/IPv6 mask)", s)
		}
	}
	// A same-family mask still parses.
	if err := ValidateIPSpec("192.0.2.0&255.255.255.0"); err != nil {
		t.Errorf("same-family mask rejected: %v", err)
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
	if err := ValidateACL([]AclEntry{{Prefix: "192.0.2.1/32", Key: "undefined"}}, defined); err == nil {
		t.Error("unknown key accepted")
	}
}

// TestParseIPSpec_RejectsBareAddress is the enforcement side of the deliberate
// breaking change: a bare IP (no explicit boundary) is rejected, but an explicit
// /32 or /128 — and the other spec forms — are still accepted.
func TestParseIPSpec_RejectsBareAddress(t *testing.T) {
	for _, spec := range []string{"192.0.2.7", "2001:db8::1"} {
		err := ValidateIPSpec(spec)
		if err == nil {
			t.Errorf("ValidateIPSpec(%q) = nil, want a bare-address rejection", spec)
			continue
		}
		if !strings.Contains(err.Error(), "explicit prefix length") {
			t.Errorf("ValidateIPSpec(%q) error = %q, want it to mention an explicit prefix length", spec, err)
		}
	}
	// The error suggests the family-correct mask (/32 for v4, /128 for v6).
	if err := ValidateIPSpec("192.0.2.7"); err == nil || !strings.Contains(err.Error(), "192.0.2.7/32") {
		t.Errorf("v4 bare address should suggest /32, got %v", err)
	}
	if err := ValidateIPSpec("2001:db8::1"); err == nil || !strings.Contains(err.Error(), "2001:db8::1/128") {
		t.Errorf("v6 bare address should suggest /128, got %v", err)
	}
	// Explicit single-host masks and the other boundary forms still parse.
	for _, spec := range []string{"192.0.2.7/32", "2001:db8::1/128", "192.0.2.0/24", "192.0.2.0&255.255.255.0", "192.0.2.10-192.0.2.20"} {
		if err := ValidateIPSpec(spec); err != nil {
			t.Errorf("ValidateIPSpec(%q) = %v, want accepted", spec, err)
		}
	}
	// A no-boundary token that isn't an address at all keeps the "bad ip-spec"
	// parse error — distinct from the bare-address rejection above. ("not-an-ip"
	// would route to the range branch via its hyphen, so use a separator-free token.)
	if err := ValidateIPSpec("garbage"); err == nil || !strings.Contains(err.Error(), "bad ip-spec") {
		t.Errorf(`ValidateIPSpec("garbage") = %v, want "bad ip-spec" error`, err)
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
