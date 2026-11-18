/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import "testing"

// AuthDNSQuery added port 53 to a server address that did not end in ":53".
// An address with another port came out as "[127.0.0.1:5300]:53", which cannot
// be dialled; a bare IPv6 address ending in ":53" was taken for one with a port
// and was dialled without it; an address under three bytes long panicked.
func TestAuthServerAddr(t *testing.T) {
	cases := []struct{ ns, want string }{
		{"192.0.2.1", "192.0.2.1:53"},
		{"192.0.2.1:53", "192.0.2.1:53"},
		{"192.0.2.1:5300", "192.0.2.1:5300"},
		{"2001:db8::1", "[2001:db8::1]:53"},
		{"fd00::53", "[fd00::53]:53"},
		{"[2001:db8::1]:53", "[2001:db8::1]:53"},
		{"[2001:db8::1]:5300", "[2001:db8::1]:5300"},
		{"ns.example.", "ns.example.:53"},
		{"ns.example.:5300", "ns.example.:5300"},
		{"", ":53"},
		{"a", "a:53"},
	}
	for _, c := range cases {
		if got := authServerAddr(c.ns); got != c.want {
			t.Errorf("authServerAddr(%q) = %q, want %q", c.ns, got, c.want)
		}
	}
}
