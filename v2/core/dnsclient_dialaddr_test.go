/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import "testing"

// A signal port arrives already joined. The client's own port must not be
// joined on again, and a bare address — v4 or v6 — still gets the default.
func TestDialAddr(t *testing.T) {
	for _, tc := range []struct{ server, port, want string }{
		{"192.0.2.1", "53", "192.0.2.1:53"},
		{"192.0.2.1", "853", "192.0.2.1:853"},
		{"192.0.2.1:1234", "853", "192.0.2.1:1234"},
		{"2001:db8::1", "853", "[2001:db8::1]:853"},
		{"2001:db8::1", "443", "[2001:db8::1]:443"},
		{"[2001:db8::1]:1234", "853", "[2001:db8::1]:1234"},
	} {
		if got := dialAddr(tc.server, tc.port); got != tc.want {
			t.Errorf("dialAddr(%q, %q) = %q, want %q", tc.server, tc.port, got, tc.want)
		}
	}
}
