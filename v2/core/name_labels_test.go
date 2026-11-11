/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import "testing"

func TestTrimLeadingLabels(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
		want string
	}{
		{"_dns.ns1.example.", 1, "ns1.example."},
		{"_853._udp.ns1.example.", 2, "ns1.example."},
		// What is left keeps the spelling it had.
		{"_DNS.Ns1.Example.", 1, "Ns1.Example."},
		// An escaped prefix is one label, however many bytes spell it.
		{`\_dns.ns1.example.`, 1, "ns1.example."},
		{`\095dns.ns1.example.`, 1, "ns1.example."},
		// A dot inside a label does not end it; a backslash escaped before a
		// dot does not escape the dot.
		{`a\.b.ns1.example.`, 1, "ns1.example."},
		{`a\\.ns1.example.`, 1, "ns1.example."},
		{"ns1.example.", 0, "ns1.example."},
		{"_dns.", 1, ""},
		{"example.", 2, ""},
		{".", 1, ""},
	} {
		if got := TrimLeadingLabels(tc.name, tc.n); got != tc.want {
			t.Errorf("TrimLeadingLabels(%q, %d) = %q, want %q", tc.name, tc.n, got, tc.want)
		}
	}
}
