/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import "testing"

// TestParseServerAddressForms pins down what @<server> means for every form
// dig and kdig accept. The bare-IPv6 rows are #441: url.URL.Port() splits at
// the last colon, so "2001:db8::5" used to yield port "5" -- the query went
// to the right address on an invented port, and the only symptom was
// "connection refused".
func TestParseServerAddressForms(t *testing.T) {
	tests := []struct {
		arg       string
		server    string
		port      string // "" = unset, so the caller applies the transport default
		transport string
	}{
		{arg: "::1", server: "::1", transport: "Do53"},
		{arg: "2001:db8::5", server: "2001:db8::5", transport: "Do53"},
		{arg: "[::1]", server: "::1", transport: "Do53"},
		{arg: "[2001:db8::5]:5354", server: "2001:db8::5", port: "5354", transport: "Do53"},
		{arg: "192.0.2.5", server: "192.0.2.5", transport: "Do53"},
		{arg: "192.0.2.5:5354", server: "192.0.2.5", port: "5354", transport: "Do53"},
		{arg: "ns.example.com", server: "ns.example.com", transport: "Do53"},
		{arg: "ns.example.com:5354", server: "ns.example.com", port: "5354", transport: "Do53"},
		{arg: "tls://192.0.2.5", server: "192.0.2.5", transport: "DoT"},
		{arg: "tls://[2001:db8::5]:8853", server: "2001:db8::5", port: "8853", transport: "DoT"},
		// Scheme'd bare IPv6. url.Parse takes a numeric last hextet as a
		// port and rejects a hex one outright, so both halves need
		// handling: the first row parsed to port "5", the second failed
		// with an "invalid port" the user never typed.
		{arg: "tls://2001:db8::5", server: "2001:db8::5", transport: "DoT"},
		{arg: "tls://2001:db8::beef", server: "2001:db8::beef", transport: "DoT"},
		{arg: "quic://::1", server: "::1", transport: "DoQ"},
		{arg: "2001:db8::beef", server: "2001:db8::beef", transport: "Do53"},
	}

	for _, tc := range tests {
		t.Run(tc.arg, func(t *testing.T) {
			opts, err := ParseServer(tc.arg, map[string]string{})
			if err != nil {
				t.Fatalf("ParseServer(%q) returned error: %v", tc.arg, err)
			}
			if opts["server"] != tc.server {
				t.Errorf("server = %q, want %q", opts["server"], tc.server)
			}
			if opts["port"] != tc.port {
				t.Errorf("port = %q, want %q", opts["port"], tc.port)
			}
			if opts["transport"] != tc.transport {
				t.Errorf("transport = %q, want %q", opts["transport"], tc.transport)
			}
		})
	}
}

// TestParseServerRejectsGarbage keeps the error paths honest: a malformed
// address must fail loudly rather than resolve to something dialable.
func TestParseServerRejectsGarbage(t *testing.T) {
	for _, arg := range []string{"[not:an:ip]", "ns.example.com:53:54", "ftp://192.0.2.5"} {
		if opts, err := ParseServer(arg, map[string]string{}); err == nil {
			t.Errorf("ParseServer(%q) accepted it: %v", arg, opts)
		}
	}
}
