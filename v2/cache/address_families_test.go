/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

// A stub server whose configured addresses are all of a family not in use
// cannot be queried, and AddStub says so; one that keeps some says only that
// the others are left out.
func TestAddStubSaysWhenAServerLosesEveryAddress(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	for _, tc := range []struct {
		name              string
		addrs             []string
		unusable, partial bool
	}{
		{"IPv6 only", []string{"2001:db8::53"}, true, false},
		{"both", []string{"192.0.2.53", "2001:db8::53"}, false, true},
		{"IPv4 only", []string{"192.0.2.53"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf.Reset()
			rrcache := NewRRsetCache(log.Default(), false, false)
			rrcache.SetAddressFamilies(true, false)
			if err := rrcache.AddStub("stub.test.", []AuthServer{{Name: "ns.stub.test.", Addrs: tc.addrs}}); err != nil {
				t.Fatalf("AddStub: %v", err)
			}
			out := buf.String()
			if got := strings.Contains(out, "cannot be queried"); got != tc.unusable {
				t.Errorf("unusable warning: %v, want %v; log: %q", got, tc.unusable, out)
			}
			if got := strings.Contains(out, "are left out"); got != tc.partial {
				t.Errorf("partial note: %v, want %v; log: %q", got, tc.partial, out)
			}
		})
	}
}
