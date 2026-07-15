/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package transport

import "testing"

func TestPlainDo53(t *testing.T) {
	yes := []string{"Do53", "do53", "Do53-TCP", "do53-tcp", "tcp", "TCP"}
	for _, s := range yes {
		if !PlainDo53(s) {
			t.Errorf("PlainDo53(%q) = false, want true", s)
		}
	}
	no := []string{"DoT", "DoH", "DoQ", "dot", "quic", ""}
	for _, s := range no {
		if PlainDo53(s) {
			t.Errorf("PlainDo53(%q) = true, want false", s)
		}
	}
}
