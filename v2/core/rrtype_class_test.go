/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import (
	"testing"

	"github.com/miekg/dns"
)

// The edges of every RFC 6895 section 3.1 range, and OPT, the one Meta-TYPE
// inside a data range.
func TestRRtypeClasses(t *testing.T) {
	for _, tc := range []struct {
		rrtype         uint16
		meta, reserved bool
	}{
		{0, false, true},
		{1, false, false},
		{40, false, false},
		{dns.TypeOPT, true, false},
		{42, false, false},
		{127, false, false},
		{dns.TypeNXNAME, true, false},
		{dns.TypeANY, true, false},
		{256, false, false},
		{61439, false, false},
		{61440, false, true},
		{65279, false, true},
		{65280, false, false},
		{65534, false, false},
		{65535, false, true},
	} {
		if got := IsMetaType(tc.rrtype); got != tc.meta {
			t.Errorf("IsMetaType(%d) = %v, want %v", tc.rrtype, got, tc.meta)
		}
		if got := IsReservedType(tc.rrtype); got != tc.reserved {
			t.Errorf("IsReservedType(%d) = %v, want %v", tc.rrtype, got, tc.reserved)
		}
	}
}
