/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package transport

import (
	core "github.com/johanix/tdns/v2/core"
)

// PlainDo53 reports whether transport is plain Do53 (UDP, with query-time TCP
// fallback) or explicit Do53-over-TCP. Zone transfers use miekg dns.Transfer,
// which always dials TCP regardless; both labels are valid for AXFR/IXFR.
func PlainDo53(s string) bool {
	t, err := core.StringToTransport(s)
	if err != nil {
		return false
	}
	return t == core.TransportDo53 || t == core.TransportDo53TCP
}
