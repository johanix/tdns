/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// truncatingResponseWriter truncates oversized UDP responses to the client's
// advertised EDNS buffer size (RFC 6891) before delegating to the inner writer.
// Only WriteMsg is overridden; every other dns.ResponseWriter method is promoted
// from the embedded writer unchanged.
type truncatingResponseWriter struct {
	dns.ResponseWriter
	udp     bool
	bufsize uint16
}

func (w *truncatingResponseWriter) WriteMsg(m *dns.Msg) error {
	if w.udp && m.Len() > int(w.bufsize) {
		m.Truncate(int(w.bufsize))
	}
	return w.ResponseWriter.WriteMsg(m)
}

// udpTruncate wraps next so Do53-over-UDP responses that exceed the requester's
// advertised EDNS UDP payload size are truncated and marked TC. TCP (and any
// non-UDP transport on this mux) passes responses through unchanged.
//
// Install only on the Do53 mux — not on createAuthDnsHandler, which is also
// used unwrapped by DoH and DoQ (QUIC must never be truncated).
func udpTruncate(next func(dns.ResponseWriter, *dns.Msg)) func(dns.ResponseWriter, *dns.Msg) {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		// Defensive: a nil RemoteAddr should never happen for a real Do53
		// request, but treat "unknown transport" as non-UDP and never truncate
		// rather than panic (a panic here would only reach the handler's
		// recover() as a SERVFAIL).
		udp := false
		if ra := w.RemoteAddr(); ra != nil {
			udp = ra.Network() == "udp"
		}
		w = &truncatingResponseWriter{
			ResponseWriter: w,
			udp:            udp,
			bufsize:        edns0.RequestUDPSize(r),
		}
		next(w, r)
	}
}
