/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import "github.com/miekg/dns"

// requestWire returns the request exactly as the transport received it, or
// nil when no writer in the chain kept it. It looks through tdns's own
// ResponseWriter wrappers (Unwrap), as connectionState does.
//
// A SIG(0) signature (RFC 2931) covers the request as sent, so it must be
// verified over these bytes. Packing the parsed message again gives different
// bytes whenever the sender compressed names differently, as BIND's nsupdate
// does, and the signature then fails.
//
// The Do53 and DoT servers keep the bytes of a request that ends in a SIG RR
// (dns.RawRequester in the johanix/dns fork). The DoH and DoQ writers keep
// every request they unpacked.
func requestWire(w dns.ResponseWriter) []byte {
	for w != nil {
		if rr, ok := w.(interface{ RawRequest() []byte }); ok {
			return rr.RawRequest()
		}
		u, ok := w.(interface{ Unwrap() dns.ResponseWriter })
		if !ok {
			return nil
		}
		w = u.Unwrap()
	}
	return nil
}
