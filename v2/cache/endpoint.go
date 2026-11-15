/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"strconv"

	"github.com/miekg/dns"

	core "github.com/johanix/tdns/v2/core"
)

// Endpoint is where one transport of a nameserver is reached: a name and a
// port (docs/2026-11-14-transport-signal-alternative-endpoint.md, section 2).
// Target is "" for the nameserver itself, the name whose _dns. label owns the
// signal record (TargetName "."), and otherwise the name whose addresses the
// transport is sent to. Port 0 is the transport's default port at that name
// (853 for DoT and DoQ, 443 for DoH).
//
// A Target is stored only from a record whose whole path validated Secure
// (R1, R5); the resolver decides that before it installs the signal. Do53
// gets no endpoint: cleartext stays at the nameserver's own name on port 53
// until it gets transports of its own.
type Endpoint struct {
	Target string
	Port   uint16
}

// IsDefault reports whether ep is the transport's default endpoint: the
// nameserver's own name at the usual port.
func (ep Endpoint) IsDefault() bool {
	return ep.Target == "" && ep.Port == 0
}

// String renders ep as "target:port", with "." for the nameserver itself and
// no port for the default one.
func (ep Endpoint) String() string {
	target := ep.Target
	if target == "" {
		target = "."
	}
	if ep.Port == 0 {
		return target
	}
	return target + ":" + strconv.Itoa(int(ep.Port))
}

// endpointTransport reports whether t can be given an endpoint. Do53 cannot:
// a signal does not move cleartext off the nameserver's own name and port 53.
func endpointTransport(t core.Transport) bool {
	return t != core.TransportDo53 && t != core.TransportDo53TCP
}

// endpointsFromReceived is the endpoints a signal assigns: its ports and its
// targets, by transport. Nil when it assigns none, so installing it clears
// the previous endpoints.
func endpointsFromReceived(received *ReceivedSignal) map[core.Transport]Endpoint {
	if received == nil {
		return nil
	}
	var out map[core.Transport]Endpoint
	set := func(t core.Transport, f func(*Endpoint)) {
		if !endpointTransport(t) {
			return
		}
		if out == nil {
			out = map[core.Transport]Endpoint{}
		}
		ep := out[t]
		f(&ep)
		out[t] = ep
	}
	for t, p := range DialPorts(received.Ports) {
		set(t, func(ep *Endpoint) { ep.Port = p })
	}
	for t, target := range received.Targets {
		if target == "" || target == "." {
			continue
		}
		set(t, func(ep *Endpoint) { ep.Target = dns.Fqdn(target) })
	}
	return out
}

// GetTransportEndpoint returns the endpoint the latest signal assigned to t;
// the zero Endpoint, the default one, when it assigned none. Do53 and Do53TCP
// always get the default. Thread-safe.
func (as *AuthServer) GetTransportEndpoint(t core.Transport) Endpoint {
	if as == nil || !endpointTransport(t) {
		return Endpoint{}
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.TransportEndpoints[t]
}

// GetTransportEndpoints returns a copy of the endpoints the latest signal
// assigned. Thread-safe.
func (as *AuthServer) GetTransportEndpoints() map[core.Transport]Endpoint {
	if as == nil {
		return nil
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	return copyMap(as.TransportEndpoints)
}

// AllowsAddrFamily reports whether addr is of an address family the resolver
// uses (imrengine.outbound-address-families): the test AddAddr applies to the
// server's own addresses, for an address of one of its endpoints.
func (as *AuthServer) AllowsAddrFamily(addr string) bool {
	if as == nil {
		return false
	}
	return as.families.allows(addr)
}

// IncrementRedirectedCounter records that a query's answer was carried by a
// redirected endpoint over t, the actual wire transport.
func (as *AuthServer) IncrementRedirectedCounter(t core.Transport) {
	if as == nil {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.RedirectedCounters == nil {
		as.RedirectedCounters = make(map[core.Transport]uint64)
	}
	as.RedirectedCounters[t]++
}

// AddIgnoredRedirects records n signal records with a target that were
// ignored for want of a Secure path.
func (as *AuthServer) AddIgnoredRedirects(n int) {
	if as == nil || n <= 0 {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	as.IgnoredRedirects += uint64(n)
}
