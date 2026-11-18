/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package imr

// ImrOptions is what NewImr takes besides the imrengine: configuration. They
// are the few things a resolver reads from outside it, so that an application
// can build one without a Config. The zero value is a resolver with no large
// DNSSEC algorithms, the default DNSKEY transport, nowhere to report server
// errors, and no own zones.
type ImrOptions struct {
	// LargeAlgorithms is the set of DNSSEC algorithms whose DNSKEYs and
	// signatures are too large for a UDP response. RefreshDnssecPolicy replaces
	// it on a live resolver.
	LargeAlgorithms map[uint8]bool
	// DNSKEYTransport is the transport policy for DNSKEY queries.
	DNSKEYTransport DNSKEYTransportPolicy
	// Errors is where the resolver reports the server-wide error conditions it
	// owns. Nil is a sink that drops them.
	Errors ErrorSink
	// PendingOwnZone reports whether zone is one this server is to answer from
	// but does not yet. Trust-anchor set-up asks it, and does not fetch the keys
	// of such a zone. Nil is a server that has no zones of its own.
	PendingOwnZone func(zone string) bool
	// OwnZones is the zones of the server the resolver runs in: questions
	// about them are answered from them, in process (imr_own_zone.go). Nil
	// is a server that has no zones of its own.
	OwnZones OwnZones
	// Quiet suppresses informational logging (useful for CLI tools).
	Quiet bool
}

// ErrorSink is where a resolver reports the server-wide error conditions it
// owns: the forward table's quarantine and its upstreams' reachability.
// *ServerErrorRegistry is one.
type ErrorSink interface {
	SetImrForwardZoneError(msg string)
	ClearImrForwardZoneError()
	SetImrForwardUpstreamError(msg string)
	ClearImrForwardUpstreamError()
	SetImrForwardUpstreamConfigError(msg string)
	ClearImrForwardUpstreamConfigError()
	// List returns the conditions that are set.
	List() []ServerError
}

// noErrorSink is the ErrorSink that drops everything.
type noErrorSink struct{}

func (noErrorSink) SetImrForwardZoneError(string)           {}
func (noErrorSink) ClearImrForwardZoneError()               {}
func (noErrorSink) SetImrForwardUpstreamError(string)       {}
func (noErrorSink) ClearImrForwardUpstreamError()           {}
func (noErrorSink) SetImrForwardUpstreamConfigError(string) {}
func (noErrorSink) ClearImrForwardUpstreamConfigError()     {}
func (noErrorSink) List() []ServerError                     { return nil }
