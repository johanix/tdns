/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package imr

import (
	"context"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Entry points into the resolver's transport-signal handling and trust-anchor
// set-up, for tdns's tests that drive the resolver together with the daemon:
// what the daemon's signal publisher or a hosted zone produces, read by the
// resolver as it would read it from the wire. Nothing in the resolver or the
// daemon calls them.

// ApplyTransportSignal applies the signal kvMap (token to weight) to server,
// as a received oots signal is applied. It reports whether the signal named a
// transport the resolver uses.
func ApplyTransportSignal(server *cache.AuthServer, kvMap map[string]uint8) bool {
	return applyTransportMapToServer(server, kvMap)
}

// InstallTransportSignal is ApplyTransportSignal with the ports and targets a
// signal assigned, where it arrived and the validation state of its path.
func InstallTransportSignal(server *cache.AuthServer, kvMap map[string]uint8, ports map[core.Transport]uint16,
	targets map[core.Transport]string, via string, path []cache.SignalHop) bool {
	return installTransportMap(server, kvMap, ports, targets, via, path)
}

// TransportSignalFromAdditional reads server's transport signal from the
// Additional section of r, as from a referral or an answer.
func (imr *Imr) TransportSignalFromAdditional(ctx context.Context, server *cache.AuthServer, r *dns.Msg) {
	imr.parseTransportForServerFromAdditional(ctx, server, r)
}

// InstallSVCBSignal installs the transport signal the SVCB records svcbs carry
// for server, as a signal looked up at server's _dns name is installed. It
// reports whether one was.
func (imr *Imr) InstallSVCBSignal(server *cache.AuthServer, svcbs []*dns.SVCB) bool {
	pending := map[string]*svcbSignalSet{}
	for _, svcb := range svcbs {
		imr.collectSVCBSignal(pending, server.Name, svcb)
	}
	installed, _ := imr.installSVCBSignal(server, pending[cache.ServerKey(server.Name)])
	return installed
}

// SetUpTrustAnchors runs the trust-anchor set-up Start runs in the
// background, for the anchors in ic, and returns its error.
func (imr *Imr) SetUpTrustAnchors(ctx context.Context, ic Config) error {
	return imr.initializeImrTrustAnchors(ctx, ic)
}

// TransportSignalFromAnswer applies the transport signal in rrset, the answer
// to a signal lookup at owner validated as vstate, to the servers it is for.
func (imr *Imr) TransportSignalFromAnswer(owner string, rrset *core.RRset, vstate cache.ValidationState) {
	imr.applyTransportRRsetFromAnswer(owner, rrset, vstate)
}
