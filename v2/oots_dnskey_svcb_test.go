/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The DNSKEY transport is picked from one reading of the server's signal.
// With a signal flipping between doq:0,dot:100 and doq:100,dot:0, both of
// which offer an encrypted transport, force_encrypted always finds one.
// Reading the signal once per transport checked could refuse DoQ under one
// signal and DoT under the next, and find none.
func TestDNSKEYTransportIsPickedFromOneReadingOfTheSignal(t *testing.T) {
	imr := newTestImr(t)
	imr.dnskeyTransport = DNSKEYTransportForceEncrypted
	server := cache.NewAuthServer("ns.flip.example.")
	dotOnly := map[string]uint8{"doq": 0, "dot": 100}
	doqOnly := map[string]uint8{"doq": 100, "dot": 0}
	applyTransportMapToServer(server, dotOnly)
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			if i%2 == 0 {
				applyTransportMapToServer(server, doqOnly)
			} else {
				applyTransportMapToServer(server, dotOnly)
			}
		}
	}()
	defer func() {
		stop.Store(true)
		wg.Wait()
	}()
	deadline := time.Now().Add(time.Second)
	for n := 0; time.Now().Before(deadline); n++ {
		if got := imr.preferredDNSKEYTransport(server); got != core.TransportDoQ && got != core.TransportDoT {
			t.Fatalf("reading %d: transport %d, want DoQ or DoT", n, got)
		}
	}
}

// A DNSKEY attempt for a transport redirected to a target none of whose
// addresses may be used dials nothing, and has no key: another nameserver
// at the same address keeps its own attempt at the default endpoint.
func TestADNSKEYAttemptThatDialsNothingHasNoKey(t *testing.T) {
	imr, server, zone, _ := epLameZoneImr(t)
	imr.dnskeyTransport = DNSKEYTransportForceEncrypted
	redirectTo(server, map[string]uint8{"dot": 100}, core.TransportDoT, 1234)
	imr.endpointAddrs.set(epLameTarget, []string{"192.0.2.53"}, time.Now().Add(time.Hour))
	zone.RecordZoneEndpointFailureForRcode("192.0.2.53", 1234, core.TransportDoT, dns.RcodeRefused, false)
	other := cache.NewAuthServer("ns2." + epLameZone)
	other.AddAddr(epLameNSAddr)
	applyTransportMapToServer(other, map[string]uint8{"dot": 100})
	ctx := context.Background()

	a := imr.resolveDNSKEYAttempt(ctx, server, zone, epLameNSAddr)
	if key, ok := a.key(); ok {
		t.Errorf("an attempt that dials nothing has the key %+v", key)
	}
	if _, ok := a.err.(errEndpointUnavailable); !ok {
		t.Errorf("err %v, want errEndpointUnavailable", a.err)
	}
	if key, ok := imr.resolveDNSKEYAttempt(ctx, other, zone, epLameNSAddr).key(); !ok || key != (cache.AddrXport{Addr: epLameNSAddr, Transport: core.TransportDoT}) {
		t.Errorf("the other nameserver's key %+v %v, want its default DoT endpoint", key, ok)
	}
}

// The DNSKEY bypass does not dial an endpoint that is backed off: forced TCP
// whose signalled port is backed off gives way to port 53, and with port 53
// backed off too no attempt is made.
func TestTheDNSKEYBypassDoesNotDialABackedOffEndpoint(t *testing.T) {
	imr, server, zone, _ := epLameZoneImr(t)
	imr.dnskeyTransport = DNSKEYTransportTryEncrypted
	applyTransportMapWithPorts(server, map[string]uint8{"udp": 100}, map[core.Transport]uint16{core.TransportDo53TCP: 5354})
	tcp := core.NewFakeDNSClient(core.TransportDo53TCP)
	q := new(dns.Msg)
	q.SetQuestion(epLameZone, dns.TypeDNSKEY)
	reply := new(dns.Msg)
	reply.SetReply(q)
	tcp.Set(epLameZone, epLameNSAddr, core.FakeResponse{Msg: reply})
	tcp.Set(epLameZone, epLameNSAddr+":5354", core.FakeResponse{Msg: reply})
	imr.Cache.DNSClient[core.TransportDo53TCP] = tcp
	server.RecordEndpointAddrFailure(epLameNSAddr, 5354, core.TransportDo53TCP, errors.New("i/o timeout"))
	server.RecordEndpointAddrFailure(epLameNSAddr, 0, core.TransportDo53TCP, errors.New("i/o timeout"))

	_, _, _, _, err := imr.tryServer(context.Background(), server, zone, epLameNSAddr, core.TransportDo53, q, epLameZone, dns.TypeDNSKEY, true, cache.ClassNone, attemptSelection{})
	if _, ok := err.(errEndpointUnavailable); !ok {
		t.Errorf("err %v, want errEndpointUnavailable", err)
	}
	if n := len(tcp.Calls()); n != 0 {
		t.Errorf("%d dial(s) to a backed-off endpoint", n)
	}
}

// A record whose mandatory SvcParam names a key tdns does not support is
// ignored whole, oots and ALPN-only records alike, and gives no TLSA. The
// other records of the RRset stay.
func TestARecordWithAnUnsupportedMandatoryKeyIsIgnored(t *testing.T) {
	const owner = "_dns.ns.mandatory.example."
	set := &svcbSignalSet{}
	for _, s := range []string{
		owner + ` 3600 IN SVCB 1 . mandatory=ipv4hint alpn=dot port=1234 ipv4hint=192.0.2.1`,
		owner + ` 3600 IN SVCB 2 . mandatory=key65000 oots="doq:100" key65000=x`,
		owner + ` 3600 IN SVCB 3 . mandatory=port alpn=doh port=4443`,
	} {
		set.add(mustRR(t, s).(*dns.SVCB))
	}
	if len(set.recs) != 0 {
		t.Errorf("oots records %+v, want none", set.recs)
	}
	if len(set.alpn) != 1 || !slices.Equal(set.alpn[0].alpn, []string{"doh"}) || set.alpn[0].port != 4443 {
		t.Errorf("ALPN records %+v, want only the doh one", set.alpn)
	}
	if svcbUsable(set.rrs[0].(*dns.SVCB)) {
		t.Error("a record with an unsupported mandatory key is read for its TLSA")
	}
	if len(set.rrs) != 3 {
		t.Errorf("the set holds %d records of the RRset, want all 3", len(set.rrs))
	}
}

// An ALPN identifier is read as decoded: one that holds a comma is one
// identifier, not two, and gives no transport it only spells.
func TestAnALPNIdentifierWithACommaStaysOne(t *testing.T) {
	rr := &dns.SVCB{
		Hdr:      dns.RR_Header{Name: "_dns.ns.alpn.example.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 3600},
		Priority: 1,
		Target:   ".",
		Value:    []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: []string{"x,dot"}}},
	}
	rec, ok := alpnRecordFromSVCB(rr)
	if ok && slices.Contains(rec.alpn, "dot") {
		t.Errorf("ALPN tokens %v: dot from the identifier x,dot", rec.alpn)
	}
	server := cache.NewAuthServer("ns.alpn.example.")
	set := &svcbSignalSet{}
	set.add(rr)
	newTestImr(t).installSVCBSignal(server, set)
	if w := server.GetTransportWeights(); w[core.TransportDoT] != 0 {
		t.Errorf("weights %v: DoT from the identifier x,dot", w)
	}
}
