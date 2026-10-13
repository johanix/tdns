/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The origination rule for a derived app that registered its app type
// (RegisterOriginationRuleAppType; docs/2026-07-25-secondary-zones-immutable.md,
// Amendment 2; johanix/tdns-mp#144).
//
// Every load and refresh here goes through a running RefreshEngine, with the
// three refreshers a daemon sees: the config refresher that starts a zone's
// first load, the one a NOTIFY builds, and the forced one `config reload-zones`
// queues for every zone. The upstream is a real server on a local port.

// derivedSignerApp stands for a derived app that relays some zones and signs
// others, and has registered for the rule. derivedEditorApp stands for one that
// has not: an app that changes the zones it holds as a secondary. Both are
// outside tdns's own range of app types; nothing else uses them.
const (
	derivedSignerApp AppType = TdnsEsAppTypeMax
	derivedEditorApp AppType = TdnsEsAppTypeMax - 1
)

// asDerivedApp runs the rest of the test as app, with a keystore. The app type
// and the keystore are put back afterwards.
func asDerivedApp(t *testing.T, app AppType) *KeyDB {
	t.Helper()
	authApp(t)
	Globals.App.Type = app
	return Conf.Internal.KeyDB
}

// registerTestOriginationRuleApp registers app for the origination rule for
// the rest of the test only: the registry is process-wide.
func registerTestOriginationRuleApp(t *testing.T, app AppType) {
	t.Helper()
	if originationRuleAppTypes[app] {
		t.Fatalf("app type %d is already registered for the origination rule", app)
	}
	RegisterOriginationRuleAppType(app)
	t.Cleanup(func() { delete(originationRuleAppTypes, app) })
}

// relayUpstream is an upstream whose zone the test replaces while it is
// served: one address, a new version at each publish, as a signer's zone is.
type relayUpstream struct {
	addr string
	cur  atomic.Pointer[ZoneData]
}

// publish makes the upstream serve example. at serial.
func (u *relayUpstream) publish(t *testing.T, serial uint32) {
	t.Helper()
	pzd := &ZoneData{
		ZoneName:    ovZone,
		ZoneStore:   MapZone,
		ZoneType:    Primary,
		Logger:      discardLogger(),
		Ready:       true,
		Status:      ZoneStatusReady,
		Downstreams: []AclEntry{{Prefix: "127.0.0.0/8", Key: NOKEY}},
	}
	if _, _, err := pzd.ReadZoneData(ovUpstreamZone(serial), true); err != nil {
		t.Fatalf("upstream ReadZoneData: %v", err)
	}
	pzd.InstallInitialSnapshot()
	t.Cleanup(pzd.stopPublisher)
	u.cur.Store(pzd)
}

func startRelayUpstream(t *testing.T, serial uint32) *relayUpstream {
	t.Helper()
	u := &relayUpstream{}
	u.publish(t, serial)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		ln.Close()
		t.Fatalf("listen udp on the tcp port: %v", err)
	}
	u.addr = ln.Addr().String()

	srvCtx, srvCancel := context.WithCancel(t.Context())
	mux := dns.NewServeMux()
	mux.HandleFunc(ovZone, func(w dns.ResponseWriter, r *dns.Msg) {
		pzd := u.cur.Load()
		if len(r.Question) == 1 {
			switch r.Question[0].Qtype {
			case dns.TypeAXFR, dns.TypeIXFR:
				_, _ = pzd.ZoneTransferOut(srvCtx, w, r, nil)
				return
			}
		}
		m := new(dns.Msg)
		m.SetReply(r)
		if soa, err := pzd.GetSOA(); err == nil && soa != nil {
			m.Answer = append(m.Answer, soa)
		}
		_ = w.WriteMsg(m)
	})
	var started sync.WaitGroup
	started.Add(2)
	tcpSrv := &dns.Server{Listener: ln, Handler: mux, MsgAcceptFunc: MsgAcceptFunc,
		NotifyStartedFunc: started.Done}
	udpSrv := &dns.Server{PacketConn: pc, Handler: mux, NotifyStartedFunc: started.Done}
	go func() { _ = tcpSrv.ActivateAndServe() }()
	go func() { _ = udpSrv.ActivateAndServe() }()
	t.Cleanup(func() {
		srvCancel()
		_ = tcpSrv.Shutdown()
		_ = udpSrv.Shutdown()
	})
	done := make(chan struct{})
	go func() { started.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the upstream did not start")
	}
	return u
}

// relayedZone is example. in a running RefreshEngine: a secondary of a
// relayUpstream, pre-registered the way ParseZones leaves a zone and loaded by
// the config refresher.
type relayedZone struct {
	zd   *ZoneData
	conf *Config
	up   *relayUpstream
	opts map[ZoneOption]bool
	halt func()
}

// startRelayedZone starts an engine on kdb and loads the zone through it.
// opts are the options its configuration gives it. prepare, when not nil, runs
// on the pre-registered zone before the load, where a derived app attaches
// its refresh callbacks.
func startRelayedZone(t *testing.T, kdb *KeyDB, up *relayUpstream, opts map[ZoneOption]bool,
	prepare func(*ZoneData)) *relayedZone {
	t.Helper()
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 1)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)

	zd := &ZoneData{ZoneName: ovZone, Logger: discardLogger(), FirstZoneLoad: true}
	zd.registerStandardRefreshHooks(conf.Internal.DelegationSyncQ)
	if prepare != nil {
		prepare(zd)
	}
	Zones.Set(ovZone, zd)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); RefreshEngine(ctx, conf) }()
	var once sync.Once
	halt := func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("RefreshEngine did not shut down")
			}
			zd.stopPublisher()
			Zones.Remove(ovZone)
		})
	}
	t.Cleanup(halt)

	z := &relayedZone{zd: zd, conf: conf, up: up, opts: opts, halt: halt}
	conf.Internal.RefreshZoneCh <- z.configRefresher()
	deadline := time.Now().Add(10 * time.Second)
	for {
		zd.mu.Lock()
		first := zd.FirstZoneLoad
		zd.mu.Unlock()
		if !first && zd.publishedSnapshot() != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the zone did not load")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The zone is served before the engine is done with its first load: the
	// recorded serial is settled after the first publish. The engine takes
	// one request at a time and runs a first load inline, so the answer to a
	// second request, here a refresh that finds nothing new, means the first
	// load is over.
	z.notified(t)
	return z
}

// configRefresher is the refresher ParseZones builds from the zone's
// configuration: its options are a fresh map every time.
func (z *relayedZone) configRefresher() ZoneRefresher {
	opts := make(map[ZoneOption]bool, len(z.opts))
	for k, v := range z.opts {
		opts[k] = v
	}
	return ZoneRefresher{
		Name:          ovZone,
		ZoneType:      Secondary,
		ZoneStore:     MapZone,
		PrimariesConf: []PeerConf{{Addr: z.up.addr}},
		Primaries:     []PeerConf{{Addr: z.up.addr}},
		Options:       opts,
		ConfigUpdate:  true,
	}
}

func (z *relayedZone) run(t *testing.T, zr ZoneRefresher) {
	t.Helper()
	zr.Wait = true
	zr.Response = make(chan RefresherResponse, 1)
	z.conf.Internal.RefreshZoneCh <- zr
	select {
	case resp := <-zr.Response:
		if resp.Error {
			t.Fatalf("refresh: %s", resp.ErrorMsg)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the refresh was not answered")
	}
}

// notified runs the refresh a NOTIFY from the upstream starts.
func (z *relayedZone) notified(t *testing.T) {
	t.Helper()
	z.run(t, ZoneRefresher{Name: ovZone, ZoneStore: MapZone})
}

// reloaded runs the refresh `config reload-zones` queues for the zone: forced,
// so the zone is fetched again whether its serial moved or not.
func (z *relayedZone) reloaded(t *testing.T) {
	t.Helper()
	zr := z.configRefresher()
	zr.Force = true
	z.run(t, zr)
}

// served is the serial of the SOA the zone answers with. The snapshot's own
// serial and the zone's CurrentSerial must agree with it.
func (z *relayedZone) served(t *testing.T) uint32 {
	t.Helper()
	snap := z.zd.publishedSnapshot()
	if snap == nil || snap.Apex == nil {
		t.Fatal("no published snapshot")
	}
	soaRRs := snap.Apex.RRtypes.GetOnlyRRSet(dns.TypeSOA).RRs
	if len(soaRRs) != 1 {
		t.Fatalf("the apex has %d SOA records", len(soaRRs))
	}
	serial := soaRRs[0].(*dns.SOA).Serial
	z.zd.mu.Lock()
	cur := z.zd.CurrentSerial
	z.zd.mu.Unlock()
	if serial != snap.Serial || serial != cur {
		t.Fatalf("the served SOA says %d, the snapshot %d, CurrentSerial %d", serial, snap.Serial, cur)
	}
	return serial
}

func (z *relayedZone) wantServed(t *testing.T, want uint32, when string) {
	t.Helper()
	if got := z.served(t); got != want {
		t.Fatalf("%s: the zone serves serial %d, want the upstream's %d", when, got, want)
	}
}

// ownTXT is a zone change of the daemon's own, as its internal publishers
// send it to the zone updater.
func ownTXT(t *testing.T) UpdateRequest {
	t.Helper()
	return UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       ovZone,
		Actions:        []dns.RR{mustRR(t, `own.example. 3600 IN TXT "of our own"`)},
		InternalUpdate: true,
		Trusted:        true,
		Description:    "test: a change of the daemon's own",
	}
}

// A zone a registered app only relays serves the upstream's serial: after the
// first load, after refreshes, after a forced re-fetch of an unchanged serial
// and after a restart, in every outbound-soa-serial mode. The SOA it relays
// carries the upstream's RRSIG, made over the upstream's serial, so any other
// serial is an SOA that does not validate.
func TestRegisteredAppRelaysTheUpstreamSerial(t *testing.T) {
	for _, mode := range []string{OutboundSoaSerialKeep, OutboundSoaSerialPersist, OutboundSoaSerialUnixtime} {
		t.Run(mode, func(t *testing.T) {
			kdb := asDerivedApp(t, derivedSignerApp)
			registerTestOriginationRuleApp(t, derivedSignerApp)
			if err := applyOutboundSoaSerial(kdb, mode); err != nil {
				t.Fatalf("%s mode: %v", mode, err)
			}
			up := startRelayUpstream(t, 40)
			z := startRelayedZone(t, kdb, up, nil, nil)
			z.wantServed(t, 40, "after the first load")

			up.publish(t, 41)
			z.notified(t)
			z.wantServed(t, 41, "after one refresh")

			// two upstream changes in one refresh
			up.publish(t, 43)
			z.notified(t)
			z.wantServed(t, 43, "after a refresh that carried two upstream changes")

			// nothing new upstream: no transfer, nothing moves
			z.notified(t)
			z.wantServed(t, 43, "after a refresh with nothing new")

			// `config reload-zones`: the zone is fetched again at the serial it holds
			z.reloaded(t)
			z.wantServed(t, 43, "after a forced re-fetch of an unchanged serial")
			z.reloaded(t)
			z.wantServed(t, 43, "after a second forced re-fetch")

			up.publish(t, 44)
			z.notified(t)
			z.wantServed(t, 44, "after a refresh that followed the re-fetches")

			// The record of a relayed zone is the serial it serves, so that
			// a zone the app starts to sign across a restart can land past it.
			if got, err := kdb.LoadOutgoingSerial(ovZone); err != nil || got != 44 {
				t.Fatalf("the relayed zone's recorded serial is %d (err %v), want the 44 it serves", got, err)
			}

			// The rest of the rule holds too. Nothing of the daemon's own
			// goes into a relayed zone, and nothing moves its serial: the
			// API refuses a bump and the updater a change.
			if msg := zoneOriginationRefusal(z.zd, "bump"); msg == "" {
				t.Fatal("the API would bump the serial of a relayed zone")
			}
			kdb.UpdateQ = make(chan UpdateRequest, 4)
			if res := runUpdaterForResult(t, kdb, ownTXT(t)); res.Err == nil || res.Applied {
				t.Fatalf("the updater took a change into a relayed zone: applied=%v err=%v", res.Applied, res.Err)
			}
			if psfHasOwner(z.zd, "own.example.") {
				t.Fatal("a relayed zone serves a record of the daemon's own")
			}
			z.wantServed(t, 44, "after a refused bump and a refused change")

			// The restart: a new engine and a new zone on the same keystore.
			z.halt()
			again := startRelayedZone(t, kdb, up, nil, nil)
			again.wantServed(t, 44, "after a restart")
			again.reloaded(t)
			again.wantServed(t, 44, "after a restart and a forced re-fetch")
		})
	}
}

// The upgrade: the keystore of a relayed zone that counted its own serial
// holds the highest serial it published, ahead of the upstream's. The first
// load does not land past it, and the record becomes the serial the zone
// serves, so no later start finds the counted one either.
func TestRegisteredAppRelayDropsTheSerialItCountedBefore(t *testing.T) {
	kdb := asDerivedApp(t, derivedSignerApp)
	registerTestOriginationRuleApp(t, derivedSignerApp)
	if err := applyOutboundSoaSerial(kdb, OutboundSoaSerialPersist); err != nil {
		t.Fatalf("persist mode: %v", err)
	}
	if err := kdb.SaveOutgoingSerial(ovZone, 47); err != nil {
		t.Fatalf("seed the recorded serial: %v", err)
	}
	up := startRelayUpstream(t, 44)
	z := startRelayedZone(t, kdb, up, nil, nil)
	z.wantServed(t, 44, "after the first load over a record of 47")
	if got, err := kdb.LoadOutgoingSerial(ovZone); err != nil || got != 44 {
		t.Fatalf("the recorded serial is %d (err %v), want the 44 the zone serves: the 47 it counted before is gone", got, err)
	}
	z.halt()
	again := startRelayedZone(t, kdb, up, nil, nil)
	again.wantServed(t, 44, "after a restart")
}

// A relayed zone the app starts to sign across a restart goes on from one past
// the serial it was serving. Its upstream is another one from then on, with a
// serial of its own, here far below; the servers downstream of the zone hold
// the serial it relayed and would not transfer a lower one. The record of the
// relayed serial is what the first load lands past.
func TestRegisteredAppZoneThatStartsToSignAcrossARestartGoesOnPastWhatItRelayed(t *testing.T) {
	kdb := asDerivedApp(t, derivedSignerApp)
	registerTestOriginationRuleApp(t, derivedSignerApp)

	var signs atomic.Bool
	prepare := func(zd *ZoneData) {
		zd.OnZonePreRefresh = append(zd.OnZonePreRefresh, func(_, incoming *ZoneData) {
			if on := signs.Load(); incoming.Options[OptInlineSigning] != on {
				incoming.Options[OptInlineSigning] = on
			}
		})
	}
	up := startRelayUpstream(t, 40)
	z := startRelayedZone(t, kdb, up, nil, prepare)
	up.publish(t, 43)
	z.notified(t)
	z.wantServed(t, 43, "relayed, after a refresh")

	z.halt()
	signs.Store(true)
	up.publish(t, 7)
	again := startRelayedZone(t, kdb, up, nil, prepare)
	if got := again.served(t); got != 44 {
		t.Fatalf("the zone the app started to sign across a restart serves %d, want 44: one past the 43 it relayed, not its new upstream's 7", got)
	}
	up.publish(t, 8)
	again.notified(t)
	if got := again.served(t); got != 45 {
		t.Fatalf("after a refresh the signed zone serves %d, want 45: its own count", got)
	}

	// And back: the app stops signing the zone across another restart. It
	// relays again, at its upstream's serial, and the record follows it down,
	// so the count it kept while it signed is not what a later start lands
	// past.
	again.halt()
	signs.Store(false)
	up.publish(t, 20)
	relay := startRelayedZone(t, kdb, up, nil, prepare)
	relay.wantServed(t, 20, "relayed again, after a restart")
	if got, err := kdb.LoadOutgoingSerial(ovZone); err != nil || got != 20 {
		t.Fatalf("the recorded serial is %d (err %v), want the 20 the zone relays", got, err)
	}
}

// The same zone, once inline-signing is on for it, keeps a serial of its own.
// A derived app switches the option on in a pre-refresh callback, on the
// incoming zone's options, which are the served zone's: that is the moment a
// relayed zone becomes one the app signs. From there the zone goes on from one
// past the serial it was serving, whatever the upstream's serial is, and counts
// by itself at every refresh and forced re-fetch. A restart lands past the
// highest serial it published.
//
// No DNSSEC policy is bound here and nothing is signed: what is under test is
// the serial, and that follows the option alone.
func TestRegisteredAppZoneKeepsItsOwnSerialOnceItSigns(t *testing.T) {
	kdb := asDerivedApp(t, derivedSignerApp)
	registerTestOriginationRuleApp(t, derivedSignerApp)

	var signs atomic.Bool
	prepare := func(zd *ZoneData) {
		zd.OnZonePreRefresh = append(zd.OnZonePreRefresh, func(_, incoming *ZoneData) {
			if on := signs.Load(); incoming.Options[OptInlineSigning] != on {
				incoming.Options[OptInlineSigning] = on
			}
		})
	}
	up := startRelayUpstream(t, 40)
	z := startRelayedZone(t, kdb, up, nil, prepare)
	z.wantServed(t, 40, "relayed, after the first load")
	up.publish(t, 43)
	z.notified(t)
	z.wantServed(t, 43, "relayed, after a refresh")

	// The app starts signing the zone. Its upstream is another one from here
	// on, with a serial of its own, below the one the zone was serving.
	signs.Store(true)
	up.publish(t, 7)
	z.reloaded(t)
	if got := z.served(t); got != 44 {
		t.Fatalf("the zone the app started to sign serves %d, want 44: one past the 43 it was serving", got)
	}
	up.publish(t, 8)
	z.notified(t)
	if got := z.served(t); got != 45 {
		t.Fatalf("after a refresh the signed zone serves %d, want 45: its own count", got)
	}
	z.reloaded(t)
	if got := z.served(t); got != 46 {
		t.Fatalf("after a forced re-fetch the signed zone serves %d, want 46: its own count", got)
	}
	if got, err := kdb.LoadOutgoingSerial(ovZone); err != nil || got != 46 {
		t.Fatalf("the signed zone's recorded serial is %d (err %v), want 46", got, err)
	}

	z.halt()
	again := startRelayedZone(t, kdb, up, nil, prepare)
	if got := again.served(t); got != 47 {
		t.Fatalf("after a restart the signed zone serves %d, want 47: past the 46 it published", got)
	}
}

// The guard for every derived app that has not registered: it counts its own
// serial for a secondary, as it always did, and lands past it at a restart. A
// derived app that edits the zones it holds as a secondary depends on that.
// One app's registration must not reach another app type.
func TestUnregisteredAppSecondaryKeepsItsOwnSerial(t *testing.T) {
	kdb := asDerivedApp(t, derivedEditorApp)
	registerTestOriginationRuleApp(t, derivedSignerApp) // somebody else's
	if err := applyOutboundSoaSerial(kdb, OutboundSoaSerialPersist); err != nil {
		t.Fatalf("persist mode: %v", err)
	}
	up := startRelayUpstream(t, 40)
	z := startRelayedZone(t, kdb, up, nil, nil)
	if got := z.served(t); got != 40 {
		t.Fatalf("after the first load: %d, want 40", got)
	}
	z.reloaded(t)
	if got := z.served(t); got != 41 {
		t.Fatalf("after a forced re-fetch: %d, want 41: one past what it served, not the upstream's 40", got)
	}
	z.reloaded(t)
	if got := z.served(t); got != 42 {
		t.Fatalf("after a second forced re-fetch: %d, want 42", got)
	}
	up.publish(t, 41)
	z.notified(t)
	if got := z.served(t); got != 43 {
		t.Fatalf("after a refresh: %d, want 43: one past what it served, not the upstream's 41", got)
	}
	if got, err := kdb.LoadOutgoingSerial(ovZone); err != nil || got != 43 {
		t.Fatalf("recorded serial %d (err %v), want 43", got, err)
	}

	z.halt()
	again := startRelayedZone(t, kdb, up, nil, nil)
	if got := again.served(t); got != 44 {
		t.Fatalf("after a restart: %d, want 44: past the 43 it published, not the upstream's 41", got)
	}

	// And the other gates stand down: the API would bump, and the updater
	// takes a change of the daemon's own into the zone.
	if msg := zoneOriginationRefusal(again.zd, "bump"); msg != "" {
		t.Fatalf("the API refuses a bump on an unregistered app's secondary: %s", msg)
	}
	again.zd.mu.Lock()
	again.zd.UpdatePolicy = policyAllowing(dns.TypeTXT)
	again.zd.mu.Unlock()
	kdb.UpdateQ = make(chan UpdateRequest, 4)
	if res := runUpdaterForResult(t, kdb, ownTXT(t)); res.Err != nil || !res.Applied {
		t.Fatalf("an unregistered app's secondary refused a change of its own: applied=%v err=%v", res.Applied, res.Err)
	}
	if !psfHasOwner(again.zd, "own.example.") {
		t.Fatal("the change was answered as applied and is not served")
	}
	if got := again.served(t); got != 45 {
		t.Fatalf("after a change of its own: %d, want 45", got)
	}
}

// The predicate itself, for a registered type and for its neighbours.
func TestOriginationRuleAppliesToARegisteredAppType(t *testing.T) {
	secondary := &ZoneData{ZoneType: Secondary, Options: map[ZoneOption]bool{}}
	primary := &ZoneData{ZoneType: Primary, Options: map[ZoneOption]bool{}}
	inline := &ZoneData{ZoneType: Secondary, Options: map[ZoneOption]bool{OptInlineSigning: true}}

	withAppType(t, derivedSignerApp)
	if !zoneMayOriginateContent(secondary) {
		t.Fatal("before it registered, a derived app's secondary must originate")
	}
	registerTestOriginationRuleApp(t, derivedSignerApp)
	if zoneMayOriginateContent(secondary) {
		t.Error("a registered app's secondary without inline-signing must NOT originate")
	}
	if !zoneMayOriginateContent(inline) {
		t.Error("a registered app's inline-signing secondary must originate")
	}
	if !zoneMayOriginateContent(primary) {
		t.Error("a registered app's primary must originate")
	}

	// The registration is the type's alone.
	for _, other := range []AppType{derivedEditorApp, AppTypeAgent, 0} {
		Globals.App.Type = other
		if !zoneMayOriginateContent(secondary) {
			t.Errorf("app type %d did not register and its secondary is gated", other)
		}
	}
	Globals.App.Type = AppTypeAuth
	if zoneMayOriginateContent(secondary) {
		t.Error("a tdns-auth secondary must still not originate")
	}

	// The option normalizer stays tdns-auth's: a registered app may switch
	// inline-signing on after the parse, so nothing is stripped there.
	opts := map[ZoneOption]bool{OptPublishZonemd: true, OptAllowUpdates: true}
	eff, mode, suppressed, msg := normalizeOptionsForRole(derivedSignerApp, Secondary, opts, OutboundSoaSerialUnixtime)
	if len(suppressed) != 0 || msg != "" || mode != OutboundSoaSerialUnixtime || !eff[OptPublishZonemd] || !eff[OptAllowUpdates] {
		t.Errorf("the normalizer stripped a registered app's options: suppressed %v, mode %q, %q", suppressed, mode, msg)
	}
}

// An option the daemon set by itself (SetRuntimeOption) is in no
// configuration, and a config update replaces a zone's options with the
// configured ones. The update must not take the option away: until the daemon
// set it again, at the next transfer and not before, the zone would be one it
// does not sign, and under the origination rule that is a zone that mirrors
// its upstream's serial and refuses a change of the daemon's own.
func TestRuntimeOptionSurvivesAConfigUpdate(t *testing.T) {
	kdb := asDerivedApp(t, derivedSignerApp)
	registerTestOriginationRuleApp(t, derivedSignerApp)

	var signs atomic.Bool
	signs.Store(true)
	prepare := func(zd *ZoneData) {
		zd.OnZonePreRefresh = append(zd.OnZonePreRefresh, func(served, _ *ZoneData) {
			served.SetRuntimeOption(OptInlineSigning, signs.Load())
		})
	}
	inline := func(z *relayedZone) bool {
		z.zd.mu.Lock()
		defer z.zd.mu.Unlock()
		return z.zd.Options[OptInlineSigning]
	}
	up := startRelayUpstream(t, 40)
	z := startRelayedZone(t, kdb, up, nil, prepare)
	if !inline(z) {
		t.Fatal("the option the daemon set at the first load is not on")
	}
	up.publish(t, 50)
	z.notified(t)
	if got := z.served(t); got != 41 {
		t.Fatalf("the zone the daemon signs serves %d, want 41: its own count, not the upstream's 50", got)
	}

	// A config update with nothing new upstream: no transfer follows, so
	// nothing sets the option again.
	z.run(t, z.configRefresher())
	if !inline(z) {
		t.Fatal("a config update took away the option the daemon set by itself")
	}
	if msg := zoneOriginationRefusal(z.zd, "bump"); msg != "" {
		t.Fatalf("after a config update the zone the daemon signs refuses a bump: %s", msg)
	}
	if got := z.served(t); got != 41 {
		t.Fatalf("after a config update the zone serves %d, want the 41 it served", got)
	}

	// The same through `config reload-zones`, which fetches the zone again:
	// the zone counts on, it does not drop to its upstream's serial.
	z.reloaded(t)
	if got := z.served(t); got != 42 {
		t.Fatalf("after a forced re-fetch the zone serves %d, want 42: its own count", got)
	}

	// The daemon's word, not the option's history: once it says the zone is
	// not its to sign, a config update does not bring the option back.
	signs.Store(false)
	up.publish(t, 51)
	z.notified(t)
	if inline(z) {
		t.Fatal("the option is still on after the daemon switched it off")
	}
	z.run(t, z.configRefresher())
	if inline(z) {
		t.Fatal("a config update switched on an option the daemon had switched off")
	}
}

// The overlay itself: the configured options are the caller's and are not
// changed, and a zone with no run-time option gets them back as they are.
func TestRuntimeOptionsAreLaidOverTheConfiguredOnes(t *testing.T) {
	zd := &ZoneData{ZoneName: "example.", Options: map[ZoneOption]bool{}}
	configured := map[ZoneOption]bool{OptAllowUpdates: true}

	zd.mu.Lock()
	got := zd.withRuntimeOptionsLocked(configured)
	zd.mu.Unlock()
	if len(got) != 1 || !got[OptAllowUpdates] {
		t.Fatalf("with no run-time option: %v, want the configured options", got)
	}

	zd.SetRuntimeOption(OptInlineSigning, true)
	zd.mu.Lock()
	got = zd.withRuntimeOptionsLocked(configured)
	zd.mu.Unlock()
	if !got[OptInlineSigning] || !got[OptAllowUpdates] {
		t.Fatalf("with inline-signing set at run time: %v, want it beside the configured option", got)
	}
	if configured[OptInlineSigning] || len(configured) != 1 {
		t.Fatalf("the configured options were changed: %v", configured)
	}

	// Off is the daemon's word too: it replaces a configured on.
	zd.SetRuntimeOption(OptInlineSigning, false)
	zd.mu.Lock()
	got = zd.withRuntimeOptionsLocked(map[ZoneOption]bool{OptInlineSigning: true})
	zd.mu.Unlock()
	if got[OptInlineSigning] {
		t.Fatal("a configured inline-signing won over the daemon switching it off")
	}
}

// Setting a run-time option gives the zone a new options map; the map it had
// is not written to. That map is read without the zone's lock by the query
// and refresh paths, and the incoming zone of a refresh in progress holds it
// as well, so a write into it could meet a read of it and stop the process.
func TestSettingARuntimeOptionDoesNotWriteTheMapTheZoneHad(t *testing.T) {
	had := map[ZoneOption]bool{OptAllowUpdates: true}
	zd := &ZoneData{ZoneName: "example.", Options: had}
	incoming := &ZoneData{ZoneName: "example.", Options: zd.Options} // as a refresh builds it

	zd.SetRuntimeOption(OptInlineSigning, true)
	if !zd.Options[OptInlineSigning] || !zd.Options[OptAllowUpdates] {
		t.Fatalf("the zone's options after the set: %v, want inline-signing beside what it had", zd.Options)
	}
	if had[OptInlineSigning] || len(had) != 1 {
		t.Fatalf("the map the zone had was written to: %v", had)
	}
	if incoming.Options[OptInlineSigning] {
		t.Fatal("the incoming zone's map, shared with the served zone's old one, was written to")
	}

	// An option that already reads as asked for is no change: the same map.
	is := zd.Options
	zd.SetRuntimeOption(OptInlineSigning, true)
	zd.SetRuntimeOption(OptMultiProvider, false)
	if len(zd.Options) != len(is) || zd.Options[OptMultiProvider] {
		t.Fatalf("a set that changes nothing changed the options: %v", zd.Options)
	}
	zd.mu.Lock()
	if on, set := zd.runtimeOptions[OptMultiProvider]; !set || on {
		t.Error("the daemon's \"off\" for an option that was not on is not recorded: a later config that sets it would win")
	}
	zd.mu.Unlock()

	// Off replaces the map too.
	zd.SetRuntimeOption(OptInlineSigning, false)
	if zd.Options[OptInlineSigning] {
		t.Fatal("inline-signing still reads on after the daemon switched it off")
	}
	if !is[OptInlineSigning] {
		t.Fatal("switching the option off wrote the map the zone had before")
	}
}

// The other place a reload replaces a zone's options: ParseZones, when it
// reads the configuration of a zone that is already loaded. The option the
// daemon set by itself stays there too, and an option the reload adds to the
// configuration arrives beside it.
func TestRuntimeOptionSurvivesAReparseOfTheZoneConfiguration(t *testing.T) {
	withAppType(t, derivedSignerApp)
	registerTestOriginationRuleApp(t, derivedSignerApp)
	zd := testSnapshotZone(t, ovZone, ovUpstreamZone(40))
	zd.Options = map[ZoneOption]bool{}
	zd.SetRuntimeOption(OptInlineSigning, true)

	conf := &Config{Zones: []ZoneConf{{Name: ovZone, Type: "primary", Store: "map",
		Zonefile: "/nonexistent", OptionsStrs: []string{"fold-case"}}}}
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 10)
	if _, _, err := conf.ParseZones(context.Background(), true); err != nil {
		t.Fatalf("reload: %v", err)
	}
	zd.mu.Lock()
	inline, fold := zd.Options[OptInlineSigning], zd.Options[OptFoldCase]
	zd.mu.Unlock()
	if !inline {
		t.Fatal("the reload took away the option the daemon set by itself")
	}
	if !fold {
		t.Fatal("the reload did not install the option the configuration added")
	}
}
