/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// #917, the child's side: a key is bootstrapped only once the zone's
// nameservers serve it.

const (
	servedZone = "child.example."
	servedOld  = "child.example. 3600 IN KEY 512 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="
	servedNew  = "child.example. 3600 IN KEY 512 3 15 dGVzdGtleWZvcnRoZWJvb3RzdHJhcHJhY2UxMjM0NTY="
)

func keyRRsAt(t *testing.T, owner string, keys ...string) []dns.RR {
	t.Helper()
	var out []dns.RR
	for _, k := range keys {
		rr, err := dns.NewRR(k)
		if err != nil {
			t.Fatalf("%q: %v", k, err)
		}
		rr.Header().Name = owner
		out = append(out, rr)
	}
	return out
}

// servedZoneView is what the zone's nameservers serve, look by look: the KEY
// RRset at the apex per server address, and per signal name. A server
// address missing from apex does not answer.
type servedZoneView struct {
	t      *testing.T
	looks  int
	apex   func(look int) map[string][]string
	signal func(look int) map[string][]string
}

func (v *servedZoneView) check() keyServedCheck {
	return keyServedCheck{
		zone:        servedZone,
		keyRR:       servedNew,
		nameservers: func() ([]string, error) { return []string{"ns1.example.net.", "ns2.example.org."}, nil },
		addresses: func(ctx context.Context, ns string) []string {
			return []string{ns + ":53"}
		},
		askServer: func(ctx context.Context, qname, addr string) ([]dns.RR, error) {
			if qname != servedZone {
				v.t.Errorf("the apex check asked for %s, want %s", qname, servedZone)
			}
			keys, ok := v.apex(v.looks)[addr]
			if !ok {
				return nil, errors.New("timeout")
			}
			return keyRRsAt(v.t, qname, keys...), nil
		},
		askFresh: func(ctx context.Context, qname string) ([]dns.RR, error) {
			if v.signal == nil {
				return nil, nil
			}
			return keyRRsAt(v.t, qname, v.signal(v.looks)[qname]...), nil
		},
	}
}

// look is the check, counted.
func (v *servedZoneView) look(ctx context.Context) (keyServedState, string) {
	defer func() { v.looks++ }()
	return v.check().look(ctx)
}

const (
	servedNS1 = "ns1.example.net.:53"
	servedNS2 = "ns2.example.org.:53"
)

// The case of #917. The zone published its previous key, and one nameserver
// takes the new one later than the other. The parent does not know the new
// key and the child would bootstrap at once. It waits instead until both
// serve the new key, and bootstraps then.
func TestABootstrapWaitsUntilEveryNameserverServesTheKey(t *testing.T) {
	v := &servedZoneView{t: t, apex: func(look int) map[string][]string {
		if look < 2 {
			return map[string][]string{servedNS1: {servedOld, servedNew}, servedNS2: {servedOld}}
		}
		return map[string][]string{servedNS1: {servedOld, servedNew}, servedNS2: {servedOld, servedNew}}
	}}
	kp := &keyStateParent{t: t, waitOK: true, answers: [][]uint8{
		{edns0.KeyStateUnknown},
		{edns0.KeyStateTrusted},
	}}
	poll := kp.poll()
	poll.served = v.look
	lookAtBootstrap := -1
	bootstrap := poll.bootstrap
	poll.bootstrap = func(ctx context.Context) error {
		lookAtBootstrap = v.looks
		return bootstrap(ctx)
	}

	if err := (&Config{}).pollParentKeyState(context.Background(), poll); err != nil {
		t.Fatalf("poll ended with %v, want the key trusted", err)
	}
	if kp.bootstraps != 1 || lookAtBootstrap != 3 {
		t.Fatalf("%d bootstraps, the first after %d looks; want one, after the third look found both nameservers serving the key",
			kp.bootstraps, lookAtBootstrap)
	}
	want := []time.Duration{keyServedWait.first, 2 * keyServedWait.first}
	if len(kp.waits) != 2 || kp.waits[0] != want[0] || kp.waits[1] != want[1] {
		t.Errorf("waited %v between the looks, want %v", kp.waits, want)
	}
}

// A signal name that serves another KEY holds the bootstrap as the apex does:
// the parent's verdict on it is as final. A signal name that serves no KEY
// does not: the parent finds nothing there and looks again.
func TestABootstrapWaitsWhileASignalNameServesAnotherKey(t *testing.T) {
	both := map[string][]string{servedNS1: {servedNew}, servedNS2: {servedNew}}
	sig1 := signalOwnerName(signalPrefixSig0Key, servedZone, "ns1.example.net.")
	v := &servedZoneView{t: t,
		apex: func(int) map[string][]string { return both },
		signal: func(look int) map[string][]string {
			if look == 0 {
				return map[string][]string{sig1: {servedOld}}
			}
			return map[string][]string{sig1: {servedNew}}
		}}

	state, why := v.look(context.Background())
	if state != keyNotServedYet || !strings.Contains(why, sig1) {
		t.Fatalf("with %s serving the previous KEY the look says %v (%s), want not served yet, naming it", sig1, state, why)
	}
	if state, why := v.look(context.Background()); state != keyServed {
		t.Fatalf("with the new KEY at %s and nothing at the other signal name the look says %v (%s), want served", sig1, state, why)
	}
}

// A nameserver that does not answer is left out: the parent cannot get an
// answer from it either. When none answers, nothing can be told, and the
// bootstrap is not held.
func TestANameserverThatDoesNotAnswerDoesNotHoldTheBootstrap(t *testing.T) {
	v := &servedZoneView{t: t, apex: func(int) map[string][]string {
		return map[string][]string{servedNS1: {servedNew}}
	}}
	if state, why := v.look(context.Background()); state != keyServed {
		t.Errorf("with ns1 serving the key and ns2 silent the look says %v (%s), want served", state, why)
	}

	v.apex = func(int) map[string][]string { return nil }
	if state, why := v.look(context.Background()); state != keyServedUnknown {
		t.Errorf("with no nameserver answering the look says %v (%s), want unknown", state, why)
	}

	var waited []time.Duration
	ok := waitUntilKeyServed(context.Background(), servedZone, 4711, v.look,
		func(ctx context.Context, d time.Duration) bool { waited = append(waited, d); return true }, keyServedWait)
	if !ok || len(waited) != 0 {
		t.Errorf("with no nameserver answering the wait returned %v after waiting %v, want true at once", ok, waited)
	}
}

// A nameserver that never takes the key delays the bootstrap by the pace's
// limit, and does not stop it.
func TestABootstrapGoesAheadAfterTheLimit(t *testing.T) {
	v := &servedZoneView{t: t, apex: func(int) map[string][]string {
		return map[string][]string{servedNS1: {servedNew}, servedNS2: {servedOld}}
	}}
	pace := keyServedPace{first: time.Second, max: 4 * time.Second, limit: 10 * time.Second}
	var waited []time.Duration
	ok := waitUntilKeyServed(context.Background(), servedZone, 4711, v.look,
		func(ctx context.Context, d time.Duration) bool { waited = append(waited, d); return true }, pace)
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second}
	if !ok || len(waited) != len(want) {
		t.Fatalf("returned %v after waiting %v, want true after %v", ok, waited, want)
	}
	for i := range want {
		if waited[i] != want[i] {
			t.Fatalf("waited %v, want %v", waited, want)
		}
	}
}

// A shutdown while waiting for the key to be served sends nothing.
func TestAShutdownWhileWaitingForTheKeyToBeServedSendsNothing(t *testing.T) {
	v := &servedZoneView{t: t, apex: func(int) map[string][]string {
		return map[string][]string{servedNS1: {servedOld}, servedNS2: {servedOld}}
	}}
	kp := &keyStateParent{t: t, waitOK: false, answers: [][]uint8{{edns0.KeyStateUnknown}}}
	poll := kp.poll()
	poll.served = v.look

	if err := (&Config{}).pollParentKeyState(context.Background(), poll); err == nil {
		t.Error("a shutdown during the wait was reported as success")
	}
	if kp.bootstraps != 0 {
		t.Errorf("%d bootstraps after the wait was cut short", kp.bootstraps)
	}
}

// askServerForKey takes an authoritative answer, with the KEY RRset or
// without, and nothing else.
func TestAskServerForKeyTakesOnlyAnAuthoritativeAnswer(t *testing.T) {
	var aa bool
	var rcode int
	var keys []string
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	srv := &dns.Server{Listener: ln, Net: "tcp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = aa
		m.Rcode = rcode
		m.Answer = keyRRsAt(t, r.Question[0].Name, keys...)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	addr := ln.Addr().String()
	ctx := context.Background()

	aa, rcode, keys = true, dns.RcodeSuccess, []string{servedOld, servedNew}
	if rrs, err := askServerForKey(ctx, servedZone, addr); err != nil || len(rrs) != 2 || !matchKeyRR(rrs, servedNew) {
		t.Errorf("an authoritative answer with two KEYs gave %v, %v", rrs, err)
	}
	aa, rcode, keys = true, dns.RcodeNameError, nil
	if rrs, err := askServerForKey(ctx, servedZone, addr); err != nil || len(rrs) != 0 {
		t.Errorf("an authoritative NXDOMAIN gave %v, %v; want no KEY and no error", rrs, err)
	}
	aa, rcode, keys = false, dns.RcodeSuccess, []string{servedNew}
	if _, err := askServerForKey(ctx, servedZone, addr); err == nil {
		t.Error("an answer that is not authoritative was taken")
	}
	aa, rcode, keys = true, dns.RcodeServerFailure, nil
	if _, err := askServerForKey(ctx, servedZone, addr); err == nil {
		t.Error("a SERVFAIL was taken as an answer")
	}
}
