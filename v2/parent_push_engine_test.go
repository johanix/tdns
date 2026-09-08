/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func withParentPushQueue(t *testing.T, depth int) chan ParentPushRequest {
	t.Helper()
	prev := Conf.Internal.ParentPushQ
	t.Cleanup(func() { Conf.Internal.ParentPushQ = prev })
	q := make(chan ParentPushRequest, depth)
	Conf.Internal.ParentPushQ = q
	return q
}

// A childsync-proxy with an async ddns writer over a fake primary, its store
// seeded from the served zone, and the engine running.
type pushFixture struct {
	zd   *ZoneData
	sink *updateSink
	done chan struct{}
}

func startPushFixture(t *testing.T, rcode int, targets ...string) (*pushFixture, context.CancelFunc) {
	t.Helper()
	withAgentTsigKey(t)
	withParentPushQueue(t, 16)
	var sink *updateSink
	if len(targets) == 0 {
		sink = startUpdateSink(t, rcode)
		targets = []string{sink.addr}
	}
	kdb := newTestKeyDB(t)
	zd := adoptParent(t, kdb)
	zd.ZoneType = Secondary
	zd.Options[OptChildSyncProxy] = true
	store := &DBDelegationBackend{kdb: kdb}
	writer := &ddnsParentZoneWriter{
		zd: zd, store: store, targets: targets, keyName: testAgentTsigKey,
		retryInterval: 20 * time.Millisecond, maxAttempts: 2,
	}
	zd.DelegationBackend = &composedDelegationBackend{name: "push", store: store, writer: writer, async: true, zd: zd}
	if _, _, err := zd.AdoptServedDelegations(); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ParentPushEngine(ctx, &Conf)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("ParentPushEngine did not exit on cancel")
		}
	})
	return &pushFixture{zd: zd, sink: sink, done: done}, cancel
}

func childAdd(t *testing.T, zd *ZoneData, rrs ...string) {
	t.Helper()
	ur := UpdateRequest{Cmd: "CHILD-UPDATE", ZoneName: zd.ZoneName}
	for _, s := range rrs {
		ur.Actions = append(ur.Actions, mustDsyncRR(t, s))
	}
	if err := zd.DelegationBackend.ApplyChildUpdate(zd.ZoneName, ur); err != nil {
		t.Fatalf("ApplyChildUpdate: %v", err)
	}
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The whole outbound half: a child update is recorded, the engine computes
// the delta between the store and the served zone, and the primary receives
// exactly that delta as one signed UPDATE.
func TestPushEngineDeliversAChildUpdateAsADelta(t *testing.T) {
	f, _ := startPushFixture(t, dns.RcodeSuccess)

	childAdd(t, f.zd,
		"delta.parent.example. 3600 IN NS ns.delta.parent.example.",
		"ns.delta.parent.example. 3600 IN A 192.0.2.4")

	m := f.sink.wait(t, 3*time.Second)
	if m.Opcode != dns.OpcodeUpdate || len(m.Question) != 1 || m.Question[0].Name != "parent.example." {
		t.Fatalf("not an UPDATE for the parent: %v", m)
	}
	if signed, verified := f.sink.tsig(); !signed || !verified {
		t.Fatalf("the push must be TSIG-signed: signed=%v verified=%v", signed, verified)
	}
	got := actionStrings(m.Ns)
	want := []string{
		"IN delta.parent.example.\t3600\tIN\tNS\tns.delta.parent.example.",
		"IN ns.delta.parent.example.\t3600\tIN\tA\t192.0.2.4",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the primary received:\n%s\nwant exactly the delta:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	waitFor(t, 2*time.Second, "the success to be recorded", func() bool {
		st := f.zd.ParentPushStatus()
		return !st.LastOK.IsZero() && len(st.Failures) == 0 && !st.Running
	})
	if f.zd.HasError(DelegationSyncWarning) {
		t.Fatalf("a successful push left a warning: %+v", f.zd.Errors)
	}
}

// The delta is recomputed from the store at push time, not replayed from
// the request: after two updates for one child the primary's latest UPDATE
// carries the child's whole intended delta.
func TestPushEngineRecomputesTheDeltaFromTheStore(t *testing.T) {
	f, _ := startPushFixture(t, dns.RcodeSuccess)

	childAdd(t, f.zd, "alpha.parent.example. 3600 IN NS ns2.alpha.parent.example.")
	childAdd(t, f.zd, "alpha.parent.example. 3600 IN NS ns3.alpha.parent.example.")

	waitFor(t, 3*time.Second, "a push carrying both additions", func() bool {
		m := f.sink.last()
		if m == nil {
			return false
		}
		s := strings.Join(actionStrings(m.Ns), "\n")
		return strings.Contains(s, "ns2.alpha") && strings.Contains(s, "ns3.alpha")
	})
	// And nothing the parent already serves for alpha is in the delta: the
	// store was seeded from the zone, so ns.alpha, the DS and the glue are
	// intended AND served.
	if s := strings.Join(actionStrings(f.sink.last().Ns), "\n"); strings.Contains(s, "\tNS\tns.alpha.") || strings.Contains(s, "\tDS\t") {
		t.Fatalf("the delta re-sends what the parent already serves:\n%s", s)
	}
}

// A REFUSED is the primary's policy saying no: one attempt, a terminal
// failure on the zone naming the child, and a warning -- never a retry loop.
func TestPushEngineRecordsATerminalRejection(t *testing.T) {
	f, _ := startPushFixture(t, dns.RcodeRefused)

	childAdd(t, f.zd, "delta.parent.example. 3600 IN NS ns.delta.parent.example.")
	f.sink.wait(t, 3*time.Second)

	waitFor(t, 2*time.Second, "the failure to be recorded", func() bool {
		return len(f.zd.ParentPushStatus().Failures) == 1
	})
	fl := f.zd.ParentPushStatus().Failures[0]
	if fl.Subject != "delta.parent.example." || !fl.Terminal || fl.Attempts != 1 {
		t.Fatalf("failure = %+v; want the child, terminal, one attempt", fl)
	}
	if !strings.Contains(fl.LastErr, "REFUSED") {
		t.Errorf("the failure should name the rcode: %s", fl.LastErr)
	}
	time.Sleep(100 * time.Millisecond)
	if n := f.sink.count(); n != 1 {
		t.Fatalf("a terminal rejection was retried: %d attempts reached the primary", n)
	}
	ze, ok := f.zd.Errors[DelegationSyncWarning]
	if !ok || !strings.HasPrefix(ze.Msg, parentPushWarningPrefix) || !strings.Contains(ze.Msg, "delta.parent.example.") {
		t.Fatalf("expected a push warning naming the child, got %+v", f.zd.Errors)
	}
}

// A SERVFAIL is transient: bounded retries with backoff, then a non-terminal
// failure the next refresh will retry.
func TestPushEngineRetriesATransientFailureThenWarns(t *testing.T) {
	f, _ := startPushFixture(t, dns.RcodeServerFailure)

	childAdd(t, f.zd, "delta.parent.example. 3600 IN NS ns.delta.parent.example.")
	waitFor(t, 3*time.Second, "both attempts to reach the primary", func() bool { return f.sink.count() >= 2 })
	waitFor(t, 2*time.Second, "the failure to be recorded", func() bool {
		return len(f.zd.ParentPushStatus().Failures) == 1
	})
	fl := f.zd.ParentPushStatus().Failures[0]
	if fl.Terminal || fl.Attempts != 2 {
		t.Fatalf("failure = %+v; want non-terminal after the configured 2 attempts", fl)
	}
}

// A push that later lands clears the failure and, with none left, the warning.
func TestPushEngineClearsTheWarningWhenAPushLands(t *testing.T) {
	f, _ := startPushFixture(t, dns.RcodeRefused)
	childAdd(t, f.zd, "delta.parent.example. 3600 IN NS ns.delta.parent.example.")
	waitFor(t, 3*time.Second, "the rejection", func() bool { return len(f.zd.ParentPushStatus().Failures) == 1 })

	f.sink.mu.Lock()
	f.sink.rcode = dns.RcodeSuccess
	f.sink.mu.Unlock()
	if !enqueueParentPush(ParentPushRequest{Kind: ParentPushChildren, ZoneData: f.zd, Children: []string{"delta.parent.example."}, Reason: "test"}) {
		t.Fatal("enqueue failed")
	}
	waitFor(t, 3*time.Second, "the failure to clear", func() bool {
		return len(f.zd.ParentPushStatus().Failures) == 0 && !f.zd.HasError(DelegationSyncWarning)
	})
}

// A full queue drops the request and says so; it never blocks the caller,
// which is the ZoneUpdater.
func TestEnqueueParentPushNeverBlocks(t *testing.T) {
	q := withParentPushQueue(t, 1)
	zd := &ZoneData{ZoneName: "parent.example."}
	q <- ParentPushRequest{Kind: ParentPushAdvertisement, ZoneData: zd}

	done := make(chan bool, 1)
	go func() { done <- enqueueParentPush(ParentPushRequest{Kind: ParentPushAdvertisement, ZoneData: zd}) }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("a full queue reported the request as accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("enqueueParentPush blocked on a full queue")
	}
}

// Shutdown with a primary that accepts the connection and never answers: the
// engine exits, and so does the zone's worker, because the exchange is
// cancellable.
func TestPushEngineExitsOnShutdownWithAHungPrimary(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{}, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			go func() {
				buf := make([]byte, 4096)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })

	f, cancel := startPushFixture(t, 0, ln.Addr().String())
	childAdd(t, f.zd, "delta.parent.example. 3600 IN NS ns.delta.parent.example.")
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("the push never reached the hung primary")
	}

	start := time.Now()
	cancel()
	select {
	case <-f.done:
	case <-time.After(2 * time.Second):
		t.Fatal("ParentPushEngine did not exit within 2s of cancel")
	}
	waitFor(t, 2*time.Second, "the zone's worker to exit", func() bool { return !f.zd.ParentPushStatus().Running })
	if time.Since(start) > 2*time.Second {
		t.Fatalf("shutdown took %s", time.Since(start))
	}
}

func TestDiffDelegation(t *testing.T) {
	data := func(rrs ...string) map[string]map[uint16][]dns.RR {
		out := map[string]map[uint16][]dns.RR{}
		for _, s := range rrs {
			rr := mustDsyncRR(t, s)
			o, ty := rr.Header().Name, rr.Header().Rrtype
			if out[o] == nil {
				out[o] = map[uint16][]dns.RR{}
			}
			out[o][ty] = append(out[o][ty], rr)
		}
		return out
	}
	want := adoptableDelegationRR("alpha.parent.example.")

	served := data(
		"alpha.parent.example. 3600 IN NS ns.alpha.parent.example.",
		"alpha.parent.example. 3600 IN DS 1 13 2 00",
		"ns.alpha.parent.example. 3600 IN A 192.0.2.51")
	intended := data(
		"alpha.parent.example. 0 IN NS ns2.alpha.parent.example.",
		"ns.alpha.parent.example. 0 IN A 192.0.2.51",
		"ns.alpha.parent.example. 0 IN AAAA 2001:db8::51",
		"alpha.parent.example. 0 IN TXT \"a type the parent does not hold for a child\"")

	got := actionStrings(diffDelegation(intended, served, 7200, want))
	wantActions := []string{
		"NONE alpha.parent.example.\t0\tNONE\tDS\t1 13 2 00",
		"NONE alpha.parent.example.\t0\tNONE\tNS\tns.alpha.parent.example.",
		"IN alpha.parent.example.\t7200\tIN\tNS\tns2.alpha.parent.example.",
		"IN ns.alpha.parent.example.\t7200\tIN\tAAAA\t2001:db8::51",
	}
	if strings.Join(got, "\n") != strings.Join(wantActions, "\n") {
		t.Fatalf("delta:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantActions, "\n"))
	}

	if d := diffDelegation(served, served, 7200, want); len(d) != 0 {
		t.Fatalf("identical states produced a delta: %v", actionStrings(d))
	}
	if d := diffDelegation(map[string]map[uint16][]dns.RR{}, served, 7200, want); len(d) != 3 {
		t.Fatalf("an empty intent must remove everything served: %v", actionStrings(d))
	}
}
