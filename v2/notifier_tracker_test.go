/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// #1007: the tracker's bookkeeping, apart from any sending.

var errNoAnswer = errors.New("i/o timeout")

func soaKey(zone, target string) notifyKey {
	return notifyKey{zone: zone, target: target, rrtype: dns.TypeSOA}
}

// The wait doubles from the configured interval, up to an hour -- or up to the
// interval itself when that is set longer -- and a long retry list cannot
// overflow it.
func TestNotifyRetryWait(t *testing.T) {
	cases := []struct {
		interval time.Duration
		attempt  int
		want     time.Duration
	}{
		{10 * time.Second, 1, 10 * time.Second},
		{10 * time.Second, 2, 20 * time.Second},
		{10 * time.Second, 5, 160 * time.Second},
		{10 * time.Second, 100, time.Hour},
		{2 * time.Hour, 1, 2 * time.Hour},
		{2 * time.Hour, 5, 2 * time.Hour},
	}
	for _, c := range cases {
		if got := notifyRetryWait(c.interval, c.attempt); got != c.want {
			t.Errorf("notifyRetryWait(%s, %d) = %s, want %s", c.interval, c.attempt, got, c.want)
		}
	}
}

// A newer version that arrives while a send is in flight goes out with the
// ZoneData it came with, not the one the finished send used.
func TestSupersedingNotifyUsesTheNewZoneData(t *testing.T) {
	tr := NewNotifyTracker()
	key := soaKey("a.example.", "192.0.2.1:53")
	old, replacement := &ZoneData{ZoneName: "a.example."}, &ZoneData{ZoneName: "a.example."}
	if !tr.begin(key, old, true) {
		t.Fatal("the first version was not sent")
	}
	if tr.begin(key, replacement, true) {
		t.Fatal("a second send started while one was in flight")
	}
	again, zd := tr.done(key, notifyAttempt{rcode: dns.RcodeSuccess}, 5, time.Second, time.Now())
	if !again || zd != replacement {
		t.Errorf("done = (%v, %p), want (true, the replacement %p)", again, zd, replacement)
	}
}

// The schedule hands out resends in time order, and skips one that was moved.
func TestNotifyScheduleFindsTheEarliestResend(t *testing.T) {
	tr := NewNotifyTracker()
	now := time.Now()
	for i, target := range []string{"192.0.2.1:53", "192.0.2.2:53", "192.0.2.3:53"} {
		key := soaKey("a.example.", target)
		tr.begin(key, &ZoneData{ZoneName: "a.example."}, true)
		// 1 is due last, 2 first.
		tr.done(key, notifyAttempt{err: errNoAnswer}, 5, time.Duration(3-i)*time.Second, now)
	}
	next, ok := tr.nextDue()
	if !ok || !next.Equal(now.Add(time.Second)) {
		t.Fatalf("nextDue = %s, %v; want the 1s resend", next, ok)
	}
	got := tr.due(now.Add(2500 * time.Millisecond))
	if len(got) != 2 || got[0].key.target != "192.0.2.3:53" || got[1].key.target != "192.0.2.2:53" {
		t.Errorf("due after 2.5s = %v, want 192.0.2.3 then 192.0.2.2", got)
	}
	if got := tr.due(now.Add(2500 * time.Millisecond)); len(got) != 0 {
		t.Errorf("a resend was handed out twice: %v", got)
	}
	// The one left gets an answer before its time: its entry is stale.
	tr.mu.Lock()
	tr.targets[soaKey("a.example.", "192.0.2.1:53")].due = time.Time{}
	tr.mu.Unlock()
	if next, ok := tr.nextDue(); ok {
		t.Errorf("a cancelled resend is still scheduled for %s", next)
	}
}

// A target dropped from the zone's downstreams is forgotten; one with a send in
// flight is forgotten when the send returns.
func TestNotifyRetireForgetsRemovedTargets(t *testing.T) {
	tr := NewNotifyTracker()
	zd := &ZoneData{ZoneName: "a.example."}
	kept, removed, busy := soaKey("a.example.", "192.0.2.1:53"), soaKey("a.example.", "192.0.2.2:53"), soaKey("a.example.", "192.0.2.3:53")
	for _, key := range []notifyKey{kept, removed, busy} {
		tr.begin(key, zd, true)
	}
	tr.done(kept, notifyAttempt{rcode: dns.RcodeSuccess}, 5, time.Second, time.Now())
	tr.done(removed, notifyAttempt{err: errNoAnswer}, 5, time.Second, time.Now())

	tr.retire("A.example.", dns.TypeSOA, []string{kept.target})
	if got := len(tr.Status("a.example.")); got != 2 {
		t.Fatalf("after retiring, %d targets remain, want the kept and the busy one", got)
	}
	if next, ok := tr.nextDue(); ok {
		t.Errorf("a retired target still has a resend at %s", next)
	}
	tr.done(busy, notifyAttempt{rcode: dns.RcodeSuccess}, 5, time.Second, time.Now())
	if st := tr.Status("a.example."); len(st) != 1 || st[0].Target != kept.target {
		t.Errorf("after the busy send returned: %+v", st)
	}
}

// The state of a zone no longer served -- or served by a new ZoneData -- is
// released once at rest; a scheduled resend is left to run its course.
func TestNotifyPruneReleasesZonesNoLongerServed(t *testing.T) {
	tr := NewNotifyTracker()
	served, gone, readded := &ZoneData{ZoneName: "a.example."}, &ZoneData{ZoneName: "b.example."}, &ZoneData{ZoneName: "c.example."}
	retrying := &ZoneData{ZoneName: "d.example."}
	for _, zd := range []*ZoneData{served, gone, readded, retrying} {
		key := soaKey(zd.ZoneName, "192.0.2.1:53")
		tr.begin(key, zd, true)
		a := notifyAttempt{rcode: dns.RcodeSuccess}
		if zd == retrying {
			a = notifyAttempt{err: errNoAnswer}
		}
		tr.done(key, a, 5, time.Minute, time.Now())
	}
	current := func(zone string) (*ZoneData, bool) {
		switch zone {
		case "a.example.":
			return served, true
		case "c.example.":
			return &ZoneData{ZoneName: zone}, true
		}
		return nil, false
	}
	if n := tr.prune(current, func(*ZoneData) []string { return []string{"192.0.2.1:53"} }); n != 2 {
		t.Errorf("pruned %d targets, want 2 (the deleted zone and the re-added one)", n)
	}
	for zone, want := range map[string]int{"a.example.": 1, "b.example.": 0, "c.example.": 0, "d.example.": 1} {
		if got := len(tr.Status(zone)); got != want {
			t.Errorf("%s: %d targets left, want %d", zone, got, want)
		}
	}
}

// zone desc shows what the target is doing now: a retry scheduled for a new
// version outranks having given up on an old one, and a NOTIFY that could not
// be signed says so.
func TestNotifyStatusStates(t *testing.T) {
	tr := NewNotifyTracker()
	zd := &ZoneData{ZoneName: "a.example."}
	key := soaKey("a.example.", "192.0.2.1:53")
	tr.begin(key, zd, true)
	tr.done(key, notifyAttempt{err: errNoAnswer}, 0, time.Second, time.Now())
	if st := tr.Status("a.example.")[0].State; st != "given up" {
		t.Fatalf("after the only try: %q", st)
	}
	tr.begin(key, zd, true)
	tr.done(key, notifyAttempt{err: errNoAnswer}, 5, time.Second, time.Now())
	if st := tr.Status("a.example.")[0].State; st != "retrying" {
		t.Errorf("a new version with a resend scheduled shows %q, want retrying", st)
	}
	tr.begin(key, zd, true)
	tr.done(key, notifyAttempt{setupErr: errors.New("no such key")}, 5, time.Second, time.Now())
	if st := tr.Status("a.example.")[0].State; st != "cannot sign" {
		t.Errorf("a NOTIFY that could not be signed shows %q", st)
	}
	tr.begin(key, zd, true)
	tr.done(key, notifyAttempt{rcode: dns.RcodeRefused}, 5, time.Second, time.Now())
	if s := tr.Status("a.example.")[0]; s.State != "rejected" || s.LastError != "REFUSED" || !s.NextAttempt.IsZero() {
		t.Errorf("a refused NOTIFY shows %q (%q, next %v), want rejected, REFUSED, no resend", s.State, s.LastError, s.NextAttempt)
	}
}

// A negative notify-retries is ignored, so the next level's setting applies.
func TestNegativeNotifyRetriesAreIgnored(t *testing.T) {
	minus := -1
	tr := NewNotifyTracker()
	tr.setDefaults(&minus, "")
	if tr.retries != DefaultNotifyRetries {
		t.Errorf("server-wide -1 gave %d retries, want the default", tr.retries)
	}
	retries, _ := zoneNotifyRetrySettings("a.example.", &ZoneConf{NotifyRetries: &minus})
	if retries != nil {
		t.Errorf("a zone's -1 was kept as %d", *retries)
	}
}

// A request whose caller waits gets an answer even with no target, rather than
// waiting out its own deadline.
func TestNotifyWithAWaitingCallerAndNoTargetIsAnswered(t *testing.T) {
	_, q := runNotifier(t, 5, "30ms")
	zd := loadIxfrTestZone(t, basicZone)
	resp := make(chan NotifyResponse, 1)
	q <- NotifyRequest{ZoneName: zd.ZoneName, ZoneData: zd, RRtype: dns.TypeDNSKEY, Response: resp}
	select {
	case r := <-resp:
		if !r.Error {
			t.Errorf("a NOTIFY to no target reported success: %+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no answer for a request with no target")
	}
}

// A burst waits as queued jobs, not goroutines: no more than notifyMaxInFlight
// sends run at once, and a job a caller waits on goes ahead of the rest.
func TestNotifyDispatchIsBounded(t *testing.T) {
	prevTimeout := notifyTimeout
	notifyTimeout = 100 * time.Millisecond
	t.Cleanup(func() { notifyTimeout = prevTimeout })
	addr, _ := startCountingSink(t, "udp", 1000, dns.RcodeSuccess)
	zd := loadIxfrTestZone(t, basicZone)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	n := &notifier{ctx: ctx, conf: &Config{}, tracker: NewNotifyTracker(), results: make(chan notifyResult, notifyMaxInFlight)}

	const burst = notifyMaxInFlight + 24
	for i := 0; i < burst; i++ {
		n.launch(notifyJob{zd: zd, rrtype: dns.TypeSOA, target: addr})
	}
	b := &notifyBatch{left: 1}
	n.launch(notifyJob{zd: zd, rrtype: dns.TypeDNSKEY, target: addr, batch: b})
	if n.running != notifyMaxInFlight || len(n.waiting) != burst-notifyMaxInFlight || len(n.urgent) != 1 {
		t.Fatalf("running %d, waiting %d, urgent %d", n.running, len(n.waiting), len(n.urgent))
	}
	// The first send to finish makes room for the waiting caller's job.
	n.finish(<-n.results)
	if len(n.urgent) != 0 || n.running != notifyMaxInFlight {
		t.Errorf("after one finished: running %d, urgent %d; the caller's job should have started", n.running, len(n.urgent))
	}
	for left := burst; left > 0; left-- {
		if n.running > notifyMaxInFlight {
			t.Fatalf("%d sends running at once", n.running)
		}
		n.finish(<-n.results)
	}
	if n.running != 0 || len(n.waiting) != 0 {
		t.Errorf("after the burst: running %d, waiting %d", n.running, len(n.waiting))
	}
}

// The last downstream removed: the publish's empty request retires the zone's
// downstream state, a scheduled resend included, and sends nothing.
func TestNotifyLastDownstreamRemovedRetiresTheTargets(t *testing.T) {
	tr := NewNotifyTracker()
	zd := &ZoneData{ZoneName: "a.example."}
	key := soaKey("a.example.", "192.0.2.1:53")
	tr.begin(key, zd, true)
	tr.done(key, notifyAttempt{err: errNoAnswer}, 5, time.Minute, time.Now())
	n := &notifier{ctx: context.Background(), conf: &Config{}, tracker: tr, results: make(chan notifyResult, 1)}
	n.handle(NotifyRequest{ZoneName: zd.ZoneName, ZoneData: zd, RRtype: dns.TypeSOA}, true)
	if st := tr.Status("a.example."); len(st) != 0 {
		t.Errorf("after the last downstream was removed: %+v", st)
	}
	if n.running != 0 || len(n.waiting) != 0 {
		t.Errorf("an empty request started sends: running %d, waiting %d", n.running, len(n.waiting))
	}
}

// A publish with no downstreams left tells the tracker, if it holds state for
// the zone; a zone that never had downstreams costs nothing.
func TestPublishWithNoDownstreamsTellsTheTracker(t *testing.T) {
	prev := Conf.Internal.NotifyTracker
	tr := NewNotifyTracker()
	Conf.Internal.NotifyTracker = tr
	t.Cleanup(func() { Conf.Internal.NotifyTracker = prev })

	zd := loadIxfrTestZone(t, basicZone)
	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))
	if got := tr.takePending(); len(got) != 0 {
		t.Fatalf("a zone the tracker does not know marked %d requests", len(got))
	}
	tr.begin(notifyKey{zone: zd.ZoneName, target: "192.0.2.53:53", rrtype: dns.TypeCDS}, zd, false)
	stageAndPublish(t, zd, stageAddA(t, zd, "parent.example.test.", "192.0.2.13"))
	if got := tr.takePending(); len(got) != 0 {
		t.Fatalf("state from a CDS NOTIFY to the parent marked %d requests", len(got))
	}
	tr.begin(soaKey(zd.ZoneName, aDownstream), zd, true)
	stageAndPublish(t, zd, stageAddA(t, zd, "two.example.test.", "192.0.2.12"))
	got := tr.takePending()
	if len(got) != 1 || len(got[0].Targets) != 0 {
		t.Errorf("want one empty request, got %+v", got)
	}
}

// A request marked but not yet taken counts too: a publish that removes the
// last downstream replaces it with the empty one, so the removed target is
// not sent to.
func TestPublishWithNoDownstreamsReplacesAPendingRequest(t *testing.T) {
	prev := Conf.Internal.NotifyTracker
	tr := NewNotifyTracker()
	Conf.Internal.NotifyTracker = tr
	t.Cleanup(func() { Conf.Internal.NotifyTracker = prev })

	zd := loadIxfrTestZone(t, basicZone)
	tr.Mark(soaRequest(zd, aDownstream))
	stageAndPublish(t, zd, stageAddA(t, zd, "one.example.test.", "192.0.2.11"))
	got := tr.takePending()
	if len(got) != 1 || len(got[0].Targets) != 0 {
		t.Errorf("want the pending request replaced by an empty one, got %+v", got)
	}
}

// prune drops a downstream target the zone no longer has, scheduled resend
// included, and leaves state that did not come from the downstream set.
func TestNotifyPruneDropsRemovedDownstreams(t *testing.T) {
	tr := NewNotifyTracker()
	zd := &ZoneData{ZoneName: "a.example."}
	kept, removed, other := soaKey("a.example.", "192.0.2.1:53"), soaKey("a.example.", "192.0.2.2:53"), soaKey("a.example.", "192.0.2.9:53")
	tr.begin(kept, zd, true)
	tr.begin(removed, zd, true)
	tr.begin(other, zd, false)
	for _, key := range []notifyKey{kept, removed, other} {
		tr.done(key, notifyAttempt{err: errNoAnswer}, 5, time.Minute, time.Now())
	}
	current := func(string) (*ZoneData, bool) { return zd, true }
	if n := tr.prune(current, func(*ZoneData) []string { return []string{kept.target} }); n != 1 {
		t.Errorf("pruned %d targets, want the removed downstream only", n)
	}
	targets := map[string]bool{}
	for _, st := range tr.Status("a.example.") {
		targets[st.Target] = true
	}
	if !targets[kept.target] || targets[removed.target] || !targets[other.target] {
		t.Errorf("after pruning: %v", targets)
	}
}

// A job queued for a target that was retired while it waited is not sent.
func TestNotifyQueuedJobForARetiredTargetIsDropped(t *testing.T) {
	tr := NewNotifyTracker()
	zd := &ZoneData{ZoneName: "a.example."}
	key := soaKey("a.example.", "192.0.2.2:53")
	tr.begin(key, zd, true)
	tr.retire("a.example.", dns.TypeSOA, nil)
	n := &notifier{ctx: context.Background(), conf: &Config{}, tracker: tr, results: make(chan notifyResult, 1)}
	if !n.dropStale(notifyJob{zd: zd, rrtype: dns.TypeSOA, target: key.target}) {
		t.Fatal("a queued job for a retired target was not dropped")
	}
	if len(tr.Status("a.example.")) != 0 {
		t.Error("the retired target's state was kept")
	}
}

// A job whose waiting caller has gone is not sent, and the batch is still
// answered, as a failure.
func TestNotifyJobForAGoneCallerIsDropped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	zd := &ZoneData{ZoneName: "a.example."}
	resp := make(chan NotifyResponse, 1)
	b := &notifyBatch{req: NotifyRequest{ZoneName: zd.ZoneName, ZoneData: zd, RRtype: dns.TypeCDS, Targets: []string{"192.0.2.1:53"}, Response: resp, Ctx: ctx}, left: 1}
	n := &notifier{ctx: context.Background(), conf: &Config{}, tracker: NewNotifyTracker(), results: make(chan notifyResult, 1)}
	n.launch(notifyJob{zd: zd, rrtype: dns.TypeCDS, target: "192.0.2.1:53", batch: b})
	if n.running != 0 {
		t.Errorf("a job for a gone caller was sent")
	}
	select {
	case r := <-resp:
		if !r.Error {
			t.Errorf("the batch reported success: %+v", r)
		}
	case <-time.After(time.Second):
		t.Error("the batch was not answered")
	}
}
