/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// laneMarkerZone is a zone under a parent of its own, whose request marks a
// point in the intake. The lanes runner dispatches intake in order, so once a
// handler has seen the marker every request sent before it has been queued or
// merged. An empty intake does not say that: the runner may have read the
// last request and not yet dispatched it.
const laneMarkerZone = "marker.elsewhere.example."

// isLaneMarker reports whether ds is the marker, and acknowledges it on marked.
func isLaneMarker(ds DelegationSyncRequest, marked chan<- struct{}) bool {
	if ds.ZoneName != laneMarkerZone {
		return false
	}
	marked <- struct{}{}
	return true
}

// allDispatched sends the marker and waits for its handler, whose lanes must
// acknowledge it with isLaneMarker.
func allDispatched(t *testing.T, q chan DelegationSyncRequest, marked <-chan struct{}) {
	t.Helper()
	offer(t, q, laneRequest(laneZone(laneMarkerZone, "elsewhere.example."), "marker"))
	receive(t, marked, "the marker, sent after every request so far")
}

// A zone that keeps changing behind a parent that does not answer must not
// grow the parent's queue with each change: it keeps one waiting request per
// command, and the merged requests still carry every change. The running
// request is never merged into, since it may have read the zone already.
func TestAZoneThatKeepsChangingDoesNotGrowItsParentsQueue(t *testing.T) {
	zd := laneZone("busy.down.example.", "down.example.")
	const changes = 250

	release := make(chan struct{})
	started := make(chan struct{}, 1)
	marked := make(chan struct{}, 1)
	var mu sync.Mutex
	var ran []DelegationSyncRequest
	q, _, _ := startLanes(t, func(ctx context.Context, ds DelegationSyncRequest) {
		if isLaneMarker(ds, marked) {
			return
		}
		mu.Lock()
		first := len(ran) == 0
		ran = append(ran, ds)
		mu.Unlock()
		if first {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
	})

	change := func(i int) DelegationSyncRequest {
		ds := laneRequest(zd, "SYNC-DELEGATION")
		ds.SyncStatus.NsAdds = []dns.RR{mustRR(t, fmt.Sprintf("busy.down.example. 3600 IN NS ns%d.example.", i))}
		return ds
	}
	offer(t, q, change(0))
	receive(t, started, "the first sync to start and stick")

	for i := 1; i <= changes; i++ {
		offer(t, q, change(i))
		se := laneRequest(zd, "SIGNALS-EDITED")
		se.SignalTypes = []uint16{dns.TypeCDS}
		if i%2 == 0 {
			se.SignalTypes = []uint16{dns.TypeCSYNC}
		}
		offer(t, q, se)
		offer(t, q, laneRequest(zd, "EXPLICIT-SYNC-DELEGATION"))
		offer(t, q, laneRequest(zd, "REFRESH-SYNC-DELEGATION"))
	}
	allDispatched(t, q, marked)
	// The running sync, and one waiting request of each of the four commands.
	if pos := waitingIn(t, zd.ZoneName); pos.Waiting != 5 {
		t.Fatalf("the zone has %d requests in the queue, want 5: the running sync and one of each command", pos.Waiting)
	}

	close(release)
	waitFor(t, 2*time.Second, "the merged requests to run", func() bool {
		_, ok := DelegationSyncWaiting(zd.ZoneName)
		return !ok
	})

	mu.Lock()
	defer mu.Unlock()
	var cmds []string
	for _, ds := range ran {
		cmds = append(cmds, ds.Command)
	}
	want := []string{"SYNC-DELEGATION", "SYNC-DELEGATION", "SIGNALS-EDITED", "EXPLICIT-SYNC-DELEGATION", "REFRESH-SYNC-DELEGATION"}
	if !slices.Equal(cmds, want) {
		t.Fatalf("ran %v, want %v", cmds, want)
	}
	if n := len(ran[0].SyncStatus.NsAdds); n != 1 {
		t.Errorf("the running sync carries %d NS adds, want its own 1: nothing may merge into it", n)
	}
	if n := len(ran[1].SyncStatus.NsAdds); n != changes {
		t.Errorf("the merged sync carries %d NS adds, want all %d changes", n, changes)
	}
	if got := ran[2].SignalTypes; !slices.Equal(got, []uint16{dns.TypeCDS, dns.TypeCSYNC}) {
		t.Errorf("the merged SIGNALS-EDITED names %v, want CDS and CSYNC", got)
	}
}

// For each record the later operation wins; DS stays as older left it when
// newer has no opinion about it. A record older adds and newer removes keeps
// the two apart.
func TestMergeDelegationSyncDiffsLaterOperationWins(t *testing.T) {
	ns1 := mustRR(t, "child.example. 3600 IN NS ns1.example.")
	ns2 := mustRR(t, "child.example. 3600 IN NS ns2.example.")
	ns3 := mustRR(t, "child.example. 3600 IN NS ns3.example.")
	ns4 := mustRR(t, "child.example. 3600 IN NS ns4.example.")
	ds1 := mustRR(t, "child.example. 3600 IN DS 12345 15 2 0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20")

	older := DelegationSyncStatus{
		NsAdds:     []dns.RR{ns3},      // ns3 is left alone below
		NsRemoves:  []dns.RR{ns2, ns4}, // ns2 is added again below; ns4 is left alone
		NewDS:      []dns.RR{ds1},
		NewDSKnown: true,
		Unread:     []string{"DS"},
	}
	newer := DelegationSyncStatus{
		NsAdds:    []dns.RR{dns.Copy(ns2)},
		NsRemoves: []dns.RR{dns.Copy(ns1)},
		NewNS:     []dns.RR{ns2, ns3},
		Unread:    []string{"DS", "ns2.example. A"},
	}
	m, ok := mergeDelegationSyncDiffs(older, newer)
	if !ok {
		t.Fatal("not merged; newer removes nothing older adds")
	}

	has := func(list []dns.RR, rr dns.RR) bool {
		return slices.ContainsFunc(list, func(x dns.RR) bool { return sameRecord(x, rr) })
	}
	for _, c := range []struct {
		what      string
		rr        dns.RR
		add, rmov bool
	}{
		{"removed, then added", ns2, true, false},
		{"added, then left alone", ns3, true, false},
		{"removed, then left alone", ns4, false, true},
		{"left alone, then removed", ns1, false, true},
	} {
		if has(m.NsAdds, c.rr) != c.add || has(m.NsRemoves, c.rr) != c.rmov {
			t.Errorf("%s: in adds %v, in removes %v; want %v, %v", c.what,
				has(m.NsAdds, c.rr), has(m.NsRemoves, c.rr), c.add, c.rmov)
		}
	}
	if len(m.NsAdds) != 2 || len(m.NsRemoves) != 2 {
		t.Errorf("merged %d adds and %d removes, want 2 and 2 with no record twice", len(m.NsAdds), len(m.NsRemoves))
	}
	if len(m.NewNS) != 2 {
		t.Errorf("the complete new NS set is not newer's: %v", m.NewNS)
	}
	if !m.NewDSKnown || len(m.NewDS) != 1 {
		t.Errorf("newer had no opinion about DS, so older's must stand: known %v, %d DS", m.NewDSKnown, len(m.NewDS))
	}
	if !slices.Equal(m.Unread, []string{"DS", "ns2.example. A"}) {
		t.Errorf("Unread = %v, want both reads' gaps once each", m.Unread)
	}

	// A newer that withdraws the DS (known, empty) wins over older's DS.
	newer.NewDSKnown, newer.NewDS = true, nil
	if m, _ := mergeDelegationSyncDiffs(older, newer); !m.NewDSKnown || len(m.NewDS) != 0 {
		t.Errorf("newer withdrew the DS, merged has known %v and %d DS", m.NewDSKnown, len(m.NewDS))
	}

	// Added, then removed: kept apart, in every list that becomes an UPDATE.
	glue := mustRR(t, "ns1.child.example. 3600 IN A 192.0.2.1")
	for _, c := range []struct {
		what         string
		older, newer DelegationSyncStatus
	}{
		{"NS", DelegationSyncStatus{NsAdds: []dns.RR{ns1}}, DelegationSyncStatus{NsRemoves: []dns.RR{removalOf(ns1)}}},
		{"A", DelegationSyncStatus{AAdds: []dns.RR{glue}}, DelegationSyncStatus{ARemoves: []dns.RR{removalOf(glue)}}},
		{"DS", DelegationSyncStatus{DSAdds: []dns.RR{ds1}}, DelegationSyncStatus{DSRemoves: []dns.RR{ds1}}},
	} {
		if _, ok := mergeDelegationSyncDiffs(c.older, c.newer); ok {
			t.Errorf("%s added and then removed was merged; the merged removal reaches a parent that never had the addition", c.what)
		}
	}
}

// A request someone waits on gets its own answer: it is never merged, nor is a
// request merged into it. Commands not listed are never merged either.
func TestARequestSomeoneWaitsOnIsNeverMerged(t *testing.T) {
	zd := laneZone("asked.down.example.", "down.example.")

	release := make(chan struct{})
	started := make(chan struct{}, 1)
	q, _, _ := startLanes(t, func(ctx context.Context, ds DelegationSyncRequest) {
		if ds.Command == "first" {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		if ds.Response != nil {
			ds.Response <- DelegationSyncStatus{ZoneName: ds.ZoneName}
		}
	})
	offer(t, q, laneRequest(zd, "first"))
	receive(t, started, "the first request to start and stick")

	var answers []chan DelegationSyncStatus
	ask := func(cmd string) {
		ds := laneRequest(zd, cmd)
		ds.Response = make(chan DelegationSyncStatus, 1)
		answers = append(answers, ds.Response)
		offer(t, q, ds)
	}
	ask("DELEGATION-STATUS")
	ask("DELEGATION-STATUS")
	ask("EXPLICIT-SYNC-DELEGATION")
	offer(t, q, laneRequest(zd, "EXPLICIT-SYNC-DELEGATION")) // not into the asked one before it
	ask("EXPLICIT-SYNC-DELEGATION")                          // nor into the unasked one before it
	offer(t, q, laneRequest(zd, "SYNC-DNSKEY-RRSET"))
	offer(t, q, laneRequest(zd, "SYNC-DNSKEY-RRSET"))

	waitFor(t, 2*time.Second, "every request in the queue", func() bool {
		pos, ok := DelegationSyncWaiting(zd.ZoneName)
		return ok && pos.Waiting == 8
	})
	close(release)
	for i, ch := range answers {
		receive(t, ch, fmt.Sprintf("answer %d of %d", i+1, len(answers)))
	}
}

// The merged request takes the fresher retry counts, so a new trigger joining
// a retry close to its limit restores the zone's retries.
func TestAMergedRequestKeepsTheFresherRetryCounts(t *testing.T) {
	failed := time.Now().Add(-time.Minute)
	retry := DelegationSyncRequest{Command: "REFRESH-SYNC-DELEGATION", ZoneName: "child.example.",
		Attempt: 3, FailedAt: failed}
	fresh := DelegationSyncRequest{Command: "REFRESH-SYNC-DELEGATION", ZoneName: "child.example."}

	for _, c := range []struct {
		name          string
		waiting, next DelegationSyncRequest
	}{
		{"a fresh trigger joins a waiting retry", retry, fresh},
		{"a retry joins a waiting fresh trigger", fresh, retry},
	} {
		m, ok := mergeDelegationSyncRequests(c.waiting, c.next)
		if !ok {
			t.Fatalf("%s: not merged", c.name)
		}
		if m.Attempt != 0 || !m.FailedAt.IsZero() {
			t.Errorf("%s: attempt %d, failed at %v; want the fresh trigger's 0 and none", c.name, m.Attempt, m.FailedAt)
		}
	}

	setup := DelegationSyncRequest{Command: "DELEGATION-SYNC-SETUP", ZoneName: "child.example.", Attempt: 2, ReBootstrapRound: 1}
	m, ok := mergeDelegationSyncRequests(setup, DelegationSyncRequest{Command: "DELEGATION-SYNC-SETUP", ZoneName: "child.example."})
	if !ok || m.Attempt != 0 || m.ReBootstrapRound != 0 {
		t.Errorf("setup merge: ok %v, attempt %d, round %d; want a fresh setup's 0 and 0", ok, m.Attempt, m.ReBootstrapRound)
	}
}

// Two retries merged stand for both, so the merged one is dropped only when
// both would have been. A refresh failed, a sync then succeeded, and a refresh
// failed again after a glue change: the success supersedes the first retry and
// not the second, so the merged retry must still run.
func TestAMergedRetryIsDroppedOnlyWhenBothWouldBe(t *testing.T) {
	firstFail := time.Now().Add(-3 * time.Minute)
	success := firstFail.Add(time.Minute)
	secondFail := success.Add(time.Minute)
	first := DelegationSyncRequest{Command: "REFRESH-SYNC-DELEGATION", ZoneName: "child.example.",
		Attempt: 1, FailedAt: firstFail}
	second := first
	second.FailedAt = secondFail

	zd := &ZoneData{ZoneName: "child.example."}
	succeededAt := func(at time.Time) {
		zd.mu.Lock()
		zd.delegationLastSyncOK = at
		zd.mu.Unlock()
	}
	for _, c := range []struct {
		name          string
		waiting, next DelegationSyncRequest
	}{
		{"the first failure's retry waits", first, second},
		{"the second failure's retry waits", second, first},
	} {
		m, ok := mergeDelegationSyncRequests(c.waiting, c.next)
		if !ok {
			t.Fatalf("%s: not merged", c.name)
		}
		succeededAt(success)
		if delegationSyncRetrySuperseded(zd, m) {
			t.Errorf("%s: the merged retry is dropped for a success between the two failures;"+
				" the second failure is never retried", c.name)
		}
		succeededAt(secondFail.Add(time.Minute))
		if !delegationSyncRetrySuperseded(zd, m) {
			t.Errorf("%s: a success after both failures does not drop the merged retry", c.name)
		}
	}
}

// The join with a tdns parent (#843), which refuses an UPDATE that deletes a
// record it does not hold. Behind a parent that does not answer, one change
// adds the glue address X and the next replaces X with Y. The parent has had
// neither. Each sync that runs is sent to a direct-backend parent as the
// delta UPDATE the child sends, and Y must land: merged, the two were one
// UPDATE deleting X, which the parent refused with Y in it.
func TestGlueAddedThenReplacedReachesAParentThatRefusesAbsentDeletes(t *testing.T) {
	parent, kdb := dsdParentZone(t)
	child := laneZone(dsdChild, dsdParent)
	held := mustRR(t, "ns1.child.parent.example. 3600 IN A 192.0.2.54") // the parent has it
	x := mustRR(t, "ns1.child.parent.example. 3600 IN A 192.0.2.60")
	y := mustRR(t, "ns1.child.parent.example. 3600 IN A 192.0.2.61")

	release := make(chan struct{})
	started := make(chan struct{}, 1)
	marked := make(chan struct{}, 1)
	var mu sync.Mutex
	var refused []error
	q, _, _ := startLanes(t, func(ctx context.Context, ds DelegationSyncRequest) {
		if isLaneMarker(ds, marked) {
			return
		}
		if ds.Command == "first" {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
			return
		}
		m, err := buildDelegationUpdate(dsdParent, dsdChild, ds.SyncStatus, UpdateModeDelta)
		if err != nil {
			t.Errorf("buildDelegationUpdate: %v", err)
			return
		}
		wire, err := m.Pack()
		if err != nil {
			t.Errorf("packing the UPDATE: %v", err)
			return
		}
		r := new(dns.Msg)
		if err := r.Unpack(wire); err != nil {
			t.Errorf("unpacking the UPDATE: %v", err)
			return
		}
		if _, err := dsdApply(t, parent, kdb, r.Ns); err != nil {
			mu.Lock()
			refused = append(refused, err)
			mu.Unlock()
		}
	})
	change := func(adds, removes []dns.RR) {
		ds := laneRequest(child, "SYNC-DELEGATION")
		ds.SyncStatus = DelegationSyncStatus{ZoneName: dsdChild, AAdds: adds}
		for _, rr := range removes {
			ds.SyncStatus.ARemoves = append(ds.SyncStatus.ARemoves, removalOf(rr))
		}
		offer(t, q, ds)
	}
	served := func() []string {
		od := getOwnerFrom(parent.publishedSnapshot(), "ns1.child.parent.example.")
		if od == nil {
			t.Fatal("the parent does not serve ns1.child.parent.example.")
		}
		var out []string
		for _, rr := range od.RRtypes.GetOnlyRRSet(dns.TypeA).RRs {
			out = append(out, rr.(*dns.A).A.String())
		}
		slices.Sort(out)
		return out
	}

	offer(t, q, laneRequest(child, "first"))
	receive(t, started, "the first request to start and stick")
	change([]dns.RR{x}, nil)
	change([]dns.RR{y}, []dns.RR{x})
	// The opposite order merges into the second: a record the parent holds,
	// removed and added again, is an add of a record it holds.
	change(nil, []dns.RR{held})
	change([]dns.RR{held}, nil)
	allDispatched(t, q, marked)
	if pos := waitingIn(t, child.ZoneName); pos.Waiting != 3 {
		t.Errorf("%d of the zone's requests in the queue, want 3: the running one and the two kept apart", pos.Waiting)
	}

	close(release)
	waitFor(t, 2*time.Second, "the syncs to run", func() bool {
		_, ok := DelegationSyncWaiting(child.ZoneName)
		return !ok
	})
	mu.Lock()
	defer mu.Unlock()
	for _, err := range refused {
		t.Errorf("the parent refused a sync: %v", err)
	}
	if got, want := served(), []string{"192.0.2.54", "192.0.2.61"}; !slices.Equal(got, want) {
		t.Errorf("the parent serves glue %v, want %v", got, want)
	}
}

// A merge does not move a zone's request past one of the zone's that a caller
// waits on. The status request reads the parent and answers what it finds:
// that must be the parent after the sync that arrived before it, not after one
// that arrived later.
func TestAMergeDoesNotJumpARequestACallerWaitsOn(t *testing.T) {
	zd := laneZone("order.down.example.", "down.example.")

	release := make(chan struct{})
	started := make(chan struct{}, 1)
	marked := make(chan struct{}, 1)
	var mu sync.Mutex
	var ran []string
	q, _, _ := startLanes(t, func(ctx context.Context, ds DelegationSyncRequest) {
		if isLaneMarker(ds, marked) {
			return
		}
		if ds.Command == "first" {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
			return
		}
		mu.Lock()
		ran = append(ran, fmt.Sprintf("%s/%d", ds.Command, len(ds.SyncStatus.NsAdds)))
		mu.Unlock()
		if ds.Response != nil {
			ds.Response <- DelegationSyncStatus{ZoneName: ds.ZoneName}
		}
	})
	change := func(i int) DelegationSyncRequest {
		ds := laneRequest(zd, "SYNC-DELEGATION")
		ds.SyncStatus.NsAdds = []dns.RR{mustRR(t, fmt.Sprintf("order.down.example. 3600 IN NS ns%d.example.", i))}
		return ds
	}

	offer(t, q, laneRequest(zd, "first"))
	receive(t, started, "the first request to start and stick")
	offer(t, q, change(1))
	status := laneRequest(zd, "DELEGATION-STATUS")
	status.Response = make(chan DelegationSyncStatus, 1)
	offer(t, q, status)
	offer(t, q, change(2))
	allDispatched(t, q, marked)
	if pos := waitingIn(t, zd.ZoneName); pos.Waiting != 4 {
		t.Errorf("%d of the zone's requests in the queue, want 4: the later sync was merged past the status request", pos.Waiting)
	}

	close(release)
	receive(t, status.Response, "the status answer")
	waitFor(t, 2*time.Second, "the zone's requests to run", func() bool {
		_, ok := DelegationSyncWaiting(zd.ZoneName)
		return !ok
	})
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"SYNC-DELEGATION/1", "DELEGATION-STATUS/0", "SYNC-DELEGATION/1"}; !slices.Equal(ran, want) {
		t.Errorf("ran %v, want %v", ran, want)
	}
}
