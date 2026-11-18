/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"slices"
	"strings"
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

// Two differences that only add merge into the union of their additions; DS
// stays as older left it when newer has no opinion about it. A difference that
// removes a record merges with none.
func TestMergeDelegationSyncDiffsMergesOnlyAdditions(t *testing.T) {
	ns1 := mustRR(t, "child.example. 3600 IN NS ns1.example.")
	ns2 := mustRR(t, "child.example. 3600 IN NS ns2.example.")
	ns3 := mustRR(t, "child.example. 3600 IN NS ns3.example.")
	ds1 := mustRR(t, "child.example. 3600 IN DS 12345 15 2 0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20")

	older := DelegationSyncStatus{
		NsAdds:     []dns.RR{ns1, ns3},
		NewDS:      []dns.RR{ds1},
		NewDSKnown: true,
		Unread:     []string{"DS"},
	}
	newer := DelegationSyncStatus{
		NsAdds: []dns.RR{ns2, dns.Copy(ns3)},
		NewNS:  []dns.RR{ns1, ns2, ns3},
		Unread: []string{"DS", "ns2.example. A"},
	}
	m, ok := mergeDelegationSyncDiffs(older, newer)
	if !ok {
		t.Fatal("not merged; neither removes anything")
	}
	if len(m.NsAdds) != 3 || len(m.NsRemoves) != 0 {
		t.Errorf("merged %d adds and %d removes, want ns1, ns2 and ns3 added once each", len(m.NsAdds), len(m.NsRemoves))
	}
	for _, rr := range []dns.RR{ns1, ns2, ns3} {
		if !slices.ContainsFunc(m.NsAdds, func(x dns.RR) bool { return sameRecord(x, rr) }) {
			t.Errorf("the merged difference does not add %s", rr)
		}
	}
	if len(m.NewNS) != 3 {
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

	// A removal on either side, in any list, keeps the two apart.
	glue := mustRR(t, "ns1.child.example. 3600 IN A 192.0.2.1")
	glue6 := mustRR(t, "ns1.child.example. 3600 IN AAAA 2001:db8::1")
	adds := DelegationSyncStatus{NsAdds: []dns.RR{ns2}}
	for _, c := range []struct {
		what         string
		older, newer DelegationSyncStatus
	}{
		{"newer removes what older adds", DelegationSyncStatus{NsAdds: []dns.RR{ns1}}, DelegationSyncStatus{NsRemoves: []dns.RR{removalOf(ns1)}}},
		{"older removes, newer adds another", DelegationSyncStatus{ARemoves: []dns.RR{removalOf(glue)}}, adds},
		{"older adds, newer removes another", adds, DelegationSyncStatus{AAAARemoves: []dns.RR{removalOf(glue6)}}},
		{"both remove", DelegationSyncStatus{DSRemoves: []dns.RR{ds1}}, DelegationSyncStatus{Removes: []dns.RR{removalOf(glue)}}},
		{"a DNSKEY removal", DelegationSyncStatus{DNSKEYRemoves: []dns.RR{ds1}}, adds},
	} {
		if _, ok := mergeDelegationSyncDiffs(c.older, c.newer); ok {
			t.Errorf("%s: merged; a deletion the parent refuses would take the other's changes with it", c.what)
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

// glueChange is one SYNC-DELEGATION's change to ns1.child.parent.example.'s
// A glue.
type glueChange struct{ adds, removes []dns.RR }

// syncsToADirectParent is the join with a tdns parent, which refuses an UPDATE
// that deletes a record it does not hold, with everything in it (#843). It
// queues each change as a SYNC-DELEGATION behind a request that sticks, as
// behind a parent that does not answer, and then lets them run. Each sync that
// runs is sent to a direct-backend parent (dsdParentZone) as the delta UPDATE
// the child sends. It returns how many of the zone's requests were in the
// queue once all were, the running one included; what the parent refused; and
// the A glue it then serves for ns1.child.parent.example.
func syncsToADirectParent(t *testing.T, changes []glueChange) (waiting int, refused []error, served []string) {
	t.Helper()
	parent, kdb := dsdParentZone(t)
	child := laneZone(dsdChild, dsdParent)

	release := make(chan struct{})
	started := make(chan struct{}, 1)
	marked := make(chan struct{}, 1)
	var mu sync.Mutex
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

	offer(t, q, laneRequest(child, "first"))
	receive(t, started, "the first request to start and stick")
	for _, c := range changes {
		ds := laneRequest(child, "SYNC-DELEGATION")
		ds.SyncStatus = DelegationSyncStatus{ZoneName: dsdChild, AAdds: c.adds}
		for _, rr := range c.removes {
			ds.SyncStatus.ARemoves = append(ds.SyncStatus.ARemoves, removalOf(rr))
		}
		offer(t, q, ds)
	}
	allDispatched(t, q, marked)
	waiting = waitingIn(t, child.ZoneName).Waiting

	close(release)
	waitFor(t, 2*time.Second, "the syncs to run", func() bool {
		_, ok := DelegationSyncWaiting(child.ZoneName)
		return !ok
	})
	od := getOwnerFrom(parent.publishedSnapshot(), "ns1.child.parent.example.")
	if od == nil {
		t.Fatal("the parent does not serve ns1.child.parent.example.")
	}
	for _, rr := range od.RRtypes.GetOnlyRRSet(dns.TypeA).RRs {
		served = append(served, rr.(*dns.A).A.String())
	}
	slices.Sort(served)
	mu.Lock()
	defer mu.Unlock()
	return waiting, refused, served
}

// One change adds the glue address X and the next replaces X with Y. The
// parent has had neither. Merged, the two were one UPDATE deleting X, which
// the parent refused with Y in it. A record removed and added back is two
// requests as well: the removal merges with nothing.
func TestGlueAddedThenReplacedReachesAParentThatRefusesAbsentDeletes(t *testing.T) {
	held := mustRR(t, "ns1.child.parent.example. 3600 IN A 192.0.2.54") // the parent has it
	x := mustRR(t, "ns1.child.parent.example. 3600 IN A 192.0.2.60")
	y := mustRR(t, "ns1.child.parent.example. 3600 IN A 192.0.2.61")

	waiting, refused, served := syncsToADirectParent(t, []glueChange{
		{adds: []dns.RR{x}},
		{adds: []dns.RR{y}, removes: []dns.RR{x}},
		{removes: []dns.RR{held}},
		{adds: []dns.RR{held}},
	})
	if waiting != 5 {
		t.Errorf("%d of the zone's requests in the queue, want 5: the running one and four kept apart", waiting)
	}
	for _, err := range refused {
		t.Errorf("the parent refused a sync: %v", err)
	}
	if want := []string{"192.0.2.54", "192.0.2.61"}; !slices.Equal(served, want) {
		t.Errorf("the parent serves glue %v, want %v", served, want)
	}
}

// A deletion the parent refuses takes nothing else with it, in either order:
// an address added beside it, in a request of its own, still lands. Merged,
// the two were one UPDATE, and the parent refused all of it.
func TestADeletionTheParentRefusesTakesNothingElseWithIt(t *testing.T) {
	z := mustRR(t, "ns1.child.parent.example. 3600 IN A 192.0.2.62")
	absent := mustRR(t, "ns1.child.parent.example. 3600 IN A 192.0.2.99") // the parent never had it
	for _, c := range []struct {
		name    string
		changes []glueChange
	}{
		{"the deletion second", []glueChange{{adds: []dns.RR{z}}, {removes: []dns.RR{absent}}}},
		{"the deletion first", []glueChange{{removes: []dns.RR{absent}}, {adds: []dns.RR{z}}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			waiting, refused, served := syncsToADirectParent(t, c.changes)
			if waiting != 3 {
				t.Errorf("%d of the zone's requests in the queue, want 3: the running one and two kept apart", waiting)
			}
			if len(refused) != 1 {
				t.Errorf("the parent refused %d syncs, want 1, the deletion: %v", len(refused), refused)
			}
			if want := []string{"192.0.2.54", "192.0.2.62"}; !slices.Equal(served, want) {
				t.Errorf("the parent serves glue %v, want %v", served, want)
			}
		})
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
		ran = append(ran, ranLabel(ds))
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
	if want := []string{"SYNC-DELEGATION ns1.example.", "DELEGATION-STATUS", "SYNC-DELEGATION ns2.example."}; !slices.Equal(ran, want) {
		t.Errorf("ran %v, want %v", ran, want)
	}
}

// ranLabel is a request's command and the NS targets it adds, as a test
// records the order requests ran in.
func ranLabel(ds DelegationSyncRequest) string {
	label := ds.Command
	var targets []string
	for _, rr := range ds.SyncStatus.NsAdds {
		targets = append(targets, rr.(*dns.NS).Ns)
	}
	if len(targets) > 0 {
		label += " " + strings.Join(targets, ",")
	}
	return label
}

// A merge moves a request ahead of the zone's requests that wait between it
// and the one it joins, and only live reconciliations may be overtaken so. A
// SIGNALS-EDITED merged ahead of a SYNC-DELEGATION would send the DS the keys
// call for now, and the SYNC-DELEGATION's stored DS after it; a sync merged
// ahead of the zone's setup could reach the parent before its key. A sync may
// pass a live reconciliation, which then sees its change.
func TestAMergeOvertakesOnlyLiveReconciliations(t *testing.T) {
	sd := func(zd *ZoneData, ns string) DelegationSyncRequest {
		ds := laneRequest(zd, "SYNC-DELEGATION")
		ds.SyncStatus.NsAdds = []dns.RR{mustRR(t, zd.ZoneName+" 3600 IN NS "+ns)}
		return ds
	}
	for _, c := range []struct {
		name    string
		send    func(zd *ZoneData) []DelegationSyncRequest
		waiting int
		ran     []string
	}{
		{"a live reconciliation past a stored sync",
			func(zd *ZoneData) []DelegationSyncRequest {
				return []DelegationSyncRequest{laneRequest(zd, "SIGNALS-EDITED"), sd(zd, "ns1.example."), laneRequest(zd, "SIGNALS-EDITED")}
			},
			4, []string{"SIGNALS-EDITED", "SYNC-DELEGATION ns1.example.", "SIGNALS-EDITED"}},
		{"a sync past the zone's setup",
			func(zd *ZoneData) []DelegationSyncRequest {
				return []DelegationSyncRequest{sd(zd, "ns1.example."), laneRequest(zd, "DELEGATION-SYNC-SETUP"), sd(zd, "ns2.example.")}
			},
			4, []string{"SYNC-DELEGATION ns1.example.", "DELEGATION-SYNC-SETUP", "SYNC-DELEGATION ns2.example."}},
		{"a sync past a live reconciliation merges",
			func(zd *ZoneData) []DelegationSyncRequest {
				return []DelegationSyncRequest{sd(zd, "ns1.example."), laneRequest(zd, "SIGNALS-EDITED"), sd(zd, "ns2.example.")}
			},
			3, []string{"SYNC-DELEGATION ns1.example.,ns2.example.", "SIGNALS-EDITED"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			zd := laneZone("overtake.down.example.", "down.example.")
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
				ran = append(ran, ranLabel(ds))
				mu.Unlock()
			})
			offer(t, q, laneRequest(zd, "first"))
			receive(t, started, "the first request to start and stick")
			for _, ds := range c.send(zd) {
				offer(t, q, ds)
			}
			allDispatched(t, q, marked)
			if pos := waitingIn(t, zd.ZoneName); pos.Waiting != c.waiting {
				t.Errorf("%d of the zone's requests in the queue, want %d", pos.Waiting, c.waiting)
			}
			close(release)
			waitFor(t, 2*time.Second, "the zone's requests to run", func() bool {
				_, ok := DelegationSyncWaiting(zd.ZoneName)
				return !ok
			})
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(ran, c.ran) {
				t.Errorf("ran %v, want %v", ran, c.ran)
			}
		})
	}
}
