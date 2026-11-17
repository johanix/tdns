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

// A zone that keeps changing behind a parent that does not answer must not
// grow the parent's queue with each change: it keeps one waiting request per
// command, and the merged requests still carry every change. The running
// request is never merged into, since it may have read the zone already.
func TestAZoneThatKeepsChangingDoesNotGrowItsParentsQueue(t *testing.T) {
	zd := laneZone("busy.down.example.", "down.example.")
	const changes = 250

	release := make(chan struct{})
	started := make(chan struct{}, 1)
	var mu sync.Mutex
	var ran []DelegationSyncRequest
	q, _, _ := startLanes(t, func(ctx context.Context, ds DelegationSyncRequest) {
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
	waitFor(t, 2*time.Second, "the intake to drain", func() bool { return len(q) == 0 })
	// The running sync, and one waiting request of each of the four commands.
	waitFor(t, 2*time.Second, "the zone's requests to settle", func() bool {
		pos, ok := DelegationSyncWaiting(zd.ZoneName)
		return ok && pos.Waiting == 5
	})

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
// newer has no opinion about it.
func TestMergeDelegationSyncDiffsLaterOperationWins(t *testing.T) {
	ns1 := mustRR(t, "child.example. 3600 IN NS ns1.example.")
	ns2 := mustRR(t, "child.example. 3600 IN NS ns2.example.")
	ns3 := mustRR(t, "child.example. 3600 IN NS ns3.example.")
	ns4 := mustRR(t, "child.example. 3600 IN NS ns4.example.")
	ds1 := mustRR(t, "child.example. 3600 IN DS 12345 15 2 0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20")

	older := DelegationSyncStatus{
		NsAdds:     []dns.RR{ns1, ns3}, // ns1 is removed again below; ns3 is left alone
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
	m := mergeDelegationSyncDiffs(older, newer)

	has := func(list []dns.RR, rr dns.RR) bool {
		return slices.ContainsFunc(list, func(x dns.RR) bool { return sameRecord(x, rr) })
	}
	for _, c := range []struct {
		what      string
		rr        dns.RR
		add, rmov bool
	}{
		{"added, then removed", ns1, false, true},
		{"removed, then added", ns2, true, false},
		{"added, then left alone", ns3, true, false},
		{"removed, then left alone", ns4, false, true},
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
	if m := mergeDelegationSyncDiffs(older, newer); !m.NewDSKnown || len(m.NewDS) != 0 {
		t.Errorf("newer withdrew the DS, merged has known %v and %d DS", m.NewDSKnown, len(m.NewDS))
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
